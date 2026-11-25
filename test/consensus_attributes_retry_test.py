#!/usr/bin/env python3
"""Bounded loopback-only SSE attribute lookup regression; no execution RPC."""
import argparse
import hashlib
import http.server
import json
import socket
import subprocess
import threading
import time

from consensus_tracker_test import Handler as BaseHandler, ROOT, PARENT, FULL

ALT_ROOT, ALT_PARENT = ("0x" + byte * 32 for byte in ("66", "77"))


def attributes(alternate=False):
    root, parent = (ALT_ROOT, ALT_PARENT) if alternate else (ROOT, PARENT)
    return {"version": "gloas", "context": {"role": "alternate" if alternate else "primary"},
            "data": {"proposal_slot": "102", "parent_block_root": root,
                     "parent_block_hash": parent,
                     "payload_attributes": {"timestamp": "1224", "withdrawals": []}}}


class Beacon(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode):
        super().__init__(("127.0.0.1", 0), PersistentHandler if mode == "pooled" else Handler)
        self.mode = mode
        self.headers = self.streams = self.lookups = self.attribute_lookups = 0
        self.initial = threading.Event()
        self.stopping = threading.Event()
        self.active = 0
        self.sent = []
        self.accepts = 0
        self.idle_graph_connection = None

    def get_request(self):
        stream = super().get_request()
        self.accepts += 1
        return stream


class Handler(BaseHandler):
    def do_GET(self):
        s = self.server
        if self.path == "/eth/v2/debug/fork_choice":
            s.lookups += 1
            if s.active:
                s.attribute_lookups += 1
                attempt = s.attribute_lookups
                if s.mode == "lookup_timeout" and attempt == 1:
                    time.sleep(1.3)
                if s.mode in ("recover", "alternates") and attempt in (1, 3):
                    time.sleep(.35)
                if s.mode != "pooled" and (attempt == 1 or (s.mode == "alternates" and attempt == 3) or s.mode == "exhausted"):
                    # Clean EOF before any response header is precisely the
                    # Zig HttpConnectionClosing observed in the retained logs.
                    self.close_connection = True
                    return
                if s.mode in ("lookup_timeout", "cancel"):
                    s.stopping.wait(4)
                    return
            nodes = [{"block_root": root, "slot": "101", "payload_status": status,
                      "validity": "valid", "execution_block_hash": parent,
                      "extra_data": {"execution_optimistic": s.mode == "optimistic" and s.active > 0}}
                     for root, status, parent in ((ROOT, "empty", PARENT), (ROOT, "full", FULL),
                                                   (ALT_ROOT, "full", ALT_PARENT))]
            if s.mode == "unbound" and s.active:
                nodes = [node for node in nodes if node["execution_block_hash"] != PARENT]
            self.respond({"data": {"extra_data": {"head": {"block_root": ROOT, "payload_status": "full"}},
                                    "fork_choice_nodes": nodes}})
            if not s.active:
                s.idle_graph_connection = self.connection
            s.initial.set()
            return
        if self.path.startswith("/eth/v1/events?"):
            s.streams += 1
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                assert s.initial.wait(1), "initial reconciliation did not arrive"
                if s.mode == "pooled":
                    # Let the completed HTTP/1.1 response return to the client's
                    # pool, then close that idle socket. The first attribute GET
                    # is lost before a request reaches this server. The paired
                    # pre-fix control proves this actually exercises stale reuse.
                    time.sleep(.1)
                    s.idle_graph_connection.shutdown(socket.SHUT_RDWR)
                    s.idle_graph_connection.close()
                for alternate in ([False, True] if s.mode == "alternates" else [False]):
                    s.active += 1
                    body = attributes(alternate)
                    if s.mode == "malformed":
                        body["version"] = "fulu"
                    s.sent.append({"body": body, "wallMs": int(time.time() * 1000)})
                    kind = "head_v2" if s.mode == "head_close" else "execution_payload" if s.mode == "payload_close" else "payload_attributes"
                    self.event(kind, body)
                    if s.mode == "alternates":
                        # Keep both frames distinct, without reconnect/replay.
                        time.sleep(.55)
                s.stopping.wait(4)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
            return
        return super().do_GET()


class PersistentHandler(Handler):
    protocol_version = "HTTP/1.1"


def trial(probe, mode, expect_loss=False):
    server = Beacon(mode)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    deadline = 1 if mode == "cancel" else 3
    started = time.monotonic()
    try:
        # Ask for one extra observation to prove no duplicate delivery while the
        # stream remains connected. A bounded observation timeout is expected.
        run = subprocess.run([probe, f"http://127.0.0.1:{server.server_port}", "3", str(deadline), "attributes"],
                             text=True, capture_output=True, timeout=deadline + 3)
        elapsed = time.monotonic() - started
        rows = [json.loads(line) for line in run.stdout.splitlines()]
        expected = 0 if expect_loss else 2 if mode == "alternates" else 1 if mode in ("recover", "pooled") else 0
        assert len(rows) == expected, {"mode": mode, "rows": rows, "stderr": run.stderr,
                                       "attributeLookups": server.attribute_lookups}
        assert run.returncode != 0 and "ObservationTimeout" in run.stderr, run.stderr
        assert server.streams == 1, server.streams
        if expect_loss:
            assert server.attribute_lookups == (0 if mode == "pooled" else 1), server.attribute_lookups
        else:
            expected_lookups = 4 if mode == "alternates" else 1 if mode in ("head_close", "payload_close", "pooled") else 2
            assert server.attribute_lookups == expected_lookups, server.attribute_lookups
        for row, event in zip(rows, server.sent):
            # Match the existing SSE decoder's data-line normalization.
            encoded = "\n".join(line.lstrip(" ") for line in json.dumps(event["body"], indent=2).splitlines()) + "\n"
            assert row["jsonHash"] == "0x" + hashlib.sha256(encoded.encode()).hexdigest(), row
            assert row["parent"] == event["body"]["data"]["parent_block_hash"]
            assert row["beaconRoot"] == event["body"]["data"]["parent_block_root"]
            assert event["wallMs"] <= row["receivedWallMs"] <= event["wallMs"] + 200, row
            assert row["deliveredMonoMs"] - row["receivedMonoMs"] >= (0 if mode == "pooled" else 300), row
        if mode in ("recover", "pooled", "alternates") and not expect_loss:
            assert "head event lookup" not in run.stderr, run.stderr
        if mode in ("exhausted", "head_close", "payload_close") and not expect_loss:
            kind = "head" if mode == "head_close" else "execution_payload" if mode == "payload_close" else "payload_attributes"
            assert f"head event lookup kind={kind}: HttpConnectionClosing" in run.stderr, run.stderr
        if mode == "lookup_timeout" and not expect_loss:
            assert "ConsensusTimeout" in run.stderr, run.stderr
        if mode == "optimistic" and not expect_loss:
            assert "UnverifiedConsensusHead" in run.stderr, run.stderr
        if mode == "unbound" and not expect_loss:
            assert "UnavailableExecutionHead" in run.stderr, run.stderr
        if mode == "malformed" and not expect_loss:
            assert "PostGloasRequired" in run.stderr, run.stderr
        assert elapsed < deadline + 1, elapsed  # cancellation joins the in-flight lookup
        return {"mode": mode, "passed": True, "expectedLoss": expect_loss,
                "seconds": elapsed, "attributeLookups": server.attribute_lookups,
                "streamConnections": server.streams, "tcpAccepts": server.accepts, "attributes": rows, "stderr": run.stderr}
    finally:
        server.stopping.set()
        server.shutdown()
        server.server_close()
        worker.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--expect-loss", action="store_true")
    args = parser.parse_args()
    modes = ("recover", "pooled") if args.expect_loss else ("recover", "pooled", "alternates", "exhausted", "lookup_timeout", "cancel", "optimistic", "unbound", "malformed", "head_close", "payload_close")
    for mode in modes:
        print(json.dumps(trial(args.probe, mode, args.expect_loss)), flush=True)


if __name__ == "__main__":
    main()
