#!/usr/bin/env python3
"""Exercise the native tracker against a loopback beacon fixture, without EL RPC."""
import argparse
import http.server
import json
import subprocess
import threading
import time

ROOT, PARENT, FULL, NEXT = ("0x" + byte * 32 for byte in ("11", "22", "33", "44"))


class Beacon(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode):
        super().__init__(("127.0.0.1", 0), Handler)
        self.mode = mode
        self.phase = "full"
        self.headers = self.streams = self.lookups = 0


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, obj):
        encoded = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass  # expected when the native two-second deadline cancels a request

    def event(self, name="head_v2"):
        self.wfile.write(f"event: {name}\ndata: {{}}\n\n".encode())
        self.wfile.flush()

    def do_GET(self):
        s = self.server
        if self.path == "/eth/v1/beacon/headers/finalized":
            s.headers += 1
            if s.mode == "timeout" and s.headers == 1:
                time.sleep(2.3)
            return self.respond({"execution_optimistic": False, "finalized": s.mode != "unfinalized",
                                 "data": {"root": ROOT, "canonical": True,
                                          "header": {"message": {"slot": "100"}}}})
        if self.path == f"/eth/v2/beacon/blocks/{ROOT}":
            return self.respond({"version": "gloas", "execution_optimistic": False, "finalized": True,
                                 "data": {"message": {"slot": "100", "body": {"signed_execution_payload_bid": {
                                     "message": {"parent_block_hash": PARENT, "block_hash": FULL}}}}}})
        if self.path == "/eth/v2/debug/fork_choice":
            s.lookups += 1
            phase = s.phase
            status = "empty" if phase == "empty" else "full"
            full_hash = NEXT if phase == "next" else FULL
            nodes = [{"block_root": ROOT, "slot": "101", "payload_status": p, "validity": "valid",
                      "execution_block_hash": h, "extra_data": {"execution_optimistic": phase == "optimistic"}}
                     for p, h in (("empty", PARENT), ("full", full_hash))]
            return self.respond({"data": {"extra_data": {"head": {"block_root": ROOT, "payload_status": status}},
                                          "fork_choice_nodes": nodes}})
        if self.path.startswith("/eth/v1/events?"):
            s.streams += 1
            connection = s.streams
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                time.sleep(.8)
                if s.mode == "events":
                    if connection == 1:
                        s.phase = "empty"
                        self.event()
                        time.sleep(.3)
                        self.event()  # duplicate notification must not duplicate the target
                        time.sleep(.3)
                        s.phase = "optimistic"
                        self.event("execution_payload")
                        time.sleep(.3)
                        return  # exercise reconnect before the next valid FULL head
                    s.phase = "next"
                    self.event()
                time.sleep(.5)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self.send_error(404)


def trial(probe, mode, count, deadline):
    server = Beacon(mode)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    started = time.monotonic()
    try:
        try:
            run = subprocess.run([probe, f"http://127.0.0.1:{server.server_port}", str(count), str(deadline)],
                                 text=True, capture_output=True, timeout=deadline + 5)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError({"mode": mode, "headers": server.headers, "streams": server.streams,
                                  "lookups": server.lookups, "stdout": exc.stdout, "stderr": exc.stderr}) from exc
        elapsed = time.monotonic() - started
        rows = [json.loads(line) for line in run.stdout.splitlines()]
        if mode == "unfinalized":
            assert run.returncode != 0 and "ObservationTimeout" in run.stderr, run.stderr
            assert not rows and server.lookups == 0
        else:
            assert run.returncode == 0, run.stderr
            assert len(rows) == count
            assert all(row["executionAnchor"] == PARENT and row["beaconAnchor"] == ROOT for row in rows)
            if mode == "events":
                assert [row["executionHead"] for row in rows] == [FULL, PARENT, NEXT], rows
                assert server.streams >= 2 and server.lookups >= 4
                assert "UnverifiedConsensusHead" in run.stderr
            if mode == "timeout":
                assert server.headers >= 2 and elapsed >= 3 and "ConsensusTimeout" in run.stderr
        return {"scenario": mode, "passed": True, "seconds": elapsed,
                "updates": rows, "headerRequests": server.headers, "streamConnections": server.streams,
                "headLookups": server.lookups, "stderr": run.stderr}
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    for mode, count, deadline in (("events", 3, 10), ("timeout", 1, 9), ("unfinalized", 1, 3)):
        print(json.dumps(trial(args.probe, mode, count, deadline)), flush=True)


if __name__ == "__main__":
    main()
