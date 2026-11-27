#!/usr/bin/env python3
"""Summarize complete matched blocks without treating within-process pairs as independent."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dist(values):
    return {"n": len(values), "min": min(values), "median": statistics.median(values),
            "max": max(values), "values": values}


def mean(values):
    return statistics.mean(values)


def metrics(rows):
    def native_total(row, field):
        return sum(branch["native"][field] for branch in row["finalMetrics"])

    seals = sum(native_total(row, "seal_calls") for row in rows)
    return {
        "inLoopProcessCpuMs": mean([row["cpuNs"] for row in rows]) / 1e6,
        "inLoopElapsedMs": mean([row["elapsedNs"] for row in rows]) / 1e6,
        "sealCpuPerSealMs": sum(native_total(row, "seal_cpu_ns") for row in rows) / seals / 1e6,
        "sealWallPerSealMs": sum(native_total(row, "seal_wall_ns") for row in rows) / seals / 1e6,
        "stateRootWallMs": mean([sum(b["native"]["seal_stage_ns"][4] for b in row["finalMetrics"]) for row in rows]) / 1e6,
        "lateQueueMs": mean([row["lateQueueNs"] for row in rows]) / 1e6,
        "lateReceiveToPrimaryPublicationMs": mean([row["lateToPublicationNs"][0] for row in rows]) / 1e6,
        "lateAppendToPrimaryPublicationMs": mean([row["lateToPublicationNs"][0] - row["lateToAppendNs"][0] for row in rows]) / 1e6,
        "nodeReads": mean([native_total(row, "node_reads") for row in rows]),
        "fallbackReads": mean([sum(b["node_cache"]["fallback_reads"] for b in row["finalMetrics"]) for row in rows]),
        "ownerReads": mean([sum(b["node_cache"]["owner_reads"] for b in row["finalMetrics"]) for row in rows]),
        "seals": mean([sum(row["sealsByBranch"]) for row in rows]),
        "peakSealScratchBytes": max(b["native"]["seal_scratch_peak_bytes"] for row in rows for b in row["finalMetrics"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs=3, type=Path)
    args = parser.parse_args()
    result = {"scriptSha256": sha(Path(__file__)), "blocks": [], "pairs": [], "summary": {},
              "independentUnit": "process; two measured observations per schedule inside each process",
              "timingScope": "synthetic native owner loop, not publisher Prepared, gossip or live deadlines"}
    expected_binaries = None
    expected_fixture = None
    payloads = {}
    fixed_cache = None
    fixed_counts = None
    for block, path in enumerate(args.manifests):
        manifest = json.loads(path.read_text())
        assert manifest["qualified"] and manifest["literalPayloadAndReceiptEquality"] and manifest["fixedWorkEqual"]
        order = "".join("A" if arm == "control" else "B" for arm in manifest["order"])
        assert order == ("BAAB" if block == 1 else "ABBA")
        binaries = {arm: item["sha256"] for arm, item in manifest["binaries"].items()}
        fixture = sha(path.parent / "fixture.zig")
        if expected_binaries is None:
            expected_binaries, expected_fixture = binaries, fixture
        assert binaries == expected_binaries and fixture == expected_fixture
        runs = []
        for run in manifest["runs"]:
            assert run["exitCode"] == 0 and len(run["samples"]) == 6
            for schedule, item in run["payloads"].items():
                artifact = path.parent / item["path"]
                assert sha(artifact) == item["sha256"]
                data = artifact.read_bytes()
                if schedule not in payloads:
                    payloads[schedule] = data
                assert data == payloads[schedule]
            for row in run["samples"]:
                if row["schedule"] != "fixed_work":
                    continue
                comparable = [{key: value for key, value in b["node_cache"].items() if key != "owner_reads"} for b in row["finalMetrics"]]
                counts = [[b["native"][key] for key in ("account_reads", "storage_reads", "code_reads", "node_reads", "node_bytes", "seal_calls", "append_calls", "transaction_attempts")] for b in row["finalMetrics"]]
                if fixed_cache is None:
                    fixed_cache, fixed_counts = comparable, counts
                assert comparable == fixed_cache and counts == fixed_counts
                for b in row["finalMetrics"]:
                    stat = b["node_cache"]
                    assert stat["owner_reads"] == (stat["fallback_reads"] if run["arm"] == "control" else 0)
            scheduled = {}
            for schedule in ("fixed_work", "deployed_owner"):
                rows = [row for row in run["samples"] if row["schedule"] == schedule and not row["warmup"]]
                assert len(rows) == 2 and {row["primaryId"] for row in rows} == {1, 2}
                scheduled[schedule] = metrics(rows)
            noise = [json.loads(line) for line in (path.parent / f'{run["index"]}-{run["arm"]}.noise.jsonl').read_text().splitlines()]
            loads = [row["loadAverage"][0] for row in noise]
            pressure = [float(row["files"]["/proc/pressure/cpu"].split("avg10=", 1)[1].split()[0]) for row in noise]
            runs.append({"index": run["index"], "arm": run["arm"], "metrics": scheduled,
                         "processUsage": run["processUsage"],
                         "load1Range": [min(loads), max(loads)], "cpuPressureAvg10Range": [min(pressure), max(pressure)]})
        assert len(runs) == 4
        result["blocks"].append({"index": block, "order": order, "manifestSha256": sha(path),
                                 "startedUtc": manifest["startedUtc"], "finishedUtc": manifest["finishedUtc"], "runs": runs})
        for indices in ((0, 1), (2, 3)):
            control = next(runs[i] for i in indices if runs[i]["arm"] == "control")
            treatment = next(runs[i] for i in indices if runs[i]["arm"] == "treatment")
            pair = {"block": block, "controlProcess": control["index"], "treatmentProcess": treatment["index"], "metrics": {}}
            for schedule in ("fixed_work", "deployed_owner"):
                pair["metrics"][schedule] = {
                    field: {"control": value, "treatment": treatment["metrics"][schedule][field],
                            "difference": treatment["metrics"][schedule][field] - value,
                            "percent": (treatment["metrics"][schedule][field] / value - 1) * 100 if value else None}
                    for field, value in control["metrics"][schedule].items()}
            result["pairs"].append(pair)
    for schedule in ("fixed_work", "deployed_owner"):
        result["summary"][schedule] = {
            field: {"control": dist([pair["metrics"][schedule][field]["control"] for pair in result["pairs"]]),
                    "treatment": dist([pair["metrics"][schedule][field]["treatment"] for pair in result["pairs"]]),
                    "pairedDifference": dist([pair["metrics"][schedule][field]["difference"] for pair in result["pairs"]]),
                    "pairedPercent": dist([pair["metrics"][schedule][field]["percent"] for pair in result["pairs"]])}
            for field in result["pairs"][0]["metrics"][schedule]}
    first = json.loads(payloads["fixed_work"])
    other = json.loads(payloads["deployed_owner"])
    assert first["primary"] == other["primary"] and first["secondary"] == other["secondary"]
    result.update(qualified=True, binaries=expected_binaries, fixtureSha256=expected_fixture,
                  literalCompletePayloadAndSupplementalReceiptEquality=True,
                  payloadArtifactSha256={key: hashlib.sha256(value).hexdigest() for key, value in payloads.items()},
                  stateRoots=[bytes(first[key]["header"]["state_root"]).hex() for key in ("primary", "secondary")],
                  blockHashes=[bytes(first[key]["block_hash"]).hex() for key in ("primary", "secondary")],
                  fixedCacheStatisticsExceptOwnerReads=fixed_cache, fixedNativeCounts=fixed_counts)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
