"""SIGKILL around native state/checkpoint commits, then independently reopen."""
import argparse
import json
from pathlib import Path
import select
import signal
import subprocess
import tempfile


def trial(probe, phase, expected):
    with tempfile.TemporaryDirectory(prefix="zevm-state-crash-") as directory:
        path = Path(directory) / "db"
        path.mkdir()
        subprocess.run([probe, "init", str(path)], capture_output=True, check=True, timeout=10)
        process = subprocess.Popen([probe, phase, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 10)[0]:
                raise RuntimeError("Native crash barrier timed out")
            line = process.stdout.readline()
            if not line:
                _, stderr = process.communicate(timeout=10)
                raise RuntimeError(f"Native crash probe exited before barrier: {stderr}")
            if json.loads(line) != {"ready": phase}:
                raise RuntimeError("Unexpected native crash barrier")
            process.kill()
            _, stderr = process.communicate(timeout=10)
            assert process.returncode == -signal.SIGKILL, (process.returncode, stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
        reopened = subprocess.run([probe, "inspect", str(path)], capture_output=True, text=True, check=True, timeout=10)
        result = json.loads(reopened.stdout)
        assert result["authenticated"] and result["number"] == expected and result["balance"] == expected * 42, result
        return {"phase": phase, "signal": "SIGKILL", "passed": True, "reopened": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    for phase, expected in (("before-commit", 1), ("after-commit", 2)):
        print(json.dumps(trial(str(Path(args.probe).resolve()), phase, expected)), flush=True)


if __name__ == "__main__":
    main()
