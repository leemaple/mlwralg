"""Run one check, preserving its machine-readable success report."""
import json
from pathlib import Path
import subprocess
import sys

report = Path(sys.argv[1])
report.parent.mkdir(parents=True, exist_ok=True)
report.unlink(missing_ok=True)  # A failed run must not leave stale success evidence.
result = subprocess.run(sys.argv[2:], text=True, capture_output=True, timeout=590)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
if result.returncode:
    sys.exit(result.returncode)
json.loads(result.stdout)
report.write_text(result.stdout, encoding="utf-8")
