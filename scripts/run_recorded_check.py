"""Run one check, preserving its machine-readable success report."""
import json
from pathlib import Path
import subprocess
import sys

report = Path(sys.argv[1])
report.parent.mkdir(parents=True, exist_ok=True)
report.unlink(missing_ok=True)  # A failed run must not leave stale success evidence.
failure = report.with_suffix('.failure.json')
failure.unlink(missing_ok=True)
try:
    result = subprocess.run(sys.argv[2:], text=True, capture_output=True, timeout=590)
except subprocess.TimeoutExpired as error:
    failure.write_text(json.dumps({'returncode':124,'error':'timeout','command':sys.argv[2:]}))
    raise SystemExit(124) from error
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
if result.returncode:
    failure.write_text(json.dumps({'returncode':result.returncode,'command':sys.argv[2:],
                                  'stdout':result.stdout,'stderr':result.stderr},indent=2))
    print(f'Check failed (return code {result.returncode}); evidence: {failure}',file=sys.stderr)
    sys.exit(result.returncode)
json.loads(result.stdout)
report.write_text(result.stdout, encoding="utf-8")
