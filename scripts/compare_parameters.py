"""Compare actual shared parameters from two execution reports, without rounding."""
import json
from pathlib import Path
import sys

left, right = [json.loads(Path(path).read_text()) for path in sys.argv[1:3]]
fixture = json.loads((Path(__file__).resolve().parents[1] / "tests/fixtures/parameters.json").read_text())
for report in (left, right):
    if report["profile"] != fixture["profile"]:
        raise SystemExit("Execution profile differs from pinned parameter fixture")
    for key in ("public_modulus_primes", "source_modulus_primes"):
        if key in report and report[key] != fixture[key]:
            raise SystemExit("Research modulus differs from pinned parameter fixture: " + key)
if left["profile"] != right["profile"]:
    keys = set(left["profile"]) | set(right["profile"])
    different = [key for key in sorted(keys) if left["profile"].get(key) != right["profile"].get(key)]
    raise SystemExit("Parameter mismatch: " + ", ".join(different))
for report in (left, right):
    for name, value in report["max_absolute_error"].items():
        if not 0 <= value <= 1e-6:
            raise SystemExit(f"Invalid error result: {name}={value}")
print("PASS: identical shared profile, ordered RNS primes, roots, auxiliary basis, and encoding scales")
