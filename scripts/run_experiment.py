"""Record machine, source identity, raw observations, and offline-readable CSVs."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity(root):
    paths = [root / "CMakeLists.txt"]
    for directory in ("include", "src", "apps"):
        paths.extend(p for p in (root / directory).rglob("*") if p.is_file())
    files = {str(p.relative_to(root)): digest(p) for p in sorted(paths)}
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(canonical).hexdigest(), "files": files}


def environment(executable):
    info = {"system": platform.system(), "release": platform.release(),
            "architecture": platform.machine(), "logical_cpus": os.cpu_count(),
            "python": platform.python_version(), "executable_sha256": digest(executable),
            "openmp": False, "native_optimization": False, "build_type": "Release"}
    if sys.platform == "darwin":
        info["cpu"] = command("sysctl", "-n", "machdep.cpu.brand_string")
        info["memory_bytes"] = int(command("sysctl", "-n", "hw.memsize"))
    elif sys.platform.startswith("linux"):
        cpu = Path("/proc/cpuinfo").read_text()
        info["cpu"] = next((x.split(":", 1)[1].strip() for x in cpu.splitlines()
                            if x.startswith("model name")), platform.processor())
        mem = Path("/proc/meminfo").read_text()
        info["memory_bytes"] = int(next(x.split()[1] for x in mem.splitlines()
                                        if x.startswith("MemTotal:"))) * 1024
    cache = executable.parent / "CMakeCache.txt"
    if cache.exists():
        entries = dict(line.split("=", 1) for line in cache.read_text().splitlines()
                       if "=" in line and not line.startswith(("#", "//")))
        compiler = entries.get("CMAKE_CXX_COMPILER:FILEPATH", "c++")
        info["compiler"] = command(compiler, "--version")
        info["cxx_release_flags"] = entries.get("CMAKE_CXX_FLAGS_RELEASE:STRING", "unknown")
    return info


def write_csv(path, header, rows):
    # BOM permits a double-click in Windows Excel without corrupting Chinese.
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--config", type=Path, help="UTF-8 key=value parameter file")
    parser.add_argument('--compact', action='store_true', help='Paper-inspired pair/BV construction')
    for option in ("l", "k", "n", "depth", "slots", "scale-bits", "first-mod-bits", "samples", "warmups",
                   "security-bits", "precision-bits", "key-trials", "message-seed", "smudge-bound", "rotation-steps", "message-bound", "scale-log2", "initial-scale-bits",
                   'divisor-bits', 'gadget-bits', 'public-extra-bits', 'rotation-gadget-bits', 'symmetric-relinearization', 'packed-public-key'):
        parser.add_argument("--" + option, type=float if option in ("message-bound", "scale-log2") else int, default=None)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    executable = args.executable.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name in ("experiment.json", "native-output.json", "timings.csv", "timing-samples.csv",
                 "correctness.csv", "slots.csv", "depth-correctness.csv", "depth-slots.csv",
                 "failure.json", "resolved.conf", "parameters.csv"):
        (output / name).unlink(missing_ok=True)
    identity = source_identity(root)
    metadata = {"started_utc": datetime.now(timezone.utc).isoformat(),
                "source_commit": command("git", "-C", str(root), "rev-parse", "HEAD"),
                "source_identity": identity, "environment": environment(executable)}
    invocation = [str(executable)]
    if args.compact:
        invocation += ['--compact']
    if args.config is not None:
        invocation += ["--config", str(args.config.resolve())]
    for option in ("l", "k", "n", "depth", "slots", "scale-bits", "first-mod-bits", "samples", "warmups",
                   "security-bits", "precision-bits", "key-trials", "message-seed", "smudge-bound", "rotation-steps", "message-bound", "scale-log2", "initial-scale-bits",
                   'divisor-bits', 'gadget-bits', 'public-extra-bits', 'rotation-gadget-bits', 'symmetric-relinearization', 'packed-public-key'):
        value = getattr(args, option.replace("-", "_"))
        if value is not None:
            invocation += ["--" + option, str(value)]
    metadata["invocation"] = invocation
    with (output / "native-output.json").open("w") as native, (output / "experiment.log").open("w") as log:
        process = subprocess.Popen(invocation,
                                   stdout=native, stderr=subprocess.PIPE, text=True)
        for line in process.stderr:
            log.write(line)
            log.flush()
            print(line, end="", file=sys.stderr, flush=True)
        result = process.wait()
    if result or source_identity(root) != identity:
        (output / "failure.json").write_text(json.dumps({"exit_code": result,
            "error": "native failure or implementation changed during run"}, indent=2))
        raise SystemExit(result or 1)
    report = json.loads((output / "native-output.json").read_text())
    report.update(metadata)
    report["completed_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "experiment.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    # Pin the actual N, including when the request was N=0. This snapshot can
    # be fed back to --config to reproduce this workload on another machine.
    resolved = dict(report["requested_parameters"])
    resolved["N"] = report["profile"]["ring_dimension"]
    (output / "resolved.conf").write_text("# Resolved experiment parameters\n" +
        "".join(f"{key} = {value}\n" for key, value in resolved.items()))
    write_csv(output / "parameters.csv", ["parameter", "requested", "resolved"],
              [[key, report["requested_parameters"][key], value] for key, value in resolved.items()])
    write_csv(output / "timings.csv", ["operation", "samples", "mean_ms", "median_ms", "min_ms",
              "max_ms", "stddev_sample_ms", "p95_nearest_rank_ms"],
              [[name, len(item["samples_ms"])] + [item[key] for key in (
                  "mean_ms", "median_ms", "min_ms", "max_ms", "stddev_sample_ms", "p95_nearest_rank_ms")]
               for name, item in report["timings"].items()])
    write_csv(output / "timing-samples.csv", ["operation", "sample_index", "milliseconds"],
              [[name, i + 1, ms] for name, item in report["timings"].items()
               for i, ms in enumerate(item["samples_ms"])])
    metric_rows, slot_rows = [], []
    for case in report["correctness"]:
        for metric in case["metrics"]:
            prefix = [case["trial"], case["case"], metric["operation"]]
            metric_rows.append(prefix + [metric[key] for key in ("level", "scale", "log2_scale",
                "max_absolute_error", "precision_bits", "inverse_scale", "error_times_scale",
                "passes_precision_target", "passes_inverse_scale")])
            for i, (expected, actual, error) in enumerate(zip(metric["expected"], metric["actual"],
                                                             metric["slot_absolute_errors"])):
                slot_rows.append(prefix + [i] + expected + actual + [error])
    write_csv(output / "correctness.csv", ["trial", "case", "operation", "level", "scale", "log2_scale",
              "max_absolute_error", "precision_bits", "inverse_scale", "error_times_scale",
              "passes_precision_target", "passes_inverse_scale"], metric_rows)
    write_csv(output / "slots.csv", ["trial", "case", "operation", "slot", "expected_real", "expected_imag",
              "actual_real", "actual_imag", "absolute_error"], slot_rows)
    depth_rows, depth_slots = [], []
    for case in report['correctness']:
        for layer, metric in enumerate(case.get('depth_circuit', {}).get('metrics', []), 1):
            prefix = [case['trial'], case['case'], layer]
            depth_rows.append(prefix + [metric[key] for key in ('level', 'scale', 'max_absolute_error',
                'precision_bits', 'inverse_scale', 'error_times_scale', 'passes_precision_target', 'passes_inverse_scale')])
            for i, (expected, actual, error) in enumerate(zip(metric['expected'], metric['actual'], metric['slot_absolute_errors'])):
                depth_slots.append(prefix + [i] + expected + actual + [error])
    write_csv(output / 'depth-correctness.csv', ['trial', 'case', 'layer', 'level', 'scale',
        'max_absolute_error', 'precision_bits', 'inverse_scale', 'error_times_scale',
        'passes_precision_target', 'passes_inverse_scale'], depth_rows)
    write_csv(output / 'depth-slots.csv', ['trial', 'case', 'layer', 'slot', 'expected_real',
        'expected_imag', 'actual_real', 'actual_imag', 'absolute_error'], depth_slots)
    print(f"Recorded {len(report['correctness'])} cases and {len(report['timings'])} timed operations in {output}")


if __name__ == "__main__":
    main()
