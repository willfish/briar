#!/usr/bin/env python3
"""Matched wall-clock latency comparison between Briar and the pinned oracle.

Both CLIs scan the same immutable corpus with the same detector selection and
verification disabled. Compare complete, order-independent JSON findings before
reporting a speed ratio. Measure startup-inclusive wall time and per-invocation
RSS, not the supervisor's cumulative child-process high-water mark.

The objective is a final full-scope comparison once every identity is ported.
This harness is designed for that final run; use --sample for a quick smoke run
while the migration is still in progress, and never present a sampled run as the
final latency result.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import select
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path("/nix/store/x9i5r16anymg2zn986y866zl3x8a6prq-trufflehog-3.97.2/bin/.trufflehog-wrapped")


def load_fixtures():
    spec = importlib.util.spec_from_file_location("cli_reference", ROOT / "tests/cli_reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selectors(cases):
    ordered = []
    for _, _, selector, _, _ in cases:
        if selector not in ordered:
            ordered.append(selector)
    return ",".join(ordered)


def isolated(command, home):
    return [
        "unshare", "--user", "--map-root-user", "--net", "bash", "-eu", "-c",
        'ip link set dev lo up; exec "$@"', "briar-latency", *command,
    ], {"HOME": home, "PATH": os.environ["PATH"], "LANG": "C.UTF-8"}


def measure(command, environment, timeout):
    """Measure one isolated child with wait4, never cumulative RUSAGE_CHILDREN."""
    # A child-specific wait4 result is essential: RUSAGE_CHILDREN is a lifetime
    # maximum, so a later small process otherwise inherits an earlier peak.
    # pidfds provide a timed wait without reaping the child or polling delays.
    # Regular temporary output files also avoid pipe backpressure during wait4.
    with tempfile.TemporaryDirectory(prefix="run-", dir=environment) as directory:
        home = Path(directory) / "home"
        home.mkdir()
        wrapped, env = isolated(command, str(home))
        started = time.perf_counter()
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(wrapped, stdout=stdout, stderr=stderr,
                                       env=env, start_new_session=True)
            pidfd = None
            try:
                pidfd = os.pidfd_open(process.pid)
                if not select.select([pidfd], [], [], timeout)[0]:
                    raise subprocess.TimeoutExpired(command, timeout)
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                stdout.seek(0)
                stderr.seek(0)
                return {
                    "wall_ms": elapsed_ms, "peak_rss_kib": usage.ru_maxrss,
                    "user_ms": usage.ru_utime * 1000, "system_ms": usage.ru_stime * 1000,
                    "stdout": stdout.read(), "stderr": stderr.read(), "exit": process.returncode,
                }
            finally:
                if pidfd is not None:
                    os.close(pidfd)
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()


def findings(payload):
    rows = [json.loads(line) for line in payload.splitlines() if line.strip()]
    if any(not isinstance(row, dict) or "DetectorType" not in row for row in rows):
        raise ValueError("scanner output is not JSON findings")
    ordered = sorted(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)
    return {"count": len(rows), "sha256": hashlib.sha256("\n".join(ordered).encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=0,
                        help="use only the first N filesystem fixtures (smoke run)")
    parser.add_argument("--runs", type=int, default=5, help="measured runs after one warmup")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--out", default="state/latency/latest.json")
    parser.add_argument("--label", default="smoke")
    parser.add_argument("--corpus", type=Path, help="flat directory of synthetic files, each at most 64 KiB")
    parser.add_argument("--detectors", help="explicit detector CSV; required with --corpus")
    parser.add_argument("--reference-concurrency", type=int, default=1)
    args = parser.parse_args()
    if args.runs < 1 or args.sample < 0 or args.timeout < 1 or args.reference_concurrency < 1:
        parser.error("runs, timeout and concurrency must be positive; sample must be nonnegative")
    if args.corpus and (args.sample or not args.detectors):
        parser.error("--corpus requires --detectors and cannot be combined with --sample")
    if any(shutil.which(tool) is None for tool in ("unshare", "ip")) or not hasattr(os, "pidfd_open"):
        parser.error("Linux pidfds, unshare and ip are required")

    (ROOT / "state").mkdir(exist_ok=True)
    module = load_fixtures()
    if args.corpus:
        cases = [(path.name, path.read_bytes(), args.detectors, "filesystem", False)
                 for path in sorted(args.corpus.iterdir()) if path.is_file()]
    else:
        cases = [case for case in module.fixtures() if case[3] == "filesystem"]
        if args.sample:
            cases = cases[:args.sample]
    if not cases or any(len(case[1]) > 65536 for case in cases):
        parser.error("the corpus must contain files, each at most 64 KiB")
    selection = args.detectors or selectors(cases)
    native = ROOT / "build/briar"
    if not native.exists() or not REFERENCE.exists():
        sys.exit("missing native binary or pinned oracle")
    module.check_reference_version(REFERENCE)

    temporary = tempfile.TemporaryDirectory(prefix="briar-latency-", dir=ROOT / "state")
    work = Path(temporary.name)
    corpus = work / "corpus"
    home = work / "home"
    corpus.mkdir()
    home.mkdir()
    digest = hashlib.sha256()
    total_bytes = 0
    for index, (name, source, _, _, _) in enumerate(cases):
        (corpus / f"{index:05d}.txt").write_bytes(source)
        digest.update(name.encode() + b"\0" + source)
        total_bytes += len(source)
    files = sorted(str(path) for path in corpus.iterdir())

    native_command = [str(native), "filesystem", *files, "--json", "--no-verification",
                      "--include-detectors=" + selection]
    reference_command = [str(REFERENCE), "--no-update", f"--concurrency={args.reference_concurrency}", "filesystem",
                         *files, "--json", "--no-verification",
                         "--include-detectors=" + selection]

    commands = {"native": native_command, "reference": reference_command}
    warmups, measurements, order = {}, {"native": [], "reference": []}, []
    load_before = os.getloadavg()

    def scan(label):
        measured = measure(commands[label], str(home), args.timeout)
        if measured["exit"]:
            sys.exit(f"{label} exited {measured['exit']}; stderr bytes={len(measured['stderr'])}")
        enabled = re.search(rb"(\d+) explicitly selected enabled detector", measured["stderr"])
        measured["enabled_implementations"] = int(enabled[1]) if enabled else None
        measured["findings"] = findings(measured.pop("stdout"))
        measured.pop("stderr")
        return measured

    for label in commands:
        warmups[label] = scan(label)
    for index in range(args.runs):
        pair = ("native", "reference") if index % 2 == 0 else ("reference", "native")
        for label in pair:
            order.append(label)
            measurements[label].append(scan(label))

    runs = {}
    for label, measured in measurements.items():
        times = [run["wall_ms"] for run in measured]
        rss = [run["peak_rss_kib"] for run in measured]
        runs[label] = {
            "warmup_ms": round(warmups[label]["wall_ms"], 3),
            "runs_ms": [round(value, 3) for value in times],
            "median_ms": round(statistics.median(times), 1),
            "min_ms": round(min(times), 1),
            "max_ms": round(max(times), 1),
            "peak_rss_kib": max(rss),
            "median_peak_rss_kib": statistics.median(rss),
            "runs_peak_rss_kib": rss,
            "runs_user_ms": [run["user_ms"] for run in measured],
            "runs_system_ms": [run["system_ms"] for run in measured],
            "findings": warmups[label]["findings"]["count"],
            "result_sha256": warmups[label]["findings"]["sha256"],
            "stable_results": all(run["findings"] == warmups[label]["findings"] for run in measured),
            "enabled_implementations": warmups[label]["enabled_implementations"],
        }
        print(f"{label}: median {runs[label]['median_ms']} ms over {args.runs} runs, "
              f"{runs[label]['findings']} findings, median peak RSS {runs[label]['median_peak_rss_kib']} KiB", flush=True)

    comparable = (all(run["stable_results"] for run in runs.values()) and
                  warmups["native"]["findings"] == warmups["reference"]["findings"])
    ratio = (statistics.median(run["wall_ms"] for run in measurements["reference"]) /
             statistics.median(run["wall_ms"] for run in measurements["native"])) if comparable else None
    if any((corpus / f"{index:05d}.txt").read_bytes() != case[1] for index, case in enumerate(cases)):
        sys.exit("a scanner modified the input corpus; measurements discarded")
    note = ("Synthetic external corpus; not a full-scope comparison of every upstream identity."
            if args.corpus else "Smoke run while the migration is incomplete; not the final full-scope latency result."
            if args.sample else "All committed filesystem fixtures; not a full-scope comparison until every identity is ported.")
    record = {
        "label": args.label,
        "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "final": False,
        "comparable": comparable,
        "note": note,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "corpus": {
            "files": len(cases),
            "bytes": total_bytes,
            "sha256": digest.hexdigest(),
            "selectors": selection,
            "detectors": len(selection.split(",")),
            "source": str(args.corpus.resolve()) if args.corpus else "committed filesystem fixtures",
        },
        "runs": runs,
        "ratio_reference_over_native": round(ratio, 3) if ratio is not None else None,
        "environment": {
            "native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
            "reference_sha256": hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "reference_version": json.loads((ROOT / "UPSTREAM.json").read_text())["version"],
            "namespace": "unshare -Urn",
            "home": "fresh empty HOME per invocation",
            "verification": "disabled on both sides",
            "concurrency": f"oracle --concurrency={args.reference_concurrency}; native single-process",
            "measurement_order": order,
            "rss": "wait4 per-child peak, KiB on Linux, including isolation setup; no cumulative supervisor peak",
            "wall_time": "startup inclusive, including network namespace setup and JSON output",
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                               if line.startswith("model name")), "unknown"),
            "kernel": os.uname().release,
            "load_average_before": load_before,
            "load_average_after": os.getloadavg(),
        },
    }
    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2) + "\n")
    temporary.cleanup()
    if comparable:
        print(f"matched complete JSON findings; reference/native {ratio:.3f}x over {len(cases)} files; record {out_path}", flush=True)
    else:
        print(f"Findings differ or vary between runs; no comparable speed ratio. Record {out_path}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
