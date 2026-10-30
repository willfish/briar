#!/usr/bin/env python3
"""Matched wall-clock latency comparison between Briar and the pinned oracle.

Both CLIs scan the same immutable corpus with the same detector selection and
verification disabled. This script measures startup-inclusive wall time, which
is what a user observes, and reports the aggregate finding count from each side
so a timing run cannot silently compare different work.

The objective is a final full-scope comparison once every identity is ported.
This harness is designed for that final run; use --sample for a quick smoke run
while the migration is still in progress, and never present a sampled run as the
final latency result.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import resource
import shutil
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


def isolated(command, timeout, home):
    return [
        "unshare", "--user", "--map-root-user", "--net", "bash", "-eu", "-c",
        'ip link set dev lo up; exec "$@"', "briar-latency", *command,
    ], {"HOME": home, "PATH": os.environ["PATH"], "LANG": "C.UTF-8"}


def measure(command, environment, timeout):
    """Return (wall_ms, max_rss_kib, stdout, stderr, exit)."""
    wrapped, env = isolated(command, timeout, environment)
    started = time.perf_counter()
    process = subprocess.Popen(wrapped, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = process.communicate(timeout=timeout)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return elapsed_ms, usage.ru_maxrss, out, err, process.returncode


def count_rows(payload):
    rows = 0
    for line in payload.splitlines():
        if line.startswith(b"{"):
            rows += 1
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=0,
                        help="use only the first N filesystem fixtures (smoke run)")
    parser.add_argument("--runs", type=int, default=5, help="measured runs after one warmup")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--out", default="state/latency/latest.json")
    parser.add_argument("--label", default="smoke")
    args = parser.parse_args()

    module = load_fixtures()
    cases = [case for case in module.fixtures() if case[3] == "filesystem"]
    if args.sample:
        cases = cases[:args.sample]
    selection = selectors(cases)
    native = ROOT / "build/briar"
    if not native.exists() or not REFERENCE.exists():
        sys.exit("missing native binary or pinned oracle")

    work = Path(tempfile.mkdtemp(prefix="briar-latency-", dir=ROOT / "state"))
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
    reference_command = [str(REFERENCE), "--no-update", "--concurrency=1", "filesystem",
                         str(corpus), "--json", "--no-verification",
                         "--include-detectors=" + selection]

    runs = {}
    for label, command in (("native", native_command), ("reference", reference_command)):
        warm_ms, _, out, err, code = measure(command, str(home), args.timeout)
        if code != 0:
            sys.exit(f"{label} warmup exited {code}: {err[-400:]}")
        warm_rows = count_rows(out)
        times, rss = [], []
        for _ in range(args.runs):
            elapsed, peak, out, err, code = measure(command, str(home), args.timeout)
            if code != 0:
                sys.exit(f"{label} run exited {code}: {err[-400:]}")
            if count_rows(out) != warm_rows:
                sys.exit(f"{label} produced unstable finding counts")
            times.append(elapsed)
            rss.append(peak)
        runs[label] = {
            "warmup_ms": round(warm_ms, 1),
            "runs_ms": [round(value, 1) for value in times],
            "median_ms": round(statistics.median(times), 1),
            "min_ms": round(min(times), 1),
            "max_ms": round(max(times), 1),
            "peak_rss_kib": max(rss),
            "findings": warm_rows,
        }
        print(f"{label}: median {runs[label]['median_ms']} ms over {args.runs} runs, "
              f"{warm_rows} findings, peak RSS {runs[label]['peak_rss_kib']} KiB", flush=True)

    if runs["native"]["findings"] != runs["reference"]["findings"]:
        print("WARNING: finding counts differ; timing is not comparable", file=sys.stderr)
    ratio = runs["reference"]["median_ms"] / runs["native"]["median_ms"] if runs["native"]["median_ms"] else 0.0
    record = {
        "label": args.label,
        "final": False,
        "note": ("Smoke run while the migration is incomplete; not the final full-scope latency result."
                 if args.sample or "sample" in args.label else
                 "Corpus is the committed fixture set; this is not the final full-scope comparison until every identity is ported."),
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "corpus": {
            "files": len(cases),
            "bytes": total_bytes,
            "sha256": digest.hexdigest(),
            "selectors": selection,
            "detectors": len(selection.split(",")),
        },
        "runs": runs,
        "ratio_reference_over_native": round(ratio, 3),
        "environment": {
            "native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
            "reference_sha256": hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),
            "namespace": "unshare -Urn",
            "home": "initially empty",
            "verification": "disabled on both sides",
            "concurrency": "oracle --concurrency=1; native single-process",
        },
    }
    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"ratio (reference/native) {ratio:.3f}x over {len(cases)} files; record {out_path}", flush=True)
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
