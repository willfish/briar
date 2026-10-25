#!/usr/bin/env python3
"""Compare implemented CLI slices and PLAIN/BASE64 decoding with the pinned reference.

Both programs run in a network namespace with an empty HOME. This is a slice
acceptance check, not a declaration of global TruffleHog parity. Fixtures are
synthetic; mismatch messages never print candidate values.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def synthetic(label, length):
    material = b""
    counter = 0
    while len(material) < length:
        material += hashlib.sha256(f"briar-offline-fixture:{label}:{counter}".encode()).hexdigest().encode()
        counter += 1
    return material[:length]


def alnum(label, length):
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    material = b""
    counter = 0
    while len(material) < length:
        material += bytes(alphabet[byte % len(alphabet)] for byte in hashlib.sha256(f"briar-alnum:{label}:{counter}".encode()).digest())
        counter += 1
    return material[:length]


def fixtures():
    cases = []
    for name, length, number in (("abuseipdb", 80, 521), ("abyssale", 40, 239)):
        key = synthetic(name, length)
        base = name.encode()
        for label, payload in (
            ("normal", base + b" key: " + key),
            ("keyword_case", base.upper() + b" key: " + key),
            ("no_keyword", b"unrelated " + key),
            ("prefix_40", base + b" " * 40 + key),
            ("prefix_41", base + b" " * 41 + key),
            ("word_suffix", base + b" " + key + b"z"),
            ("multiple", base + b" " + key + b"\n" + base + b" " + synthetic(name + "second", length)),
            ("duplicate", base + b" " + key + b"\n" + base + b" " + key),
            ("false_positive", base + b" " + b"x" * length),
        ):
            cases.append((name + "_" + label, payload, str(number), "stdin", False))
        cases.append((name + "_cleaning", base + b" " + key + b"\n" + base + b" " + synthetic(name + "second", length), str(number), "stdin", True))
        cases.append((name + "_filesystem", b"ordinary first line\n" + base + b" key: " + key + b"\n", str(number), "filesystem", False))
    for version in (1, 2):
        key = alnum(f"accuweather-v{version}", 32) + (b"%3D" if version == 1 else b"")
        other = alnum(f"accuweather-v{version}-second", 32) + (b"%3D" if version == 1 else b"")
        selector = f"303.v{version}"
        for label, payload in (
            ("normal", b"accuweather " + key),
            ("multiple", b"accuweather " + key + b"\naccuweather " + other),
            ("duplicate", b"accuweather " + key + b"\naccuweather " + key),
            ("low_entropy", b"accuweather " + b"x" * len(key)),
            ("prefix_40", b"accuweather" + b" " * 40 + key),
            ("prefix_41", b"accuweather" + b" " * 41 + key),
        ):
            cases.append((f"accuweather_v{version}_" + label, payload, selector, "stdin", False))
    legacy = alnum("accuweather-wildcard", 32) + b"%3D"
    cases.append(("accuweather_version_wildcard", b"accuweather " + legacy, "303", "stdin", False))
    aio = b"aio_" + alnum("adafruitio", 28)
    for label, payload in (("normal", b"adafruitio " + aio), ("bare", aio), ("duplicate", aio + b"\n" + aio)):
        cases.append(("adafruitio_" + label, payload, "390", "stdin", False))
    key = synthetic("abyssale", 40)
    replacement = "\ufffd".encode()
    for label, payload in (
        ("ascii_baseline", b"abyssale " + key + b"\n"),
        ("valid_nonascii_surrounding", "\u00e9 abyssale ".encode() + key + " \u4e16\u754c\n".encode()),
        ("valid_40_runes_80_bytes", b"abyssale" + "\u00e9".encode() * 40 + key + b"\n"),
        ("valid_41_runes_82_bytes", b"abyssale" + "\u00e9".encode() * 41 + key + b"\n"),
        ("invalid_before_keyword", b"\xffabyssale " + key + b"\n"),
        ("invalid_after_key", b"abyssale " + key + b"\xff\n"),
        ("invalid_20_pairs_40_bytes", b"abyssale" + b"\xc0\x80" * 20 + key + b"\n"),
        ("invalid_21_pairs_42_bytes", b"abyssale" + b"\xc0\x80" * 21 + key + b"\n"),
        ("truncated_2_byte_tail", b"abyssale " + key + b"\xc2"),
        ("truncated_3_byte_tail", b"abyssale " + key + b"\xe2\x82"),
        ("truncated_4_byte_tail", b"abyssale " + key + b"\xf0\x9f\x92"),
        ("valid_controls", b"abyssale\0\t\n\r\f\x7f" + key),
        ("invalid_controls", b"abyssale\0\t\n\r\f\x7f" + key + b"\xff"),
        ("valid_literal_replacement_40", b"abyssale" + replacement * 40 + key),
        ("invalid_literal_replacement_13", b"abyssale" + replacement * 13 + b"\xff" + key),
        ("invalid_literal_replacement_14", b"abyssale" + replacement * 14 + b"\xff" + key),
    ):
        cases.append(("plain_utf8_" + label, payload, "239", "stdin", False))
    lines = b"heading\nabyssale " + key + b"\nabyssale " + key + b"\n"
    ignore = b"heading\nabyssale " + key + b"\n# trufflehog:ignore\n"
    for label, payload in (
        ("valid_lines", lines), ("invalid_lines", lines + b"\xff"),
        ("valid_ignore_next_line", ignore), ("invalid_ignore_next_line", ignore + b"\xff"),
    ):
        cases.append(("plain_utf8_" + label, payload, "239", "filesystem", False))

    plain = b"abyssale " + key
    other = b"abyssale " + synthetic("base64-second", 40)
    encoded = base64.b64encode(plain)
    encoded_other = base64.b64encode(other)
    raw_url = base64.urlsafe_b64encode(b"???" + plain).rstrip(b"=")
    assert b"_" in raw_url
    nested = encoded
    for label, payload in (
        ("standard", encoded),
        ("standard_slash", base64.b64encode(b"???" + plain)),
        ("raw_url", raw_url),
        ("unpadded", encoded.rstrip(b"=")),
        ("assignment", b"secret=" + encoded),
        ("key_assignment", b"abyssale key=" + base64.b64encode(key)),
        ("quoted_assignment", b"secret='" + encoded + b"'"),
        ("leading_end_chars", b"+-_/=" + encoded),
        ("two_encoded_findings", encoded + b"\n" + encoded_other),
        ("encoded_duplicate", encoded + b"\n" + encoded),
        ("mixed_plain_encoded", plain + b"\n" + encoded_other),
        ("mixed_encoded_plain", encoded_other + b"\n" + plain),
        ("plain_encoded_duplicate", plain + b"\n" + encoded),
        ("encoded_plain_duplicate", encoded + b"\n" + plain),
        ("intermediate_findings", encoded + b"\n" + base64.b64encode(encoded_other)),
        ("false_positive", base64.b64encode(b"abyssale " + b"x" * 40)),
        ("no_keyword", base64.b64encode(b"unrelated " + key)),
    ):
        cases.append(("base64_" + label, payload, "239", "stdin", False))
    for depth in range(2, 7):
        nested = base64.b64encode(nested)
        cases.append((f"base64_nested_{depth}", nested, "239", "stdin", False))
    cases.append(("base64_cleaning", encoded + b"\n" + encoded_other, "239", "stdin", True))
    cases.append(("base64_multiple_detectors", encoded + b"\n" + base64.b64encode(b"abuseipdb " + synthetic("abuseipdb", 80)),
                  "239,521", "stdin", False))
    for label, payload, selector in (
        ("adafruitio", b"aio_" + alnum("adafruitio-base64", 28), "390"),
        ("accuweather_v2", b"accuweather " + alnum("accuweather-base64", 32), "303.v2"),
    ):
        cases.append(("base64_" + label, base64.b64encode(payload), selector, "stdin", False))
    multiline = base64.b64encode(b"heading\n" + plain + b"\n")
    for label, payload in (
        ("filesystem_multiline", b"file header\n" + multiline + b"\n"),
        ("filesystem_duplicates", b"header\n" + encoded + b"\n" + encoded + b"\n"),
        ("filesystem_same_line_duplicates", encoded + b"; " + encoded),
        ("filesystem_mixed_duplicate", b"header\n" + plain + b"\n" + encoded),
        ("filesystem_shifted_plain", multiline + b"\n" + other),
        ("filesystem_encoded_ignore", base64.b64encode(plain + b" # trufflehog:ignore")),
        ("original_bytes_fanout", b"header\n" + encoded + b"\n" + b"." * 1024 + b"\xff"),
    ):
        cases.append(("base64_" + label, payload, "239", "filesystem", False))
    return cases


def run_isolated(command, source=b"", timeout=45):
    isolated = ["unshare", "--user", "--map-root-user", "--net", "bash", "-eu", "-c",
                'ip link set dev lo up; exec "$@"', "briar-reference", *command]
    with tempfile.TemporaryDirectory(prefix="briar-empty-home-", dir=ROOT / "state") as home:
        assert not list(Path(home).iterdir())
        return subprocess.run(isolated, input=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, env={"HOME": home, "PATH": os.environ["PATH"], "LANG": "C.UTF-8"})


def invoke(binary, source, detector, kind, cleaning, directory, reference_run=False):
    command = [str(binary)]
    if reference_run:
        # Controls for the Go oracle, not claims that native updater/concurrency
        # options are already ported. Compare only the shared implemented path.
        command.extend(["--no-update", "--concurrency=1"])
    command.extend(["--no-verification", "--json", "--include-detectors=" + detector])
    if cleaning:
        command.append("--filter-unverified")
    command.append(kind)
    stdin = source
    if kind == "filesystem":
        path = directory / "fixture.txt"
        path.write_bytes(source)
        command.append(str(path))
        stdin = b""
    result = run_isolated(command, stdin)
    if result.returncode != 0:
        raise AssertionError(f"{binary.name} exited {result.returncode}; stderr bytes={len(result.stderr)}")
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return sorted(rows, key=lambda row: (row["DetectorType"], row["Raw"], json.dumps(row.get("SourceMetadata"), sort_keys=True)))


def reference_matches(case, actual, expected):
    # The oracle has eight detector workers even at --concurrency=1. Notifier
    # dedup is first-arrival, not decoder-priority: repeated identical runs can
    # retain either label for a finding present in PLAIN and BASE64. Native
    # ordering stays PLAIN-first; only these observed duplicate identities vary.
    racing = {
        "base64_mixed_plain_encoded", "base64_mixed_encoded_plain",
        "base64_plain_encoded_duplicate", "base64_encoded_plain_duplicate",
        "base64_filesystem_mixed_duplicate",
    }
    name, source, _, kind, _ = case
    if len(actual) != len(expected):
        return False
    for got, want in zip(actual, expected):
        if got == want:
            continue
        if name not in racing or got["DecoderName"] != "PLAIN" or want["DecoderName"] != "BASE64":
            return False
        offset = source.find(got["Raw"].encode())
        if offset < 0:
            return False
        if kind == "filesystem" and got["SourceMetadata"]["Data"]["Filesystem"]["line"] != 1 + source[:offset].count(b"\n"):
            return False
        if {key: value for key, value in got.items() if key != "DecoderName"} != {key: value for key, value in want.items() if key != "DecoderName"}:
            return False
    return True


def compare(native, reference, case):
    name, source, detector, kind, cleaning = case
    with tempfile.TemporaryDirectory(prefix="briar-reference-", dir=ROOT / "state") as tmp:
        directory = Path(tmp)
        expected = invoke(reference, source, detector, kind, cleaning, directory, reference_run=True)
        actual = invoke(native, source, detector, kind, cleaning, directory)
    if not reference_matches(case, actual, expected):
        details = [f"result counts native={len(actual)}, reference={len(expected)}"]
        for index, (got, want) in enumerate(zip(actual, expected)):
            differing = sorted(key for key in set(got) | set(want) if got.get(key) != want.get(key) or (key in got) != (key in want))
            if differing:
                details.append(f"result {index} differing fields={','.join(differing)}")
        raise AssertionError(name + ": " + "; ".join(details))


def check_reference_version(reference):
    version = json.loads((ROOT / "UPSTREAM.json").read_text())["version"]
    result = run_isolated([str(reference), "--no-update", "--version"], timeout=30)
    output = (result.stdout + result.stderr).decode(errors="replace")
    if result.returncode or not re.search(r"(?<![\d.])" + re.escape(version) + r"(?![\d.])", output):
        raise SystemExit("reference executable is not the pinned version")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", type=Path, default=ROOT / "build/briar")
    parser.add_argument("--reference", type=Path, required=True)
    args = parser.parse_args()
    if shutil.which("unshare") is None or shutil.which("ip") is None:
        raise SystemExit("Linux network-namespace isolation and ip are required for reference execution")
    (ROOT / "state").mkdir(exist_ok=True)
    check_reference_version(args.reference)
    cases = fixtures()
    suite = unittest.TestSuite()
    for case in cases:
        suite.addTest(unittest.FunctionTestCase(lambda case=case: compare(args.native.resolve(), args.reference.resolve(), case), description=case[0]))
    print(f"Pinned-reference comparisons: {len(cases)}; synthetic inputs; network isolated", flush=True)
    print("Known cross-decoder oracle duplicates may race on DecoderName only; native ordering is PLAIN-first.", flush=True)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
