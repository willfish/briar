#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic, offline acceptance of the explicitly bounded native CLI slice."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
base = ["--json", "--no-verification", "--include-detectors=239,521"]
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def invoke(args, data=b"", code=0):
    proc = subprocess.run([binary, *args], input=data, capture_output=True, timeout=10)
    check(proc.returncode == code, f"exit {proc.returncode}, expected {code}: {proc.stderr.decode()}")
    if code not in (0, 183):
        check(not proc.stdout, "a failed scan must not emit partial success output")
        check(proc.stderr.startswith(b"briar: "), "explicit failure diagnostic required")
    return proc, [json.loads(line) for line in proc.stdout.splitlines()]


alphabet = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y4z6"
key40 = (alphabet * 2)[:40]
key80 = (alphabet * 2)[:80]
key32 = (alphabet * 2)[:32]
text = f"AbuseIPDB = {key80}\nABYSSALE = {key40}\r\nabstract = {key32}\n".encode()
_, rows = invoke(["stdin", *base], text)
check({r["DetectorType"] for r in rows} == {239, 521}, "default membership and explicit selector")
expected_fields = {
    "SourceMetadata", "SourceID", "SourceType", "SourceName", "DetectorType", "DetectorName",
    "DetectorDescription", "DecoderName", "Verified", "VerificationFromCache", "Raw", "RawV2",
    "Redacted", "ExtraData", "StructuredData", "SecretParts",
}
for row in rows:
    check(set(row) == expected_fields, "upstream first-batch printer field names and omissions")
    check(row["SourceMetadata"] == {"Data": {"Stdin": {}}}, "stdin metadata has no invented lines")
    check(row["SourceType"] == 40 and row["SourceID"] == 1, "stdin source type and local source ID")
    check(row["SourceName"] == "trufflehog - stdin" and row["DecoderName"] == "PLAIN", "source/decoder names")
    check(not row["Verified"] and not row["VerificationFromCache"], "no-verification result status")
    check(row["Raw"] == (key40 if row["DetectorType"] == 239 else key80), "binary-length raw copy")
    check(row["RawV2"] == row["Redacted"] == "", "default empty strings")
    check(row["ExtraData"] is None and row["StructuredData"] is None, "default NULL maps")
    check(row["SecretParts"] == {"key": row["Raw"]}, "secret parts")
    check(row["DetectorName"] == ("Abyssale" if row["DetectorType"] == 239 else "AbuseIPDB"), "registry type names")
    check(bool(row["DetectorDescription"]), "detector description retained")

_, rows = invoke(["stdin", *base], f"abyssale {key40}\nabyssale {key40}\n".encode())
check(len(rows) == 1, "stdin deduplication follows metadata, not invented line numbers")
_, rows = invoke(["stdin", *base, "--exclude-detectors=Abyssale.v0"], text)
check(len(rows) == 1 and rows[0]["DetectorType"] == 521, "exclude and wildcard version selector")
_, rows = invoke(["stdin", *base, "--results=verified"], text)
check(not rows, "result selection is separate from extraction")
_, rows = invoke(["stdin", *base, "--fail"], text, 183)
check(len(rows) == 2, "upstream --fail exit code")

plain = f"abyssale {key40}".encode()
other_key40 = key40[::-1]
other = f"abyssale {other_key40}".encode()
encoded = base64.b64encode(plain)
encoded_other = base64.b64encode(other)
raw_url = base64.urlsafe_b64encode(b"???" + plain).rstrip(b"=")
check(b"_" in raw_url, "RawURL fixture exercises the URL-only alphabet")
for payload in (encoded, raw_url, b"secret=" + encoded, b"abyssale key=" + base64.b64encode(key40.encode())):
    _, rows = invoke(["stdin", *base], payload)
    check(len(rows) == 1 and rows[0]["Raw"] == key40 and rows[0]["DecoderName"] == "BASE64",
          "standard/RawURL and assignment decoding use BASE64 metadata")
_, rows = invoke(["stdin", *base], plain + b"\n" + encoded_other)
check([(r["Raw"], r["DecoderName"]) for r in rows] == [(key40, "PLAIN"), (other_key40, "BASE64")],
      "PLAIN fan-out runs first and Base64 retains the distinct encoded finding")
for payload in (plain + b"\n" + encoded, encoded + b"\n" + plain):
    _, rows = invoke(["stdin", *base], payload)
    check(len(rows) == 1 and rows[0]["DecoderName"] == "PLAIN",
          "cross-decoder duplicates keep the first PLAIN result regardless of source order")
_, rows = invoke(["stdin", *base], encoded + b"\n" + encoded)
check(len(rows) == 1 and rows[0]["DecoderName"] == "BASE64", "encoded stdin occurrences deduplicate")
_, rows = invoke(["stdin", *base], encoded + b"\n" + base64.b64encode(encoded_other))
check({r["Raw"] for r in rows} == {key40, other_key40} and all(r["DecoderName"] == "BASE64" for r in rows),
      "retain intermediate and later-depth Base64 findings")
nested = encoded
for depth in range(2, 7):
    nested = base64.b64encode(nested)
    if depth in (2, 5, 6):
        _, rows = invoke(["stdin", *base], nested)
        check(len(rows) == (1 if depth <= 5 else 0), "pinned default stops after five Base64 passes")
fp_encoded = base64.b64encode(b"abyssale " + b"x" * 40)
_, rows = invoke(["stdin", *base], fp_encoded)
check(not rows, "decoded results pass through the normal false-positive filter")
_, rows = invoke(["stdin", *base, "--results=filtered_unverified"], fp_encoded)
check(len(rows) == 1 and rows[0]["DecoderName"] == "BASE64", "decoded false positives can be retained")

with tempfile.TemporaryDirectory(prefix="briar-core-") as directory:
    path = Path(directory) / "synthetic.txt"
    fp_key = "EXAMPLE" + key40[:33]
    source = (
        f"abyssale {key40}\n"
        f"abyssale {key40}\n"
        f"abyssale {key40}; abyssale {key40}\n"
        f"abyssale {key40} # trufflehog:ignore\n"
        f"# trufflehog:ignore abyssale {key40}\n"
        f"abyssale {fp_key}\n"
    )
    path.write_text(source)
    _, rows = invoke(["filesystem", str(path), *base])
    check([r["SourceMetadata"]["Data"]["Filesystem"]["line"] for r in rows] == [1, 2, 3, 5],
          "duplicate line placement, location-aware deduplication and after-secret ignore tag")
    check(all(r["SourceMetadata"]["Data"]["Filesystem"]["file"] == str(path) for r in rows), "filesystem path")
    check(all(r["SourceType"] == 15 and r["SourceName"] == "trufflehog - filesystem" for r in rows), "filesystem envelope")
    check(all(r["Raw"] == key40 for r in rows), "engine false-positive marking is not detector filtering")
    _, cleaned = invoke(["filesystem", str(path), *base, "--filter-unverified"])
    check(len(cleaned) == 1 and cleaned[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 1,
          "cleaning is opt-in and keeps first unverified result")
    _, retained = invoke(["filesystem", str(path), *base, "--results=filtered_unverified"])
    check(len(retained) == 5 and any(r["Raw"] == fp_key for r in retained), "retain wordlist false positives")
    normalization = Path(directory) / "normalization.txt"
    lines = f"heading\nabyssale {key40}\nabyssale {key40}\n".encode()
    normalization.write_bytes(lines)
    _, rows = invoke(["filesystem", str(normalization), *base])
    check([r["SourceMetadata"]["Data"]["Filesystem"]["line"] for r in rows] == [2, 3],
          "valid UTF-8 keeps newline and duplicate locations")
    normalization.write_bytes(lines + b"\xff")
    _, rows = invoke(["filesystem", str(normalization), *base])
    check(len(rows) == 1 and rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 1,
          "invalid-input normalization removes newlines; placement and dedup use decoded data")
    ignore = f"heading\nabyssale {key40}\n# trufflehog:ignore\n".encode()
    normalization.write_bytes(ignore)
    _, rows = invoke(["filesystem", str(normalization), *base])
    check(len(rows) == 1, "valid UTF-8 keeps ignore tag on next line")
    normalization.write_bytes(ignore + b"\xff")
    _, rows = invoke(["filesystem", str(normalization), *base])
    check(not rows, "invalid-input control replacement joins the ignore tag to the decoded secret line")
    decoded_file = Path(directory) / "base64.txt"
    multiline = base64.b64encode(b"heading\n" + plain + b"\n")
    decoded_file.write_bytes(b"file header\n" + multiline + b"\n")
    _, rows = invoke(["filesystem", str(decoded_file), *base])
    check(len(rows) == 1 and rows[0]["DecoderName"] == "BASE64" and
          rows[0]["SourceMetadata"]["Data"]["Filesystem"] == {"file": str(decoded_file), "line": 3},
          "filesystem metadata counts decoded newlines, not encoded source lines")
    decoded_file.write_bytes(b"header\n" + encoded + b"\n" + encoded + b"\n")
    _, rows = invoke(["filesystem", str(decoded_file), *base])
    check([r["SourceMetadata"]["Data"]["Filesystem"]["line"] for r in rows] == [2, 3] and
          all(r["DecoderName"] == "BASE64" for r in rows), "encoded duplicates retain different filesystem locations")
    decoded_file.write_bytes(b"header\n" + plain + b"\n" + encoded)
    _, rows = invoke(["filesystem", str(decoded_file), *base])
    check([(r["DecoderName"], r["SourceMetadata"]["Data"]["Filesystem"]["line"]) for r in rows] == [("PLAIN", 2), ("BASE64", 3)],
          "dedup excludes decoder identity but includes source location")
    decoded_file.write_bytes(multiline + b"\n" + other)
    _, rows = invoke(["filesystem", str(decoded_file), *base])
    check({(r["Raw"], r["DecoderName"], r["SourceMetadata"]["Data"]["Filesystem"]["line"]) for r in rows} ==
          {(other_key40, "PLAIN", 2), (key40, "BASE64", 2), (other_key40, "BASE64", 4)},
          "do not remap decoder-relative line numbers back onto original source offsets")
    decoded_file.write_bytes(base64.b64encode(plain + b" # trufflehog:ignore"))
    _, rows = invoke(["filesystem", str(decoded_file), *base])
    check(not rows, "ignore handling reads decoded text")
    decoded_file.write_bytes(b"header\n" + encoded + b"\n" + b"." * 1024 + b"\xff")
    _, rows = invoke(["filesystem", str(decoded_file), *base])
    check(len(rows) == 1 and rows[0]["DecoderName"] == "BASE64" and
          rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 2,
          "Base64 gets original bytes, not PLAIN's invalid-input control normalization")
    invoke(["filesystem", directory, *base], code=1)
    link = Path(directory) / "link.txt"
    link.symlink_to(path)
    invoke(["filesystem", str(link), *base], code=1)
    missing = Path(directory) / "missing.txt"
    invoke(["filesystem", str(path), str(missing), *base], code=1)

# Missing implementations are errors, never empty successful default/all scans.
for args in (
    ["stdin", "--json", "--no-verification"],
    ["stdin", "--json", "--no-verification", "--include-detectors=all"],
    ["stdin", "--json", "--no-verification", "--include-detectors=239,all"],
    ["stdin", "--json", "--no-verification", "--include-detectors=999999"],
    ["stdin", "--json", "--no-verification", "--include-detectors=AWS"],
    ["stdin", "--json", "--no-verification", "--include-detectors=384"],
    ["stdin", "--json", "--no-verification", "--include-detectors=239.v1"],
    ["stdin", "--json", "--no-verification", "--include-detectors=239-521"],
    ["stdin", "--json", "--include-detectors=239"],
    ["stdin", "--no-verification", "--include-detectors=239"],
    ["git", *base],
    ["stdin", *base, "--filter-entropy=3"],
    ["stdin", *base, "--max-decode-depth=2"],
    ["stdin", *base, "--exclude-detectors=all"],
):
    invoke(args, text, code=1)
for payload in (
    b"abyssale\0" + key40.encode(),
    "\u00e9 abyssale ".encode() + key40.encode() + " \u4e16\u754c".encode(),
    b"abyssale " + key40.encode() + b"\xc2",
    b"abyssale " + key40.encode() + b"\xe2\x82",
    b"abyssale " + key40.encode() + b"\xf0\x9f\x92",
):
    _, rows = invoke(["stdin", *base], payload)
    check(len(rows) == 1 and rows[0]["Raw"] == key40 and rows[0]["DecoderName"] == "PLAIN",
          "PLAIN decoding accepts valid Unicode/controls and replaces malformed tails")
prefix = f"abyssale {key40}\n".encode()
_, rows = invoke(["stdin", *base], prefix + b"x" * (64 * 1024 - len(prefix) - 1) + b"\xff")
check(len(rows) == 1, "64 KiB cap applies to original bytes, not expanded decoder output")
invoke(["stdin", *base], b"x" * (64 * 1024 + 1), code=1)
_, rows = invoke(["stdin", *base], b"")
check(not rows, "empty supported input")

print(f"end-to-end: {checks} assertions, 0 failures (synthetic stdin/filesystem, verification disabled)")
