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


def positioned(parts, size=None):
    end = max(offset + len(value) for offset, value in parts)
    size = end + 32 if size is None else size
    check(end <= size <= 65536, "bounded synthetic fixture")
    source = bytearray(b"." * size)
    for offset, value in parts:
        source[offset:offset + len(value)] = value
    return bytes(source)


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

def utf16_bytes(payload, endian="le"):
    return payload.decode("ascii").encode("utf-16" + endian)


for payload in (utf16_bytes(plain), utf16_bytes(plain, "be"), utf16_bytes(plain) + b"\xff",
                utf16_bytes(plain, "be") + b"Q",
                ("abyssale " + key40[:20] + "\u00e9" + key40[20:]).encode("utf-16le")):
    _, rows = invoke(["stdin", *base], payload)
    check(len(rows) == 1 and rows[0]["Raw"] == key40 and rows[0]["DecoderName"] == "UTF16",
          "UTF16 extracts printable ASCII from original LE/BE bytes and ignores odd tails")
    check(rows[0]["SourceMetadata"] == {"Data": {"Stdin": {}}} and not rows[0]["VerificationFromCache"] and
          not rows[0]["Verified"] and rows[0]["SecretParts"] == {"key": key40},
          "decoder seen-data cache does not invent verification or source metadata")
_, rows = invoke(["stdin", *base], utf16_bytes(plain + b" \n" + plain + b" "))
check(len(rows) == 1 and rows[0]["DecoderName"] == "UTF16", "decoded UTF16 stdin duplicates collapse")
mixed_utf16 = utf16_bytes(plain + b" ", "be") + utf16_bytes(other + b" ")
_, rows = invoke(["stdin", *base], mixed_utf16)
check([r["Raw"] for r in rows] == [other_key40, key40], "UTF16 concatenates LE buffer before BE, not physical input order")
_, rows = invoke(["stdin", *base, "--filter-unverified"], mixed_utf16)
check(len(rows) == 1 and rows[0]["Raw"] == other_key40, "cleaning sees the LE-first decoded result order")
interleaved = b"".join(bytes((c, 0)) if i % 2 == 0 else bytes((0, c)) for i, c in enumerate(plain))
_, rows = invoke(["stdin", *base], interleaved)
check(not rows, "UTF16 heuristic does not reconstruct physical-order mixed-endian characters")
for payload, label in (
    (base64.b64encode(utf16_bytes(plain)), "UTF16"),
    (base64.b64encode(utf16_bytes(plain, "be")), "UTF16"),
    (utf16_bytes(encoded), "BASE64"),
    (utf16_bytes(encoded, "be"), "BASE64"),
    (base64.b64encode(utf16_bytes(encoded)), "BASE64"),
    (utf16_bytes(base64.b64encode(utf16_bytes(plain))), "UTF16"),
):
    _, rows = invoke(["stdin", *base], payload)
    check(len(rows) == 1 and rows[0]["Raw"] == key40 and rows[0]["DecoderName"] == label,
          "nested Base64/UTF16 result uses the final successful decoder name")
leading = b" " + plain
for prefix, label in ((leading, "PLAIN"), (base64.b64encode(leading), "BASE64")):
    _, rows = invoke(["stdin", *base], prefix + b"!!" + utf16_bytes(other))
    check([(r["Raw"], r["DecoderName"]) for r in rows] == [(key40, label), (other_key40, "UTF16")],
          "independent original-chunk fan-out retains intermediate and converging-path findings")
    _, rows = invoke(["stdin", *base], prefix + b"!!" + utf16_bytes(plain))
    check(len(rows) == 1 and rows[0]["DecoderName"] == label,
          "breadth-first default decoder order wins native cross-decoder duplicate identities")
_, rows = invoke(["stdin", *base], base64.b64encode(encoded) + b"!!" + utf16_bytes(encoded))
check(len(rows) == 1 and rows[0]["DecoderName"] == "BASE64", "convergent next-input data still yields its finding")
nested = plain
for depth in range(1, 7):
    nested = utf16_bytes(nested) if depth % 2 else base64.b64encode(nested)
    if depth >= 2:
        _, rows = invoke(["stdin", *base], nested)
        check(len(rows) == (1 if depth <= 5 else 0), "shared default depth is five across alternating codecs")
        if rows:
            check(rows[0]["DecoderName"] == "UTF16", "the innermost successful codec determines DecoderName")
_, rows = invoke(["stdin", *base], utf16_bytes(plain + b" # trufflehog:ignore"))
check(len(rows) == 1, "UTF16 stdin does not acquire filesystem ignore semantics")

def escaped_bytes(payload):
    return "".join(r"\u%04x" % c for c in payload).encode("ascii")


escaped = escaped_bytes(plain)
for payload, label in (
    (escaped, "ESCAPED_UNICODE"),
    (base64.b64encode(escaped), "ESCAPED_UNICODE"),
    (escaped_bytes(encoded), "BASE64"),
    (utf16_bytes(escaped, "be"), "ESCAPED_UNICODE"),
    (escaped_bytes(utf16_bytes(plain)), "UTF16"),
    (escaped_bytes(base64.b64encode(utf16_bytes(plain, "be"))), "UTF16"),
):
    _, rows = invoke(["stdin", *base], payload)
    check(len(rows) == 1 and rows[0]["Raw"] == key40 and rows[0]["DecoderName"] == label,
          "escaped Unicode participates in original-byte and nested codec fan-out")
    check(rows[0]["SourceMetadata"] == {"Data": {"Stdin": {}}} and
          not rows[0]["VerificationFromCache"] and rows[0]["SecretParts"] == {"key": key40},
          "escaped decoding preserves result and source metadata without a verification cache")
_, rows = invoke(["stdin", *base], escaped + b"!!" + escaped_bytes(encoded_other))
check([(row["Raw"], row["DecoderName"]) for row in rows] ==
      [(key40, "ESCAPED_UNICODE"), (other_key40, "BASE64")],
      "intermediate escaped findings survive another decoding pass")
third_key, fourth_key = key40[1:] + key40[:1], other_key40[1:] + other_key40[:1]
assert len({key40, other_key40, third_key, fourth_key}) == 4
siblings = (b" " + plain + b"!!" + encoded_other + b"!!" +
            utf16_bytes(f"abyssale {third_key}".encode()) + b"!!" +
            escaped_bytes(f"abyssale {fourth_key}".encode()))
_, rows = invoke(["stdin", *base], siblings)
check([(row["Raw"], row["DecoderName"]) for row in rows] ==
      [(key40, "PLAIN"), (other_key40, "BASE64"), (third_key, "UTF16"), (fourth_key, "ESCAPED_UNICODE")],
      "all non-PLAIN decoders independently see original bytes in pinned order")
nested = plain
for depth in range(1, 7):
    nested = escaped_bytes(nested[:1]) + nested[1:]
    if depth >= 5:
        _, rows = invoke(["stdin", *base], nested)
        check(len(rows) == (1 if depth == 5 else 0), "escaped decoding shares the five-pass depth limit")
_, rows = invoke(["stdin", *base], rb"\UFFFFFFFF !!" + escaped)
check(not rows, "unchanged invalid high-priority output is scanned but not rescheduled")
for payload in (b"\xff" + escaped, b"U+0020\xc3\xa9U+0061 byssale " + key40.encode()):
    _, rows = invoke(["stdin", *base], payload)
    check(len(rows) == 1 and rows[0]["Raw"] == key40 and rows[0]["DecoderName"] == "ESCAPED_UNICODE",
          "malformed decoded UTF-8 does not suppress a later valid credential")
for gap, count in ((b"\xff", 0), (b"\xef\xbf\xbd", 1)):
    _, rows = invoke(["stdin", *base], escaped_bytes(b"abyssale ") + gap + key40.encode())
    check(len(rows) == count, "RE2 matches may cross a literal RuneError but not invalid UTF-8 bytes")

part = "c7d8e9f0"
second_part = "d8e9f0a1"
secret = key32[::-1]
aha_key = "b7c9d2e5f6b8c3d4" * 4
alibaba_id = "LTAI" + (part * 3)[:17]
for selector, key, component, part_name, payload in (
    ("0", key32[:30], alibaba_id, "id", f"{alibaba_id}\n{key32[:30]}"),
    ("453", key32, secret[:16], "secret", f"amadeus {key32}\namadeus {secret[:16]}"),
    ("431", key32, part, "id", f"adzuna {key32}\nadzuna {part}"),
    ("693", key32[:20], "734", "id", f"aeroworkflow {key32[:20]}\naeroworkflow 734"),
    ("197", key32, secret, "secret", f"agora\nkey {key32}\nsecret {secret}"),
    ("802", aha_key, "synthetic.aha.io", "url", f"aha {aha_key}\nsynthetic.aha.io"),
):
    args = ["stdin", "--json", "--no-verification", "--include-detectors=" + selector]
    _, rows = invoke(args, payload.encode())
    check(len(rows) == 1, "multipart descriptor now uses the implemented span behavior")
    row = rows[0]
    check(set(row) == expected_fields and "Version" not in row, "multipart printer fields do not invent a result version")
    check(row["DetectorType"] == int(selector) and row["Raw"] == key and row["RawV2"] == key + component,
          "multipart Raw and concatenated RawV2 retain distinct meanings")
    check(row["SecretParts"] == {"key": key, part_name: component}, "multipart secret parts")
    check(row["Redacted"] == "" and row["ExtraData"] is None and row["StructuredData"] is None,
          "multipart defaults preserve NULL maps and empty redaction")
    check(not row["Verified"] and not row["VerificationFromCache"], "multipart CLI never verifies")
    _, version_zero = invoke([*args[:-1], "--include-detectors=" + selector + ".v0"], payload.encode())
    check(version_zero == rows, "version-zero selector is a wildcard, not a new result field")

for distance, bridged, expected in ((1500, False, 1), (2048, False, 1), (2049, False, 0),
                                     (11000, True, 1), (15000, True, 0)):
    pieces = [(0, f"adzuna {key32}\n".encode()), (distance, f"adzuna {part}\n".encode())]
    if bridged:
        pieces.extend((at, b"adzuna\n") for at in range(1800, distance, 1800))
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=431"], positioned(pieces))
    check(len(rows) == expected, "merge adjacent multipart windows, but never merge across raw source chunks")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=197"], f"key {key32}\nsecret {secret}".encode())
check(not rows, "Agora extraction aliases do not substitute for its declared prefilter keyword")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=802"], f"aha {aha_key}".encode())
check(not rows, "Aha extraction prefix is not its aha.io dispatch keyword")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=802"], f"aha {aha_key}\naha.io".encode())
check(len(rows) == 1 and rows[0]["SecretParts"]["url"] == "aha.io", "Aha fallback applies only after keyword dispatch")

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
    chunked = Path(directory) / "chunks.txt"
    multipart_args = ["filesystem", str(chunked), "--json", "--no-verification", "--include-detectors=431"]
    chunked.write_bytes(f"header\nadzuna {key32}\nadzuna {part}\nadzuna example1".encode())
    _, rows = invoke(multipart_args)
    check(len(rows) == 2 and {r["RawV2"] for r in rows} == {key32 + part, key32 + "example1"},
          "dedup and false-positive checks do not collapse RawV2 onto Raw")
    check(all(r["SourceMetadata"]["Data"]["Filesystem"]["line"] == 2 for r in rows),
          "line placement locates Raw, not its multipart RawV2 concatenation")
    chunked.write_bytes(positioned([(11000, f"adzuna {key32}\n".encode()), (11100, f"adzuna {part}\n".encode()),
                                   (14000, f"adzuna {secret}\n".encode()), (14100, f"adzuna {second_part}\n".encode())]))
    _, rows = invoke(multipart_args)
    check({(r["Raw"], r["RawV2"], r["SourceMetadata"]["Data"]["Filesystem"]["line"]) for r in rows} ==
          {(key32, key32 + part, 1), (secret, secret + second_part, 3)},
          "filesystem advances over content only; peek findings deduplicate at the same location")
    chunked.write_bytes(positioned([(100, f"adzuna {key32}\n".encode()), (200, f"adzuna {part}\n".encode()),
                                   (14000, f"adzuna {key32}\n".encode()), (14100, f"adzuna {second_part}\n".encode())]))
    _, rows = invoke(multipart_args)
    check({(r["RawV2"], r["SourceMetadata"]["Data"]["Filesystem"]["line"]) for r in rows} ==
          {(key32 + part, 1), (key32 + second_part, 3)}, "same Raw at separate chunks retains RawV2 and location identity")
    for id_at, expected in ((13297, 1), (13298, 0)):
        chunked.write_bytes(positioned([(10000, f"adzuna {key32}\n".encode()), (11800, b"adzuna\n"),
                                       (id_at, f"adzuna {part}\n".encode())]))
        _, rows = invoke(multipart_args)
        check(len(rows) == expected, "multipart capture must fit in the clipped 3 KiB forward peek")
    for at in (10210, 13300):
        chunked.write_bytes(positioned([(0, b"header\n"), (at, plain + b"\n")]))
        _, rows = invoke(["filesystem", str(chunked), *base])
        check(len(rows) == 1 and rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 2,
              "content/peek boundary findings retain one correct filesystem location")
    chunked.write_bytes(positioned([(0, b"header\n"), (100, plain + b"\n"), (15000, b"\xff")]))
    _, rows = invoke(["filesystem", str(chunked), *base])
    check(len(rows) == 1 and rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 2,
          "invalid UTF-8 in a later chunk does not normalize an earlier chunk's controls")
    pair = f"adzuna {key32}\nadzuna {part}".encode()
    chunked.write_bytes(positioned([(0, b"header\n"), (13280, base64.b64encode(pair))]))
    _, rows = invoke(multipart_args)
    check(len(rows) == 1 and rows[0]["DecoderName"] == "BASE64" and rows[0]["RawV2"] == key32 + part and
          rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 2,
          "source chunks precede Base64 decoding and decoded multipart line placement")
    utf16_file = Path(directory) / "utf16.txt"
    for endian in ("le", "be"):
        utf16_file.write_bytes(utf16_bytes(b"heading\n" + plain + b" \n", endian))
        _, rows = invoke(["filesystem", str(utf16_file), *base])
        check(len(rows) == 1 and rows[0]["DecoderName"] == "UTF16" and
              rows[0]["SourceMetadata"]["Data"]["Filesystem"] == {"file": str(utf16_file), "line": 1},
              "UTF16 discards control newlines; filesystem location uses the decoded chunk")
    utf16_file.write_bytes(utf16_bytes(plain + b" \n" + plain + b" "))
    _, rows = invoke(["filesystem", str(utf16_file), *base])
    check(len(rows) == 1 and rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 1,
          "UTF16 physical source lines may deduplicate onto one decoded location")
    utf16_file.write_bytes(utf16_bytes(base64.b64encode(b"heading\n" + plain)))
    _, rows = invoke(["filesystem", str(utf16_file), *base])
    check(len(rows) == 1 and rows[0]["DecoderName"] == "BASE64" and
          rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 2,
          "nested location comes from final Base64 view, not its UTF16 parent or OriginalData")
    utf16_file.write_bytes(utf16_bytes(plain + b" # trufflehog:ignore"))
    _, rows = invoke(["filesystem", str(utf16_file), *base])
    check(not rows, "filesystem ignore tags read the UTF16 decoded view")
    for payload, label in ((utf16_bytes(plain), "UTF16"), (utf16_bytes(encoded), "BASE64")):
        utf16_file.write_bytes(positioned([(0, b"header\n"), (10240, payload)]))
        _, rows = invoke(["filesystem", str(utf16_file), *base])
        check([r["SourceMetadata"]["Data"]["Filesystem"]["line"] for r in rows] == [1, 2] and
              all(r["DecoderName"] == label and not r["VerificationFromCache"] for r in rows),
              "decoder frontier/seen data reset per raw chunk; peek retains both decoder-relative locations")
    utf16_file.write_bytes(utf16_bytes(f"heading\nadzuna {key32} \nadzuna {part} ".encode()))
    _, rows = invoke(["filesystem", str(utf16_file), "--json", "--no-verification", "--include-detectors=431"])
    check(len(rows) == 1 and rows[0]["RawV2"] == key32 + part and rows[0]["DecoderName"] == "UTF16" and
          rows[0]["SecretParts"] == {"key": key32, "id": part} and
          rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 1,
          "UTF16 dispatch preserves multipart fields and decoded Raw-based location")
    escaped_file = Path(directory) / "escaped.txt"
    escaped_source = escaped_bytes(b"heading\n" + plain + b"\n")
    escaped_file.write_bytes(utf16_bytes(escaped_source, "be"))
    _, rows = invoke(["filesystem", str(escaped_file), *base])
    check(len(rows) == 1 and rows[0]["DecoderName"] == "ESCAPED_UNICODE" and
          rows[0]["SourceMetadata"]["Data"]["Filesystem"] == {"file": str(escaped_file), "line": 2},
          "escaped newlines determine final decoded filesystem location")
    check(escaped_file.read_bytes() == utf16_bytes(escaped_source, "be"),
          "nested decoder views never modify original input bytes")
    escaped_file.write_bytes(escaped_bytes(plain + b" # trufflehog:ignore"))
    _, rows = invoke(["filesystem", str(escaped_file), *base])
    check(not rows, "filesystem ignore handling reads the escaped decoded view")
    pair = f"heading\nadzuna {key32}\nadzuna {part}".encode()
    escaped_file.write_bytes(escaped_bytes(pair))
    _, rows = invoke(["filesystem", str(escaped_file), "--json", "--no-verification", "--include-detectors=431"])
    check(len(rows) == 1 and rows[0]["RawV2"] == key32 + part and
          rows[0]["SecretParts"] == {"key": key32, "id": part} and
          rows[0]["SourceMetadata"]["Data"]["Filesystem"]["line"] == 2,
          "escaped decoding retains multipart identity and Raw-based line metadata")
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
    ["stdin", "--json", "--no-verification", "--include-detectors=301"],
    ["stdin", "--json", "--no-verification", "--include-detectors=239.v1"],
    ["stdin", "--json", "--no-verification", "--include-detectors=431.v1"],
    ["stdin", "--json", "--no-verification", "--include-detectors=693.v1"],
    ["stdin", "--json", "--no-verification", "--include-detectors=197.v1"],
    ["stdin", "--json", "--no-verification", "--include-detectors=802.v1"],
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
