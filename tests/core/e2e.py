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

# Default overlap probing still applies with verification disabled. Native
# registry order is deterministic; the reference's Go-map winner can vary.
overlap_cause = ("more than one detector has found this result; for your safety, verification has been disabled. "
                 "You can override this behavior by using the --allow-verification-overlap flag")
shared_pat = "0/1234567890123456:" + key32
overlap_args = ["stdin", "--json", "--no-verification", "--include-detectors=98,41"]
_, rows = invoke(overlap_args, ("asana " + shared_pat).encode())
by_type = {row["DetectorType"]: row for row in rows}
check(len(rows) == 2 and set(by_type) == {98, 41}, "overlap retains both Asana identities")
check(by_type[41].get("VerificationError") == overlap_cause and
      "VerificationError" not in by_type[98], "only later different-type match gets overlap error")
for category, wanted in (("unknown", 41), ("unverified", 98)):
    _, rows = invoke([*overlap_args, "--results=" + category], ("asana " + shared_pat).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == wanted, "overlap participates in result filtering")

for changes, expected_error in ((3, True), (4, False)):
    near = "z" * changes + key32[changes:]
    data = f"assemblyai {key32}\natera {near}".encode()
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=389,800"], data)
    by_type = {row["DetectorType"]: row for row in rows}
    check(len(rows) == 2 and set(by_type) == {389, 800}, "similar credentials retain both identities")
    check((by_type[800].get("VerificationError") == overlap_cause) == expected_error and
          "VerificationError" not in by_type[389], "rune similarity uses strict source threshold")

# A flagged detector is not normally dispatched again unless a later window
# re-adds it. Its other, nonoverlapping candidate in this window is not emitted.
data = f"assemblyai {key32}\natera {key32}\natera {key32[::-1]}".encode()
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=389,800"], data)
check(len(rows) == 2 and all(row["Raw"] == key32 for row in rows), "overlap removes pending detector dispatch")
hex_key = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d0e2"
other_hex = "c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"
data = f"amplitude {hex_key}\namplitude {other_hex}\nassemblyai {hex_key}".encode()
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=42,389"], data)
check(len(rows) == 3 and all("VerificationError" not in row for row in rows), "overlap compares RawV2 before Raw")
data = f"accuweather {key32}x7z\naccuweather {key32}".encode()
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=303"], data)
check(len(rows) == 2 and all("VerificationError" not in row for row in rows), "same type versions never overlap")

# AWS's custom cleaner is always selected, but is a no-op without verification.
aws_id = "AKIAQWERTYUIOPASDFGH"
aws_secrets = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd")
data = (aws_id + "\n\n" + "\n\n".join(aws_secrets)).encode()
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=AWS"], data)
check(len(rows) == 2 and all(row["DetectorType"] == 2 for row in rows), "named AWS selection preserves unverified pairs")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=2", "--filter-unverified"], data)
check({row["RawV2"] for row in rows} == {aws_id + ":" + secret for secret in aws_secrets},
      "AWS custom cleaner overrides generic unverified collapsing")

# Missing implementations are errors, never empty successful default/all scans.
for args in (
    ["stdin", "--json", "--no-verification"],
    ["stdin", "--json", "--no-verification", "--include-detectors=all"],
    ["stdin", "--json", "--no-verification", "--include-detectors=239,all"],
    ["stdin", "--json", "--no-verification", "--include-detectors=999999"],
    ["stdin", "--json", "--no-verification", "--include-detectors=1"],
    ["stdin", "--json", "--no-verification", "--include-detectors=384"],
    ["stdin", "--json", "--no-verification", "--include-detectors=301"],
    ["stdin", "--json", "--no-verification", "--include-detectors=293"],
    ["stdin", "--json", "--no-verification", "--include-detectors=973"],
    ["stdin", "--json", "--no-verification", "--include-detectors=973.v0"],
    ["stdin", "--json", "--no-verification", "--include-detectors=867"],
    ["stdin", "--json", "--no-verification", "--include-detectors=867.v0"],
    ["stdin", "--json", "--no-verification", "--include-detectors=908"],
    ["stdin", "--json", "--no-verification", "--include-detectors=908.v0"],
    ["stdin", "--json", "--no-verification", "--include-detectors=585"],
    ["stdin", "--json", "--no-verification", "--include-detectors=585.v0"],
    ["stdin", "--json", "--no-verification", "--include-detectors=257"],
    ["stdin", "--json", "--no-verification", "--include-detectors=257.v0"],
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
    ["stdin", *base, "--allow-verification-overlap"],
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

proc, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=7"], b"key A!bcdefghijklmnop", code=1)
check(b"no enabled implemented detectors selected" in proc.stderr, "Generic remains source-disabled despite explicit selection")
proc, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=326"], b"getemail", code=1)
check(b"no enabled implemented detectors selected" in proc.stderr, "GetEmail remains source-disabled despite explicit selection")
proc, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=327"], b"getemails", code=1)
check(b"no enabled implemented detectors selected" in proc.stderr, "GetEmails remains source-disabled despite explicit selection")

github_old = "b7c9d2e5f6b8c3d4e1f0a2c4e6b8f1d3a5c7e9b2"
github_new = "ghp_" + key40[:36]
for selector, number, raw, payload, version in (
    ("Getgist", 210, key80[:68], "getgist " + key80[:68] + "XYZ", None),
    ("Getresponse", 861, key32, "getresponse " + key32, None),
    ("GetSandbox", 633, key40, "getsandbox " + key40 + "\ngetsandbox " + key32[:18], None),
    ("Github.v1", 8, github_old, "github_token " + github_old, "1"),
    ("Github.v2", 8, github_new, github_new, "2"),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], payload.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "enabled named provider selection dispatches its scanner")
    check(rows[0]["Raw"] == raw and rows[0]["SecretParts"] == {"key": raw}, "only the original visible key is projected")
    check(not rows[0]["Verified"] and not rows[0]["RawV2"] and not rows[0]["Redacted"], "NoV preserves the provider's absent fields")
    if version:
        check(rows[0]["ExtraData"]["version"] == version, "GitHub selector retains exact version metadata")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Github.v0"],
                 ("github_token " + github_old + "\n" + github_new).encode())
check(len(rows) == 2 and {row["ExtraData"]["version"] for row in rows} == {"1", "2"}, "version-zero selector includes both enabled GitHub identities")

githubapp_key = "-----BEGIN RSA PRIVATE KEY-----\nQ7r2T9\n-----END RSA PRIVATE KEY-----"
githubapp_input = ("github 012345\n" + githubapp_key).encode()
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GitHubApp"], githubapp_input)
check(not rows, "default wordlists filter the RSA private-key label")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GitHubApp", "--results=filtered_unverified"], githubapp_input)
check(len(rows) == 1 and rows[0]["Raw"] == githubapp_key and rows[0]["SecretParts"] == {"key": githubapp_key}, "NoV retains matching PEM text without parsing and keeps app IDs hidden")
check(rows[0]["ExtraData"] == {"rotation_guide": "https://howtorotate.com/docs/tutorials/github/"} and not rows[0]["RawV2"], "app metadata has no invented ID or version")
github_oauth_id = key32[:20]
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GitHubOauth2"],
                 ("github " + github_oauth_id + "\ngithub " + github_old).encode())
check(len(rows) == 1 and rows[0]["Raw"] == github_oauth_id, "OAuth NoV dispatch does not require native SDK transport")
check(rows[0]["RawV2"] == github_oauth_id + github_old and rows[0]["SecretParts"] == {"id": github_oauth_id, "secret": github_old}, "GitHub OAuth keeps both credential roles")
check(rows[0]["ExtraData"] == {"rotation_guide": "https://howtorotate.com/docs/tutorials/github/"}, "GitHub OAuth rotation metadata is retained")
gitlab_keys = (key32[:20], "glpat-" + key32[:20], "glpat-" + key40[:27] + "X7qY" + key32[:9])
for version, raw in enumerate(gitlab_keys, 1):
    payload = ("gitlab " + raw if version == 1 else raw).encode()
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Gitlab.v" + str(version)], payload)
    check(len(rows) == 1 and rows[0]["Raw"] == raw, "each GitLab version dispatches its own extraction grammar")
    check(rows[0]["RawV2"] == raw + "https://gitlab.com" and rows[0]["SecretParts"] == {"key": raw, "host": "https://gitlab.com"}, "GitLab endpoint construction is observable even in NoV")
    check(rows[0]["ExtraData"] == {"version": str(version), "rotation_guide": "https://howtorotate.com/docs/tutorials/gitlab/"}, "GitLab version and rotation metadata remain explicit")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Gitlab.v0"],
                 ("gitlab " + "\n".join(gitlab_keys)).encode())
check(len(rows) == 3 and {row["ExtraData"]["version"] for row in rows} == {"1", "2", "3"}, "version-zero selector includes all three enabled GitLab identities")
gitlab_oauth_id = (github_old * 2)[:64]
gitlab_oauth_secret = "gloas-" + gitlab_oauth_id[::-1]
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GitLabOauth2"],
                 ("application_id " + gitlab_oauth_id + "\n" + gitlab_oauth_secret).encode())
check(len(rows) == 1 and rows[0]["Raw"] == gitlab_oauth_secret, "OSS defaults enable the exact GitLab OAuth feature gate")
check(rows[0]["RawV2"] == gitlab_oauth_id + gitlab_oauth_secret + "https://gitlab.com", "GitLab OAuth identity includes the endpoint")
check(rows[0]["SecretParts"] == {"client_id": gitlab_oauth_id, "client_secret": gitlab_oauth_secret, "endpoint": "https://gitlab.com"} and rows[0]["ExtraData"] is None, "GitLab OAuth metadata does not inherit GitHub fields")

canvas_key = key80[:43] + "="
canvas_prefix = "gocanvas Mailbox@fixture.invalid\ngocanvas "
cardless_key = "live_" + key40[:39] + "-"
for selector, number, raw, payload in (
    ("Gitter", 555, key40, "GiTtEr " + key40),
    ("Glassnode", 569, "Z" + key32[1:27], "GlAsSnOdE Z" + key32[1:27]),
    ("GoCanvas", 714, canvas_key, canvas_prefix + canvas_key + " "),
    ("GoCardless", 184, cardless_key, "gocardless " + cardless_key + " "),
    ("GoCardless", 184, cardless_key + '"', "gocardless " + cardless_key + '"'),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], payload.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "enabled named selector dispatches the provider")
    check(rows[0]["Raw"] == raw and rows[0]["SecretParts"] == {"key": raw}, "only the visible key is projected, including a consumed quote")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None, "required hidden email does not become invented metadata")
    check(not rows[0]["Verified"] and not rows[0]["VerificationFromCache"], "NoV does not invoke the provider")
for selector, payload in (
    ("GoCanvas", "gocanvas " + canvas_key + " "),
    ("GoCanvas", canvas_prefix + canvas_key + "\t"),
    ("GoCardless", cardless_key + " "),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], payload.encode())
    check(not rows, "required hidden email, consumed delimiter and dispatch keyword are not optional")

godaddy_secret = key32[:22]
google_gemini_key = "AIzaSy" + key40[:32] + "-"
google_oauth_token = "ya29." + key32
for selector, number, raw, payload, extra in (
    ("GoDaddy.v1", 1008, key40[:37], "godaddy " + key40[:37] + "\ngodaddy " + godaddy_secret, {}),
    ("GoDaddy.v2", 1008, key40[:35], "godaddy " + key40[:35] + "\ngodaddy " + godaddy_secret, {}),
    ("GoodDay", 654, key32, "GoOdDaY " + key32, None),
    ("GoogleGeminiAPIKey", 1041, google_gemini_key, google_gemini_key + "EXTRA", None),
    ("GoogleOauth2", 69, google_oauth_token, google_oauth_token, None),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], payload.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "named selector dispatches its enabled version")
    check(rows[0]["Raw"] == raw and rows[0]["SecretParts"] == {"key": raw}, "hidden GoDaddy secret is required but never projected")
    check(rows[0]["ExtraData"] == extra and not rows[0]["RawV2"], "NoV keeps the source's empty map distinct from nil and adds no version metadata")
    check(rows[0]["Redacted"] == (raw[:8] + "..." if number == 1041 else ""), "Google Gemini retains redaction without verification")
    check(not rows[0]["Verified"] and not rows[0]["VerificationFromCache"], "NoV does not reach HTTP or expiry formatting")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GoDaddy.v0"],
                 ("godaddy " + key40[:37] + "\ngodaddy " + key40[:35] + "\ngodaddy " + godaddy_secret).encode())
check(len(rows) == 2 and {row["Raw"] for row in rows} == {key40[:37], key40[:35]}, "version-zero selector includes both GoDaddy grammars")
check(all(row["ExtraData"] == {} and not row["RawV2"] for row in rows), "NoV does not add Environment or reveal hidden secrets")
for selector, payload in (
    ("GoDaddy.v1", "godaddy " + key40[:37]),
    ("GoogleGeminiAPIKey", "AIZASY" + google_gemini_key[6:]),
    ("GoogleOauth2", "YA29." + google_oauth_token[5:]),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], payload.encode())
    check(not rows, "required counterpart and direct case-sensitive token prefixes remain observable")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GoogleOauth2"],
                 (google_oauth_token + "\n" + google_oauth_token).encode())
check(len(rows) == 1 and rows[0]["Raw"] == google_oauth_token, "Google OAuth token identity preserves original bytes and uniqueness")

grafana_key = "glc_eyJ" + key32 + key32[:28]
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Grafana"], grafana_key.encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 830, "Grafana selector dispatches its enabled scanner")
check(rows[0]["Raw"] == grafana_key and rows[0]["SecretParts"] == {"key": grafana_key}, "Grafana publishes the complete key without JWT interpretation")
check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None, "Grafana adds no invented metadata")
check(not rows[0]["Verified"] and not rows[0]["VerificationFromCache"], "Grafana NoV does not contact the provider")

grafana_service_key = "glsa_" + key40 + "_"
grafana_domain = "Tenant97.grafana.net"
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GrafanaServiceAccount"],
                 (grafana_service_key + "\n" + grafana_domain).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 963, "Grafana service-account selector dispatches its enabled scanner")
check(rows[0]["Raw"] == grafana_service_key and rows[0]["RawV2"] == grafana_domain + ":" + grafana_service_key, "service-account RawV2 is domain then key, not key then domain")
check(rows[0]["SecretParts"] == {"domain": grafana_domain, "key": grafana_service_key}, "service-account domain and key are both visible parts")
check(not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "service-account NoV adds no metadata or verification")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GrafanaServiceAccount"], grafana_service_key.encode())
check(not rows, "a service-account key alone is not a complete credential")

graphcms_plain = "ey" + (key32 * 3)[:73] + "!ey" + (key32 * 12)[:365] + "?" + (key32 * 22)[:683]
# Center the dispatch window on the long token; the span hint is not a token cap.
graphcms_key = graphcms_plain[:200] + "graphcms" + graphcms_plain[208:]
graphcms_id = key32[:25]
for raw in (graphcms_key, graphcms_key[:75] + "\0" + graphcms_key[76:]):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GraphCMS"],
                     (raw + "\ngraph " + graphcms_id).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == 223, "GraphCMS selector reaches its long wildcard token")
    check(rows[0]["Raw"] == raw and rows[0]["SecretParts"] == {"key": raw}, "GraphCMS preserves original wildcard bytes and hides its required ID")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "GraphCMS NoV does not add metadata or send a query")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GraphCMS"], graphcms_key.encode())
check(not rows, "GraphCMS requires its hidden ID")

graphhopper_key = key32[:18] + "-" + key32[:17]
for raw, following in ((graphhopper_key, ""), (graphhopper_key[:35] + "-", "x")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Graphhopper"],
                     ("GrApHhOpPeR " + raw + following).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == 436, "Graphhopper selector dispatches its enabled scanner")
    check(rows[0]["Raw"] == raw and rows[0]["SecretParts"] == {"key": raw}, "Graphhopper preserves context-dependent hyphen captures without UUID validation")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Graphhopper NoV does not geocode or add metadata")

groovehq_key = key32 * 2
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Groovehq"],
                 ("GrOoVeHq " + groovehq_key + "EXTRA").encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 206, "Groovehq selector dispatches its enabled scanner")
check(rows[0]["Raw"] == groovehq_key and rows[0]["SecretParts"] == {"key": groovehq_key}, "Groovehq retains the bounded prefix without an ending boundary")
check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Groovehq NoV adds no metadata or requests")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Groovehq"], ("groove " + groovehq_key).encode())
check(not rows, "Groovehq dispatch still requires the longer provider keyword")

gtmetrix_key = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e3"
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=GTMetrix"], ("GtMeTrIx " + gtmetrix_key).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 763, "GTMetrix selector dispatches its enabled scanner")
check(rows[0]["Raw"] == gtmetrix_key and rows[0]["SecretParts"] == {"key": gtmetrix_key}, "GTMetrix publishes its lowercase-hex key")
check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "GTMetrix NoV does not send Basic credentials")

guardian_key = "A7z9w2y5-g6h8-j3k4-m1n0-p2q4r6s8t1u3"
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Guardianapi"], ("GuArDiAnApI " + guardian_key).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 259, "Guardianapi selector dispatches its enabled scanner")
check(rows[0]["Raw"] == guardian_key and rows[0]["SecretParts"] == {"key": guardian_key}, "Guardianapi preserves first-block uppercase A and nonhex lower-alphanumeric blocks")
check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Guardianapi NoV does not search content or add metadata")
for payload in ("guardianapi B" + guardian_key[1:], "guardianapi " + guardian_key[:9] + "A" + guardian_key[10:], "guardian " + guardian_key):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Guardianapi"], payload.encode())
    check(not rows, "Guardianapi keeps its asymmetric alphabet and longer dispatch keyword")

groq_key = "gsk_" + key40 + key32[:12]
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Groq"], (groq_key + "\n" + groq_key).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 988, "Groq selector preserves exact-token uniqueness")
check(rows[0]["Raw"] == groq_key and rows[0]["SecretParts"] == {"key": groq_key}, "Groq publishes its complete direct token")
check(rows[0]["ExtraData"] == {"rotation_guide": "https://howtorotate.com/docs/tutorials/groq/"}, "Groq retains rotation metadata without verification")
check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and not rows[0]["Verified"], "Groq NoV does not list models or invent token metadata")

gyazo_key = key40 + "Z7q"
for raw, following in ((gyazo_key, ""), (gyazo_key[:42] + "-", "x")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Gyazo"], ("GyAzO " + raw + following).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == 467, "Gyazo selector dispatches its enabled scanner")
    check(rows[0]["Raw"] == raw and rows[0]["SecretParts"] == {"key": raw}, "Gyazo preserves the complete capture and trailing-hyphen boundary")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Gyazo NoV does not fetch images or add metadata")

gumroad_key = key40 + "Ab7"
for raw, following in ((gumroad_key, ""), (gumroad_key[:42] + "-", "x")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Gumroad"], ("GuMrOaD " + raw + following).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == 792, "Gumroad selector dispatches its enabled scanner")
    check(rows[0]["Raw"] == raw and rows[0]["SecretParts"] == {"key": raw}, "Gumroad preserves the full mixed-alphanumeric and hyphen capture")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Gumroad NoV does not send its nonempty GET or add metadata")

for selector in ("Guru", "570"):
    proc, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector],
                        b"guru AbC@de.fg\nguru ghijklmn-opqr-stuv-wxyz-0123456789ab", code=1)
    check(not rows and b"no enabled implemented detectors selected" in proc.stderr, "Guru stays absent from source defaults despite explicit selection")

happyscribe_key = key32[:23] + "Z"
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Happyscribe"], ("HaPpYsCrIbE " + happyscribe_key).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 507, "Happyscribe selector dispatches its enabled scanner")
check(rows[0]["Raw"] == happyscribe_key and rows[0]["SecretParts"] == {"key": happyscribe_key}, "Happyscribe preserves its mixed-alphanumeric key")
check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Happyscribe NoV does not fetch transcriptions or add metadata")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Happyscribe"], ("happyscribe " + happyscribe_key[:23]).encode())
check(not rows, "Happyscribe requires all 24 token bytes")

harness_key = "pat." + key32[:10] + "_" + key32[:11] + ".a19b28c37d46e50fa19b28c3." + key32[:20]
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Harness"], ("HaRnEsS " + harness_key).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 1020, "Harness selector dispatches its enabled scanner")
check(rows[0]["Raw"] == harness_key and rows[0]["SecretParts"] == {"key": harness_key}, "Harness retains the complete literal PAT grammar")
check(rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Harness NoV does not fetch user data or invent last-login metadata")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=1020"], ("harness PAT." + harness_key[4:]).encode())
check(not rows, "Harness folds the keyword, not its literal token prefix")
harvest_key = key40 + "." + key40 + "_" + key32[:15]
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Harvest"], ("harvest " + harvest_key + "\nharvest 004203").encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 260, "Harvest requires and binds its independently prefixed hidden account ID")
check(rows[0]["Raw"] == harvest_key and rows[0]["SecretParts"] == {"key": harvest_key}, "Harvest does not expose its hidden ID")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Harvest"], ("harvest " + harvest_key).encode())
check(not rows, "Harvest cannot emit a key without an account ID")
vault_origin = "https://alpha100.hashicorp.cloud:8200"
vault_batch_key = "hvb." + key40 + key32[:10]
vault_service_key = "hvs." + key40 * 2 + key32[:10]
for selector, number, key, prefix in (("HashiCorpVaultBatchToken", 1061, vault_batch_key, ""),
                                     ("HashiCorpVaultToken", 1062, vault_service_key, ""),
                                     ("1062", 1062, "s." + key32[:18], "vault ")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (prefix + key + "\n" + vault_origin + "/team/path").encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Vault source selectors dispatch enabled token grammars")
    check(rows[0]["Raw"] == key and rows[0]["RawV2"] == key + ":" + vault_origin, "Vault token metadata uses the captured origin, not the full path")
    check(rows[0]["SecretParts"] == {"key": key, "url": vault_origin} and rows[0]["Redacted"] == key[:8] + "...", "Vault preserves endpoint parts and source redaction")
    check(rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Vault NoV does not look up tokens")
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (prefix + key).encode())
    check(not rows, "Vault tokens require a selected endpoint even without verification")
vault_binary_origin = "https://a\0\v☃.hashicorp.cloud"
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=1061"], (vault_batch_key + "\n" + vault_binary_origin + "/path").encode())
check(len(rows) == 1 and rows[0]["SecretParts"]["url"] == vault_binary_origin, "Vault found origins preserve NUL, VT and Unicode bytes")
check(rows[0]["RawV2"] == vault_batch_key + ":" + vault_binary_origin, "Vault RawV2 cannot silently truncate its endpoint")
vault_role = "fb2ca917-481c-4b1d-af03-768c2de0a51b"
vault_secret = "A19D3C72-5B84-4E06-9AF1-32C47D8B906E"
vault_auth_prefix = "role " + vault_role + "\n" + " " * 64 + "\nsecret " + vault_secret + "\n"
vault_auth_url = vault_origin + "/a\0b/"
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=HashiCorpVaultAuth"], (vault_auth_prefix + vault_auth_url).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 1036, "Vault AppRole dispatches its two required UUID roles")
check(rows[0]["Raw"] == vault_secret and rows[0]["RawV2"] == vault_role + ":" + vault_secret, "AppRole Raw and RawV2 preserve their distinct credential roles")
check(rows[0]["SecretParts"] == {"role_id": vault_role, "secret_id": vault_secret}, "AppRole does not add a URL secret part")
check(rows[0]["ExtraData"] == {"URL": vault_auth_url} and not rows[0]["Redacted"] and not rows[0]["Verified"], "AppRole NoV retains the whole binary path and never issues a login")

hasura_key, hasura_domain = key40 + key32[:24], "Project101.hasura.app"
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Hasura"], ("HaSuRa " + hasura_key + "\n" + hasura_domain).encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 1030, "Hasura dispatches required key-domain products")
check(rows[0]["Raw"] == hasura_key and rows[0]["RawV2"] == hasura_domain + ":" + hasura_key, "Hasura RawV2 keeps domain before key")
check(rows[0]["SecretParts"] == {"domain": hasura_domain, "key": hasura_key} and rows[0]["ExtraData"] is None, "Hasura NoV preserves both roles without verification metadata")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=1030"], ("hasura " + hasura_key).encode())
check(not rows, "Hasura cannot emit a key without its domain")
hellosign_key = key40[:30] + "-/+" + key40[:31]
helpcrunch_key = (key40 * 9)[:328]
helpcrunch_key = helpcrunch_key[:100] + "+/=" + helpcrunch_key[103:]
for selector, number, key, prefix in (("HelloSign", 395, hellosign_key, "HeLlOsIgN "),
                                     ("HelpCrunch", 164, helpcrunch_key, "HeLpCrUnCh "),
                                     ("Helpscout", 153, "z" + key40[1:], "HeLpScOuT ")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (prefix + key).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Help provider selectors dispatch enabled source scanners")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Help providers retain complete provider-specific captures")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Help provider NoV does not probe services or invent metadata")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=HelpCrunch"], ("helpcrunch " + helpcrunch_key + "EXTRA").encode())
check(len(rows) == 1 and rows[0]["Raw"] == helpcrunch_key, "HelpCrunch has no ending boundary and retains its complete 328-byte prefix")

hereapi_key = key40 + key32[:3]
heroku_v1 = "A7e3c19a-8b26-4f9d-a2e7-3b1c8d6f9052"
heroku_v2 = "HRKU-AA" + key40 + key32[:18]
hiveage_key = key40[:9] + "_-" + key40[10:19]
for selector, number, key, prefix in (("HereAPI", 408, hereapi_key, "HeReApI "),
                                     ("Heroku.v1", 19, heroku_v1, "HeRoKu "),
                                     ("Heroku.v2", 19, heroku_v2, ""),
                                     ("Hiveage", 572, hiveage_key, "HiVeAgE ")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (prefix + key).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "HereAPI, Heroku versions and Hiveage dispatch their source grammars")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Provider captures remain byte-exact and key-only")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV adds no version metadata or service results")
hereapi_binary = hereapi_key[:20] + "\0" + hereapi_key[21:]
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=408"], ("hereapi " + hereapi_binary).encode())
check(len(rows) == 1 and rows[0]["Raw"] == hereapi_binary and rows[0]["SecretParts"] == {"key": hereapi_binary}, "HereAPI NoV retains embedded NUL instead of applying URL-constructor rules")
for selector in ("Hive", "571"):
    proc, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector],
                        ("hive " + key40[:17] + "\nhive " + key32).encode(), code=1)
    check(not rows and b"no enabled implemented detectors selected" in proc.stderr, "Explicit Hive selectors cannot enable its commented source default")

holidayapi_key, holistic_key = key40[:36], hex_key * 2
honeycomb_old, honeycomb_new = hex_key, "Z" + key40[:21]
host_key = "z" + key40[:13]
for selector, number, key, prefix in (("HolidayAPI", 361, holidayapi_key, "HoLiDaYaPi "),
                                     ("Holistic", 764, holistic_key, "HoLiStIc "),
                                     ("Honeycomb", 877, honeycomb_old, "HoNeYcOmB "),
                                     ("Honeycomb", 877, honeycomb_new, "Honeycomb "),
                                     ("Host", 556, host_key, "HoSt.Io ")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (prefix + key).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "HolidayAPI, Holistic, both Honeycomb formats and Host dispatch enabled scanners")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Source-specific capture grammars preserve complete keys")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV neither verifies services nor invents metadata")
for prefix in ("host ", "host.io" + ":" * 38):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=556"], (prefix + host_key).encode())
    check(not rows, "Host needs literal host.io dispatch and its extraction prefix's forty-rune budget")

html2pdf_key = key40 + key32[:24]
hubspot_v1 = "G7h3Z1k9-gHi2-JkL3-mNo4-PqRsTuVwXyZ5"
hubspot_na, hubspot_eu = "pat-na1-" + hubspot_v1, "pat-eu1-" + hubspot_v1
huggingface_key, huggingface_org = "hf_" + key40[:34], "api_org_" + key40[:34]
for selector, number, key, prefix in (("Html2Pdf", 355, html2pdf_key, "HtMl2PdF "),
                                     ("HubSpotApiKey.v1", 107, hubspot_v1, "HaPi_KeY "),
                                     ("107.v2", 107, hubspot_na, ""),
                                     ("HubSpotApiKey.v2", 107, hubspot_eu, ""),
                                     ("HuggingFace", 926, huggingface_key, ""),
                                     ("926", 926, huggingface_org, ""),
                                     ("Humanity", 508, key40, "HuMaNiTy ")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (prefix + key).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Html2Pdf, HubSpot versions, both HuggingFace prefixes and Humanity dispatch real scanners")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Provider-specific captures stay complete and key-only")
    expected_redacted = key[8:] + "..." if number == 107 and key.startswith("pat-") else ""
    check(rows[0]["Redacted"] == expected_redacted and not rows[0]["RawV2"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "Only HubSpot v2 exposes its complete UUID-tail redaction; NoV invents no metadata")

hunter_key = key40[:10] + "_-" + key40[12:]
hybiscus_key = key40 + key32[:3]
hypertrack_account, hypertrack_key = key40[:27], key40 + "_-" + key32[:12]
for selector, number, key, source in (("Hunter", 72, hunter_key, "HuNtEr " + hunter_key),
                                     ("Hybiscus", 773, hybiscus_key, "HyBiScUs " + hybiscus_key),
                                     ("Hypertrack", 459, hypertrack_key, "hypertrack " + hypertrack_account + "\nhypertrack " + hypertrack_key)):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Hunter, Hybiscus and Hypertrack dispatch enabled source scanners")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Complete captures remain key-only; Hypertrack account stays hidden")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV invents no metadata or service results")
for selector in ("IbmCloudUserKey", "73"):
    proc, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector],
                        ("ibm " + key40 + key32[:4]).encode(), code=1)
    check(not rows and b"no enabled implemented detectors selected" in proc.stderr, "IBM name and numeric selectors cannot enable its commented source default")

iconfinder_key = key40 + key32[:24]
iexapis_key = "sk_" + key32
iexcloud_key = key40[:12] + "_" + key40[13:35]
imagekit_key = key32 + "_=Z9"
for selector, number, key, source in (("IconFinder", 487, iconfinder_key, "IcOnFiNdEr " + iconfinder_key),
                                     ("Iexapis", 813, iexapis_key, "IeXaPiS " + iexapis_key),
                                     ("Iexcloud", 557, iexcloud_key, "IeXcLoUd " + iexcloud_key),
                                     ("Imagekit", 250, imagekit_key, "ImAgEkIt " + imagekit_key + "EXTRA")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "IconFinder, distinct IEX providers and Imagekit dispatch their exact grammars")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Imagekit retains its 36-byte longer-token prefix; all results stay key-only")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV neither probes services nor invents metadata")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=813"], iexapis_key.encode())
check(not rows, "Iexapis requires its provider dispatch keyword, not merely the literal sk_ token prefix")

imagga_key = key40[:20] + "=" + key40[21:] + key32
impala_key = key40 + "_Z" + key32[:4]
insightly_key = key32 + "-z9q"
for selector, number, key, source in (("Imagga", 349, imagga_key, "ImAgGa " + imagga_key + "EXTRA"),
                                     ("Impala", 509, impala_key, "ImPaLa " + impala_key),
                                     ("Infura", 906, key32, "InFuRa " + key32),
                                     ("Insightly", 271, insightly_key, "InSiGhTlY " + insightly_key)):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Imagga, Impala, Infura and Insightly dispatch exact provider grammars")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Imagga retains its longer-token prefix; Infura and Insightly are not hex or UUID validators")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV exposes only source key metadata and never probes services")

instabot_key = key40[:20] + "=+/" + key40[23:] + "Q7z9"
instamojo_secret = key40 * 3 + key32[:8]
intercom_key = base64.b64encode(b"tok:" + bytes(range(40))).decode()
intercom_short = base64.b64encode(b"tok:" + bytes(range(37))).decode()
intercom_crlf = intercom_short[:8] + "\r\n\r\n" + intercom_short[8:]
interseller_key = "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3"
for selector, number, key, source in (("Instabot", 856, instabot_key, "InStAbOt " + instabot_key + "EXTRA"),
                                     ("Instamojo", 941, key40, "instamojo " + instamojo_secret + "\ninstamojo " + key40),
                                     ("Intercom", 156, intercom_key, "InTeRcOm " + intercom_key),
                                     ("156", 156, intercom_short, "intercom    " + intercom_short),
                                     ("Intercom", 156, intercom_crlf, "intercom " + intercom_crlf),
                                     ("Interseller", 858, interseller_key, "InTeRsElLeR " + interseller_key)):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Instabot, Instamojo, Intercom and Interseller dispatch real scanners")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Instamojo's secret stays hidden; Intercom retains trimmed encoded bytes including interior CRLF")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV validates Intercom tokens without probing services or inventing metadata")

intra42_ud, intra42_af = "s-s4t2ud-" + hex_key * 2, "s-s4t2af-" + hex_key * 2
intra42_id = "u-s4t2af-" + hex_key[::-1] * 2
intrinio_key = "Z" + key40[1:] + key32[:4]
invoiceocean_key, ip2location_key = key40[:20], key32.upper()
for selector, number, key, source in (("Intra42", 987, intra42_ud, intra42_ud + "\n" + intra42_id),
                                     ("987", 987, intra42_af, intra42_af + "\n" + intra42_id),
                                     ("Intrinio", 579, intrinio_key, "InTrInIo " + intrinio_key),
                                     ("InvoiceOcean", 689, invoiceocean_key, "invoiceocean " + invoiceocean_key + "\ntenant7.invoiceocean.com"),
                                     ("Ip2location", 940, ip2location_key, "Ip2LoCaTiOn " + ip2location_key)):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Intra42 flavors, Intrinio, InvoiceOcean and Ip2location dispatch source grammars")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Required Intra42 IDs and InvoiceOcean hosts remain hidden")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV does not issue tokens, access invoices or invent metadata")

for selector, number, key, prefix in (("Ipapi", 362, key32, "IpApI "),
                                      ("IPGeolocation", 356, key32, "IpGeOlOcAtIoN "),
                                      ("IPInfo", 939, hex_key[:14], "IpInFo "),
                                      ("IPinfoDB", 530, key32 * 2, "IpInFoDb ")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (prefix + key).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Ipapi, IPGeolocation, IPInfo and IPinfoDB dispatch enabled scanners")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "IP provider findings retain original key bytes")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV does not access geolocation services or invent metadata")

for selector, number, key, source in (("IpStack", 133, "A" + hex_key[1:], "IpStAcK A" + hex_key[1:]),
                                      ("Leadfeeder", 329, key40 + "A7z", "LeAdFeEdEr " + key40 + "A7z"),
                                      ("LocationIQ", 450, "pk." + key32, "LoCaTiOnIq pk." + key32),
                                      ("Loginradius", 510, interseller_key, "LoGiNrAdIuS " + interseller_key),
                                      ("MadKudu", 715, hex_key, "MaDkUdU " + hex_key),
                                      ("Mailerlite", 228, key32, "MaIlErLiTe " + key32)):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Six named IP and lead/email provider scanners dispatch source grammars")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Original hex case, direct pk prefix and UUID-shaped bytes remain unnormalized")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV preserves key-only fields without contacting providers")

for selector, number, key, source in (("IPQuality", 478, key32, "IpQuAlItY " + key32),
                                      ("Jotform", 287, "A" + key32.lower()[1:], "JoTfOrM A" + key32.lower()[1:]),
                                      ("Jumpcloud", 131, key40, "JuMpClOuD " + key40),
                                      ("Juro", 295, key40, "JuRo " + key40),
                                      ("Kanban", 686, key32[:12].upper(), "KaNbAn " + key32[:12].upper() + "\ntenant7.kanbantool.com")):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Five named IP and workflow provider scanners dispatch source grammars")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Jotform's uppercase A is accepted and Kanban's required host remains hidden")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV preserves key-only fields without provider actions")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Kanban"], ("kanban " + key32[:12].upper()).encode())
check(not rows, "Kanban still requires a hidden host with verification disabled")

jupiterone_key = (key40 * 2)[:76]
mailjet_basic_key = (key40 * 3)[:87] + "="
for selector, number, key, source in (("JupiterOne", 982, jupiterone_key, "JuPiTeRoNe " + jupiterone_key),
                                      ("MagicBell", 786, key40, "MaGiCbElL " + key40 + "\nUser@Example.test"),
                                      ("Mailboxlayer", 145, key32.lower(), "MaIlBoXlAyEr " + key32.lower()),
                                      ("MailJetBasicAuth", 105, mailjet_basic_key, "MaIlJeT " + mailjet_basic_key + "TAIL"),
                                      ("MailJetSMS", 106, key32, "MaIlJeT " + key32)):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Five named security/email scanners dispatch their source grammars")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Literal Basic bytes and hidden MagicBell email preserve key-only findings")
    check(not rows[0]["RawV2"] and not rows[0]["Redacted"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV performs no provider, email or SMS action")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=MagicBell"], ("magicbell " + key40).encode())
check(not rows, "MagicBell still requires a hidden email with verification disabled")

keenio_key = (key40 * 2)[:64].upper()
kickbox_key = "_" + (key40 * 2)[:64]
for selector, number, key, source in (("Kanbantool", 853, key32[:12].upper(), "KaNbAnToOl " + key32[:12].upper()),
                                      ("KarmaCRM", 296, key32[:20], "KaRmAcRm " + key32[:20]),
                                      ("KeenIO", 140, keenio_key, "KeEn " + keenio_key + "\nkeen " + key32[:24].lower()),
                                      ("Kickbox", 573, kickbox_key, "KiCkBoX " + kickbox_key)):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Four corrected provider scanners dispatch real version-zero implementations")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Kanbantool self-domain and hidden Keen ID do not alter key-only findings")
    check(not rows[0]["RawV2"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV leaves verifier-only metadata and actions absent")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=KeenIO"], ("keen " + keenio_key).encode())
check(not rows, "KeenIO still requires its independent hidden ID without verification")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=KarmaCRM"], ("karma " + key32[:20]).encode())
check(not rows, "Karma extraction prefix does not replace karmacrm engine dispatch")

klipfolio_key = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e3a5c7e9f1"
knapsackpro_key = "g" + key32[1:].lower()
for selector, number, key in (("Klipfolio", 740, klipfolio_key), ("KnapsackPro", 760, knapsackpro_key)):
    source = selector.upper() + " " + key
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number, "Two named dashboard and test scanners dispatch real version-zero implementations")
    check(rows[0]["Raw"] == key and rows[0]["SecretParts"] == {"key": key}, "Hex-only and nonhex lowercase-alphanumeric grammars retain key-only fields")
    check(not rows[0]["RawV2"] and rows[0]["ExtraData"] is None and not rows[0]["Verified"], "NoV makes no provider or test-suite request")

klaviyo_key = "pk_" + klipfolio_key[:34]
for key in (klaviyo_key, "pk_Ab12Cd_" + klipfolio_key[:34]):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Klaviyo"], key.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == 935 and rows[0]["Raw"] == key, "Klaviyo dispatches both source key formats without a provider-name prefix")
    check(rows[0]["SecretParts"] == {"key": key} and not rows[0]["RawV2"] and rows[0]["ExtraData"] is None, "Klaviyo keeps key-only metadata without an invented version")
kontent_env = "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3"
kontent_key = "ey" + "A" * 30 + ".ey" + "B" * 200 + "." + "C" * 40
kontent_source = "env " + kontent_env + "\nkontent " + kontent_key
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=Kontent"], kontent_source.encode())
check(len(rows) == 1 and rows[0]["DetectorType"] == 328 and rows[0]["Raw"] == kontent_env, "Kontent uses its required environment as Raw")
check(rows[0]["RawV2"] == kontent_env + kontent_key and rows[0]["SecretParts"] == {"env_id": kontent_env, "key": kontent_key}, "Kontent preserves separator-free environment/key RawV2 and both parts")
for selector, number, key in (("Meistertask", 656, key40 + "G7h"), ("MessageBird", 111, key32[:8] + "_-" + key32[10:25])):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], (selector.upper() + " " + key).encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number and rows[0]["Raw"] == key, "Task and messaging scanners dispatch exact alphanumeric and underscore/hyphen grammars")
    check(rows[0]["SecretParts"] == {"key": key} and not rows[0]["Verified"] and not rows[0]["RawV2"], "NoV performs no task or messaging action")

kraken_key = (key40 * 2)[:56]
kraken_private = (key40 * 3)[:88]
kucoin_key = "c19c2539c53367c726a5c04c"
kucoin_passphrase = "Briar!7pw"
langfuse_secret = "sk-lf-" + kontent_env
langfuse_public = "pk-lf-" + kontent_env
for selector, number, source, key, parts, raw_v2 in (
    ("Kraken", 186, "kraken " + kraken_key + "\nkraken " + kraken_private + " ", kraken_key,
     {"key": kraken_key, "private_key": kraken_private}, kraken_key + kraken_private),
    ("KuCoin", 736, "kucoin " + kucoin_passphrase + "\nkucoin " + kontent_env + "\nkucoin\t" + kucoin_key, kucoin_key,
     {"key": kucoin_key, "passphrase": kucoin_passphrase}, kucoin_key + kucoin_passphrase),
    ("Kylas", 272, "kylas " + key32.lower() + "g7h9", key32.lower() + "g7h9",
     {"key": key32.lower() + "g7h9"}, ""),
    ("Langfuse", 1021, "langfuse " + langfuse_public + "\nlangfuse " + langfuse_secret, langfuse_secret,
     {"key": langfuse_secret}, ""),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number and rows[0]["Raw"] == key, "Crypto, CRM and AI scanners dispatch their actual source grammars")
    check(rows[0]["SecretParts"] == parts and rows[0]["RawV2"] == raw_v2, "Hidden keys and separator-free credential projections retain exact metadata")
    check(not rows[0]["Verified"] and rows[0]["ExtraData"] is None, "NoV performs no balance, account, CRM or AI service action")

langsmith_key = "lsv2_pt_" + klipfolio_key[:32] + "_" + klipfolio_key[:10]
larksuite_token = "t-" + key32[:20]
larksuite_id = "cli_" + key32[:16]
for selector, number, source, key, parts, raw_v2, extra in (
    ("LanguageLayer", 489, "LANGUAGELAYER " + knapsackpro_key, knapsackpro_key, {"key": knapsackpro_key}, "", None),
    ("LangSmith", 1028, langsmith_key, langsmith_key, {"key": langsmith_key}, "", None),
    ("LarkSuite", 991, "lark " + larksuite_token, larksuite_token, {"key": larksuite_token}, "", {"token_type": "Tenant Access Token"}),
    ("LarkSuiteApiKey", 992, "lark " + larksuite_id + "\nlark " + key32, larksuite_id,
     {"key": larksuite_id, "secret": key32}, larksuite_id + key32, None),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number and rows[0]["Raw"] == key, "Language and Lark scanners dispatch source-derived version-zero grammars")
    check(rows[0]["SecretParts"] == parts and rows[0]["RawV2"] == raw_v2 and rows[0]["ExtraData"] == extra, "Lark token kind and required hidden credentials retain exact result fields")
    check(not rows[0]["Verified"], "NoV performs no language, AI, calendar or token-issuance action")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=LarkSuite"], ("lark t-" + key32[:16] + ".json").encode())
check(not rows, "LarkSuite retains its provider-specific extension false-positive classification")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=LarkSuiteApiKey"], ("lark " + larksuite_id).encode())
check(not rows, "LarkSuiteApiKey requires its independent hidden secret even without verification")

launchdarkly_key = "api-" + key32[:8].lower() + "-" + key32[8:12].lower() + "-4" + key32[13:16].lower() + "-" + key32[16:20].lower() + "-" + key32[20:].lower()
lemlist_key = klipfolio_key[:32]
lemonsqueezy_signature = (key40 * 13)[:512]
lemonsqueezy_prefix = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + (key32 * 10)[:314] + "."
lemonsqueezy_clipped = lemonsqueezy_prefix + lemonsqueezy_signature
# An internal keyword makes the complete token visible in the default radius.
lemonsqueezy_signature = lemonsqueezy_signature[:48] + "lemonsqueezy" + lemonsqueezy_signature[60:]
lemonsqueezy_key = lemonsqueezy_prefix + lemonsqueezy_signature
for selector, number, source, key, extra in (
    ("LaunchDarkly", 191, launchdarkly_key, launchdarkly_key, {}),
    ("Lemlist", 841, "LEMLIST " + lemlist_key, lemlist_key, None),
    ("LemonSqueezy", 952, "lemonsqueezy " + lemonsqueezy_key, lemonsqueezy_key, None),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number and rows[0]["Raw"] == key, "LaunchDarkly, Lemlist and LemonSqueezy dispatch source-derived version-zero grammars")
    check(rows[0]["SecretParts"] == {"key": key} and rows[0]["RawV2"] == "" and rows[0]["ExtraData"] == extra, "LaunchDarkly's empty NoV map remains distinct from absent metadata")
    check(not rows[0]["Verified"], "NoV performs no feature-flag, outreach or product service action")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=LaunchDarkly"], ("mob-" + launchdarkly_key[4:]).encode())
check(not rows, "Public LaunchDarkly mobile keys remain excluded")
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=LemonSqueezy"], ("lemonsqueezy " + lemonsqueezy_clipped).encode())
check(not rows, "An external keyword alone clips the long token at the source's default radius")

ldap_url = "ldap://192.0.2.7/dc=Briar"
ldap_user, ldap_password = "BriarZ", key32[:20]
ldap_raw = "\t".join((ldap_url, ldap_user, ldap_password))
ldap_parts = {"url": ldap_url, "username": ldap_user, "password": ldap_password}
ldap_source = ldap_url + "\nuser '" + ldap_user + "'\npass '" + ldap_password + "'"
ldap_iad = 'OpenDSObject("' + ldap_url.replace("ldap://", "LDAP://") + '", "' + ldap_user + '", "' + ldap_password + '", 1)'
for source in (ldap_source, ldap_iad):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=LDAP"], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == 901 and rows[0]["Raw"] == ldap_raw, "LDAP dispatches both source credential forms and projects the URL scheme")
    check(rows[0]["SecretParts"] == ldap_parts and rows[0]["RawV2"] == "" and rows[0]["ExtraData"] is None, "LDAP retains URL, username and password parts without invented metadata")
    check(not rows[0]["Verified"], "LDAP NoV performs no dial, bind or TLS action")

lendflow_segments = [(key40 * 6)[:n] for n in (36, 235, 32, 47, 162, 42, 40, 66, 59, 7, 220)]
lendflow_key = ".".join(lendflow_segments[:2]) + "." + "-".join(lendflow_segments[2:])
lessannoyingcrm_key = (key40 * 2)[:57]
lessannoyingcrm_key = lessannoyingcrm_key[:20] + "-" + lessannoyingcrm_key[21:]
lexigram_key = (key40 * 8)[:301]
linearapi_key = "lin_api_" + key40
for selector, number, source, key in (
    ("Lendflow", 668, "lendflow " + lendflow_key, lendflow_key),
    ("LessAnnoyingCRM", 267, "lessannoyingcrm " + lessannoyingcrm_key, lessannoyingcrm_key),
    ("Lexigram", 437, "LEXIGRAM " + lexigram_key, lexigram_key),
    ("LinearAPI", 177, linearapi_key, linearapi_key),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorType"] == number and rows[0]["Raw"] == key, "Financial, CRM, medical and project scanners dispatch their exact source grammars")
    check(rows[0]["SecretParts"] == {"key": key} and rows[0]["RawV2"] == "" and rows[0]["ExtraData"] is None, "The four single-key scanners retain only source result fields")
    check(not rows[0]["Verified"], "NoV performs no financial, CRM, medical or project service action")
for selector, source in (
    ("LDAP", ldap_url + "\nuser '" + ldap_user + "'"),
    ("Lendflow", "lendflow " + lendflow_key[:-1]),
    ("LessAnnoyingCRM", "less " + lessannoyingcrm_key),
    ("Lexigram", "lexigram " + lexigram_key[:-1]),
    ("LinearAPI", "LIN_API_" + key40),
):
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=" + selector], source.encode())
    check(not rows, "Hidden LDAP credentials, exact lengths, CRM dispatch and sensitive Linear prefixes remain required")

for version, token in ((1, key32[:24]), (2, "ATATT" + key40 + "=" + key32[:8])):
    source = "jira " + token + "\njira XKName@grum.com\njira X\u212aName@grum.com"
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=120.v" + str(version)], source.encode())
    check(len(rows) == 1 and rows[0]["DetectorName"] == "JiraToken" and rows[0]["Raw"] == token, "Both Jira versions dispatch real scanners and deduplicate captured emails after Go lowercase")
    check(rows[0]["RawV2"] == "xkname@grum.com:" + token + ":api.atlassian.com", "Jira's rewritten email byte length controls RawV2")
    check(rows[0]["SecretParts"] == {"token": token, "email": "xkname@grum.com", "domain": "api.atlassian.com"}, "The fallback host and source-lowercased email retain their named parts")
    check(rows[0]["ExtraData"] == {"rotation_guide": "https://howtorotate.com/docs/tutorials/atlassian/", "version": str(version)} and not rows[0]["Verified"], "Jira keeps source version/rotation metadata without authenticating")
    _, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=120.v" + str(version)], ("jira " + token).encode())
    check(not rows, "Both Jira versions require an independent captured email")

# ADC deliberately byte-slices this valid Unicode token into invalid UTF8.
# Preserve C result bytes, but repair the outer JSON string like Go's encoder.
adc = json.dumps({"client_id": key32 + ".apps.googleusercontent.com", "client_secret": "offline",
                  "refresh_token": "abé", "type": "authorized_user"}).encode()
_, rows = invoke(["stdin", "--json", "--no-verification", "--include-detectors=983"], adc)
check(len(rows) == 1, "ADC byte-sliced redaction still emits one valid JSON finding")
check(rows[0]["Raw"] == key32, "ADC keeps the first-dot identifier")
check(rows[0]["RawV2"] == key32 + "abé", "outer repair does not alter original credential bytes")
check(rows[0]["Redacted"] == "ab\ufffd...\ufffd", "outer JSON replaces each invalid redaction byte like Go")
check(rows[0]["SecretParts"]["refresh_token"] == "abé", "hidden token remains intact")

print(f"end-to-end: {checks} assertions, 0 failures (synthetic stdin/filesystem, verification disabled)")
