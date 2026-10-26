#!/usr/bin/env python3
"""Compare implemented CLI slices and the four wired decoders with the pinned reference.

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


def positioned(parts, size=None):
    end = max(offset + len(value) for offset, value in parts)
    size = end + 32 if size is None else size
    assert end <= size <= 65536
    source = bytearray(b"." * size)
    for offset, value in parts:
        source[offset:offset + len(value)] = value
    return bytes(source)


def multipart_fixtures():
    key = b"b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2"[:32]
    secret = key[::-1]
    part = b"c7d8e9f0"
    cases = []
    for name, number, key_line, part_line in (
        ("adzuna", 431, b"adzuna " + key, b"adzuna " + part),
        ("aeroworkflow", 693, b"aeroworkflow " + key[:20], b"aeroworkflow 734"),
        ("agora", 197, b"key " + key, b"secret " + secret),
    ):
        prefix = b"agora\n" if name == "agora" else b""
        normal = prefix + key_line + b"\n" + part_line
        for label, source, kind, clean in (
            ("normal", normal, "stdin", False),
            ("reversed", prefix + part_line + b"\n" + key_line, "stdin", False),
            ("missing_part", prefix + key_line, "stdin", False),
            ("duplicates", normal + b"\n" + normal, "stdin", False),
            ("cleaning", normal + b"\n" + normal, "stdin", True),
            ("filesystem", b"header\n" + normal + b"\n" + normal, "filesystem", False),
        ):
            cases.append((f"multipart_{name}_" + label, source, str(number), kind, clean))
        cases.append((f"multipart_{name}_version_zero", normal, f"{number}.v0", "stdin", False))
    cases.append(("multipart_adzuna_raw_v2_distinct", b"header\nadzuna " + key + b"\nadzuna " + part + b"\nadzuna example1", "431", "filesystem", False))
    cases.append(("multipart_agora_aliases_are_not_prefilter_keywords", b"key " + key + b"\nsecret " + secret, "197", "stdin", False))
    cases.append(("multipart_agora_cartesian_skip_equal", b"agora " + key + b"\nagora " + secret, "197", "stdin", False))
    cases.append(("multipart_agora_equal_parts", b"agora\nkey " + key + b"\nsecret " + key, "197", "stdin", False))

    aha = b"b7c9d2e5f6b8c3d4" * 4
    for label, source in (
        ("normal", b"aha " + aha + b"\nsynthetic.aha.io"),
        ("missing_dispatch_keyword", b"aha " + aha),
        ("bare_host_fallback", b"aha " + aha + b"\naha.io"),
        ("duplicate_hosts", b"aha " + aha + b"\nsynthetic.aha.io\nsynthetic.aha.io"),
        ("two_hosts", b"aha " + aha + b"\nsynthetic.aha.io\nsecond.aha.io"),
        ("keyword_case_url_fallback", b"AHA " + aha + b"\nsynthetic.AHA.IO"),
    ):
        cases.append(("multipart_aha_" + label, source, "802", "stdin", False))
    cases.append(("multipart_aha_version_zero", b"aha " + aha + b"\nsynthetic.aha.io", "802.v0", "stdin", False))
    cases.append(("multipart_aha_filesystem", b"header\naha " + aha + b"\nsynthetic.aha.io\nsecond.aha.io", "802", "filesystem", False))

    for distance, bridged in ((1500, False), (2048, False), (2049, False), (11000, False), (11000, True), (15000, True)):
        parts = [(0, b"adzuna " + key + b"\n"), (distance, b"adzuna " + part + b"\n")]
        if bridged:
            parts.extend((at, b"adzuna\n") for at in range(1800, distance, 1800))
        source = positioned(parts)
        name = f"multipart_distance_{distance}" + ("_bridged" if bridged else "")
        cases.append((name, source, "431", "stdin", False))
        if bridged:
            cases.append((name + "_filesystem", source, "431", "filesystem", False))
    # Only the single 'agora' keyword creates a window [976, 3024).
    for label, key_at, secret_at in (("left_exact", 976, 2100), ("left_clipped", 975, 2100),
                                     ("right_exact", 976, 2985), ("right_clipped", 976, 2986)):
        source = positioned([(key_at, b"key " + key), (2000, b"agora"), (secret_at, b"secret " + secret)])
        cases.append(("multipart_span_" + label, source, "197", "stdin", False))
    return cases


def chunk_fixtures():
    key = b"b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2"[:32]
    second = key[::-1]
    part, other_part = b"c7d8e9f0", b"d8e9f0a1"
    cases = []
    for id_at in (13297, 13298):
        source = positioned([(10000, b"adzuna " + key + b"\n"), (11800, b"adzuna\n"),
                             (id_at, b"adzuna " + part + b"\n")])
        cases.append((f"chunk_multipart_peek_edge_{id_at}", source, "431", "stdin", False))
    for label, first_at, next_key in (("content_only_lines", 11000, second),
                                      ("raw_location_full_decoded_chunk", 11000, key),
                                      ("raw_v2_across_chunks", 100, key)):
        source = positioned([(first_at, b"adzuna " + key + b"\n"), (first_at + 100, b"adzuna " + part + b"\n"),
                             (14000, b"adzuna " + next_key + b"\n"), (14100, b"adzuna " + other_part + b"\n")])
        cases.append(("chunk_multipart_" + label, source, "431", "filesystem", False))
    scalar = b"abyssale " + synthetic("abyssale", 40)
    for at in (10210, 13300):
        source = positioned([(0, b"header\n"), (at, scalar + b"\n")])
        for kind in ("stdin", "filesystem"):
            cases.append((f"chunk_scalar_{at}_" + kind, source, "239", kind, False))
    for size in (10240, 13312, 65536):
        source = positioned([(0, b"header\n"), (size - len(scalar), scalar)], size)
        cases.append((f"chunk_eof_{size}", source, "239", "filesystem", False))
    source = positioned([(0, b"header\n"), (100, scalar + b"\n"), (15000, b"\xff")])
    cases.append(("chunk_plain_normalization_is_local", source, "239", "filesystem", False))
    pair = b"adzuna " + key + b"\nadzuna " + part
    source = positioned([(0, b"header\n"), (13280, base64.b64encode(pair))])
    cases.append(("chunk_base64_multipart_at_peek_edge", source, "431", "filesystem", False))
    return cases


def utf16_bytes(source, endian="le"):
    return source.decode("ascii").encode("utf-16" + endian)


def utf16_fixtures():
    key = synthetic("abyssale", 40)
    other_key = synthetic("utf16-second", 40)
    plain, other = b"abyssale " + key, b"abyssale " + other_key
    leading = b" " + plain  # Even length keeps the sibling UTF16 block aligned.
    mixed = utf16_bytes(plain + b" ", "be") + utf16_bytes(other + b" ")
    encoded = base64.b64encode(plain)
    cases = []
    for label, source in (
        ("le", utf16_bytes(plain)),
        ("be", utf16_bytes(plain, "be")),
        ("le_odd_invalid_tail", utf16_bytes(plain) + b"\xff"),
        ("be_odd_printable_tail", utf16_bytes(plain, "be") + b"Q"),
        ("mixed_endian_blocks", mixed),
        ("interleaved_endian_pairs", b"".join(bytes((c, 0)) if i % 2 == 0 else bytes((0, c)) for i, c in enumerate(plain))),
        ("printable_only", ("abyssale " + key[:20].decode() + "\u00e9" + key[20:].decode()).encode("utf-16le")),
        ("controls_removed", utf16_bytes(b"heading\n" + plain + b" \r\n")),
        ("duplicates", utf16_bytes(plain + b" \n" + plain + b" ")),
        ("no_keyword", utf16_bytes(key)),
        ("b64_to_le", base64.b64encode(utf16_bytes(plain))),
        ("b64_to_be", base64.b64encode(utf16_bytes(plain, "be"))),
        ("le_to_b64", utf16_bytes(encoded)),
        ("be_to_b64", utf16_bytes(encoded, "be")),
        ("b64_utf16_b64", base64.b64encode(utf16_bytes(encoded))),
        ("utf16_b64_utf16", utf16_bytes(base64.b64encode(utf16_bytes(plain)))),
        ("mixed_plain", leading + b"!!" + utf16_bytes(other)),
        ("mixed_b64_intermediate", base64.b64encode(leading) + b"!!" + utf16_bytes(other)),
        ("plain_duplicate", leading + b"!!" + utf16_bytes(plain)),
        ("b64_duplicate", base64.b64encode(leading) + b"!!" + utf16_bytes(plain)),
        ("convergent_frontier", base64.b64encode(encoded) + b"!!" + utf16_bytes(encoded)),
        ("stdin_ignore", utf16_bytes(plain + b" # trufflehog:ignore")),
    ):
        cases.append(("utf16_" + label, source, "239", "stdin", False))
    cases.append(("utf16_mixed_endian_cleaning", mixed, "239", "stdin", True))
    nested = plain
    for depth in range(1, 7):
        nested = utf16_bytes(nested) if depth % 2 else base64.b64encode(nested)
        if depth >= 2:
            cases.append((f"utf16_alternating_depth_{depth}", nested, "239", "stdin", False))
    for label, source in (
        ("filesystem_le_controls", utf16_bytes(b"heading\n" + plain + b" \n")),
        ("filesystem_be_controls", utf16_bytes(b"heading\n" + plain + b" \n", "be")),
        ("filesystem_duplicates", utf16_bytes(plain + b" \n" + plain + b" ")),
        ("filesystem_nested_b64", utf16_bytes(base64.b64encode(b"heading\n" + plain))),
        ("filesystem_encoded_ignore", utf16_bytes(plain + b" # trufflehog:ignore")),
        ("filesystem_peek", positioned([(0, b"header\n"), (10240, utf16_bytes(plain))])),
        ("filesystem_nested_peek", positioned([(0, b"header\n"), (10240, utf16_bytes(encoded))])),
    ):
        cases.append(("utf16_" + label, source, "239", "filesystem", False))
    part_key = b"b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2"[:32]
    pair = b"heading\nadzuna " + part_key + b" \nadzuna c7d8e9f0 "
    cases.append(("utf16_multipart_metadata", utf16_bytes(pair), "431", "filesystem", False))
    return cases


def escaped_bytes(payload):
    return "".join(r"\u%04x" % c for c in payload).encode("ascii")


def escaped_unicode_fixtures():
    key = synthetic("abyssale", 40)
    plain = b"abyssale " + key
    formats = {
        "long": r"\U{:08x}", "brace": r"\u{{{:x}}}", "perl": r"\x{{{:x}}}",
        "html_hex": "&#x{:x};", "percent": "%u{:04x}", "escaped": r"\u{:04x}",
        "code_point": "U+{:04x} ", "css": "\\{:x} ",
    }
    cases = [("escaped_syntax_" + name, "".join(fmt.format(c) for c in plain).encode("ascii"),
              "239", "stdin", False) for name, fmt in formats.items()]
    escaped = escaped_bytes(plain)
    for name, payload in (
        ("b64_to_escaped", base64.b64encode(escaped)),
        ("escaped_to_b64", escaped_bytes(base64.b64encode(plain))),
        ("utf16_to_escaped", utf16_bytes(escaped, "be")),
        ("escaped_to_utf16", escaped_bytes(utf16_bytes(plain))),
        ("escaped_b64_utf16", escaped_bytes(base64.b64encode(utf16_bytes(plain, "be")))),
        ("invalid_priority", rb"\UFFFFFFFF !!" + escaped),
        ("bad_before_keyword", b"\xff" + escaped),
        ("restored_continuation", b"U+0020\xc3\xa9U+0061 byssale " + key),
        ("bad_prefix_gap", escaped_bytes(b"abyssale ") + b"\xff" + key),
        ("valid_replacement_gap", escaped_bytes(b"abyssale ") + b"\xef\xbf\xbd" + key),
    ):
        cases.append(("escaped_" + name, payload, "239", "stdin", False))
    nested = plain
    for depth in range(1, 7):
        nested = escaped_bytes(nested[:1]) + nested[1:]
        if depth >= 5:
            cases.append((f"escaped_depth_{depth}", nested, "239", "stdin", False))
    cases.append(("escaped_filesystem_nested", utf16_bytes(escaped_bytes(b"heading\n" + plain), "be"),
                  "239", "filesystem", False))
    cases.append(("escaped_filesystem_ignore", escaped_bytes(plain + b" # trufflehog:ignore"),
                  "239", "filesystem", False))
    pair = b"heading\nadzuna " + alnum("escaped-pair", 32) + b"\nadzuna c7d8e9f0"
    cases.append(("escaped_multipart_metadata", escaped_bytes(pair), "431", "filesystem", False))
    return cases


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
    alegra_token = synthetic("alegra-oracle", 20)
    alibaba_payload = b"LTAI" + alnum("alibaba-id-oracle", 17) + b"\n" + alnum("alibaba-key-oracle", 30)
    aws_id = b"AKIAQWERTYUIOPASDFGH"
    aws_secret = alnum("aws-access-secret", 38) + b"+/"
    aws_session_token = b"YXdz" + alnum("aws-session-token", 128) + b"+/==="
    aws_session_payload = b"ASIA" + aws_id[4:] + b"\n" + aws_secret + b"\n" + aws_session_token
    entra_v0 = b"0.A" + alnum("entra-refresh-v0-head", 60) + b".Ag" + alnum("entra-refresh-v0-body", 260)
    entra_v1 = (b"1.A" + alnum("entra-refresh-v1-head", 60) + b".4.Ag" + alnum("entra-refresh-v1-body", 260) +
                b".A" + alnum("entra-refresh-v1-tail", 220))
    entra_context = b"client_id A6B39F20-17C4-4D85-9E62-0F3A7B1C5D98\ntenant Reader.onmicrosoft.com\n"
    canary_bits = ((1 << 47) | (52310077262 << 7) | 7).to_bytes(6, "big") + b"\xab\xcd\xef\x01"
    aws_canary_id = b"AKIA" + base64.b32encode(canary_bits)
    provider_cases = (
        ("airbrake_project", 125, b"airbrake key " + synthetic("airbrake-project", 32) + b"\nairbrake project 317849"),
        ("airbrake_user", 126, b"airbrake " + synthetic("airbrake-user", 40)),
        ("airship", 277, b"airship " + alnum("airship-oracle", 91)),
        ("airtable_oauth", 1014, b"airtable " + alnum("airtable-prefix", 16) + b".v1." + alnum("airtable-body", 40) + b"." + synthetic("airtable-suffix", 32)),
        ("airtable_pat", 1015, b"airtable pat" + alnum("airtable-pat", 14) + b"." + synthetic("airtable-pat-suffix", 64)),
        ("airvisual", 498, b"airvisual " + synthetic("airvisual-oracle", 36)),
        ("aiven", 917, b"aiven " + alnum("aiven-oracle", 372)),
        ("alchemy_legacy", 907, b"alchemy " + alnum("alchemy-legacy", 32)),
        ("alchemy_prefixed", 907, b"alchemy alcht_" + alnum("alchemy-prefixed", 30)),
        ("alegra", 375, b"alegra " + alegra_token + b"\nalegra fixture@example.test"),
        ("alegra_nul_id", 375, b"alegra " + alegra_token + b"\n" + b"." * 128 + b"\nalegra\x00fixture@example.test"),
        ("aletheiaapi", 522, b"aletheiaapi " + synthetic("aletheia-oracle", 32).upper()),
        ("algoliaadminkey", 170, b"algolia\nappId B7C9D2E5F6\napiKey " + alnum("algolia-admin-oracle", 32)),
        ("alibaba", 0, alibaba_payload),
        ("alienvault", 399, b"alienvault " + synthetic("alienvault-oracle", 64)),
        ("allsports", 473, b"allsports " + synthetic("allsports-oracle", 64)),
        ("amadeus", 453, b"amadeus " + alnum("amadeus-key-oracle", 32) + b"\namadeus " + alnum("amadeus-secret-oracle", 16)),
        ("ambee", 457, b"ambee " + synthetic("ambee-oracle", 64)),
        ("amplitude", 42, b"amplitude " + synthetic("amplitude-key-oracle", 32) +
         b"\namplitude " + synthetic("amplitude-secret-oracle", 32)),
        ("anthropic_api", 933, b"sk-ant-api03-" + alnum("anthropic-api-oracle", 93) + b"AA"),
        ("anthropic_admin", 933, b"sk-ant-admin01-" + alnum("anthropic-admin-oracle", 93) + b"AA"),
        ("anypoint", 179, b"anypoint b7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3\n"
         b"org c7d8e9f0-g1h2-i3j4-k5l6-m7n8o9p0q1r2"),
        ("anypointoauth2", 1032, b"anypoint id " + synthetic("anypoint-oauth-id", 32) +
         b"\nsecret " + synthetic("anypoint-oauth-secret", 32).upper()),
        ("apacta", 632, b"apacta " + synthetic("apacta-oracle", 36)),
        ("api2cart", 458, b"api2cart " + synthetic("api2cart-oracle", 32)),
        ("apideck", 212, b"apideck sk_live_" + alnum("apideck-key-oracle", 93) +
         b"\napideck " + alnum("apideck-id-oracle", 40)),
        ("apiflash", 401, b"apiflash " + alnum("apiflash-oracle", 32).lower()),
        ("apifonica", 484, b"apifonica b7c9d2e5f6g-h3j4-k1m0-n2p4-q6r8s1t3u5v7\n"
         b"apifonica c7d8e9f0g1h-i2j3-k4l5-m6n7-o8p9q0r1s2t3"),
        ("apify", 391, b"apify_api_" + alnum("apify-oracle", 36)),
        ("apilayer", 788, b"apilayer " + alnum("apilayer-oracle", 32)),
        ("apimatic", 637, b"apimatic\n" + b"." * 64 + b"\napikey " + alnum("apimatic-oracle", 64)),
        ("apimetrics", 1004, b"apimetrics " + alnum("apimetrics-oracle", 32)),
        ("apitemplate", 768, b"apitemplate " + alnum("apitemplate-oracle", 39)),
        ("appcues", 322, b"appcues " + alnum("appcues-key", 36).lower() +
         b"\nappcues " + alnum("appcues-user", 39).lower() + b"\nappcues 00427\nappcues 00428"),
        ("appfollow", 588, b"appfollow eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
         alnum("appfollow-payload", 74) + b"." + alnum("appfollow-signature", 43)),
        ("appointedd", 816, b"appointedd " + alnum("appointedd-key", 44) + b"=" +
         alnum("appointedd-rest", 43) + b"LongerSuffix"),
        ("appsynergy", 646, b"appsynergy " + alnum("appsynergy-key", 64).lower()),
        ("apptivo", 269, b"apptivo " + alnum("apptivo-api-key", 36).lower() +
         b"\napptivo " + alnum("apptivo-access-key", 32)),
        ("artifactory", 181, b"AKCp" + alnum("artifactory-token", 69) +
         b"\nsynthetic-fixture.jfrog.io"),
        ("artifactoryreferencetoken", 1042, b"cmVmdGtu" + alnum("artifactory-reference", 56) +
         b"\nsynthetic-fixture.jfrog.io"),
        ("artsy", 278, b"artsy " + alnum("artsy-key", 32) + b"\nartsy " + alnum("artsy-id", 20)),
        ("asanaoauth", 98, b"asana " + alnum("asana-oauth-key", 51).lower()),
        ("asanapat_old", 41, b"asana 0/1234567890123456:" + alnum("asana-old-pat", 32)),
        ("asanapat_new", 41, b"asana 1/1234567890123456/0987654321098765:" + alnum("asana-new-pat", 40)),
        ("assemblyai", 389, b"assemblyai " + alnum("assemblyai-key", 32).lower()),
        ("atera", 800, b"atera " + alnum("atera-key", 32).lower()),
        ("atlassian_v1", "190.v1", b"atlassian " + alnum("atlassian-v1-key", 24)),
        ("atlassian_v2", "190.v2", b"ATCTT3xFfG" + alnum("atlassian-v2-key", 45) + b"=F1c2A3b4"),
        ("atlassian_v2_org", "190.v2", b"ATCTT3xFfG" + alnum("atlassian-v2-key", 45) +
         b"=F1c2A3b4\norg zzzzzzzz-qrst-uvwx-yz12-zzzzzzzzzzzz"),
        ("bitbucketdatacenter", 1045, b"BBDC-" + alnum("bitbucket-dc-key", 45) +
         b"\nbitbucket https://bitbucket.synthetic.invalid:8443/discard?old=1"),
        ("confluencedatacenter", 1047, b"confluence " +
         base64.b64encode(b"123456789012:" + alnum("confluence-dc", 20)) +
         b"\nconfluence https://confluence.synthetic.invalid:8443/discard"),
        ("confluencedatacenter_no_endpoint", 1047, b"confluence " +
         base64.b64encode(b"123456789012:" + alnum("confluence-dc", 20))),
        ("jiradatacenterpat", 1046, b"jira " +
         base64.b64encode(b"123456789012:" + alnum("jira-dc", 20)) +
         b"\njira https://jira.synthetic.invalid:8443/discard"),
        ("jiradatacenterpat_no_endpoint", 1046, b"jira " +
         base64.b64encode(b"123456789012:" + alnum("jira-dc", 20))),
        ("audd", 376, b"audd " + alnum("audd-key", 32).lower()),
        ("auth0managementapitoken", 110, b"auth0 ey" + alnum("auth0-management", 1998) +
         b"\nfixture-tenant.us.auth0.com"),
        ("auth0managementapitoken_maximum", 110, b"eyauth0" + alnum("auth0-management-long", 4993) +
         b"\nfixture-tenant.us.auth0.com"),
        ("auth0managementapitoken_overlong", 110, b"eyauth0" + alnum("auth0-management-long", 4994) +
         b"\nfixture-tenant.us.auth0.com"),
        ("auth0oauth", 55, b"auth0 " + alnum("auth0-client-id", 32) + b"\n" +
         alnum("auth0-client-secret", 64) + b"\nfixture-tenant.us.auth0.com"),
        ("autodesk", 604, b"autodesk " + alnum("autodesk-key", 32) +
         b"\nautodesk " + alnum("autodesk-secret", 16)),
        ("autoklose", 323, b"autoklose " + alnum("autoklose-key", 32)),
        ("autopilot", 511, b"autopilot " + synthetic("autopilot-key", 32)),
        ("avazapersonalaccesstoken", 733, b"avaza 0007-" + synthetic("avaza-key", 40)),
        ("aviationstack", 564, b"aviationstack " + alnum("aviationstack-key", 32).lower()),
        ("aws_appsync", 1052, b"da2-" + alnum("appsync-key", 26).lower() + b"\nhttps://" +
         alnum("appsync-endpoint", 26).lower() + b".appsync-api.us-east-1.amazonaws.com/graphql"),
        ("axonaut", 320, b"axonaut " + alnum("axonaut-key", 32).lower()),
        ("aylien", 485, b"aylien " + alnum("aylien-key", 32).lower() +
         b"\naylien " + alnum("aylien-id", 8).lower()),
        ("ayrshare", 163, b"ayrshare " + b"-".join(alnum(f"ayrshare-key-{part}", 8).upper() for part in range(4))),
        ("azure_apim_subscription", 1019, b"https://briar-apim.azure-api.net\nsubscription " +
         alnum("azure-apim-subscription", 32)),
        ("azure_apim_subscription_fp_case", 1019, b"https://example.azure-api.net\nhttps://UPPER.azure-api.net\nsubscription " +
         alnum("azure-apim-subscription-hyphen", 15) + b"-" + alnum("azure-apim-subscription-tail", 16)),
        ("azure_entra_refresh_v0_default", 1013, entra_v0),
        ("azure_entra_refresh_v1_context", 1013, entra_context + entra_v1),
        ("azure_entra_refresh_far_context", 1013, entra_context + b"." * 3000 + b"\n" + entra_v0),
        ("azure_entra_sp_v1", "3.v1", entra_context + b"secret '" + alnum("entra-sp-v1-secret", 32) + b"'\n"),
        ("azure_entra_sp_v2", "3.v2", entra_context + b"secret 'b7c1Q~" + alnum("entra-sp-v2-secret", 31) + b"'\n"),
        ("azure_entra_sp_v2_standalone", "3.v2", b"b7c1Q~" + alnum("entra-sp-v2-standalone", 31)),
        ("azure_batch", 957, b"https://brbatch.eastus.batch.azure.com\n" + alnum("azure-batch-key", 88)),
        ("azure_batch_false_positive_override", 957, b"https://example.eastus.batch.azure.com\n" + b"=" * 88),
        ("azure_appconfig_connection", 1025, b"Endpoint=https://briar-config.azconfig.io;Id=" +
         alnum("azure-appconfig-id", 32) + b";Secret=" + base64.b64encode(alnum("azure-appconfig-secret", 32))),
        ("azure_appconfig_whole_identity", 1025, b"Endpoint=https://Briar-config.azconfig.io;Id=" +
         alnum("azure-appconfig-shared-id", 32) + b";Secret=AAECAw==\nEndpoint=https://Briar-config.azconfig.io;Id=" +
         alnum("azure-appconfig-shared-id", 32) + b";Secret=AAECAw==Q"),
        ("azure_cosmosdb_document", 971, b"briar-cosmos.documents.azure.com\n" + alnum("cosmos-document-key", 86) + b"=="),
        ("azure_cosmosdb_table", 971, b"briar-cosmos.table.cosmos.azure.com\n" + alnum("cosmos-table-key", 86) + b"=="),
        ("azure_container_registry", 958, b"briar-registry.azurecr.io\n" +
         alnum("azure-registry-password", 40) + b"+/+ACR" + alnum("azure-registry-password-tail", 6)),
        ("azure_container_registry_exclusions", 958, b"briar-registry.azurecr.io\nmyacr.azurecr.io\nprivatelink.azurecr.io\n" +
         alnum("azure-registry-first-password", 42) + b"+ACR" + alnum("azure-registry-first-tail", 6) + b"\n" +
         alnum("azure-registry-second-password", 42) + b"+ACR" + alnum("azure-registry-second-tail", 6) + b"\n" +
         alnum("azure-registry-wrong-case", 42) + b"+acr" + alnum("azure-registry-wrong-tail", 6)),
        ("azure_devops_pat", 972, b"AZURE token " + alnum("azure-devops-key", 52).lower() + b"\nAZURE org Briar-Org7"),
        ("azure_devops_pat_uppercase_key", 972, b"AZURE token " + alnum("azure-devops-upper-key", 52).upper() + b"\nAZURE org Briar-Org8"),
        ("azure_direct_management", 1024, b"https://briar-direct.management.azure-api.net\nazure " +
         alnum("azure-direct-key", 86) + b"=="),
        ("azure_direct_management_ascii_key", 1024, b"https://example.management.azure-api.net\nazure " +
         alnum("azure-direct-ascii-key", 84) + b"=="),
        ("azure_openai", 1007, b"briar-openai.openai.azure.com\napi_key " + synthetic("azure-openai-key", 32)),
        ("azure_openai_no_hostname", 1007, b".openai.azure.com\nopenai.key " + synthetic("azure-openai-standalone", 32)),
        ("azure_sas_token", 975, b"https://briar-store.blob.core.windows.net/container/blob.txt\n" +
         b"sp=r&sv=2025-01-01&sr=b&se=2027-01-02T03:04:05Z&sig=" + alnum("azure-sas-signature", 32) + b"%3D"),
        ("azure_sas_raw_order_bytes", 975, b"https://A_b.blob.core.windows.net/ab/leaf\nsas=sig=" +
         alnum("azure-sas-raw-signature", 32) + b"%3D&sr=c&se=2027-01-02T03%3a04%3A05Z&sv=9999-99-99&sp=x&sp=rr&zz=a\vvalue"),
        ("azure_search_admin", 976, b"azure " + alnum("azure-search-admin-key", 52) + b"\nazure OriginalSvc7"),
        ("azure_search_admin_services", 976, b"azure " + alnum("azure-search-multiple-key", 52) +
         b"\nazure OriginalSvc7\nazure SecondSvc8"),
        ("azure_search_query", 977, b"azure " + alnum("azure-query-key", 52) +
         b"\nazure https://briarsearch.search.windows.net/indexes/briarindex"),
        ("azure_search_query_full_match", 977, b"azure " + alnum("azure-query-full-match", 52) +
         b"\nazure\vhttps://briarsearch.search.windows.net/indexes/briarindex"),
        ("azure_storage_connection", 931, b"DefaultEndpointsProtocol=https;AccountName=briarstorage;AccountKey=" +
         alnum("azure-storage-connection", 86) + b"==;EndpointSuffix=core.windows.net"),
        ("azure_storage_blob", 931, b"https://briarstorage.blob.core.windows.net\nStorage_Key=" +
         alnum("azure-storage-blob", 86) + b"=="),
        ("azure_apim_repository", 1018, b"azure url briar-apim.scm.azure-api.net\nazure password git&172635480927&" +
         alnum("azure-apim-password", 83) + b"+/A=="),
        ("bannerbear_v1", "430.v1", b"bannerbear " + alnum("bannerbear-legacy", 22) + b"tt"),
        ("bannerbear_v2", "430.v2", b"bb_pr_" + synthetic("bannerbear-project", 30) +
         b"\nbb_ma_" + synthetic("bannerbear-master", 30) + b"\nbb_pr_" + synthetic("bannerbear-project", 30)),
        ("baremetrics", 377, b"baremetrics sk_" + alnum("baremetrics-sandbox", 18) +
         b"\nbaremetrics lk_" + alnum("baremetrics-production", 25)),
        ("beamer", 166, b"beamer " + alnum("beamer-symbol-key", 42) + b"_+/="),
        ("beamer_leading_nonword", 166, b"beamer W+" + alnum("beamer-leading-symbol", 44) + b"="),
        ("beebole", 684, b"BEEBOLE " + alnum("beebole-key", 40).lower()),
        ("besttime", 506, b"BESTTIME pri_" + synthetic("besttime-key", 32)),
        ("betterstack", 947, b"BETTERSTACK " + alnum("betterstack-key", 24)),
        ("billomat", 385, b"BILLOMAT briar7\nBILLOMAT " + synthetic("billomat-key", 32)),
        ("billomat_context_id", 385, b"billomat " + synthetic("billomat-context-key", 32) + b"\nbillomat briar8"),
        ("bitbar", 387, b"BITBAR " + alnum("bitbar-key", 32)),
        ("bitbucket_app_colon", 1029, b"briar7:ATBB" + alnum("bitbucket-app-colon", 36)),
        ("bitbucket_app_url", 1029, b"https://briar8:ATBB" + alnum("bitbucket-app-url", 36) + b"=.-@bitbucket.org.evil"),
        ("bitbucket_app_quoted", 1029, b'"briar9",\n\f"ATBB' + alnum("bitbucket-app-quoted", 36) + b'=.-"'),
        ("bitbucket_app_overwrite", 1029, b'"briara", "ATBB' + alnum("bitbucket-app-winning", 36) +
         b'=.-"\nhttps://briara:ATBB' + alnum("bitbucket-app-url-loses", 36) + b"=@bitbucket.org\nbriara:ATBB" +
         alnum("bitbucket-app-last-input-loses", 36)),
        ("bitcoinaverage", 432, b"BITCOINAVERAGE " + alnum("bitcoinaverage-key", 43)),
        ("bitfinex", 56, b"bitfinex " + alnum("bitfinex-first", 40) + b"_-Q\nbitfinex " +
         alnum("bitfinex-second", 40) + b"_-R"),
        ("bitly_access_token", 43, b"bitly " + alnum("bitly-hyphen-token", 37) + b"-g9"),
        ("bitly_leading_hyphen", 43, b"bitly-" + alnum("bitly-leading-hyphen", 39)),
        ("bitmex", 512, b"BITMEX " + alnum("bitmex-key", 22) + b"_-\nBITMEX " +
         alnum("bitmex-secret", 46) + b"_-\n"),
        ("blazemeter", 603, b"RUNSCOPE z7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3"),
        ("blitapp", 523, b"BLITAPP " + alnum("blitapp-key", 19) + b"_-" + alnum("blitapp-tail", 18)),
        ("blitapp_leading_hyphen", 523, b"blitapp-" + alnum("blitapp-leading-hyphen", 38)),
        ("blogger", 302, b"BLOGGER AIzaSy" + alnum("blogger-hyphen-key", 32) + b"-"),
        ("blogger_long_suffix", 302, b"blogger AIzaSy" + alnum("blogger-long-key", 33) + b"EXTRA"),
        ("bombbomb", 565, b"BOMBBOMB ey" + alnum("bombbomb-first", 32) + b"!ey" +
         alnum("bombbomb-second", 48) + b"?" + alnum("bombbomb-third", 35)),
        ("bombbomb_empty_segments", 565, b"bombbomb ey!ey?" + b"A" * 172),
        ("bombbomb_trim_ascii", 565, b"bombbomb ey.ey " + b"A" * 172),
        ("bombbomb_trim_unicode", 565, b"bombbomb ey.ey\xe3\x80\x80" + b"A" * 172),
        ("bombbomb_embedded_nul", 565, b"bombbomb ey" + alnum("bombbomb-nul-first", 16) + b"\0ey" +
         alnum("bombbomb-nul-second", 19) + b"~" + alnum("bombbomb-nul-third", 23)),
        ("boostnote", 707, b"BOOSTNOTE " + hashlib.sha256(b"briar-synthetic-boostnote").hexdigest().encode()),
        ("borgbase", 723, b"borgbase " + alnum("borgbase-first", 70) + b"/_." + alnum("borgbase-last", 77)),
        ("box", 1002, b"BOX " + alnum("box-access-token", 32)),
        ("box_oauth", 1003, b"box id " + alnum("box-client-id", 32) + b"\nsecret " + alnum("box-client-secret", 32)),
        ("box_oauth_subject_context", 1003, b"BOX client_id " + alnum("box-subject-client-id", 32) +
         b"\nclient_secret " + alnum("box-subject-client-secret", 32) + b"\nenterprise_id 172635480927\nuser_id 0000087"),
        ("aws_session_keys", 959, aws_session_payload),
        ("aws_session_url_encoded", 959, aws_session_payload.replace(b"+", b"%2B").replace(b"/", b"%2f").replace(b"=", b"%3D")),
        ("aws_access_keys", 2, aws_id + b"\n" + aws_secret),
        ("aws_bearer_id", 2, b"ABIA" + aws_id[4:] + b"\n" + aws_secret),
        ("aws_context_id", 2, b"ACCA" + aws_id[4:] + b"\n" + aws_secret),
        ("aws_url_encoded", 2, aws_id + b"\n" + aws_secret.replace(b"+", b"%2B").replace(b"/", b"%2f")),
        ("aws_canary_metadata", 2, aws_canary_id + b"\n" + aws_secret),
        ("aws_old_account_format", 2, b"AKIAI2BCDEFGHLMNPQR5\n" + aws_secret),
    )
    for label, number, payload in provider_cases:
        cases.append((label + "_stdin", payload, str(number), "stdin", False))
        cases.append((label + "_filesystem", b"heading\n" + payload + b"\n", str(number), "filesystem", False))
    cases.append(("aws_custom_cleaner", aws_id + b"\n\n" + aws_secret + b"\n\n" + alnum("aws-second-secret", 40), "2", "stdin", True))
    cases.append(("aws_session_custom_cleaner", aws_session_payload + b"\n\nJb3JpZ2luX2Vj" + alnum("aws-second-session", 120), "959", "stdin", True))
    cases.append(("datacenter_nonstructural", b"atlassian M" + b"A" * 43, "1046,1047", "stdin", False))
    cases.append(("bitbucketdatacenter_no_endpoint", b"BBDC-" + alnum("bitbucket-dc-key", 45), "1045", "stdin", False))
    cases.append(("alibaba_version_zero", alibaba_payload, "0.v0", "stdin", False))
    cases.extend(multipart_fixtures())
    cases.extend(chunk_fixtures())
    cases.extend(utf16_fixtures())
    cases.extend(escaped_unicode_fixtures())
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
    return sorted(rows, key=lambda row: (row["DetectorType"], row["Raw"], row["RawV2"], json.dumps(row.get("SourceMetadata"), sort_keys=True)))


def reference_matches(case, actual, expected):
    # The oracle has eight detector workers even at --concurrency=1. Notifier
    # dedup is first-arrival, not decoder-priority: repeated identical runs can
    # retain either label for a finding present in PLAIN and BASE64. Native
    # ordering stays PLAIN-first; only these observed duplicate identities vary.
    racing = {
        "base64_mixed_plain_encoded": ("PLAIN", "BASE64"),
        "base64_mixed_encoded_plain": ("PLAIN", "BASE64"),
        "base64_plain_encoded_duplicate": ("PLAIN", "BASE64"),
        "base64_encoded_plain_duplicate": ("PLAIN", "BASE64"),
        "base64_filesystem_mixed_duplicate": ("PLAIN", "BASE64"),
        "utf16_plain_duplicate": ("PLAIN", "UTF16"),
        "utf16_b64_duplicate": ("BASE64", "UTF16"),
    }
    name, source, _, kind, _ = case
    if len(actual) != len(expected):
        return False
    for got, want in zip(actual, expected):
        if got == want:
            continue
        if (got["DecoderName"], want["DecoderName"]) != racing.get(name):
            return False
        if got["DecoderName"] == "PLAIN":
            offset = source.find(got["Raw"].encode())
            if offset < 0:
                return False
            if kind == "filesystem" and got["SourceMetadata"]["Data"]["Filesystem"]["line"] != 1 + source[:offset].count(b"\n"):
                return False
        else:
            # This one observed fixture contains the same Raw in independent
            # Base64 and UTF16 branches, not as contiguous PLAIN source bytes.
            left, right = source.split(b"!!", 1)
            raw = got["Raw"].encode()
            if raw not in base64.b64decode(left, validate=True) or raw not in right.decode("utf-16le").encode("ascii"):
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
    # Default false-positive filtering must not turn these positive fixtures
    # into a vacuous zero-row comparison (for example, a 00000 digit run).
    if name in ("azure_apim_repository_stdin", "azure_apim_repository_filesystem") and (len(actual) != 1 or len(expected) != 1):
        raise AssertionError(name + ": positive fixture must produce exactly one finding")
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
