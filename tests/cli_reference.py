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
    # An internal keyword keeps the complete 681-byte token in the engine's
    # default 512-byte keyword radius without changing the detector's bounds.
    calendly_max_first = alnum("calendly-max-first", 300)
    calendly_max_first = calendly_max_first[:238] + b"calendly" + calendly_max_first[246:]
    captaindata_payload = (b"CAPTAINDATA " + synthetic("captaindata-key", 64) +
                           b"\nCAPTAINDATA b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3")
    caspio_credential = alnum("caspio-credential", 50).lower()
    caspio_payload = b"CASPIO " + caspio_credential + b"\nCASPIO briar7c9"
    cexio_value = alnum("cexio-value", 24)
    checkout_uuid = b"B7c9d2e5-F6a8-b3C4-d1E0-f2A4b6C8d1e3"
    checkout_id = b"cus_" + alnum("checkout-id", 26)
    checkvist_key = alnum("checkvist-key", 14)
    circleci_hex = synthetic("circleci-hex", 40)
    circleci_hex = circleci_hex[:20].upper() + circleci_hex[20:]
    circleci_pat = b"CCIPAT_" + alnum("circleci-payload", 22) + b"_" + circleci_hex
    clickhelp_context = b"B7c9d2.clickhelp.co\nBriar7@Fixture.Invalid\n"
    clickup_tail = b"G7B9D2E5F6H8J3K4M1N0P2Q4R6S8T1U3"
    clicksend_key = b"B7C9D2E5-F6G8-H3J4-K1M0-N2P4Q6R8S1T3"
    clicksend_email = b"Case.User@EXAMPLE.INVALID"
    clockwork_token = alnum("clockwork-token", 24)
    close_key = b"api_" + alnum("close-key", 20) + b"." + alnum("close-key-tail", 24)
    cloudconvert_min = b"ey" + synthetic("cloudconvert-first", 30) + b".ey" + synthetic("cloudconvert-second", 200) + b"." + synthetic("cloudconvert-third", 600)
    cloudconvert_max = b"ey" + synthetic("cloudconvert-max-first", 34) + b".ey" + synthetic("cloudconvert-max-second", 500) + b"." + synthetic("cloudconvert-max-third", 700)
    cloudflare_v1 = alnum("cloudflare-v1-first", 12) + b"_" + alnum("cloudflare-v1-middle", 12) + b"-" + alnum("cloudflare-v1-last", 14)
    cloudflare_v2_body = alnum("cloudflare-v2-body", 40) + synthetic("cloudflare-v2-checksum", 8)
    cloudflare_user = b"cfut_" + cloudflare_v2_body
    cloudflare_account = b"cfat_" + cloudflare_v2_body
    cloudflare_account_id = synthetic("cloudflare-account-id", 32)
    cloudflare_other_id = synthetic("cloudflare-other-id", 32)
    cloudflare_global_legacy = synthetic("cloudflare-global-legacy", 37)
    cloudflare_global_modern = b"cfk_" + cloudflare_v2_body
    cloudflare_global_email = b"Case.User@Example.INVALID"
    cloudinary_key = b"001726354809273"
    cloudinary_secret = alnum("cloudinary-secret", 27)
    cloze_key = synthetic("cloze-key", 32)
    cloze_email = b"Case.User@Example.INVALID"
    coda_key = b"-".join(alnum("coda-key-" + str(i), width).lower() for i, width in enumerate((8, 4, 4, 4, 12)))
    coda_key = b"g" + coda_key[1:]  # Lowercase alphanumeric shape, deliberately not hex.
    codemagic_key = alnum("codemagic-key", 43)
    codemagic_key = codemagic_key[:12] + b"_" + codemagic_key[13:]
    codequiry_key = alnum("codequiry-key", 64)
    codequiry_key = codequiry_key[:17] + b"-" + codequiry_key[18:]
    coinapi_key = b"G" + alnum("coinapi-key", 35).upper()
    coinapi_key = coinapi_key[:12] + b"-" + coinapi_key[13:]  # Neither hex nor UUID grouping.
    # PUBLIC scalar ONE and fictitious nonhex/underscore names, never account credentials.
    coinbase_name = b"organizations/ORG__123-AB_C-de_F-GHI_-abcdefgh1234/apiKeys/KEY__123-ZZ__-aaaa-bbbb-GHIJklmn5678"
    coinbase_der = bytes.fromhex("3012020101040101a00a06082a8648ce3d030107")
    def coinbase_pem(der):
        return b"-----BEGIN EC PRIVATE KEY-----\n" + base64.b64encode(der) + b"\n-----END EC PRIVATE KEY-----"
    coinbase_key = coinbase_pem(coinbase_der)
    coinlayer_key = b"g" + alnum("coinlayer-key", 31).lower()  # Lowercase alphanumeric, not hex.
    coinlib_key = b"g" + alnum("coinlib-key", 15).lower()
    collect2_hex = synthetic("collect2-key", 32)
    collect2_key = b"-".join(collect2_hex[a:b] for a, b in ((0, 8), (8, 12), (12, 16), (16, 20), (20, 32)))
    collect2_key = collect2_key[:14] + b"f" + collect2_key[15:19] + b"f" + collect2_key[20:]  # No UUID version/variant validation.
    column_material = alnum("column-key", 27)
    commercejs_key = b"g" + alnum("commercejs-key", 47).lower()
    commercejs_key = commercejs_key[:11] + b"_" + commercejs_key[12:]
    commodities_key = b"Z" + alnum("commodities-key", 59)
    companyhub_key = alnum("companyhub-key", 20)
    companyhub_payload = b"companyhub " + companyhub_key + b"\n" + b"!" * 48 + b"\ncompanyhub A$%^=-z9"
    confluent_key = alnum("confluent-key", 16)
    confluent_secret = alnum("confluent-secret", 64)
    confluent_secret = confluent_secret[:19] + b"+" + confluent_secret[20:37] + b"/" + confluent_secret[38:]
    contentful_pat = b"CFPAT-" + alnum("contentful-pat", 43)
    contentful_pat = contentful_pat[:17] + b"_" + contentful_pat[18:28] + b"-" + contentful_pat[29:]
    conversiontools_key = b"ey" + alnum("conversiontools-key", 165)
    conversiontools_key = conversiontools_key[:19] + b"." + conversiontools_key[20:47] + b"_" + conversiontools_key[48:]
    convertkit_key = alnum("convertkit-key", 22)
    convertkit_key = convertkit_key[:6] + b"_" + convertkit_key[7:]
    # Retain the observed sign-filtered original; change one byte for a positive control.
    convertkit_filtered_key = convertkit_key
    convertkit_sign_at = convertkit_key.lower().index(b"sign")
    convertkit_key = convertkit_key[:convertkit_sign_at] + b"x" + convertkit_key[convertkit_sign_at + 1:]
    convier_key = b"07|" + alnum("convier-key", 40)
    copper_key = b"g" + alnum("copper-key", 31).lower()
    countrylayer_key = b"g" + alnum("countrylayer-key", 31).lower()
    databricks_token = b"dapi" + hashlib.sha256(b"databricks-token").hexdigest()[:32].encode()
    databricks_other = b"dapi" + hashlib.sha256(b"databricks-other").hexdigest()[:32].encode() + b"-7"
    databricks_domain = b"briar7.cloud.databricks.com"
    datadog_api_key = alnum("datadog-api-key", 32)
    datadog_api_key = datadog_api_key[:11] + b"-" + datadog_api_key[12:]
    datagov_key = alnum("datagov-key", 40)
    deepai_key = b"g" + alnum("deepai-key", 35).lower()
    deepai_key = deepai_key[:3] + b"-" + deepai_key[4:]
    demio_key = alnum("demio-key", 32)
    demio_secret = alnum("demio-secret", 15)
    deputy_key = b"g" + alnum("deputy-key", 31).lower()
    dfuse_key = b"web_" + alnum("dfuse-key", 32).lower()
    digitalocean_key = b"G" + alnum("digitaloceantoken-key", 62) + b"z"
    digitalocean_key = digitalocean_key[:9] + b"_-" + digitalocean_key[11:]
    digitalocean_v2 = [prefix + synthetic("digitaloceanv2-" + prefix.decode(), 64)
                       for prefix in (b"dop_v1_", b"doo_v1_", b"dor_v1_")]
    discord_key = b".".join(alnum("discord-bot-" + str(width), width) for width in (24, 6, 27))
    discord_other = b".".join(alnum("discord-bot-other-" + str(width), width) for width in (24, 6, 27))
    discord_id = b"00000000000000000"
    webhook18 = b"https://discord.com/api/webhooks/000000000000000000/" + alnum("discord-webhook18", 68)
    webhook19 = b"https://discord.com/api/webhooks/9999999999999999999/" + alnum("discord-webhook19", 68)
    ditto_key = b"ghijklm0-np12-qrst-uv34-wxyz567890ab." + alnum("ditto-key", 40).lower()
    dnscheck_key, dnscheck_other = alnum("dnscheck-key", 32), alnum("dnscheck-other", 32)
    dnscheck_id = b"G7h9K2m4-N6p8-Q1r3-S5t7-U9v1W3x5Y7z9"
    dockerhub_v1 = b"ghjkmnpq-rstv-wxyz-2345-6789abcef123"
    dockerhub_pat = b"dckr_pat_" + alnum("dockerhub-pat", 27)
    dockerhub_oat = b"dckr_oat_" + alnum("dockerhub-oat", 32)
    documo_parts = (b"ey" + alnum("documo-header", 34), b"ey" + alnum("documo-payload", 154), alnum("documo-signature", 43))
    doppler_namespace = alnum("doppler-namespace", 35).lower()
    doppler_namespace = doppler_namespace[:7] + b"_" + doppler_namespace[8:16] + b"-" + doppler_namespace[17:]
    dotdigital_user = b"apiuser-" + alnum("dotdigital-user", 12).lower()
    dotdigital_password = alnum("dotdigital-password", 8)
    docusign_uuids = []
    for label in ("id", "other-id", "secret", "other-secret"):
        value = synthetic("docusign-" + label, 32)
        docusign_uuids.append(b"-".join((value[:8], value[8:12], value[12:16], value[16:20], value[20:])))
    docusign_id, docusign_other_id, docusign_secret, docusign_other_secret = docusign_uuids
    dovico_key = alnum("dovico-key", 32).lower() + b"." + alnum("dovico-key-tail", 7).lower()
    dovico_user = alnum("dovico-user", 32).lower() + b"." + alnum("dovico-user-tail", 9).lower()
    dropbox_token = b"sl." + alnum("dropbox-key", 130)
    dropbox_scoped_token = b"sl.u." + alnum("dropbox-scoped-key", 1500)
    duffel_test = b"duffel_test_" + alnum("duffel-test", 43)
    duffel_live = b"duffel_live_" + alnum("duffel-live", 43)
    duply_keys = []
    for label in ("key", "other-key"):
        value = synthetic("duply-" + label, 32)
        duply_keys.append(b"-".join((value[:8], value[8:12], value[12:16], value[16:20], value[20:])))
    duply_id = b"-".join(alnum("duply-id-" + str(i), 7).upper() for i in range(4))
    duply_other_id = b"-".join(alnum("duply-other-id-" + str(i), 7).upper() for i in range(4))
    dwolla_id = alnum("dwolla-id", 50)
    dwolla_id = dwolla_id[:17] + b"-" + dwolla_id[18:]
    dwolla_secret = alnum("dwolla-secret", 50)
    duo_host, duo_other_host = b"api-g7k9m2.duosecurity.com", b"api-h8n4p6.duosecurity.com"
    duo_ikey = b"DI" + alnum("duo-ikey", 18).upper()
    duo_other_ikey = b"DI" + alnum("duo-other-ikey", 18).upper()
    duo_skey, duo_other_skey = alnum("duo-skey", 40), alnum("duo-other-skey", 40)
    dynalist_key = alnum("dynalist-key", 128)
    dynalist_key = dynalist_key[:40] + b"-_" + dynalist_key[42:]
    eagleeye_key, eagleeye_other_key = alnum("eagleeye-key", 15), alnum("eagleeye-other-key", 15)
    eagleeye_email, eagleeye_other_email = b"u7b9r@m4c8p.k2", b"v8d2s@n5g9q.h3"
    easyinsight_key, easyinsight_id = alnum("easyinsight-key", 20), alnum("easyinsight-id", 20)
    ecostruxureit_key = b"AK1" + alnum("ecostruxureit-key", 55)
    ecostruxureit_key = ecostruxureit_key[:20] + b"/" + ecostruxureit_key[21:]
    edamam_key, edamam_other_key = alnum("edamam-key", 32).lower(), alnum("edamam-other-key", 32).lower()
    edamam_id, edamam_other_id = alnum("edamam-id", 8).lower(), alnum("edamam-other-id", 8).lower()
    edenai_first, edenai_second = alnum("edenai-first", 36), alnum("edenai-second", 92)
    edenai_last = alnum("edenai-last", 42) + b"_"
    edenai_key = edenai_first + b"." + edenai_second + b"." + edenai_last
    edenai_bytes = edenai_first + b"\x00" + edenai_second + "🧪".encode() + edenai_last
    eightxeight_key, eightxeight_other_key = alnum("eightxeight-key", 43), alnum("eightxeight-other-key", 43)
    eightxeight_id, eightxeight_other_id = alnum("eightxeight-id", 30), alnum("eightxeight-other-id", 18)
    eightxeight_id = eightxeight_id[:9] + b"_" + eightxeight_id[10:]
    elasticemail_key = alnum("elasticemail-key", 96)
    elasticemail_key = elasticemail_key[:20] + b"_" + elasticemail_key[21:70] + b"-" + elasticemail_key[71:]
    elevenlabs_v1, elevenlabs_v2 = synthetic("elevenlabs-v1", 32), b"sk_" + synthetic("elevenlabs-v2", 48)
    elevenlabs_v1_input = b"xi-api-key = '" + elevenlabs_v1.upper() + b"'"
    enablex_key, enablex_other_key = alnum("enablex-key", 36), alnum("enablex-other-key", 36)
    enablex_id, enablex_other_id = alnum("enablex-id", 24).lower(), alnum("enablex-other-id", 24).lower()
    endorlabs_key, endorlabs_secret = b"endr+" + alnum("endorlabs-key", 16), b"endr+" + alnum("endorlabs-secret", 16)
    endorlabs_key = endorlabs_key[:10] + b"-" + endorlabs_key[11:]
    enigma_key, envoy_key = alnum("enigma-key", 40), alnum("envoy-key", 220)
    eraser_key, etherscan_key = alnum("eraser-key", 20), alnum("etherscan-key", 34).upper()
    ethplorer_key = alnum("ethplorer-key", 22)
    ethplorer_key = ethplorer_key[:11] + b"-" + ethplorer_key[12:]
    eventbrite_key = alnum("eventbrite-key", 20).upper()
    everhour_hex = synthetic("everhour-key", 28)
    everhour_key = b"-".join((everhour_hex[:4], everhour_hex[4:8], everhour_hex[8:14], everhour_hex[14:20], everhour_hex[20:]))
    everhour_key = b"A" + everhour_key[1:]
    exchangerate_key = synthetic("exchangerateapi-key", 24)
    exchangerates_key = alnum("exchangeratesapi-key", 32).lower()
    exchangerates_key = exchangerates_key[:9] + b"z" + exchangerates_key[10:]
    exportsdk_tail = alnum("exportsdk-key", 36).lower()
    exportsdk_key = synthetic("exportsdk-prefix", 9) + b"_" + exportsdk_tail[:8] + b"-" + exportsdk_tail[9:]
    exportsdk_id = alnum("exportsdk-id", 36).lower()
    exportsdk_id = exportsdk_id[:12] + b"-" + exportsdk_id[13:]
    extractor_key = alnum("extractorapi-key", 40)
    extractor_key = extractor_key[:14] + b"-" + extractor_key[15:]
    facebook_id, facebook_secret = b"75019382640198752", alnum("facebookoauth-secret", 32)
    faceplusplus_key, faceplusplus_secret = alnum("faceplusplus-key", 32), alnum("faceplusplus-secret", 32)
    faceplusplus_key = faceplusplus_key[:6] + b"_" + faceplusplus_key[7:]
    faceplusplus_secret = faceplusplus_secret[:17] + b"-" + faceplusplus_secret[18:]
    fastforex_key = alnum("fastforex-key", 28).lower()
    fastforex_key = fastforex_key[:8] + b"-z" + fastforex_key[10:]
    fastly_key = alnum("fastly-key", 32)
    fastly_key = fastly_key[:7] + b"_" + fastly_key[8:19] + b"-" + fastly_key[20:]
    feedier_key = alnum("feedier-key", 32)
    fetchrss_key = alnum("fetchrss-key", 40)
    fetchrss_key = fetchrss_key[:15] + b"." + fetchrss_key[16:]
    fibery_key = synthetic("fibery-prefix", 8) + b"." + synthetic("fibery-key", 35)
    figma_v1 = b"730194-" + b"-".join(alnum("figma-v1-" + str(i), length).lower() for i, length in enumerate((8, 4, 4, 4, 12)))
    figma_v2 = b"fig|_" + alnum("figma-v2-key", 40)
    figma_v3 = b"figp_" + alnum("figma-v3-key", 52) + b"=="
    fileio_key = alnum("fileio-key", 39).upper()
    fileio_key = fileio_key[:8] + b"." + fileio_key[9:21] + b"-" + fileio_key[22:]
    finage_key = b"API_KEY" + alnum("finage-key", 32).upper()
    financialmodelingprep_key = alnum("financialmodelingprep-key", 32)
    findl_payload = alnum("findl-key", 32).lower()
    findl_key = b"-".join((findl_payload[:8], findl_payload[8:12], findl_payload[12:16], findl_payload[16:20], findl_payload[20:]))
    finnhub_key = alnum("finnhub-key", 20).lower()
    fixerio_key = alnum("fixerio-key", 32)
    flatio_key = alnum("flatio-key", 128).lower()
    fleetbase_key = b"flb_live_" + alnum("fleetbase-key", 20)
    flexport_key = b"shltm_" + alnum("flexport-key", 40)
    flexport_key = flexport_key[:13] + b"_" + flexport_key[14:31] + b"-" + flexport_key[32:]
    flickr_key = alnum("flickr-key", 32).lower()
    flightapi_key = alnum("flightapi-key", 24).lower()
    flightlabs_key = b"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.ey" + alnum("flightlabs-payload", 160) + b"." + alnum("flightlabs-signature", 86)
    flightlabs_key = flightlabs_key[:60] + b"_" + flightlabs_key[61:100] + b"-" + flightlabs_key[101:]
    flightstats_key = alnum("flightstats-key", 32).lower()
    flightstats_id = alnum("flightstats-id", 8).lower()
    float_key = synthetic("float-key", 16) + alnum("float-payload", 43) + b"="
    float_key = float_key[:20] + b"+" + float_key[21:45] + b"/" + float_key[46:]
    flowflu_key = alnum("flowflu-key", 51)
    flutterwave_key = b"FLWSECK-" + alnum("flutterwave-key", 32).lower() + b"-X"
    flyio_bypass = b"FlyV1 fm123_exampleAAAAAA+/,=_-" + alnum("flyio-payload", 581)
    flyio_filtered = flyio_bypass.replace(b"AAAAAA", b"aaaaaa", 1)
    fmfw_key = alnum("fmfw-key", 32)
    fmfw_key = fmfw_key[:12] + b"_" + fmfw_key[13:]
    fmfw_id = alnum("fmfw-id", 32)
    fmfw_id = fmfw_id[:10] + b"-" + fmfw_id[11:]
    formbucket_signature = alnum("formbucket-signature", 43)
    formbucket_signature = formbucket_signature[:12] + b"_" + formbucket_signature[13:22] + b"-" + formbucket_signature[23:]
    formbucket_key = alnum("formbucket-head", 19) + b"\0" + alnum("formbucket-payload", 27) + b"." + formbucket_signature
    formcraft_key = alnum("formcraft-key", 16).lower()
    formio_signature = alnum("formio-signature", 43)
    formio_signature = formio_signature[:8] + b"_" + formio_signature[9:20] + b"-" + formio_signature[21:]
    formio_key = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + alnum("formio-payload", 250) + b"." + formio_signature
    formsite_key = alnum("formsite-key", 32)
    foursquare_key = alnum("foursquare-key", 48).upper()
    foursquare_secret = alnum("foursquare-secret", 48).upper()
    frameio_key = b"fio-u-" + alnum("frameio-key", 64)
    frameio_key = frameio_key[:17] + b"_" + frameio_key[18:39] + b"-" + frameio_key[40:]
    freshbooks_key = alnum("freshbooks-key", 64).lower()
    freshdesk_key = alnum("freshdesk-key", 20)
    front_first, front_payload = alnum("front-first", 36), alnum("front-payload", 188)
    fulcrum_key = alnum("fulcrum-key", 80).lower()
    fullstory_v1 = alnum("fullstory-v1", 88)
    fullstory_v2 = b"na1." + alnum("fullstory-v2", 100)
    fxmarket_key = alnum("fxmarket-key", 20)
    geckoboard_key = alnum("geckoboard-key", 44)
    gemini_id, gemini_secret = alnum("gemini-id", 20), alnum("gemini-secret", 27)
    gengo_key, gengo_secret = alnum("gengo-key", 64), alnum("gengo-secret", 64)
    geoapify_key, geocode_key = synthetic("geoapify-key", 32), synthetic("geocode-key", 28)
    geocodify_key, geocodio_key = synthetic("geocodify-key", 40), synthetic("geocodio-key", 39)
    geocodio_prefix = b"GeOcOd " + geocodio_key + b"\ngeocod"
    geoipifi_key = b"Q" + synthetic("geoipifi-key", 30) + b"_"
    geoipifi_underscores = b"_" + synthetic("geoipifi-boundary", 30) + b"_"
    getgeoapi_key = synthetic("getgeoapi-key", 40)
    getgeoapi_nonhex = b"g" + synthetic("getgeoapi-nonhex", 38) + b"z"
    getgist_key = alnum("getgist-key", 68)
    getgist_key = getgist_key[:11] + b"+=" + getgist_key[13:]
    getresponse_key = b"g" + synthetic("getresponse-key", 30) + b"z"
    getsandbox_key, getsandbox_id = synthetic("getsandbox-key", 40), synthetic("getsandbox-id", 18)
    github_v1_key = synthetic("github-v1-key", 40)
    github_v2_tail = alnum("github-v2-tail", 255)
    github_oauth_id, github_oauth_secret = alnum("github-oauth-id", 20), synthetic("github-oauth-secret", 40)
    github_oauth_pair = b"github " + github_oauth_id + b"\ngithub " + github_oauth_secret
    githubapp_pem = b"-----BEGIN RSA PRIVATE KEY-----\nQ7r2T9\n-----END RSA PRIVATE KEY-----"
    githubapp_payload = b"github 012345\n" + githubapp_pem
    gitlab_v1_key = alnum("gitlab-v1-key", 20)
    gitlab_v2_key = b"glpat-" + alnum("gitlab-v2-key", 20)
    gitlab_v3_key = b"glpat-" + alnum("gitlab-v3-key", 27) + b"X7qY" + synthetic("gitlab-v3-suffix", 9)
    gitlab_v3_max = b"glpat-" + alnum("gitlab-v3-max", 300) + "😀7q😀".encode() + synthetic("gitlab-v3-suffix-max", 9)
    gitlab_oauth_id, gitlab_oauth_secret = synthetic("gitlab-oauth-id", 64), b"gloas-" + synthetic("gitlab-oauth-secret", 64)
    gitlab_oauth_pair = b"application_id " + gitlab_oauth_id + b"\n" + gitlab_oauth_secret
    gitter_key = synthetic("gitter-key", 40)
    gitter_key = gitter_key[:17] + b"-" + gitter_key[18:]
    glassnode_key = alnum("glassnode-key", 27)
    gocanvas_key = alnum("gocanvas-key", 43) + b"="
    gocanvas_prefix = b"gocanvas Mailbox95@fixture.invalid\ngocanvas "
    gocardless_key = b"live_" + b"b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2"[:39] + b"-"
    godaddy_ote = b"Z" + synthetic("godaddy-ote", 16) + b"_" + synthetic("godaddy-ote-end", 19)
    godaddy_prod = b"Q" + synthetic("godaddy-prod", 15) + b"_" + synthetic("godaddy-prod-end", 18)
    godaddy_secret = alnum("godaddy-secret", 22)
    godaddy_ote_input = b"godaddy " + godaddy_ote + b"\ngodaddy " + godaddy_secret
    godaddy_prod_input = b"godaddy " + godaddy_prod + b"\ngodaddy " + godaddy_secret
    goodday_key = b"z" + synthetic("goodday-key", 31)
    google_gemini_key = b"AIzaSy" + synthetic("google-gemini-key", 32) + b"-"
    google_oauth_token = b"ya29." + alnum("google-oauth-token", 45)
    grafana_key = b"glc_eyJ" + synthetic("grafana-key", 60)
    grafana_max = b"glc_eyJ" + synthetic("grafana-max", 160)
    grafana_service_key = b"glsa_" + alnum("grafana-service-key", 41)
    grafana_domain = b"Tenant97.grafana.net"
    graphcms_plain = b"ey" + synthetic("graphcms-header", 73) + b"." + b"ey" + synthetic("graphcms-payload", 365) + b"." + alnum("graphcms-signature", 683)
    # A keyword inside the allowed token alphabet centers its 1024-radius window.
    graphcms_key = graphcms_plain[:200] + b"graphcms" + graphcms_plain[208:]
    graphcms_nul = graphcms_key[:75] + b"\0" + graphcms_key[76:]
    graphcms_id = b"\ngraph " + synthetic("graphcms-id", 25)
    graphhopper_key = synthetic("graphhopper-key", 18) + b"-" + synthetic("graphhopper-end", 17)
    graphhopper_end_hyphen = graphhopper_key[:35] + b"-"
    groovehq_key = alnum("groovehq-key", 64)
    groq_key = b"gsk_" + alnum("groq-key", 52)
    gtmetrix_key = synthetic("gtmetrix-key", 32)
    guardian_key = b"A" + alnum("guardian-first", 7).lower() + b"-" + synthetic("guardian-second", 4) + b"-" + synthetic("guardian-third", 4) + b"-" + synthetic("guardian-fourth", 4) + b"-" + alnum("guardian-last", 12).lower()
    gumroad_key = alnum("gumroad-key", 21) + b"-" + alnum("gumroad-tail", 21)
    gyazo_key = alnum("gyazo-key", 21) + b"-" + alnum("gyazo-tail", 21)
    happyscribe_key = alnum("happyscribe-key", 24)
    harness_key = b"pat." + alnum("harness-id", 10) + b"_" + alnum("harness-id-end", 11) + b"." + synthetic("harness-hex", 24) + b"." + alnum("harness-tail", 20)
    harvest_key = alnum("harvest-a", 32) + b"." + alnum("harvest-b", 32) + b"_" + alnum("harvest-c", 31)
    harvest_input = b"HaRvEsT " + harvest_key + b"\nharvest 004203"
    vault_url = b"https://alpha100.hashicorp.cloud:8200/team//x/../users"
    vault_binary_origin = "https://a\0\v☃.hashicorp.cloud/path".encode()
    vault_batch_key = b"hvb." + alnum("vault-batch-a", 24) + b"._-" + alnum("vault-batch-b", 29)
    vault_service_key = b"hvs." + alnum("vault-service-a", 96) + b"_" + alnum("vault-service-b", 4)
    vault_legacy_key = b"s." + alnum("vault-legacy", 30)
    vault_role = b"-".join(synthetic("vault-role-" + str(i), n) for i, n in enumerate((8, 4, 4, 4, 12)))
    vault_secret = b"-".join(synthetic("vault-secret-" + str(i), n) for i, n in enumerate((8, 4, 4, 4, 12))).upper()
    vault_auth_pair = b"role " + vault_role + b"\nsecret " + vault_secret + b"\n"
    hasura_key, hasura_domain = alnum("hasura-key", 64), b"Project101.hasura.app"
    hellosign_key = alnum("hellosign-head", 30) + b"-/+" + alnum("hellosign-tail", 31)
    helpcrunch_key = alnum("helpcrunch-head", 100) + b"+/=" + alnum("helpcrunch-tail", 225)
    helpscout_key = b"z" + synthetic("helpscout-key", 39)
    hereapi_key = alnum("hereapi-key", 43)
    heroku_v1 = b"-".join(synthetic("heroku-v1-" + str(i), n) for i, n in enumerate((8, 4, 4, 4, 12)))
    heroku_v1 = b"A" + heroku_v1[1:]
    heroku_v2 = b"HRKU-AA" + alnum("heroku-v2", 58)
    hiveage_key = alnum("hiveage-head", 9) + b"_-" + alnum("hiveage-tail", 9)
    holidayapi_key = alnum("holidayapi-key", 36).lower()
    holistic_key = synthetic("holistic-key", 64)
    honeycomb_old, honeycomb_new = synthetic("honeycomb-old", 32), b"Z" + alnum("honeycomb-new", 21)
    host_key = b"z" + alnum("host-key", 13).lower()
    html2pdf_key = alnum("html2pdf-key", 64)
    hubspot_v1 = b"-".join(alnum("hubspot-v1-" + str(i), n) for i, n in enumerate((8, 4, 4, 4, 12)))
    hubspot_v1 = b"Z" + hubspot_v1[1:]
    hubspot_na, hubspot_eu = b"pat-na1-" + hubspot_v1, b"pat-eu1-" + hubspot_v1
    huggingface_key, huggingface_org = b"hf_" + alnum("huggingface-key", 34), b"api_org_" + alnum("huggingface-org", 34)
    humanity_key = alnum("humanity-key", 40).lower()
    hunter_key = b"z" + alnum("hunter-key", 39).lower()
    hunter_key = hunter_key[:15] + b"_-" + hunter_key[17:]
    hybiscus_key = alnum("hybiscus-key", 43)
    hypertrack_account, hypertrack_key = alnum("hypertrack-account", 27), alnum("hypertrack-key", 54)
    hypertrack_input = b"HyPeRtRaCk " + hypertrack_account + b"\nhypertrack " + hypertrack_key
    iconfinder_key = alnum("iconfinder-key", 64)
    iexapis_key = b"sk_z" + alnum("iexapis-key", 31).lower()
    iexcloud_key = b"z" + alnum("iexcloud-head", 16).lower() + b"_" + alnum("iexcloud-tail", 17).lower()
    imagekit_key = alnum("imagekit-head", 16) + b"_=" + alnum("imagekit-tail", 18)
    imagga_key = alnum("imagga-head", 31) + b"=" + alnum("imagga-tail", 40)
    impala_key = alnum("impala-head", 22) + b"_" + alnum("impala-tail", 23)
    infura_key = b"z" + alnum("infura-key", 31).lower()
    insightly_key = b"z" + alnum("insightly-head", 14).lower() + b"-" + alnum("insightly-tail", 20).lower()
    instabot_key = alnum("instabot-head", 20) + b"=+/" + alnum("instabot-tail", 21)
    instamojo_id, instamojo_secret = alnum("instamojo-id", 40), alnum("instamojo-secret", 128)
    instamojo_input = b"InStAmOjO " + instamojo_secret + b"\ninstamojo " + instamojo_id
    intercom_key = base64.b64encode(b"tok:" + alnum("intercom-key", 40))
    intercom_short = base64.b64encode(b"tok:" + alnum("intercom-short", 37))
    intercom_crlf = intercom_short[:8] + b"\r\n\r\n" + intercom_short[8:]
    intercom_wrong = base64.b64encode(b"TOK:" + alnum("intercom-key", 40))
    interseller_key = b"-".join(synthetic("interseller-" + str(i), n) for i, n in enumerate((8, 4, 4, 4, 12)))
    intra42_ud, intra42_af = b"s-s4t2ud-" + synthetic("intra42-ud", 64), b"s-s4t2af-" + synthetic("intra42-af", 64)
    intra42_id = b"u-s4t2af-" + synthetic("intra42-id", 64)
    intrinio_key = alnum("intrinio-key", 44)
    invoiceocean_key = alnum("invoiceocean-key", 20)
    invoiceocean_input = b"InVoIcEoCeAn " + invoiceocean_key + b"\ntenant7.invoiceocean.com"
    ip2location_key = b"Z" + alnum("ip2location-key", 31).upper()
    ipapi_key = b"z" + alnum("ipapi-key", 31).lower()
    ipgeolocation_key = b"z" + alnum("ipgeolocation-key", 31).lower()
    ipinfo_key = synthetic("ipinfo-key", 14)
    ipinfodb_key = b"z" + alnum("ipinfodb-key", 63).lower()
    ipstack_key = b"A" + synthetic("ipstack-key", 31)
    leadfeeder_key = alnum("leadfeeder-head", 18) + b"-" + alnum("leadfeeder-tail", 24)
    locationiq_key = b"pk." + alnum("locationiq-head", 16) + b"-" + alnum("locationiq-tail", 15)
    loginradius_key = b"-".join(synthetic("loginradius-" + str(i), n) for i, n in enumerate((8, 4, 4, 4, 12)))
    madkudu_key = synthetic("madkudu-key", 32)
    mailerlite_key = b"z" + alnum("mailerlite-key", 31).lower()
    ipquality_key = alnum("ipquality-key", 32)
    jotform_key = b"A" + alnum("jotform-key", 31).lower()
    jumpcloud_key = alnum("jumpcloud-key", 40)
    juro_key = alnum("juro-key", 40)
    kanban_key = alnum("kanban-key", 12).upper()
    kanban_input = b"KaNbAn " + kanban_key + b"\ntenant7.kanbantool.com"
    jupiterone_key = alnum("jupiterone-key", 76)
    magicbell_key = alnum("magicbell-key", 40)
    mailboxlayer_key = alnum("mailboxlayer-key", 32).lower()
    mailjetbasicauth_key = alnum("mailjetbasicauth-key", 87) + b"="
    mailjetsms_key = alnum("mailjetsms-key", 32)
    kanbantool_key = alnum("kanbantool-key", 12).upper()
    karmacrm_key = alnum("karmacrm-key", 20)
    keenio_key = alnum("keenio-key", 64).upper()
    keenio_id = alnum("keenio-id", 24).lower()
    kickbox_key = b"_" + alnum("kickbox-key", 64)
    klipfolio_key = synthetic("klipfolio-key", 40)
    knapsackpro_key = b"g" + alnum("knapsackpro-key", 31).lower()
    klaviyo_key = b"pk_" + synthetic("klaviyo-key", 34)
    klaviyo_newer = b"pk_Ab12Cd_" + synthetic("klaviyo-newer", 34)
    kontent_env = b"b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3"
    kontent_key = b"ey" + alnum("kontent-first", 30) + b".ey" + alnum("kontent-second", 200) + b"." + alnum("kontent-third", 40)
    meistertask_key = alnum("meistertask-key", 43)
    messagebird_key = alnum("messagebird-key", 8) + b"_-" + alnum("messagebird-tail", 15)
    kraken_key = alnum("kraken-key", 56)
    kraken_private = alnum("kraken-private", 88)
    kucoin_key = synthetic("kucoin-key", 24)
    kucoin_secret_hex = synthetic("kucoin-secret", 32)
    kucoin_secret = b"-".join(kucoin_secret_hex[a:b] for a, b in ((0, 8), (8, 12), (12, 16), (16, 20), (20, 32)))
    kucoin_passphrase = b"!" + alnum("kucoin-passphrase", 16)
    kylas_key = b"g" + alnum("kylas-key", 35).lower()
    langfuse_public_hex = synthetic("langfuse-public", 32)
    langfuse_secret_hex = synthetic("langfuse-secret", 32)
    langfuse_public = b"pk-lf-" + b"-".join(langfuse_public_hex[a:b] for a, b in ((0, 8), (8, 12), (12, 16), (16, 20), (20, 32)))
    langfuse_secret = b"sk-lf-" + b"-".join(langfuse_secret_hex[a:b] for a, b in ((0, 8), (8, 12), (12, 16), (16, 20), (20, 32)))
    languagelayer_key = b"g" + alnum("languagelayer-key", 31).lower()
    langsmith_key = b"lsv2_pt_" + synthetic("langsmith-key", 32) + b"_" + synthetic("langsmith-tail", 10)
    larksuite_token = b"t-" + alnum("larksuite-token", 20)
    larksuite_extension = b"t-" + alnum("larksuite-extension", 16) + b".json"
    larksuite_id = b"cli_" + alnum("larksuite-id", 16)
    larksuite_secret = alnum("larksuite-secret", 32)
    launchdarkly_hex = synthetic("launchdarkly-key", 32)
    launchdarkly_uuid = b"-".join((launchdarkly_hex[:8], launchdarkly_hex[8:12], b"4" + launchdarkly_hex[13:16], launchdarkly_hex[16:20], launchdarkly_hex[20:]))
    launchdarkly_key = b"api-" + launchdarkly_uuid
    lemlist_key = synthetic("lemlist-key", 32)
    lemonsqueezy_signature = alnum("lemonsqueezy-signature", 512)
    # The internal keyword keeps this 864-byte token inside the source's
    # default 512-byte dispatch radius without changing its absent hints.
    lemonsqueezy_signature = lemonsqueezy_signature[:48] + b"lemonsqueezy" + lemonsqueezy_signature[60:]
    lemonsqueezy_key = b"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + alnum("lemonsqueezy-payload", 314) + b"." + lemonsqueezy_signature
    ldap_url = b"ldap://192.0.2.7/dc=Briar"
    ldap_user, ldap_password = b"BriarZ", b"B7" + alnum("ldap-password", 18)
    ldap_payload = ldap_url + b"\nuser '" + ldap_user + b"'\npass '" + ldap_password + b"'"
    ldap_iad = b'OpenDSObject("' + ldap_url.replace(b"ldap://", b"LDAP://") + b'", "' + ldap_user + b'", "' + ldap_password + b'", 1)'
    lendflow_segments = [alnum("lendflow-segment-" + str(i), n) for i, n in enumerate((36, 235, 32, 47, 162, 42, 40, 66, 59, 7, 220))]
    lendflow_key = b".".join(lendflow_segments[:2]) + b"." + b"-".join(lendflow_segments[2:])
    lessannoyingcrm_key = alnum("lessannoyingcrm-key", 57)
    lessannoyingcrm_key = lessannoyingcrm_key[:20] + b"-" + lessannoyingcrm_key[21:]
    lexigram_key = alnum("lexigram-key", 301)
    linearapi_key = b"lin_api_" + alnum("linearapi-key", 40)
    jiratoken_v1 = alnum("jiratoken-v1-key", 24)
    jiratoken_v2 = b"ATATT" + alnum("jiratoken-v2-key", 40) + b"=" + alnum("jiratoken-v2-tail", 8)
    jiratoken_context = b"\njira X7Case@grum.com\njira z7q8.atlassian.net"
    jiratoken_kelvin = "\njira XKName@grum.com\njira X\u212aName@grum.com".encode()
    loadmill_key = alnum("loadmill-key", 40)
    meraki_key = synthetic("meraki-key", 40)
    gcp_payload = json.dumps({"type": "service_account", "client_email": "briar87@offline.invalid", "project_id": "offline87", "private_key": "not-a-key", "auth_provider_x509_cert_url": "unused", "token_uri": "https://oauth2.googleapis.com/token"}, separators=(",", ":")).encode()
    gcp_fallback = b'{"project_id":"sample","unknown":1e9999,"auth_provider_x509_cert_url":"unused"}'
    gcp_public = gcp_payload.replace(b"briar87@offline.invalid", b"image-pulling@authenticated-image-pulling.iam.gserviceaccount.com")
    gcpadc_payloads = tuple(json.dumps({"client_id": alnum("gcpadc-id", 24).decode() + ".hidden.apps.googleusercontent.com", "client_secret": "offline-secret", "refresh_token": refresh, "type": "authorized_user"}, separators=(",", ":"), ensure_ascii=False).encode() for refresh in ("offline_refresh_87", "abc\0xy", "abé"))
    ftp_fragment = b"ftp://Briar86:B7r9P2@fixture.invalid/#x:abc"
    ftp_freebsd = b"ftp://Briar86:V7pQ9r2@ftp.FreeBSD.org/path"
    d7network_key = alnum("d7network-key", 23) + b"="
    d7network_nul = d7network_key[:7] + b"\0" + d7network_key[8:]
    couchbase_prefix = b"couchbase://cb.z71p8q.cloud.couchbase.com\n"
    couchbase_payload = couchbase_prefix + b"user:Name\npass:aB7!\n"
    coinbase_escaped = coinbase_name.replace(b"/", b"\\/") + b"\n" + coinbase_key.replace(b"\n", b"\\n")
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
        ("braintreepayments", 828, b"BRAINTREE " + synthetic("braintree-private-key", 32) +
         b"\nbraintree " + alnum("braintree-public-id", 16).lower()),
        ("braintrust", 1053, b"braintrust sk-" + alnum("braintrust-token", 48)),
        ("brandfetch_v1", "333.v1", b"brandfetch " + alnum("brandfetch-legacy", 40)),
        ("brandfetch_v2", "333.v2", b"BRANDFETCH (" + alnum("brandfetch-punctuation", 39) + b"!@#="),
        ("browserstack", 756, b"browserstackUser briaruser17\n" + b"." * 64 +
         b"\nbrowserstackKey " + alnum("browserstack-access-key", 20)),
        ("browserstack_hub_wildcards", 756, b"hub-cloudXbrowserstackYcom " + alnum("browserstack-hub-key", 20) +
         b"\n" + b"." * 64 + b"\nhub-cloudXbrowserstackYcom briaruser17"),
        ("browshot", 448, b"BROWSHOT " + alnum("browshot-key", 28)),
        ("browshot_leading_hyphen", 448, b"browshot-" + alnum("browshot-leading-hyphen", 27)),
        ("bscscan", 910, b"BSCSCAN " + alnum("bscscan-key", 34).upper()),
        ("buddyns", 598, b"BUDDYNS " + alnum("buddyns-key", 40).lower()),
        ("budibase_min", 953, b"BUDIBASE " + synthetic("budibase-min-first", 32) + b"-" + synthetic("budibase-min-tail", 78)),
        ("budibase_max", 953, b"budibase " + synthetic("budibase-max-first", 32) + b"-" + synthetic("budibase-max-tail", 80)),
        ("bugherd", 602, b"BUGHERD " + alnum("bugherd-key", 22).lower()),
        ("bugsnag", 388, b"BUGSNAG z7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3"),
        ("buildkite_v1", "142.v1", b"BUILDKITE " + alnum("buildkite-legacy", 40).lower()),
        ("buildkite_v2", "142.v2", b"bkua_" + alnum("buildkite-modern", 40).lower()),
        ("bulbul", 317, b"BULBUL " + alnum("bulbul-key", 32).lower()),
        ("bulksms", 833, b"BULKSMS A7C9D2E5-F6A8-B3C4-D1E0-B2A4C6D8E1F3A\nbulksms " + alnum("bulksms-key", 29)),
        ("bulksms_symbols", 833, b"bulksms A7C9D2E5-F6A8-B3C4-D1E0-B2A4C6D8E1F3A\nbulksms " +
         alnum("bulksms-symbol-head", 5) + b"!@#$%^&*()" + alnum("bulksms-symbol-tail", 14)),
        ("buttercms", 150, b"BUTTERCMS " + alnum("buttercms-key", 40).lower()),
        ("caflou", 647, b"caflou " + b"." * 64 + b"eyJhbGciOiJIUzI1NiJ9." + alnum("caflou-payload", 131) + b"_-Q"),
        ("calendarific", 130, b"CALENDARIFIC " + alnum("calendarific-key", 32)),
        ("calendly_min", 44, b"calendly eyJ" + alnum("calendly-min-first", 100) + b".eyJ" + alnum("calendly-min-second", 100) + b".Z"),
        ("calendly_max_segments", 44, b"CALENDLY eyJ" + calendly_max_first + b".eyJ" +
         alnum("calendly-max-second", 300) + b"." + alnum("calendly-max-signature", 71) + b"_9"),
        ("calorieninja", 474, b"CALORIENINJA " + alnum("calorieninja-key", 40)),
        ("campayn", 254, b"CAMPAYN " + alnum("campayn-key", 64).lower()),
        ("cannyio", 158, b"CANNY z7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3"),
        ("capsulecrm", 270, b"CAPSULECRM " + alnum("capsulecrm-key", 58) + b"-._+=Z"),
        ("capsulecrm_leading_punct", 270, b"capsulecrm-" + alnum("capsulecrm-leading-punct", 63)),
        ("captaindata_v1", "708.v1", captaindata_payload),
        ("captaindata_v2", "708.v2", captaindata_payload),
        ("carboninterface", 578, b"CARBONINTERFACE " + alnum("carboninterface-key", 21)),
        ("cashboard", 685, b"CASHBOARD briar7\nCASHBOARD B7C-D9E-F2G-H5J"),
        ("cashboard_numeric_user", 685, b"CASHBOARD briar7\nCASHBOARD B7C-274-F2G-H5J"),
        ("caspio", 648, caspio_payload),
        ("caspio_products", 648, caspio_payload + b"\nCASPIO " + alnum("caspio-second", 50).lower()),
        ("censys", 524, b"CENSYS " + alnum("censys-token", 32) + b"\nCENSYS " + alnum("censys-user", 36).lower()),
        ("censys_leading_hyphen", 524, b"CENSYS " + alnum("censys-token", 32) + b"\nCENSYS-" + alnum("censys-leading-user", 35).lower()),
        ("centralstationcrm", 318, b"CENTRALSTATIONCRM " + alnum("centralstation-key", 30).lower()),
        ("centralstationcrm_gap_edge", 318, b"CENTRALSTATIONCRM" + b"." * 37 + alnum("centralstation-key", 30).lower()),
        ("centralstationcrm_short_no_dispatch", 318, b"centralstation " + alnum("centralstation-key", 30).lower()),
        ("cexio", 739, b"cexio " + cexio_value + b"\ncexio ab172635480"),
        ("cexio_products", 739, b"cexio " + cexio_value + b" cex.io " + alnum("cexio-second", 27) + b" cexio ab172635480"),
        ("cexio_wildcard_prefix", 739, b"cexXio " + cexio_value + b"\ncexio ab172635480"),
        ("chartmogul", 815, b"CHARTMOGUL " + alnum("chartmogul-key", 32).lower()),
        ("chatbot_underscores", 208, b"CHATBOT _" + alnum("chatbot-key", 30) + b"_"),
        ("chatfule", 692, b"CHATFUEL " + alnum("chatfuel-key", 128)),
        ("chatfule_package_spelling", 692, b"chatfule " + alnum("chatfuel-key", 128)),
        ("checio", 643, b"CHECIO pk_" + alnum("checio-key", 45).lower()),
        ("checklyhq", 649, b"CHECKLYHQ " + alnum("checklyhq-key", 32).lower()),
        ("checkout_production", 187, b"CHECKOUT sk_" + checkout_uuid + b"\nCHECKOUT " + checkout_id),
        ("checkout_sandbox_filtered", 187, b"CHECKOUT sk_test_" + checkout_uuid + b"\nCHECKOUT " + checkout_id),
        ("checkvist", 709, b"CHECKVIST " + checkvist_key + b"\nCHECKVIST Briar7+Tag@Fixture.Invalid"),
        ("checkvist_email_key", 709, b"CHECKVIST " + checkvist_key + b"\nCHECKVIST " + alnum("checkvist-email-key", 14) + b"@Fixture.Invalid"),
        ("checkvist_quoted_control", 709, b'CHECKVISTx"Briar\\\x01"@Fixture.Invalid\nCHECKVIST ' + checkvist_key),
        ("cicero", 477, b"CICERO " + alnum("cicero-key", 40).lower()),
        ("circleci_v1", "4.v1", b"CIRCLE " + circleci_hex),
        ("circleci_v1_inside_word", "4.v1", b"circleX" + circleci_hex + b"abc123"),
        ("circleci_v2", "4.v2", circleci_pat),
        ("circleci_v2_inside_word", "4.v2", b"x" + circleci_pat + b"ABCDEF"),
        ("clarifai", 57, b"CLARIFAI " + alnum("clarifai-key", 32)),
        ("clearbit_underscores", 334, b"CLEARBIT _" + alnum("clearbit-key", 33).lower() + b"_"),
        ("clickhelp", 456, clickhelp_context + b"secret " + alnum("clickhelp-key", 24)),
        ("clickhelp_hidden_keys", 456, clickhelp_context + b"secret " + alnum("clickhelp-key", 24) + b"\napi " + alnum("clickhelp-other-key", 24)),
        ("clickhelp_missing_key", 456, clickhelp_context),
        ("clicksendsms", 209, clicksend_key + b"\nclicksendsms " + clicksend_email),
        ("clicksendsms_no_space", 209, clicksend_key + b"\nCLICKSENDSMS\t" + clicksend_email),
        ("clicksendsms_trim_unicode", 209, clicksend_key + b"\nclicksendsms \t\xe3\x80\x80" + clicksend_email),
        ("clicksendsms_embedded_nul", 209, clicksend_key + b"\nCLICKSENDSMS\0" + clicksend_email),
        ("clickup_min", 366, b"CLICKUP pk_1726354_" + clickup_tail),
        ("clickup_max", 366, b"clickup pk_172635480_" + clickup_tail),
        ("cliengo", 710, b"CLIENGO b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3"),
        ("clientary_min", 307, b"RONIN Briar7\nclientary " + alnum("clientary-min-key", 24)),
        ("clientary_max", 307, b"clientary B7-C9\nronin " + alnum("clientary-max-key", 26)),
        ("clinchpad", 255, b"CLINCHPAD zsinomxc37ynfxwy9nd8sonsafxhx5qs"),
        # Pinned badlist term "safe" intentionally filters this synthetic key.
        ("clinchpad_filtered", 255, b"CLINCHPAD z" + alnum("clinchpad-key", 31).lower()),
        ("clockify", 280, b"CLOCKIFY " + alnum("clockify-key", 48)),
        ("clockworksms", 189, b"clockworksms 17263\ntextanywhere " + clockwork_token),
        ("clockworksms_textanywhere", 189, b"TEXTANYWHERE 00427\nTEXTANYWHERE " + clockwork_token),
        ("clockworksms_short_prefix", 189, b"clockwork 17263\nclockwork " + clockwork_token),
        ("clockworksms_gap_37", 189, b"clockworksms" + b"." * 37 + b"17263\ntextanywhere " + clockwork_token),
        ("clockworksms_gap_38", 189, b"clockworksms" + b"." * 38 + b"17263\ntextanywhere " + clockwork_token),
        ("closecrm", 215, b"close " + close_key),
        ("closecrm_distant", 215, b"close" + b":" * 80 + close_key),
        ("closecrm_ending_dot", 215, b"close " + close_key[:-1] + b".X"),
        ("cloudconvert", 829, b"cloudconvert " + cloudconvert_min),
        ("cloudconvert_max", 829, b"CLOUDCONVERT " + cloudconvert_max),
        ("cloudconvert_wildcard", 829, b"cloudconvert " + cloudconvert_min[:32] + b"!" + cloudconvert_min[33:235] + b"?" + cloudconvert_min[236:]),
        ("cloudconvert_embedded_nul", 829, b"cloudconvert " + cloudconvert_min[:32] + b"\0" + cloudconvert_min[33:]),
        ("cloudelements", 650, b"CLOUDELEMENTS " + alnum("cloudelements-key", 43) + b"\ncloudelements " + alnum("cloudelements-org", 32).lower()),
        ("cloudflare_api_v1", "100.v1", b"cloudflare " + cloudflare_v1),
        ("cloudflare_api_user_v2", "100.v2", cloudflare_user),
        ("cloudflare_api_account_v2", "100.v2", cloudflare_account + b" " + cloudflare_account_id),
        ("cloudflare_api_account_no_id_v2", "100.v2", cloudflare_account),
        ("cloudflare_api_account_products_v2", "100.v2", cloudflare_account + b" " + cloudflare_account_id + b" " + cloudflare_other_id + b" " + cloudflare_account_id),
        ("cloudflarecakey", 59, b"cloudflare v1.0-G" + synthetic("cloudflare-ca-first", 80) + b"-" + synthetic("cloudflare-ca-last", 89)),
        ("cloudflare_global_min_v1", "58.v1", b"CLOUDFLARE " + cloudflare_global_legacy + b" " + cloudflare_global_email),
        ("cloudflare_global_max_v1", "58.v1", b"cloudflare " + synthetic("cloudflare-global-max", 45) + b" " + cloudflare_global_email),
        ("cloudflare_global_no_email_v1", "58.v1", b"cloudflare " + cloudflare_global_legacy),
        ("cloudflare_global_v2", "58.v2", cloudflare_global_modern + b" " + cloudflare_global_email),
        ("cloudflare_global_no_email_v2", "58.v2", cloudflare_global_modern),
        ("cloudflare_global_emails_v2", "58.v2", cloudflare_global_modern + b" " + cloudflare_global_email + b" Other.User@Example.INVALID " + cloudflare_global_email),
        ("cloudflare_global_quoted_v2", "58.v2", cloudflare_global_modern + b' x"q\x07R"@Example.INVALID'),
        ("cloudimage", 721, b"CLOUDIMAGE _" + alnum("cloudimage-key", 28).lower() + b"_"),
        ("cloudinary", 1048, b"cloudinary name A7b\ncloudinary key " + cloudinary_key + b"\ncloudinary secret " + cloudinary_secret),
        ("cloudinary_url", 1048, b"cloudinary://" + cloudinary_key + b":" + cloudinary_secret + b"@B" + alnum("cloudinary-name", 49)),
        ("cloudmersive", 358, b"cloudmersive " + alnum("cloudmersive-key", 18).lower() + b"-" + alnum("cloudmersive-tail", 17).lower()),
        ("cloudplan", 324, b"CLOUDPLAN " + alnum("cloudplan-key", 11).upper() + b"-" + alnum("cloudplan-tail", 20).upper()),
        ("cloudsmith", 805, b"cloudsmith " + synthetic("cloudsmith-key", 40)),
        ("cloverly", 525, b"cloverly " + alnum("cloverly-key", 8).lower() + b":" + alnum("cloverly-middle", 9).lower() + b"_" + alnum("cloverly-tail", 9).lower()),
        ("cloze", 711, b"cloze " + cloze_key + b"\ncloze " + cloze_email),
        ("cloze_hidden_emails", 711, b"cloze " + cloze_key + b"\ncloze " + cloze_email + b"\ncloze Other.User@Example.INVALID\ncloze " + cloze_email),
        ("cloze_no_email", 711, b"cloze " + cloze_key),
        ("cloze_quoted_email", 711, b"cloze " + cloze_key + b'\ncloze x"q\x07R"@Example.INVALID'),
        ("clustdoc", 513, b"CLUSTDOC " + alnum("clustdoc-key", 60)),
        ("coda", 960, b"coda " + coda_key),
        ("codacy", 185, b"codacy " + alnum("codacy-key", 20)),
        ("codeclimate", 844, b"codeclimate " + synthetic("codeclimate-key", 40)),
        ("codemagic", 845, b"CODEMAGIC " + codemagic_key),
        ("codequiry", 783, b"codequiry " + codequiry_key),
        ("coinapi", 554, b"coinapi " + coinapi_key),
        ("coinbase_filtered", 5, coinbase_name + b"\n" + coinbase_key),
        ("coinbase_retained", 5, coinbase_name + b"\n" + coinbase_key),
        ("coinbase_retained_escaped", 5, coinbase_escaped),
        ("coinbase_retained_escaped_final", 5, coinbase_escaped + b"\\n"),
        ("coinbase_retained_original_products", 5, coinbase_name + b"\n" + coinbase_key + b"\n" + coinbase_escaped),
        ("coinbase_retained_ecdsa_label", 5, coinbase_name + b"\n" + coinbase_key.replace(b"EC PRIVATE", b"ECDSA PRIVATE")),
        ("coinbase_retained_crlf", 5, coinbase_name + b"\n" + coinbase_key.replace(b"\n", b"\r\n")),
        ("coinbase_retained_no_name", 5, coinbase_key),
        ("coinbase_retained_zero_scalar", 5, coinbase_name + b"\n" + coinbase_pem(coinbase_der.replace(b"\x04\x01\x01", b"\x04\x01\x00"))),
        ("coinbase_retained_ignored_public_and_tail", 5, coinbase_name + b"\n" + coinbase_pem(b"\x30\x18" + coinbase_der[2:] + b"\xa1\x04\x03\x02\x00\x00\x00\xff")),
        ("coinbase_retained_p224", 5, coinbase_name + b"\n" + coinbase_pem(bytes.fromhex("300f020101040101a00706052b81040021"))),
        ("coinbase_retained_p384", 5, coinbase_name + b"\n" + coinbase_pem(bytes.fromhex("300f020101040101a00706052b81040022"))),
        ("coinbase_retained_p521", 5, coinbase_name + b"\n" + coinbase_pem(bytes.fromhex("300f020101040101a00706052b81040023"))),
        ("coinlayer", 402, b"COINLAYER " + coinlayer_key),
        ("coinlib", 378, b"coinlib " + coinlib_key),
        ("collect2", 823, b"collect2 " + collect2_key),
        ("column", 749, b"column live_" + column_material),
        ("column_test_filtered", 749, b"column test_" + column_material),
        ("commercejs", 433, b"COMMERCEJS " + commercejs_key),
        ("commodities", 566, b"commodities " + commodities_key),
        ("companyhub", 256, companyhub_payload),
        ("companyhub_self", 256, b"COMPANYHUB " + companyhub_key),
        ("confluent", 60, b"confluent " + confluent_key + b"\n" + b"!" * 48 + b"\nconfluent " + confluent_secret),
        ("contentful_pat", 103, contentful_pat),
        ("conversiontools", 769, b"CONVERSIONTOOLS " + conversiontools_key),
        ("convertapi", 831, b"convertapi secret_" + alnum("convertapi-key", 16)),
        ("convertkit", 225, b"convertkit " + convertkit_key),
        ("convertkit_filtered", 225, b"convertkit " + convertkit_filtered_key),
        ("convier", 664, b"CONVIER " + convier_key),
        ("copper", 214, b"copper " + copper_key + b"\nuser7@ExAmPlE!TEST"),
        ("countrylayer", 526, b"countrylayer " + countrylayer_key),
        ("courier", 665, b"CoUrIeR pk_B7_" + alnum("courier-key", 28)),
        ("coveralls", 192, b"COVERALLS " + alnum("coveralls-key", 18) + b"-" + alnum("coveralls-tail", 18)),
        ("craftmypdf", 770, b"CRAFTMYPDF " + alnum("craftmypdf-key", 35)),
        ("crowdin", 335, b"crowdin " + alnum("crowdin-key", 80)),
        ("cryptocompare", 393, b"CRYPTOCOMPARE " + alnum("cryptocompare-key", 30).lower() + b"-" + alnum("cryptocompare-tail", 33).lower()),
        ("currencycloud", 382, b"User7@Example.invalid\nCURRENCYCLOUD " + alnum("currencycloud-key", 64).lower()),
        ("currencycloud_no_email", 382, b"currencycloud " + alnum("currencycloud-key", 64).lower()),
        ("currencycloud_hidden_emails", 382, b"User7@Example.invalid\nOther8@Example.invalid\ncurrencycloud " + alnum("currencycloud-key", 64).lower()),
        ("currencyfreaks", 499, b"CURRENCYFREAKS " + alnum("currencyfreaks-key", 32).lower()),
        ("currencylayer", 354, b"currencylayer " + alnum("currencylayer-key", 32).lower()),
        ("currencyscoop", 380, b"CURRENCYSCOOP " + alnum("currencyscoop-key", 32).lower()),
        ("currentsapi", 403, b"CURRENTSAPI -_" + alnum("currentsapi-key", 46) + b"X"),
        ("customerguru", 226, b"CuStOmErGuRu " + alnum("customerguru-key", 30) + b"\nGURU " + alnum("customerguru-id", 50)),
        ("customerio", 211, b"CUSTOMERIO " + alnum("customerio-key", 20)),
        ("customerio_products", 211, b"customerio " + alnum("customerio-key", 20) + b"\ncustomer " + alnum("customerio-id", 20)),
        ("d7network", 138, b"D7NETWORK " + d7network_key),
        ("d7network_trim", 138, b"d7network" + b" " * 23 + b"="),
        ("d7network_runes", 138, ("d7network" + "é" * 23 + "=").encode()),
        ("d7network_nul", 138, b"d7network " + d7network_nul),
        ("dandelion", 619, b"DANDELION " + alnum("dandelion-key", 32).lower()),
        ("dareboost", 762, b"dareboost " + alnum("dareboost-key", 60)),
        ("databox", 834, b"DATABOX " + alnum("databox-key", 21).lower()),
        ("databrickstoken", 62, databricks_other + b"\n" + databricks_domain),
        # Same-line duplicates keep line attribution independent of Go map order.
        ("databrickstoken_products", 62, b"\n".join((
            databricks_token + b"-12 " + databricks_token + b"-12", databricks_other,
            databricks_domain, databricks_domain, b"workspace7.gcp.databricks.com",
            b"adb-71.azuredatabricks.net"))),
        ("datadogapikey", 1043, b"DaTaDoG " + datadog_api_key),
        ("datadogapikey_no_dispatch", 1043, b"dd " + datadog_api_key),
        ("datadogtoken", 39, b"datadog " + datadog_api_key + b"\ndd " + alnum("datadog-app-key", 40)),
        ("datagov", 404, b"DaTa.GoV " + datagov_key),
        ("datagov_wildcard", 404, b"data.gov" + b"." * 50 + b"\ndataXgov " + datagov_key),
        ("deepai", 621, b"DEEPAI " + deepai_key),
        ("deepgram", 418, b"DeEpGrAm g" + alnum("deepgram-key", 39).lower()),
        ("deepseek", 1026, b"DeEpSeEk sk-" + alnum("deepseek-key", 32).lower()),
        ("delighted", 237, b"DELIGHTED " + alnum("delighted-key", 32)),
        ("demio", 863, b"demio " + demio_key + b"\nDEMIO " + demio_secret),
        ("demio_hidden_secrets", 863, b"demio " + demio_key + b"\nDEMIO " + demio_secret + b"\ndemio " + alnum("demio-other-secret", 20)),
        ("denodeploy", 954, b"ddp_" + alnum("denodeploy-key", 36) + b"\nddw_" + alnum("denodeploy-worker-key", 36)),
        ("deputy", 683, b"DEPUTY " + deputy_key + b"\none7.as.deputy.com"),
        ("deputy_hidden_hosts", 683, b"DEPUTY " + deputy_key + b"\none7.as.deputy.com\ntwo9.as.deputy.com"),
        ("deputy_no_host", 683, b"deputy " + deputy_key),
        ("detectify", 794, b"DeTeCtIfY " + alnum("detectify-key", 32).lower()),
        ("detectlanguage", 434, b"DeTeCtLaNgUaGe " + alnum("detectlanguage-key", 32).lower()),
        ("dfuse", 567, b"DFUSE" + b"." * 50 + b"\n" + dfuse_key),
        ("dfuse_no_dispatch", 567, dfuse_key),
        ("diffbot", 726, b"DiFfBoT g" + alnum("diffbot-key", 31).lower()),
        ("diggernaut", 819, b"DiGgErNaUt g" + alnum("diggernaut-key", 39).lower()),
        ("digitaloceantoken", 64, b"DIGITALOCEAN " + digitalocean_key),
        ("digitaloceantoken_short_prefix", 64, b"digitalocean" + b"." * 50 + b"\nDO " + digitalocean_key),
        ("digitaloceantoken_no_dispatch", 64, b"DO " + digitalocean_key),
        ("digitaloceanv2", 897, b" ".join(digitalocean_v2 + digitalocean_v2[:1])),
        ("discordbottoken", 65, b"DISCORD " + discord_key + b"\ndiscord " + discord_id),
        ("discordbottoken_products", 65, b"discord " + discord_key + b" discord " + discord_other + b" discord " + discord_id + b" discord 12345678901234567"),
        ("discordbottoken_no_id", 65, b"discord " + discord_key),
        ("discordwebhook_filtered", 66, webhook18 + b"MORE_SUFFIX\n" + webhook19 + b"EXTRA"),
        ("discordwebhook_retained", 66, webhook18 + b"MORE_SUFFIX\n" + webhook19 + b"EXTRA"),
        ("disqus", 789, b"DiSqUs " + alnum("disqus-key", 64)),
        ("ditto", 666, b"DiTtO " + ditto_key),
        ("dnscheck", 281, b"DnScHeCk " + dnscheck_key + b"\ndnscheck " + dnscheck_id),
        ("dnscheck_products", 281, b"dnscheck " + dnscheck_key + b" dnscheck " + dnscheck_other + b" dnscheck " + dnscheck_id + b" dnscheck " + dnscheck_id[::-1]),
        ("dnscheck_no_id", 281, b"dnscheck " + dnscheck_key),
        ("docparser", 838, b"DoCpArSeR " + synthetic("docparser-key", 40)),
        ("docker", 343, b'{"auths":{"reg.invalid":{"auth":"dTp="}}}'),
        ("docker_escaped", 343, b'{"auths":{"reg.invalid":{"auth":"dTo="}}}'.replace(b'"', b'\\"')),
        ("docker_hub", 343, b'{"auths":{"docker.io":{"auth":"dTo="}}}'),
        ("docker_empty", 343, b'{"auths":{"reg.invalid":{"auth":"Og=="}}}'),
        ("dockerhub_v1", "921.v1", b"docker " + dockerhub_v1 + b" docker user=briar7"),
        ("dockerhub_v1_pat_only", "921.v1", b"docker " + dockerhub_v1),
        ("dockerhub_v2", "921.v2", b"user=briar7 " + dockerhub_pat + b" " + dockerhub_oat),
        ("dockerhub_v2_pat_only", "921.v2", dockerhub_pat),
        ("documo", 311, b"documo" + b"." * 60 + b"\n" + b".".join(documo_parts)),
        ("documo_wildcard", 311, b"documo " + b"!".join(documo_parts)),
        ("documo_no_dispatch", 311, b".".join(documo_parts)),
        ("doppler", 196, b"dp.pt." + alnum("doppler-key", 40)),
        ("doppler_namespace", 196, b"dp.st." + doppler_namespace + b"." + alnum("doppler-long-key", 44)),
        ("dotdigital_filtered", 325, dotdigital_user + b"@apiconnector.com\npass " + dotdigital_password),
        ("dotdigital_retained", 325, dotdigital_user + b"@apiconnector.com\npass " + dotdigital_password),
        ("dotdigital_retained_bytes", 325, dotdigital_user + b"@apiconnector.com\npass A7b\x00C9d2"),
        ("dotdigital_retained_wildcard", 325, b"@apiconnector.com\n" + dotdigital_user + b"@apiconnectorXcom\npass " + dotdigital_password),
        ("docusign", 919, b"docusign\nintegration " + docusign_id + b"\nsecret " + docusign_secret),
        ("docusign_products", 919, b"docusign integration " + docusign_id + b" id " + docusign_other_id + b" secret " + docusign_secret + b" secret " + docusign_other_secret),
        ("docusign_no_secret", 919, b"docusign integration " + docusign_id),
        ("dovico", 386, b"dovico " + dovico_key + b" dovico " + dovico_user),
        ("dovico_equal", 386, b"dovico " + dovico_key + b" dovico " + dovico_key),
        ("dronahq", 651, b"DRONAHQ " + alnum("dronahq-key", 50).lower()),
        ("droneci", 135, b"DrOnEcI " + alnum("droneci-key", 32)),
        ("dropbox", 18, b"dropbox " + dropbox_token),
        ("dropbox_scoped_filtered", 18, b"dropbox " + dropbox_scoped_token),
        ("dropbox_retained_scoped", 18, b"dropbox " + dropbox_scoped_token),
        ("dropbox_no_prefix", 18, dropbox_token),
        ("duffeltoken_filtered", 1059, duffel_test + b" " + duffel_live + b" " + duffel_live),
        ("duffeltoken_retained", 1059, duffel_test + b" " + duffel_live + b" " + duffel_live),
        ("duffeltoken_suffix", 1059, duffel_live + b"A"),
        ("duply", 821, b"duply " + duply_keys[0] + b" duply " + duply_id),
        ("duply_products", 821, b"duply " + duply_keys[0] + b" duply " + duply_keys[1] + b" duply " + duply_id + b" duply " + duply_other_id),
        ("duply_no_id", 821, b"duply " + duply_keys[0]),
        ("dwolla", 180, b"dwolla " + dwolla_id + b" dwolla " + dwolla_secret),
        ("dwolla_equal", 180, b"dwolla " + dwolla_id + b" dwolla " + dwolla_id),
        ("duo", 1063, duo_host + b" duo " + duo_ikey + b" duo " + duo_skey),
        ("duo_products", 1063, duo_host + b" " + duo_other_host + b" duo " + duo_ikey + b" duo " + duo_other_ikey + b" duo " + duo_skey + b" duo " + duo_other_skey),
        ("duo_no_host", 1063, b"duosecurity duo " + duo_ikey + b" duo " + duo_skey),
        ("dynalist", 359, b"DYNALIST " + dynalist_key),
        ("dyspatch", 258, b"DySpAtCh " + alnum("dyspatch-key", 52).upper()),
        ("eagleeyenetworks", 639, b"eagleeyenetworks " + eagleeye_key + b" eagleeyenetworks " + eagleeye_email),
        ("eagleeyenetworks_products", 639, b"eagleeyenetworks " + eagleeye_key + b" eagleeyenetworks " + eagleeye_other_key + b" eagleeyenetworks " + eagleeye_email + b" eagleeyenetworks " + eagleeye_other_email),
        ("eagleeyenetworks_bytes", 639, b"eagleeyenetworks " + eagleeye_key + b" eagleeyenetworks " + eagleeye_email.replace(b".", b"\x00")),
        ("eagleeyenetworks_no_email", 639, b"eagleeyenetworks " + eagleeye_key),
        ("easyinsight", 282, b"easyinsight " + easyinsight_key + b" easyinsight " + easyinsight_id),
        ("easyinsight_roles", 282, b"easy-insight" + b"." * 60 + b"\nkey " + easyinsight_key + b" id " + easyinsight_id),
        ("easyinsight_equal", 282, b"easyinsight " + easyinsight_key + b" easyinsight " + easyinsight_key),
        ("ecostruxureit", 801, b"ECOSTRUXUREIT " + ecostruxureit_key),
        ("ecostruxureit_boundary", 801, b"ecostruxureit " + ecostruxureit_key[:-1] + b"/Q"),
        ("edamam", 424, b"edamam " + edamam_key + b" edamam " + edamam_id),
        ("edamam_products", 424, b"edamam " + edamam_key + b" edamam " + edamam_other_key + b" edamam " + edamam_id + b" edamam " + edamam_other_id),
        ("edamam_no_id", 424, b"edamam " + edamam_key),
        ("edenai", 568, b"EdEnAi " + edenai_key),
        ("edenai_bytes", 568, b"edenai " + edenai_bytes),
        ("edenai_no_lf", 568, b"edenai " + edenai_first + b"\n" + edenai_second + b"." + edenai_last),
        ("eightxeight", 727, b"8X8 " + eightxeight_key + b" 8x8 " + eightxeight_id),
        ("eightxeight_products", 727, b"8x8 " + eightxeight_key + b" 8x8 " + eightxeight_other_key + b" 8x8 " + eightxeight_id + b" 8x8 " + eightxeight_other_id),
        ("eightxeight_no_id", 727, b"8x8 " + eightxeight_key),
        ("elasticemail", 112, b"ELASTICEMAIL " + elasticemail_key),
        ("elasticemail_prefix", 112, b"elasticemail" + b"." * 60 + b"\nelastic " + elasticemail_key),
        ("elevenlabs_v1", "994.v1", elevenlabs_v1_input),
        ("elevenlabs_v1_case", "994.v1", b"xi-api-key = '" + elevenlabs_v1 + b"'\n" + elevenlabs_v1_input),
        ("elevenlabs_v1_one_separator", "994.v1", b"xi-api-key=" + elevenlabs_v1),
        ("elevenlabs_v2", "994.v2", b"xi_api_key " + elevenlabs_v2),
        ("elevenlabs_both", 994, elevenlabs_v1_input + b"\nelevenlabs " + elevenlabs_v2),
        ("enablex", 652, b"enablex " + enablex_key + b" enablex " + enablex_id),
        ("enablex_products", 652, b"enablex " + enablex_key + b" enablex " + enablex_other_key + b" enablex " + enablex_id + b" enablex " + enablex_other_id),
        ("enablex_no_id", 652, b"enablex " + enablex_key),
        ("endorlabs", 993, endorlabs_key + b" " + endorlabs_secret + b" " + endorlabs_key),
        ("endorlabs_equal", 993, endorlabs_key + b" " + endorlabs_key),
        ("enigma", 405, b"EnIgMa " + enigma_key),
        ("envoyapikey", 923, b"ENVOY " + envoy_key),
        ("eraser", 990, b"Eraser " + eraser_key),
        ("etherscan", 905, b"EtHeRsCaN " + etherscan_key),
        ("ethplorer", 283, b"ETHPLORER " + ethplorer_key),
        ("eventbrite", 962, b"EvEnTbRiTe " + eventbrite_key),
        ("everhour", 284, b"EvErHoUr " + everhour_key),
        ("everhour_bad_upper", 284, b"everhour B" + everhour_key[1:]),
        ("exchangerateapi", 360, b"EXCHANGERATE " + exchangerate_key),
        ("exchangerateapi_alias", 360, b"exchange-rate " + exchangerate_key),
        ("exchangeratesapi", 379, b"EXCHANGERATES " + exchangerates_key),
        ("exportsdk", 771, b"exportsdk " + exportsdk_key + b"\nEXPORTSDK " + exportsdk_id),
        ("extractorapi", 784, b"ExTrAcToRaPi " + extractor_key),
        ("facebookoauth", 40, b"facebook " + facebook_id + b"\nFACEBOOK " + facebook_secret),
        ("faceplusplus", 416, b"faceplusplus " + faceplusplus_key + b"\nFACEPLUSPLUS " + faceplusplus_secret),
        ("fastforex", 636, b"FASTFOREX " + fastforex_key),
        ("fastlypersonaltoken", 68, b"FaStLy " + fastly_key),
        ("feedier", 238, b"FEEDIER " + feedier_key),
        ("fetchrss", 592, b"FETCHRSS " + fetchrss_key),
        ("fibery", 808, b"FIBERY " + fibery_key + b"\nhttps://Briar79.fibery.io/"),
        ("figma_v1", "113.v1", b"FIGMA " + figma_v1),
        ("figma_v2", "113.v2", b"figma " + figma_v2),
        ("figma_v3", "113.v3", figma_v3),
        ("fileio", 527, b"FiLeIo " + fileio_key),
        ("finage", 423, b"FiNaGe " + finage_key),
        ("financialmodelingprep", 406, b"FINANCIALMODELINGPREP " + financialmodelingprep_key),
        ("findl", 667, b"FiNdL " + findl_key),
        ("finnhub", 420, b"FINNHUB " + finnhub_key),
        ("fixerio", 149, b"FiXeR " + fixerio_key),
        ("flatio", 501, b"FLAT " + flatio_key),
        ("fleetbase", 428, b"fleetbase " + fleetbase_key),
        ("flexport", 1009, flexport_key + b"Q"),  # No source end boundary: capture the first 46 bytes.
        ("flickr", 455, b"FLICKR " + flickr_key),
        ("flightapi", 528, b"FlIgHtApI " + flightapi_key),
        ("flightlabs", 848, flightlabs_key),
        ("flightstats", 642, b"FLIGHTSTATS " + flightstats_key + b"\nflightstats " + flightstats_id),
        ("float", 249, b"FLOAT " + float_key),
        ("flowflu", 265, b"FLOWFLU " + flowflu_key + b"\naccount Briar83"),
        ("flutterwave", 173, flutterwave_key),
        ("flyio_bypass", 980, flyio_bypass),
        ("flyio_filtered", 980, flyio_filtered),
        ("flyio_retained", 980, flyio_filtered),
        ("fmfw", 653, b"FMFW " + fmfw_key + b"\nfmfw " + fmfw_id),
        ("formbucket", 713, b"FoRmBuCkEt " + formbucket_key),
        ("formcraft", 812, b"FoRmCrAfT " + formcraft_key),
        ("formio", 712, b"FoRmIo " + formio_key + b" "),
        ("formsite", 839, b"FoRmSiTe " + formsite_key + b"\nformsite fs1234"),
        ("foursquare", 454, b"FOURSQUARE " + foursquare_key + b"\nfoursquare " + foursquare_secret),
        ("frameio", 199, frameio_key),
        ("frameio_uppercase", 199, b"FIO-U-" + frameio_key[6:]),
        ("freshbooks", 681, b"FRESHBOOKS " + freshbooks_key + b"\nfreshbooks https://www#Briar85\0com"),
        ("freshdesk", 678, b"FrEsHdEsK " + freshdesk_key + b"\nbriar86-" + alnum("freshdesk-host", 72).lower() + b".freshdesk.com"),
        ("front_wildcard", 427, b"FrOnT " + front_first + b"\xc3\xa9" + front_payload),
        ("front_nul", 427, b"front " + front_first + b"\0" + front_payload),
        ("ftp", 899, b"ftp://ExampleUser:sam%70le@fixture.invalid/path"),
        ("ftp_fragment_vt", 899, ftp_fragment + b"\x0bdef@tail"),
        ("ftp_fragment_nul", 899, ftp_fragment + b"\0def@tail"),
        ("ftp_skipped", 899, b"ftp://anonymous:V7pQ9r2@fixture.invalid/path\nftp://Briar86:****@fixture.invalid/path\nftp://Briar86:$BRIAR86@fixture.invalid/path"),
        ("ftp_filtered", 899, ftp_freebsd),
        ("ftp_retained", 899, ftp_freebsd),
        ("fulcrum", 285, b"FuLcRuM " + fulcrum_key),
        ("fullstory_v1", "394.v1", b"FuLlStOrY " + fullstory_v1),
        ("fullstory_v1_boundary", "394.v1", b"fullstory " + fullstory_v1[:-1] + b"+Q"),
        ("fullstory_v2_key", "394.v2", b"FULLSTORY " + fullstory_v2),
        ("fullstory_v2_no_dispatch", "394.v2", fullstory_v2),
        ("fxmarket", 381, b"FxMaRkEt " + fxmarket_key),
        ("fxmarket_boundary", 381, b"fxmarket " + fxmarket_key[:-1] + b"=Q"),
        ("gcp_plain", 6, gcp_payload),
        ("gcp_fallback", 6, gcp_fallback),
        ("gcp_escaped", 6, gcp_payload.replace(b'"', b'\\"')),
        ("gcp_public", 6, gcp_public),
        ("gcpadc", 983, gcpadc_payloads[0]),
        ("gcpadc_middle_nul", 983, gcpadc_payloads[1]),
        ("gcpadc_unicode", 983, gcpadc_payloads[2]),
        ("geckoboard", 696, b"GeCkObOaRd " + geckoboard_key),
        ("gemini_master_default_filtered", 876, b"master-" + gemini_id + b"\n" + gemini_secret),
        ("gemini_account_default_filtered", 876, b"account-" + gemini_id + b"\n" + gemini_secret),
        ("gemini_master_retained", 876, b"master-" + gemini_id + b"\n" + gemini_secret),
        ("gemini_account_retained", 876, b"account-" + gemini_id + b"\n" + gemini_secret),
        ("gengo_self", 426, b"GeNgO " + gengo_key + b"\n"),
        ("gengo_products", 426, b"gengo " + gengo_key + b"\ngengo " + gengo_secret + b"\n"),
        ("geoapify", 529, b"GeOaPiFy " + geoapify_key),
        ("geocode", 486, b"GeOcOdE " + geocode_key),
        ("geocodify", 542, b"GeOcOdIfY " + geocodify_key),
        ("geocodio", 407, geocodio_prefix + b" " + alnum("geocodio-search", 12)),
        ("geocodio_fragment_vt", 407, geocodio_prefix + b" Ab#c\vdeF"),
        ("geocodio_fragment_nul", 407, geocodio_prefix + b" Ab#c\0deF"),
        ("geocodio_empty_trim", 407, geocodio_prefix + b"\v" * 30 + b"Z"),
        ("geocodio_utf8", 407, geocodio_prefix + " Y2éR7p9q".encode()),
        ("geoipifi", 286, b"iPiFi " + geoipifi_key),
        ("geoipifi_underscore_edges", 286, b"ipifi " + geoipifi_underscores),
        ("getgeoapi", 383, b"GeTgEoApI " + getgeoapi_key),
        ("getgeoapi_nonhex", 383, b"getgeoapi " + getgeoapi_nonhex),
        ("getgist", 210, b"GeTgIsT " + getgist_key),
        ("getgist_no_end_boundary", 210, b"getgist " + getgist_key + b"XYZ"),
        ("getresponse_nonhex", 861, b"GeTrEsPoNsE " + getresponse_key),
        ("getsandbox", 633, b"GetSandbox " + getsandbox_key + b"\ngetsandbox " + getsandbox_id),
        ("getsandbox_missing_id", 633, b"getsandbox " + getsandbox_key),
        ("github_v1", "8.v1", b"github_token " + github_v1_key),
        ("github_v1_benign", "8.v1", b"github_token sha256:" + github_v1_key),
        ("github_v1_uppercase_benign", "8.v1", b"github_token SHA256:" + github_v1_key),
        ("github_v2_classic", "8.v2", b"ghp_" + github_v2_tail[:36]),
        ("github_v2_finegrained", "8.v2", b"github_pat_" + github_v2_tail),
        ("github_v2_uppercase_prefix", "8.v2", b"GHP_" + github_v2_tail[:36]),
        ("github_oauth2", 924, github_oauth_pair),
        ("github_oauth2_products", 924, github_oauth_pair + b"\ngithub " + alnum("github-oauth-id2", 20) + b"\ngithub " + synthetic("github-oauth-secret2", 40)),
        ("githubapp_default_filtered", 36, githubapp_payload),
        ("githubapp_retained", 36, githubapp_payload),
        ("githubapp_retained_padded", 36, githubapp_payload.replace(b"Q7r2T9", b"Q7r2T9=")),
        ("gitlab_v1", "9.v1", b"gitlab " + gitlab_v1_key),
        ("gitlab_v1_prefixed_skip", "9.v1", b"gitlab glpat-: " + gitlab_v1_key),
        ("gitlab_v1_uppercase_prefix", "9.v1", b"gitlab GLPAT-: " + gitlab_v1_key),
        ("gitlab_v2", "9.v2", gitlab_v2_key),
        ("gitlab_v3_wildcards", "9.v3", gitlab_v3_key),
        ("gitlab_v3_max_unicode", "9.v3", gitlab_v3_max),
        ("gitlaboauth2", 1050, gitlab_oauth_pair),
        ("gitlaboauth2_unique", 1050, gitlab_oauth_pair + b"\n" + gitlab_oauth_pair),
        ("gitter", 555, b"GiTtEr " + gitter_key),
        ("glassnode", 569, b"GlAsSnOdE " + glassnode_key),
        ("gocanvas", 714, gocanvas_prefix + gocanvas_key + b" "),
        ("gocanvas_no_email", 714, b"gocanvas " + gocanvas_key + b" "),
        ("gocanvas_tab_suffix", 714, gocanvas_prefix + gocanvas_key + b"\t"),
        ("gocardless_space", 184, b"GoCardless " + gocardless_key + b" "),
        ("gocardless_quote", 184, b"gocardless " + gocardless_key + b'"'),
        ("gocardless_no_dispatch", 184, gocardless_key + b" "),
        ("godaddy_v1", "1008.v1", godaddy_ote_input),
        ("godaddy_v2", "1008.v2", godaddy_prod_input),
        ("godaddy_v1_missing_secret", "1008.v1", b"godaddy " + godaddy_ote),
        ("godaddy_v2_hidden_secrets", "1008.v2", godaddy_prod_input + b"\ngodaddy " + alnum("godaddy-other-secret", 22)),
        ("goodday", 654, b"GoOdDaY " + goodday_key),
        ("googlegemini", 1041, google_gemini_key),
        ("googlegemini_long_suffix", 1041, google_gemini_key + b"ABC"),
        ("googlegemini_upper_prefix", 1041, b"AIZASY" + google_gemini_key[6:]),
        ("googleoauth2", 69, google_oauth_token),
        ("googleoauth2_space", 69, google_oauth_token + b" "),
        ("googleoauth2_unique", 69, google_oauth_token + b"\n" + google_oauth_token),
        ("googleoauth2_uppercase_prefix", 69, b"YA29." + google_oauth_token[5:]),
        ("grafana", 830, grafana_key),
        ("grafana_overlong", 830, grafana_max + b"EXTRA"),
        ("grafana_upper_prefix", 830, b"GLC_eyJ" + grafana_key[7:]),
        ("grafanaserviceaccount", 963, grafana_service_key + b"\n" + grafana_domain),
        ("grafanaserviceaccount_domains", 963, grafana_service_key + b"\n" + grafana_domain + b"\nsecond97.grafana.net"),
        ("grafanaserviceaccount_missing_domain", 963, grafana_service_key),
        ("graphcms", 223, graphcms_key + graphcms_id),
        ("graphcms_nul", 223, graphcms_nul + graphcms_id),
        ("graphcms_clipped", 223, b"graphcms " + graphcms_plain + graphcms_id),
        ("graphcms_no_id", 223, graphcms_key),
        ("graphcms_no_dispatch", 223, graphcms_plain + graphcms_id),
        ("graphhopper", 436, b"GrApHhOpPeR " + graphhopper_key),
        ("graphhopper_end_hyphen", 436, b"graphhopper " + graphhopper_end_hyphen + b"x"),
        ("groovehq", 206, b"GrOoVeHq " + groovehq_key),
        ("groovehq_overlong", 206, b"groovehq " + groovehq_key + b"EXTRA"),
        ("groovehq_no_dispatch", 206, b"groove " + groovehq_key),
        ("groq", 988, groq_key),
        ("groq_unique", 988, groq_key + b"\n" + groq_key),
        ("groq_upper_prefix", 988, b"GSK_" + groq_key[4:]),
        ("gtmetrix", 763, b"GtMeTrIx " + gtmetrix_key),
        ("gtmetrix_upper_key", 763, b"gtmetrix A" + gtmetrix_key[1:]),
        ("guardianapi", 259, b"GuArDiAnApI " + guardian_key),
        ("guardianapi_first_upper_other", 259, b"guardianapi B" + guardian_key[1:]),
        ("guardianapi_later_upper", 259, b"guardianapi " + guardian_key[:9] + b"A" + guardian_key[10:]),
        ("gumroad", 792, b"GuMrOaD " + gumroad_key),
        ("gumroad_end_hyphen", 792, b"gumroad " + gumroad_key[:42] + b"-x"),
        ("gyazo", 467, b"GyAzO " + gyazo_key),
        ("gyazo_end_hyphen", 467, b"gyazo " + gyazo_key[:42] + b"-x"),
        ("happyscribe", 507, b"HaPpYsCrIbE " + happyscribe_key),
        ("happyscribe_short", 507, b"happyscribe " + happyscribe_key[:23]),
        ("harness", 1020, b"HaRnEsS " + harness_key),
        ("harness_upper_prefix", 1020, b"harness PAT." + harness_key[4:]),
        ("harness_unique", 1020, b"harness " + harness_key + b"\nharness " + harness_key),
        ("harvest", 260, harvest_input),
        ("harvest_products", 260, harvest_input + b"\nharvest 006708"),
        ("harvest_missing_id", 260, b"harvest " + harvest_key),
        ("hashicorpvaultbatchtoken", 1061, vault_batch_key + b"\n" + vault_url),
        ("hashicorpvaultbatchtoken_no_url", 1061, vault_batch_key),
        ("hashicorpvaultbatchtoken_binary_origin", 1061, vault_batch_key + b"\n" + vault_binary_origin),
        ("hashicorpvaulttoken", 1062, vault_service_key + b"\n" + vault_url),
        ("hashicorpvaulttoken_legacy", 1062, b"vault " + vault_legacy_key + b"\n" + vault_url),
        ("hashicorpvaulttoken_legacy_no_dispatch", 1062, vault_legacy_key + b"\n" + vault_url),
        ("hashicorpvaulttoken_no_url", 1062, vault_service_key),
        ("hashicorpvaultauth", 1036, vault_auth_pair + vault_url),
        ("hashicorpvaultauth_missing_role", 1036, b"secret " + vault_secret + b"\n" + vault_url),
        ("hashicorpvaultauth_binary_path", 1036, vault_auth_pair + b"https://alpha100.hashicorp.cloud/p\0x/\v"),
        ("hasura", 1030, b"HaSuRa " + hasura_key + b"\n" + hasura_domain),
        ("hasura_no_domain", 1030, b"hasura " + hasura_key),
        ("hasura_no_prefix", 1030, hasura_key + b"\n" + hasura_domain),
        ("hellosign", 395, b"HeLlOsIgN " + hellosign_key),
        ("hellosign_edge", 395, b"hellosign " + hellosign_key[:63] + b"/X"),
        ("hellosign_overlong", 395, b"hellosign " + hellosign_key + b"X"),
        ("helpcrunch", 164, b"HeLpCrUnCh " + helpcrunch_key),
        ("helpcrunch_overlong", 164, b"helpcrunch " + helpcrunch_key + b"EXTRA"),
        ("helpcrunch_no_dispatch", 164, helpcrunch_key),
        ("helpscout", 153, b"HeLpScOuT " + helpscout_key),
        ("helpscout_upper_key", 153, b"helpscout Z" + helpscout_key[1:]),
        ("hereapi", 408, b"HeReApI " + hereapi_key),
        ("hereapi_binary", 408, b"hereapi " + hereapi_key[:20] + b"\0" + hereapi_key[21:]),
        ("hereapi_unicode", 408, b"hereapi " + hereapi_key[:20] + "💡".encode() + hereapi_key[21:]),
        ("hereapi_terminal_hash", 408, b"hereapi " + hereapi_key[:42] + b"#X"),
        ("heroku_v1", "19.v1", b"HeRoKu " + heroku_v1),
        ("heroku_v1_disallowed_first_B", "19.v1", b"heroku B" + heroku_v1[1:]),
        ("heroku_v2", "19.v2", heroku_v2),
        ("heroku_v2_wrong_prefix", "19.v2", b"hrku-AA" + heroku_v2[7:]),
        ("hiveage", 572, b"HiVeAgE " + hiveage_key),
        ("hiveage_edges", 572, b"hiveage-" + hiveage_key[1:-1] + b"-X"),
        ("holidayapi", 361, b"HoLiDaYaPi " + holidayapi_key),
        ("holidayapi_edges", 361, b"holidayapi_-" + holidayapi_key[1:-1] + b"-x"),
        ("holistic", 764, b"HoLiStIc " + holistic_key),
        ("holistic_upper_key", 764, b"holistic A" + holistic_key[1:]),
        ("honeycomb_old", 877, b"HoNeYcOmB " + honeycomb_old),
        ("honeycomb_new", 877, b"Honeycomb " + honeycomb_new),
        ("honeycomb_upper_old", 877, b"Honeycomb A" + honeycomb_old[1:]),
        ("host", 556, b"HoSt.Io " + host_key),
        ("host_no_dispatch", 556, b"host " + host_key),
        ("host_gap38", 556, b"host.io" + b":" * 38 + host_key),
        ("html2pdf", 355, b"HtMl2PdF " + html2pdf_key),
        ("html2pdf_overlong", 355, b"html2pdf " + html2pdf_key + b"X"),
        ("html2pdf_duplicate", 355, b"html2pdf " + html2pdf_key + b"\nhtml2pdf " + html2pdf_key),
        ("hubspot_v1", "107.v1", b"HuBaPi " + hubspot_v1),
        ("hubspot_v1_alias", "107.v1", b"HaPi_KeY " + hubspot_v1),
        ("hubspot_v1_unique", "107.v1", b"hubspot " + hubspot_v1 + b"\nhubspot " + hubspot_v1),
        ("hubspot_v2_na", "107.v2", hubspot_na),
        ("hubspot_v2_eu", "107.v2", hubspot_eu),
        ("hubspot_v2_wrong_case", "107.v2", b"PAT-na1-" + hubspot_v1),
        ("huggingface", 926, huggingface_key),
        ("huggingface_org", 926, huggingface_org),
        ("huggingface_wrong_case", 926, b"HF_" + huggingface_key[3:]),
        ("humanity", 508, b"HuMaNiTy " + humanity_key),
        ("humanity_upper_key", 508, b"humanity " + humanity_key.upper()),
        ("hunter", 72, b"HuNtEr " + hunter_key),
        ("hunter_upper_key", 72, b"hunter Z" + hunter_key[1:]),
        ("hybiscus", 773, b"HyBiScUs " + hybiscus_key),
        ("hybiscus_short", 773, b"hybiscus " + hybiscus_key[:42]),
        ("hypertrack", 459, hypertrack_input),
        ("hypertrack_missing_account", 459, b"hypertrack " + hypertrack_key),
        ("iconfinder", 487, b"IcOnFiNdEr " + iconfinder_key),
        ("iconfinder_overlong", 487, b"iconfinder " + iconfinder_key + b"X"),
        ("iexapis", 813, b"IeXaPiS " + iexapis_key),
        ("iexapis_upper_prefix", 813, b"iexapis SK_" + iexapis_key[3:]),
        ("iexapis_no_dispatch", 813, iexapis_key),
        ("iexcloud", 557, b"IeXcLoUd " + iexcloud_key),
        ("iexcloud_upper_key", 557, b"iexcloud A" + iexcloud_key[1:]),
        ("imagekit", 250, b"ImAgEkIt " + imagekit_key),
        ("imagekit_overlong", 250, b"imagekit " + imagekit_key + b"EXTRA"),
        ("imagekit_equal_start", 250, b"imagekit=" + imagekit_key[1:]),
        ("imagga", 349, b"ImAgGa " + imagga_key),
        ("imagga_overlong", 349, b"imagga " + imagga_key + b"EXTRA"),
        ("imagga_equal_start", 349, b"imagga=" + imagga_key[1:]),
        ("imagga_underscore", 349, b"imagga " + imagga_key[:31] + b"_" + imagga_key[32:]),
        ("impala", 509, b"ImPaLa " + impala_key),
        ("impala_overlong", 509, b"impala " + impala_key + b"X"),
        ("infura", 906, b"InFuRa " + infura_key),
        ("infura_upper_key", 906, b"infura A" + infura_key[1:]),
        ("insightly", 271, b"InSiGhTlY " + insightly_key),
        ("insightly_upper_key", 271, b"insightly A" + insightly_key[1:]),
        ("instabot", 856, b"InStAbOt " + instabot_key),
        ("instabot_overlong", 856, b"instabot " + instabot_key + b"EXTRA"),
        ("instamojo", 941, instamojo_input),
        ("instamojo_missing_secret", 941, b"instamojo " + instamojo_id),
        ("intercom", 156, b"InTeRcOm " + intercom_key),
        ("intercom_trim", 156, b"intercom    " + intercom_short),
        ("intercom_crlf", 156, b"intercom " + intercom_crlf),
        ("intercom_corrupt", 156, b"intercom " + intercom_key[:20] + b"!" + intercom_key[21:]),
        ("intercom_wrong_prefix", 156, b"intercom " + intercom_wrong),
        ("interseller", 858, b"InTeRsElLeR " + interseller_key),
        ("interseller_upper_key", 858, b"interseller A" + interseller_key[1:]),
        ("intra42_ud", 987, intra42_ud + b"\n" + intra42_id),
        ("intra42_af", 987, intra42_af + b"\n" + intra42_id),
        ("intra42_missing_id", 987, intra42_ud),
        ("intra42_upper_prefix", 987, b"S" + intra42_ud[1:] + b"\n" + intra42_id),
        ("intrinio", 579, b"InTrInIo " + intrinio_key),
        ("intrinio_overlong", 579, b"intrinio " + intrinio_key + b"X"),
        ("invoiceocean", 689, invoiceocean_input),
        ("invoiceocean_missing_host", 689, b"invoiceocean " + invoiceocean_key),
        ("invoiceocean_long_host", 689, b"invoiceocean " + invoiceocean_key + b"\n" + b"a" * 80 + b".invoiceocean.com"),
        ("ip2location", 940, b"Ip2LoCaTiOn " + ip2location_key),
        ("ip2location_lower_key", 940, b"ip2location z" + ip2location_key[1:]),
        ("ipapi", 362, b"IpApI " + ipapi_key),
        ("ipapi_upper_key", 362, b"ipapi G" + ipapi_key[1:]),
        ("ipgeolocation", 356, b"IpGeOlOcAtIoN " + ipgeolocation_key),
        ("ipgeolocation_upper_key", 356, b"ipgeolocation G" + ipgeolocation_key[1:]),
        ("ipinfo", 939, b"IpInFo " + ipinfo_key),
        ("ipinfo_nonhex_key", 939, b"ipinfo g" + ipinfo_key[1:]),
        ("ipinfodb", 530, b"IpInFoDb " + ipinfodb_key),
        ("ipinfodb_upper_key", 530, b"ipinfodb G" + ipinfodb_key[1:]),
        ("ipstack", 133, b"IpStAcK " + ipstack_key),
        ("ipstack_nonhex_key", 133, b"ipstack g" + ipstack_key[1:]),
        ("ipquality", 478, b"IpQuAlItY " + ipquality_key),
        ("ipquality_non_alnum", 478, b"ipquality " + ipquality_key[:15] + b"_" + ipquality_key[16:]),
        ("jotform", 287, b"JoTfOrM " + jotform_key),
        ("jotform_upper_b", 287, b"jotform B" + jotform_key[1:]),
        ("jumpcloud", 131, b"JuMpClOuD " + jumpcloud_key),
        ("jumpcloud_overlong", 131, b"jumpcloud " + jumpcloud_key + b"X"),
        ("juro", 295, b"JuRo " + juro_key),
        ("juro_overlong", 295, b"juro " + juro_key + b"X"),
        ("kanban", 686, kanban_input),
        ("kanban_missing_host", 686, b"kanban " + kanban_key),
        ("kanban_products", 686, kanban_input + b"\nkanban " + kanban_key + b"\ntenant8.kanbantool.com"),
        ("leadfeeder", 329, b"LeAdFeEdEr " + leadfeeder_key),
        ("leadfeeder_short_key", 329, b"leadfeeder " + leadfeeder_key[:-1]),
        ("locationiq", 450, b"LoCaTiOnIq " + locationiq_key),
        ("locationiq_no_dispatch", 450, locationiq_key),
        ("loginradius", 510, b"LoGiNrAdIuS " + loginradius_key),
        ("loginradius_upper_key", 510, b"loginradius A" + loginradius_key[1:]),
        ("madkudu", 715, b"MaDkUdU " + madkudu_key),
        ("madkudu_upper_key", 715, b"madkudu A" + madkudu_key[1:]),
        ("mailerlite", 228, b"MaIlErLiTe " + mailerlite_key),
        ("mailerlite_upper_key", 228, b"mailerlite G" + mailerlite_key[1:]),
        ("jupiterone", 982, b"JuPiTeRoNe " + jupiterone_key),
        ("jupiterone_overlong", 982, b"jupiterone " + jupiterone_key + b"X"),
        ("magicbell", 786, b"MaGiCbElL " + magicbell_key + b"\nUser@Example.test"),
        ("magicbell_missing_email", 786, b"magicbell " + magicbell_key),
        ("mailboxlayer", 145, b"MaIlBoXlAyEr " + mailboxlayer_key),
        ("mailboxlayer_upper_key", 145, b"mailboxlayer A" + mailboxlayer_key[1:]),
        ("mailjetbasicauth", 105, b"MaIlJeT " + mailjetbasicauth_key),
        ("mailjetbasicauth_missing_equals", 105, b"mailjet " + mailjetbasicauth_key[:-1]),
        ("mailjetsms", 106, b"MaIlJeT " + mailjetsms_key),
        ("mailjetsms_overlong", 106, b"mailjet " + mailjetsms_key + b"X"),
        ("kanbantool", 853, b"KaNbAnToOl " + kanbantool_key),
        ("kanbantool_lower_key", 853, b"kanbantool a" + kanbantool_key[1:]),
        ("karmacrm", 296, b"KaRmAcRm " + karmacrm_key),
        ("karmacrm_no_dispatch", 296, b"karma " + karmacrm_key),
        ("keenio", 140, b"KeEn " + keenio_key + b"\nkeen " + keenio_id),
        ("keenio_missing_id", 140, b"keen " + keenio_key),
        ("kickbox", 573, b"KiCkBoX " + kickbox_key),
        ("kickbox_short_key", 573, b"kickbox " + kickbox_key[1:]),
        ("klipfolio", 740, b"KlIpFoLiO " + klipfolio_key),
        ("klipfolio_upper_key", 740, b"klipfolio A" + klipfolio_key[1:]),
        ("knapsackpro", 760, b"KnApSaCkPrO " + knapsackpro_key),
        ("knapsackpro_upper_key", 760, b"knapsackpro Z" + knapsackpro_key[1:]),
        ("klaviyo", 935, klaviyo_key + b"\n" + klaviyo_newer),
        ("klaviyo_wrong_case", 935, b"P" + klaviyo_key[1:]),
        ("kontent", 328, b"env " + kontent_env + b"\nkontent " + kontent_key),
        ("kontent_missing_env", 328, b"kontent " + kontent_key),
        ("meistertask", 656, b"MeIsTeRtAsK " + meistertask_key),
        ("meistertask_short", 656, b"meistertask " + meistertask_key[:-1]),
        ("messagebird", 111, b"MeSsAgEbIrD " + messagebird_key),
        ("messagebird_short", 111, b"messagebird " + messagebird_key[:-1]),
        ("kraken", 186, b"KrAkEn " + kraken_key + b"\nkraken " + kraken_private + b" "),
        ("kraken_short_key", 186, b"kraken " + kraken_key[:-1] + b"\nkraken " + kraken_private + b" "),
        # TAB keeps the key out of the passphrase set even after the filesystem LF.
        ("kucoin", 736, b"KuCoIn " + kucoin_passphrase + b"\nkucoin " + kucoin_secret + b"\nkucoin\t" + kucoin_key),
        ("kucoin_missing_secret", 736, b"kucoin " + kucoin_passphrase + b"\nkucoin\t" + kucoin_key),
        ("kylas", 272, b"KyLaS " + kylas_key),
        ("kylas_upper_key", 272, b"kylas A" + kylas_key[1:]),
        ("langfuse", 1021, b"langfuse " + langfuse_public + b"\nlangfuse " + langfuse_secret),
        ("langfuse_missing_public", 1021, b"langfuse " + langfuse_secret),
        ("languagelayer", 489, b"LaNgUaGeLaYeR " + languagelayer_key),
        ("languagelayer_upper_key", 489, b"languagelayer G" + languagelayer_key[1:]),
        ("langsmith", 1028, langsmith_key),
        ("langsmith_wrong_case", 1028, b"L" + langsmith_key[1:]),
        ("larksuite", 991, b"LaRk " + larksuite_token),
        ("larksuite_extension", 991, b"lark " + larksuite_extension),
        ("larksuiteapikey", 992, b"LaRk " + larksuite_id + b"\nlark " + larksuite_secret),
        ("larksuiteapikey_missing_secret", 992, b"lark " + larksuite_id),
        ("launchdarkly", 191, launchdarkly_key),
        ("launchdarkly_mobile", 191, b"mob-" + launchdarkly_uuid),
        ("lemlist", 841, b"LeMlIsT " + lemlist_key),
        ("lemlist_upper_key", 841, b"lemlist A" + lemlist_key[1:]),
        ("lemonsqueezy", 952, b"LeMoNsQuEeZy " + lemonsqueezy_key),
        ("lemonsqueezy_short", 952, b"lemonsqueezy " + lemonsqueezy_key[:-1]),
        ("ldap", 901, ldap_payload),
        ("ldap_upper_scheme", 901, ldap_payload.replace(b"ldap://", b"LDAP://")),
        ("ldap_iad", 901, ldap_iad),
        ("ldap_missing_password", 901, ldap_url + b"\nuser '" + ldap_user + b"'"),
        ("lendflow", 668, b"LeNdFlOw " + lendflow_key),
        ("lendflow_short", 668, b"lendflow " + lendflow_key[:-1]),
        ("lessannoyingcrm", 267, b"LeSsAnNoYiNgCrM " + lessannoyingcrm_key),
        ("lessannoyingcrm_no_dispatch", 267, b"less " + lessannoyingcrm_key),
        ("lexigram", 437, b"LeXiGrAm " + lexigram_key),
        ("lexigram_short", 437, b"lexigram " + lexigram_key[:-1]),
        ("linearapi", 177, linearapi_key),
        ("linearapi_wrong_case", 177, b"LIN_API_" + linearapi_key[8:]),
        ("jiratoken_v1", "120.v1", b"jira " + jiratoken_v1 + jiratoken_context),
        ("jiratoken_v1_missing_email", "120.v1", b"jira " + jiratoken_v1 + b"\njira z7q8.atlassian.net"),
        ("jiratoken_v1_kelvin", "120.v1", b"jira " + jiratoken_v1 + jiratoken_kelvin),
        ("jiratoken_v2", "120.v2", b"jira " + jiratoken_v2 + jiratoken_context),
        ("jiratoken_v2_missing_email", "120.v2", b"jira " + jiratoken_v2 + b"\njira z7q8.atlassian.net"),
        ("jiratoken_v2_kelvin", "120.v2", b"jira " + jiratoken_v2 + jiratoken_kelvin),
        ("loadmill", 758, b"LoAdMiLl " + loadmill_key),
        ("loadmill_short", 758, b"loadmill " + loadmill_key[:-1]),
        ("meraki", 1000, b"MeRaKi " + meraki_key),
        ("meraki_upper_key", 1000, b"meraki " + meraki_key.upper()),
        ("couchbase_filtered", 920, couchbase_payload),
        ("couchbase_retained", 920, couchbase_payload),
        ("couchbase_retained_number_letter", 920, couchbase_prefix + "user:Name\npass:aBⅫ!\n".encode()),
        ("couchbase_retained_number_other", 920, couchbase_prefix + "user:Name\npass:aB²!\n".encode()),
        ("couchbase_retained_unicode16_upper_rejected", 920, couchbase_prefix + "user:Name\npass:a\u1c891!\n".encode()),
        ("couchbase_retained_unicode16_lower_rejected", 920, couchbase_prefix + "user:Name\npass:\u1c8aB1!\n".encode()),
        ("couchbase_retained_long_s", 920, couchbase_prefix + "uſer:Name\npaſſword:aB7!\n".encode()),
        ("couchbase_retained_empty_username", 920, couchbase_prefix + b"user:" + b"'" * 41 + b"X\npass:aB7!\n"),
        ("couchbase_retained_trim_order", 920, couchbase_prefix + "user:''\u00a0Name\npass:aB7!\n".encode()),
        ("couchbase_retained_nul", 920, couchbase_prefix + b"user:ab\0Cx\npass:aB7!\0x\n"),
        ("couchbase_retained_transformed_unique", 920, couchbase_payload + b"couchbases://cb.z71p8q.cloud.couchbase.com\nuser:'Name\npassword:'aB7!'\n"),
        ("aws_session_keys", 959, aws_session_payload),
        ("aws_session_url_encoded", 959, aws_session_payload.replace(b"+", b"%2B").replace(b"/", b"%2f").replace(b"=", b"%3D")),
        ("aws_access_keys", 2, aws_id + b"\n" + aws_secret),
        ("aws_bearer_id", 2, b"ABIA" + aws_id[4:] + b"\n" + aws_secret),
        ("aws_context_id", 2, b"ACCA" + aws_id[4:] + b"\n" + aws_secret),
        ("aws_url_encoded", 2, aws_id + b"\n" + aws_secret.replace(b"+", b"%2B").replace(b"/", b"%2f")),
        ("aws_canary_metadata", 2, aws_canary_id + b"\n" + aws_secret),
        ("aws_old_account_format", 2, b"AKIAI2BCDEFGHLMNPQR5\n" + aws_secret),
    )
    # Keep EOF genuinely suffix-free: the common filesystem wrapper adds LF.
    for kind in ("stdin", "filesystem"):
        cases.append(("gengo_no_suffix_" + kind, b"gengo " + gengo_key, "426", kind, False))
    for label, number, payload in provider_cases:
        cases.append((label + "_stdin", payload, str(number), "stdin", False))
        cases.append((label + "_filesystem", b"heading\n" + payload + b"\n", str(number), "filesystem", False))
    # Do not use the common filesystem wrapper: its final LF would satisfy
    # FormIO's REQUIRED whitespace and silently turn the EOF negative positive.
    for label, suffix in (("formio_missing_suffix", b""), ("formio_tab_suffix", b"\t")):
        payload = b"FoRmIo " + formio_key + suffix
        cases.append((label + "_stdin", payload, "712", "stdin", False))
        cases.append((label + "_filesystem", b"heading\n" + payload, "712", "filesystem", False))
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


def invoke(binary, source, detector, kind, cleaning, directory, reference_run=False, result_types=None):
    command = [str(binary)]
    if reference_run:
        # Controls for the Go oracle, not claims that native updater/concurrency
        # options are already ported. Compare only the shared implemented path.
        command.extend(["--no-update", "--concurrency=1"])
    command.extend(["--no-verification", "--json", "--include-detectors=" + detector])
    if result_types is not None:
        command.append("--results=" + result_types)
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
    if kind == "filesystem" and path.read_bytes() != source:
        raise AssertionError("filesystem scanner modified fixture input bytes")
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
    # Retained fixtures match pinned false-positive terms, including check in
    # the long scoped Dropbox payload. Use an ALREADY supported flag in BOTH
    # CLIs, not normalization/filter changes. Keep default-zero guards.
    result_types = "filtered_unverified" if name.startswith(("coinbase_retained_", "couchbase_retained_", "discordwebhook_retained_", "dotdigital_retained_", "dropbox_retained_", "duffeltoken_retained_", "flyio_retained_", "ftp_retained_", "gemini_master_retained_", "gemini_account_retained_", "githubapp_retained_")) else None
    with tempfile.TemporaryDirectory(prefix="briar-reference-", dir=ROOT / "state") as tmp:
        directory = Path(tmp)
        expected = invoke(reference, source, detector, kind, cleaning, directory, reference_run=True, result_types=result_types)
        actual = invoke(native, source, detector, kind, cleaning, directory, result_types=result_types)
    # False-positive filtering or keyword-window clipping must not turn these
    # positive fixtures into a vacuous zero-row comparison.
    if name in ("azure_apim_repository_stdin", "azure_apim_repository_filesystem",
                "calendly_max_segments_stdin", "calendly_max_segments_filesystem",
                "clinchpad_stdin", "clinchpad_filesystem",
                "column_stdin", "column_filesystem",
                "commercejs_stdin", "commercejs_filesystem",
                "commodities_stdin", "commodities_filesystem",
                "companyhub_self_stdin", "companyhub_self_filesystem",
                "confluent_stdin", "confluent_filesystem",
                "contentful_pat_stdin", "contentful_pat_filesystem",
                "conversiontools_stdin", "conversiontools_filesystem",
                "convertapi_stdin", "convertapi_filesystem",
                "convertkit_stdin", "convertkit_filesystem",
                "convier_stdin", "convier_filesystem",
                "copper_stdin", "copper_filesystem",
                "countrylayer_stdin", "countrylayer_filesystem",
                "craftmypdf_stdin", "craftmypdf_filesystem",
                "courier_stdin", "courier_filesystem",
                "coveralls_stdin", "coveralls_filesystem",
                "crowdin_stdin", "crowdin_filesystem",
                "currencyfreaks_stdin", "currencyfreaks_filesystem",
                "cryptocompare_stdin", "cryptocompare_filesystem",
                "currencylayer_stdin", "currencylayer_filesystem",
                "currencycloud_stdin", "currencycloud_filesystem",
                "currencycloud_hidden_emails_stdin", "currencycloud_hidden_emails_filesystem",
                "currencyscoop_stdin", "currencyscoop_filesystem",
                "currentsapi_stdin", "currentsapi_filesystem",
                "customerguru_stdin", "customerguru_filesystem",
                "customerio_stdin", "customerio_filesystem",
                "d7network_stdin", "d7network_filesystem",
                "d7network_trim_stdin", "d7network_trim_filesystem",
                "d7network_runes_stdin", "d7network_runes_filesystem",
                "d7network_nul_stdin", "d7network_nul_filesystem",
                "dandelion_stdin", "dandelion_filesystem",
                "dareboost_stdin", "dareboost_filesystem",
                "databox_stdin", "databox_filesystem",
                "databrickstoken_stdin", "databrickstoken_filesystem",
                "datadogapikey_stdin", "datadogapikey_filesystem",
                "datadogtoken_stdin", "datadogtoken_filesystem",
                "datagov_stdin", "datagov_filesystem",
                "datagov_wildcard_stdin", "datagov_wildcard_filesystem",
                "deepai_stdin", "deepai_filesystem",
                "deepgram_stdin", "deepgram_filesystem",
                "deepseek_stdin", "deepseek_filesystem",
                "delighted_stdin", "delighted_filesystem",
                "demio_stdin", "demio_filesystem",
                "demio_hidden_secrets_stdin", "demio_hidden_secrets_filesystem",
                "deputy_stdin", "deputy_filesystem",
                "deputy_hidden_hosts_stdin", "deputy_hidden_hosts_filesystem",
                "detectify_stdin", "detectify_filesystem",
                "detectlanguage_stdin", "detectlanguage_filesystem",
                "dfuse_stdin", "dfuse_filesystem",
                "diffbot_stdin", "diffbot_filesystem",
                "diggernaut_stdin", "diggernaut_filesystem",
                "digitaloceantoken_stdin", "digitaloceantoken_filesystem",
                "digitaloceantoken_short_prefix_stdin", "digitaloceantoken_short_prefix_filesystem",
                "discordbottoken_stdin", "discordbottoken_filesystem",
                "disqus_stdin", "disqus_filesystem", "ditto_stdin", "ditto_filesystem",
                "dnscheck_stdin", "dnscheck_filesystem", "docparser_stdin", "docparser_filesystem",
                "docker_stdin", "docker_filesystem", "docker_escaped_stdin", "docker_escaped_filesystem",
                "docker_hub_stdin", "docker_hub_filesystem",
                "dockerhub_v1_stdin", "dockerhub_v1_filesystem",
                "dockerhub_v1_pat_only_stdin", "dockerhub_v1_pat_only_filesystem",
                "dockerhub_v2_pat_only_stdin", "dockerhub_v2_pat_only_filesystem",
                "documo_stdin", "documo_filesystem", "documo_wildcard_stdin", "documo_wildcard_filesystem",
                "doppler_stdin", "doppler_filesystem", "doppler_namespace_stdin", "doppler_namespace_filesystem",
                "dotdigital_retained_stdin", "dotdigital_retained_filesystem",
                "dotdigital_retained_bytes_stdin", "dotdigital_retained_bytes_filesystem",
                "dotdigital_retained_wildcard_stdin", "dotdigital_retained_wildcard_filesystem",
                "docusign_stdin", "docusign_filesystem",
                "dronahq_stdin", "dronahq_filesystem", "droneci_stdin", "droneci_filesystem",
                "dropbox_stdin", "dropbox_filesystem", "dropbox_retained_scoped_stdin", "dropbox_retained_scoped_filesystem",
                "duply_stdin", "duply_filesystem", "duffeltoken_filtered_stdin", "duffeltoken_filtered_filesystem",
                "duo_stdin", "duo_filesystem",
                "dynalist_stdin", "dynalist_filesystem", "dyspatch_stdin", "dyspatch_filesystem",
                "eagleeyenetworks_stdin", "eagleeyenetworks_filesystem",
                "eagleeyenetworks_bytes_stdin", "eagleeyenetworks_bytes_filesystem",
                "easyinsight_roles_stdin", "easyinsight_roles_filesystem",
                "ecostruxureit_stdin", "ecostruxureit_filesystem", "ecostruxureit_boundary_stdin", "ecostruxureit_boundary_filesystem",
                "edamam_stdin", "edamam_filesystem", "edenai_stdin", "edenai_filesystem",
                "edenai_bytes_stdin", "edenai_bytes_filesystem", "eightxeight_stdin", "eightxeight_filesystem",
                "elasticemail_stdin", "elasticemail_filesystem", "elasticemail_prefix_stdin", "elasticemail_prefix_filesystem",
                "elevenlabs_v1_stdin", "elevenlabs_v1_filesystem", "elevenlabs_v2_stdin", "elevenlabs_v2_filesystem",
                "enablex_stdin", "enablex_filesystem",
                "enigma_stdin", "enigma_filesystem", "envoyapikey_stdin", "envoyapikey_filesystem",
                "eraser_stdin", "eraser_filesystem", "etherscan_stdin", "etherscan_filesystem",
                "ethplorer_stdin", "ethplorer_filesystem", "eventbrite_stdin", "eventbrite_filesystem",
                "everhour_stdin", "everhour_filesystem", "exchangerateapi_stdin", "exchangerateapi_filesystem",
                "exchangerateapi_alias_stdin", "exchangerateapi_alias_filesystem",
                "exchangeratesapi_stdin", "exchangeratesapi_filesystem", "exportsdk_stdin", "exportsdk_filesystem",
                "extractorapi_stdin", "extractorapi_filesystem", "facebookoauth_stdin", "facebookoauth_filesystem",
                "fastforex_stdin", "fastforex_filesystem", "fastlypersonaltoken_stdin", "fastlypersonaltoken_filesystem",
                "feedier_stdin", "feedier_filesystem", "fetchrss_stdin", "fetchrss_filesystem",
                "fibery_stdin", "fibery_filesystem", "figma_v1_stdin", "figma_v1_filesystem",
                "figma_v2_stdin", "figma_v2_filesystem", "figma_v3_stdin", "figma_v3_filesystem",
                "fileio_stdin", "fileio_filesystem", "finage_stdin", "finage_filesystem",
                "financialmodelingprep_stdin", "financialmodelingprep_filesystem", "findl_stdin", "findl_filesystem",
                "finnhub_stdin", "finnhub_filesystem", "fixerio_stdin", "fixerio_filesystem",
                "flatio_stdin", "flatio_filesystem", "fleetbase_stdin", "fleetbase_filesystem",
                "flexport_stdin", "flexport_filesystem", "flickr_stdin", "flickr_filesystem",
                "flightapi_stdin", "flightapi_filesystem", "flightlabs_stdin", "flightlabs_filesystem",
                "flightstats_stdin", "flightstats_filesystem", "float_stdin", "float_filesystem",
                "flowflu_stdin", "flowflu_filesystem", "flutterwave_stdin", "flutterwave_filesystem",
                "flyio_bypass_stdin", "flyio_bypass_filesystem", "flyio_retained_stdin", "flyio_retained_filesystem",
                "formbucket_stdin", "formbucket_filesystem", "formcraft_stdin", "formcraft_filesystem",
                "formio_stdin", "formio_filesystem", "formsite_stdin", "formsite_filesystem",
                "frameio_stdin", "frameio_filesystem", "freshbooks_stdin", "freshbooks_filesystem",
                "freshdesk_stdin", "freshdesk_filesystem", "front_wildcard_stdin", "front_wildcard_filesystem",
                "front_nul_stdin", "front_nul_filesystem", "fulcrum_stdin", "fulcrum_filesystem",
                "ftp_stdin", "ftp_filesystem", "ftp_fragment_vt_stdin", "ftp_fragment_vt_filesystem",
                "ftp_fragment_nul_stdin", "ftp_fragment_nul_filesystem", "ftp_retained_stdin", "ftp_retained_filesystem") and (len(actual) != 1 or len(expected) != 1):
        raise AssertionError(name + ": positive fixture must produce exactly one finding")
    if name.startswith(("fullstory_v1_", "fullstory_v2_key_", "fxmarket_")) and (len(actual) != 1 or len(expected) != 1):
        raise AssertionError(name + ": the selected Fullstory version or FXMarket boundary must retain one finding")
    if name.startswith(("gcp_plain_", "gcp_fallback_", "gcp_escaped_", "gcpadc_")) and (len(actual) != 1 or len(expected) != 1):
        raise AssertionError(name + ": the projected Google credential must retain one complete finding")
    if name.startswith("gcp_public_") and (actual or expected):
        raise AssertionError(name + ": the source's exact public Kubernetes account skip must remain empty")
    if name.startswith(("geckoboard_", "gemini_master_retained_", "gemini_account_retained_", "gengo_self_")) and (len(actual) != 1 or len(expected) != 1):
        raise AssertionError(name + ": the selected provider must retain one full finding")
    if name.startswith(("gemini_master_default_filtered_", "gemini_account_default_filtered_")) and (actual or expected):
        raise AssertionError(name + ": upstream wordlists filter the credential prefix by default")
    if name.startswith(("geoapify_", "geocode_", "geocodify_", "geocodio_", "geoipifi_", "getgeoapi_")) and (len(actual) != 1 or len(expected) != 1):
        raise AssertionError(name + ": the selected geographic provider must retain one complete finding")
    if name.startswith(("getgist_", "getresponse_", "getsandbox_", "github_")):
        empty = name.startswith(("getsandbox_missing_id_", "github_v1_benign_", "github_v2_uppercase_prefix_"))
        count = 0 if empty else 4 if name.startswith("github_oauth2_products_") else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": provider grammar, hidden ID and GitHub filtering must retain the expected findings")
    if name.startswith(("githubapp_", "gitlab_", "gitlaboauth2_")):
        empty = name.startswith(("githubapp_default_filtered_", "githubapp_retained_padded_", "gitlab_v1_prefixed_skip_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": app-key filtering and GitLab version/endpoint projection must preserve the expected findings")
    if name.startswith(("gitter_", "glassnode_", "gocanvas_", "gocardless_")):
        empty = name.startswith(("gocanvas_no_email_", "gocanvas_tab_suffix_", "gocardless_no_dispatch_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": required hidden email, consumed suffix and dispatch grammar must retain the expected findings")
    if name.startswith(("godaddy_", "goodday_", "googlegemini_", "googleoauth2_")):
        empty = name.startswith(("godaddy_v1_missing_secret_", "googlegemini_upper_prefix_", "googleoauth2_uppercase_prefix_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": hidden secret, direct prefix case and complete token grammar must retain the expected findings")
    if name.startswith(("grafana_", "grafanaserviceaccount_", "graphcms_", "graphhopper_")):
        empty = name.startswith(("grafana_upper_prefix_", "grafanaserviceaccount_missing_domain_", "graphcms_clipped_", "graphcms_no_id_", "graphcms_no_dispatch_"))
        count = 0 if empty else 2 if name.startswith("grafanaserviceaccount_domains_") else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": domain products, hidden IDs, direct prefix case and keyword windows must retain the expected findings")
    if name.startswith(("groovehq_", "groq_", "gtmetrix_", "guardianapi_")):
        empty = name.startswith(("groovehq_no_dispatch_", "groq_upper_prefix_", "gtmetrix_upper_key_", "guardianapi_first_upper_other_", "guardianapi_later_upper_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": dispatch, uniqueness and provider-specific alphabets must retain the expected findings")
    if name.startswith(("gumroad_", "gyazo_", "happyscribe_")):
        count = 0 if name.startswith("happyscribe_short_") else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": mixed alphabets, hyphen boundaries and required lengths must retain the expected findings")
    if name.startswith(("harness_", "harvest_", "hashicorpvaultbatchtoken_", "hashicorpvaulttoken_", "hashicorpvaultauth_")):
        empty = name.startswith(("harness_upper_prefix_", "harvest_missing_id_", "hashicorpvaultbatchtoken_no_url_", "hashicorpvaulttoken_legacy_no_dispatch_", "hashicorpvaulttoken_no_url_", "hashicorpvaultauth_missing_role_"))
        count = 0 if empty else 1  # Default CLI cleaning keeps one unverified occurrence product.
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact token grammar, required hidden IDs/endpoints, original URL bytes and source CLI cleaning must retain the expected findings")
    if name.startswith(("hasura_", "hellosign_", "helpcrunch_", "helpscout_")):
        empty = name.startswith(("hasura_no_domain_", "hasura_no_prefix_", "hellosign_overlong_", "helpcrunch_no_dispatch_", "helpscout_upper_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": required Hasura domains and exact provider capture boundaries must retain the expected findings")
    if name.startswith(("hereapi_", "heroku_v1_", "heroku_v2_", "hiveage_")):
        count = 0 if name.startswith(("heroku_v1_disallowed_first_B_", "heroku_v2_wrong_prefix_")) else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact provider/version grammar and byte-preserving captures must retain the expected findings")
    if name.startswith(("holidayapi_", "holistic_", "honeycomb_", "host_")):
        count = 0 if name.startswith(("holistic_upper_key_", "honeycomb_upper_old_", "host_no_dispatch_", "host_gap38_")) else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": source capture alternatives, exact alphabets and dispatch/prefix distinctions must retain the expected findings")
    if name.startswith(("html2pdf_", "hubspot_v1_", "hubspot_v2_", "huggingface_", "humanity_")):
        empty = name.startswith(("html2pdf_overlong_", "hubspot_v2_wrong_case_", "huggingface_wrong_case_", "humanity_upper_key_"))
        count = 0 if empty else 2 if name == "html2pdf_duplicate_filesystem" else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact provider/version prefixes, boundaries, uniqueness and default CLI cleaning must retain the expected findings")
    if name.startswith(("hunter_", "hybiscus_", "hypertrack_")):
        count = 0 if name.startswith(("hunter_upper_key_", "hybiscus_short_", "hypertrack_missing_account_")) else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact capture alphabets and the required hidden Hypertrack account must retain the expected findings")
    if name.startswith(("iconfinder_", "iexapis_", "iexcloud_", "imagekit_")):
        empty = name.startswith(("iconfinder_overlong_", "iexapis_upper_prefix_", "iexapis_no_dispatch_", "iexcloud_upper_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact provider grammars, dispatch and Imagekit's missing ending boundary must retain the expected findings")
    if name.startswith(("imagga_", "impala_", "infura_", "insightly_")):
        empty = name.startswith(("imagga_underscore_", "impala_overlong_", "infura_upper_key_", "insightly_upper_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact alphabets and provider-specific boundaries must retain the expected findings")
    if name.startswith(("instabot_", "instamojo_", "intercom_", "interseller_")):
        empty = name.startswith(("instamojo_missing_secret_", "intercom_corrupt_", "intercom_wrong_prefix_", "interseller_upper_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact grammars, hidden-secret requirements and unconditional Intercom decoding must retain the expected findings")
    if name.startswith(("intra42_", "intrinio_", "invoiceocean_", "ip2location_")):
        empty = name.startswith(("intra42_missing_id_", "intra42_upper_prefix_", "intrinio_overlong_", "invoiceocean_missing_host_", "ip2location_lower_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": direct Intra42 flavors, hidden IDs/hosts and exact provider alphabets must retain the expected findings")
    if name.startswith(("ipapi_", "ipgeolocation_", "ipinfo_", "ipinfodb_")):
        empty = name.startswith(("ipapi_upper_key_", "ipgeolocation_upper_key_", "ipinfo_nonhex_key_", "ipinfodb_upper_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": lowercase-alphanumeric IP keys and IPInfo's actual lowercase-hex grammar must retain exact findings")
    if name.startswith(("ipstack_", "leadfeeder_", "locationiq_", "loginradius_", "madkudu_", "mailerlite_")):
        empty = name.startswith(("ipstack_nonhex_key_", "leadfeeder_short_key_", "locationiq_no_dispatch_", "loginradius_upper_key_", "madkudu_upper_key_", "mailerlite_upper_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact provider alphabets, lengths, direct pk grammar and keyword dispatch must retain the expected findings")
    if name.startswith(("ipquality_", "jotform_", "jumpcloud_", "juro_", "kanban_")):
        empty = name.startswith(("ipquality_non_alnum_", "jotform_upper_b_", "jumpcloud_overlong_", "juro_overlong_", "kanban_missing_host_"))
        # Four direct products share Raw. Notifier dedup keeps one stdin
        # location or both distinct filesystem key lines, not all four rows.
        count = (1 if kind == "stdin" else 2) if name.startswith("kanban_products_") else 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact alphabets, hidden hosts and source-location notifier dedup must retain the expected findings")
    if name.startswith(("jupiterone_", "magicbell_", "mailboxlayer_", "mailjetbasicauth_", "mailjetsms_")):
        empty = name.startswith(("jupiterone_overlong_", "magicbell_missing_email_", "mailboxlayer_upper_key_", "mailjetbasicauth_missing_equals_", "mailjetsms_overlong_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact provider alphabets, hidden MagicBell email and Basic's missing ending boundary must retain the expected findings")
    if name.startswith(("kanbantool_", "karmacrm_", "keenio_", "kickbox_")):
        empty = name.startswith(("kanbantool_lower_key_", "karmacrm_no_dispatch_", "keenio_missing_id_", "kickbox_short_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": provider alphabets, Karma dispatch, hidden Keen ID and Kickbox minimum length must retain exact findings")
    if name.startswith(("klipfolio_", "knapsackpro_")):
        empty = name.startswith(("klipfolio_upper_key_", "knapsackpro_upper_key_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": lowercase hex versus nonhex lower-alphanumeric keys must preserve exact findings")
    if name.startswith(("klaviyo_", "kontent_", "meistertask_", "messagebird_")):
        empty = name.startswith(("klaviyo_wrong_case_", "kontent_missing_env_", "meistertask_short_", "messagebird_short_"))
        count = 0 if empty else 2 if name.startswith("klaviyo_") else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": both Klaviyo formats, required Kontent environment and exact provider alphabets must retain findings")
    if name.startswith(("kraken_", "kucoin_", "kylas_", "langfuse_")):
        empty = name.startswith(("kraken_short_key_", "kucoin_missing_secret_", "kylas_upper_key_", "langfuse_missing_public_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": required hidden crypto/public keys, exact alphabets and whitespace-delimited passphrases must retain exact findings")
    if name.startswith(("languagelayer_", "langsmith_", "larksuite_", "larksuiteapikey_")):
        empty = name.startswith(("languagelayer_upper_key_", "langsmith_wrong_case_", "larksuite_extension_", "larksuiteapikey_missing_secret_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": exact direct/prefixed grammars, token extension filtering and required hidden secret must preserve findings")
    if name.startswith(("launchdarkly_", "lemlist_", "lemonsqueezy_")):
        empty = name.startswith(("launchdarkly_mobile_", "lemlist_upper_key_", "lemonsqueezy_short_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": sensitive LaunchDarkly prefixes, lowercase Lemlist keys and exact LemonSqueezy length must retain findings")
    if name.startswith(("ldap_", "lendflow_", "lessannoyingcrm_", "lexigram_", "linearapi_")):
        empty = name.startswith(("ldap_missing_password_", "lendflow_short_", "lessannoyingcrm_no_dispatch_", "lexigram_short_", "linearapi_wrong_case_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": LDAP forms and required credentials, exact token lengths and dispatch/prefix policies must retain findings")
    if name.startswith(("jiratoken_v1_", "jiratoken_v2_")):
        count = 0 if name.startswith(("jiratoken_v1_missing_email_", "jiratoken_v2_missing_email_")) else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": source version grammar, required emails and lowercase-before-dedup must retain exact Jira findings")
    if name.startswith("loadmill_"):
        count = 0 if name.startswith("loadmill_short_") else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": Loadmill mixed-case dispatch and exact forty-byte keys must retain findings")
    if name.startswith("meraki_"):
        count = 0 if name.startswith("meraki_upper_key_") else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": Meraki keyword-only folding and lowercase-hex key grammar must retain findings")
    if name.startswith("gengo_products_") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": Gengo must retain all four directed occurrence products")
    if name.startswith("gengo_no_suffix_") and (actual or expected):
        raise AssertionError(name + ": Gengo requires an immediate space/CR/LF suffix, not EOF")
    if name.startswith("fullstory_v2_no_dispatch_") and (actual or expected):
        raise AssertionError(name + ": direct Fullstory v2 extraction must not bypass its dispatch keyword")
    if name.startswith(("ftp_skipped_", "ftp_filtered_")) and (actual or expected):
        raise AssertionError(name + ": FTP credential skips and private false-positive filtering must remain empty")
    if name in ("deputy_no_host_stdin", "deputy_no_host_filesystem") and (actual or expected):
        raise AssertionError(name + ": the hidden Deputy host is still a required credential component")
    if name in ("dfuse_no_dispatch_stdin", "dfuse_no_dispatch_filesystem") and (actual or expected):
        raise AssertionError(name + ": direct token extraction must not bypass the Dfuse dispatch keyword")
    if name in ("digitaloceantoken_no_dispatch_stdin", "digitaloceantoken_no_dispatch_filesystem") and (actual or expected):
        raise AssertionError(name + ": the short ocean/do extraction prefixes must not replace digitalocean dispatch")
    if name in ("digitaloceanv2_stdin", "digitaloceanv2_filesystem") and (len(actual) != 3 or len(expected) != 3):
        raise AssertionError(name + ": all three DigitalOceanV2 prefixes must retain unique original tokens")
    if name in ("discordbottoken_products_stdin", "discordbottoken_products_filesystem") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": bot key/ID products must preserve four distinct RawV2 and redacted-ID projections")
    if name in ("discordbottoken_no_id_stdin", "discordbottoken_no_id_filesystem") and (actual or expected):
        raise AssertionError(name + ": a Discord bot token still requires a separate prefixed ID")
    if name in ("discordwebhook_filtered_stdin", "discordwebhook_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": default wordlist must filter the webhook URL scheme in Raw")
    if name in ("discordwebhook_retained_stdin", "discordwebhook_retained_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": both webhook ID widths must preserve their captured URL prefixes")
    if name in ("dnscheck_products_stdin", "dnscheck_products_filesystem") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": DNSCheck key/ID products must retain four distinct RawV2 projections")
    if name in ("dnscheck_no_id_stdin", "dnscheck_no_id_filesystem") and (actual or expected):
        raise AssertionError(name + ": the DNSCheck ID remains required even though it is not a UUID")
    if name in ("docker_empty_stdin", "docker_empty_filesystem") and (actual or expected):
        raise AssertionError(name + ": decoded empty username and password must suppress Docker findings")
    if name in ("dockerhub_v2_stdin", "dockerhub_v2_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": both direct Dockerhub PAT and OAT shapes must dispatch and retain distinct identities")
    if name.startswith(("dockerhub_v1_pat_only_", "dockerhub_v2_pat_only_")) and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": PAT-only Dockerhub fallback must not invent a username or RawV2")
    if name in ("documo_no_dispatch_stdin", "documo_no_dispatch_filesystem") and (actual or expected):
        raise AssertionError(name + ": direct Documo extraction must not bypass the dispatch keyword")
    if name in ("dotdigital_filtered_stdin", "dotdigital_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": default wordlist must filter connect in the required Dotdigital email Raw")
    if name in ("docusign_products_stdin", "docusign_products_filesystem") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": Docusign ID/secret occurrences must retain four distinct RawV2 projections")
    if name in ("docusign_no_secret_stdin", "docusign_no_secret_filesystem") and (actual or expected):
        raise AssertionError(name + ": the Docusign secret remains required alongside its visible ID")
    if name in ("dovico_stdin", "dovico_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": identical Dovico grammars must retain both unequal directed products")
    if name in ("dovico_equal_stdin", "dovico_equal_filesystem") and (actual or expected):
        raise AssertionError(name + ": unique Dovico candidates must not produce an equal self-pair")
    if name in ("dropbox_scoped_filtered_stdin", "dropbox_scoped_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": pinned badlist check in the long scoped fixture remains filtered by default")
    if name in ("dropbox_no_prefix_stdin", "dropbox_no_prefix_filesystem") and (actual or expected):
        raise AssertionError(name + ": Dropbox sl. dispatch must not bypass the required dropbox extraction prefix")
    if name in ("duffeltoken_retained_stdin", "duffeltoken_retained_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": both unique Duffel prefixes must survive explicit retained-results selection")
    if name in ("duffeltoken_filtered_stdin", "duffeltoken_filtered_filesystem") and any(not row["Raw"].startswith("duffel_live_") for row in actual + expected):
        raise AssertionError(name + ": pinned test wordlist filtering must suppress only the test-token fixture")
    if name in ("duffeltoken_suffix_stdin", "duffeltoken_suffix_filesystem") and (actual or expected):
        raise AssertionError(name + ": Duffel must consume a nonalphabet delimiter or end at EOF, not capture an overlong prefix")
    if name in ("duply_products_stdin", "duply_products_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": hidden Duply IDs collapse only after constructing native products for both keys")
    if name in ("duply_no_id_stdin", "duply_no_id_filesystem") and (actual or expected):
        raise AssertionError(name + ": a Duply ID remains required despite its omission from findings")
    if name.startswith("duply_") and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": Duply must not invent RawV2 for hidden IDs")
    if name in ("dwolla_stdin", "dwolla_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": both unequal directed Dwolla products must remain visible")
    if name in ("dwolla_equal_stdin", "dwolla_equal_filesystem") and (actual or expected):
        raise AssertionError(name + ": unique Dwolla candidates must not produce an equal self-pair")
    if name in ("duo_products_stdin", "duo_products_filesystem") and (len(actual) != 8 or len(expected) != 8):
        raise AssertionError(name + ": all eight visible Duo host/integration-key/secret-key products must survive")
    if name in ("duo_no_host_stdin", "duo_no_host_filesystem") and (actual or expected):
        raise AssertionError(name + ": a Duo host remains required despite a separate duosecurity dispatch hint")
    if name in ("eagleeyenetworks_products_stdin", "eagleeyenetworks_products_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": hidden EagleEye emails collapse only after native products are constructed")
    if name in ("eagleeyenetworks_no_email_stdin", "eagleeyenetworks_no_email_filesystem") and (actual or expected):
        raise AssertionError(name + ": an EagleEye email remains required despite its omission from findings")
    if name.startswith("eagleeyenetworks_") and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": EagleEye must not invent RawV2 for hidden emails")
    if name in ("easyinsight_stdin", "easyinsight_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": common provider prefixes must retain both unequal EasyInsight products")
    if name in ("easyinsight_equal_stdin", "easyinsight_equal_filesystem") and (actual or expected):
        raise AssertionError(name + ": equal EasyInsight key/ID pairs must remain excluded")
    if name in ("edamam_products_stdin", "edamam_products_filesystem", "eightxeight_products_stdin", "eightxeight_products_filesystem") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": all four visible key/ID products must survive notifier deduplication")
    if name in ("edamam_no_id_stdin", "edamam_no_id_filesystem", "eightxeight_no_id_stdin", "eightxeight_no_id_filesystem") and (actual or expected):
        raise AssertionError(name + ": an application/subaccount ID remains required")
    if name in ("edenai_no_lf_stdin", "edenai_no_lf_filesystem") and (actual or expected):
        raise AssertionError(name + ": EdenAI wildcard dots exclude LF, unlike its prefix gap")
    if name in ("elevenlabs_v1_case_stdin", "elevenlabs_v1_case_filesystem", "elevenlabs_both_stdin", "elevenlabs_both_filesystem",
                "enablex_products_stdin", "enablex_products_filesystem", "endorlabs_stdin", "endorlabs_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": original case/version identities, hidden-ID products or unequal directed pairs must not collapse early")
    if name in ("elevenlabs_v1_one_separator_stdin", "elevenlabs_v1_one_separator_filesystem", "enablex_no_id_stdin", "enablex_no_id_filesystem", "endorlabs_equal_stdin", "endorlabs_equal_filesystem") and (actual or expected):
        raise AssertionError(name + ": preserve mandatory ElevenLabs syntax, required Enablex IDs and EndorLabs equality skips")
    if name.startswith("enablex_") and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": Enablex must not expose its hidden ID through RawV2")
    if name.startswith("exportsdk_") and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": ExportSDK must not expose its hidden template ID through RawV2")
    if name.startswith("faceplusplus_") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": FacePlusPlus preserves all four directed products, including both self-pairs")
    if name.startswith("foursquare_") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": FourSquare preserves four directed products, including both self-pairs")
    if name.startswith("frameio_uppercase_") and (actual or expected):
        raise AssertionError(name + ": FrameIO's direct fio-u- token prefix remains case-sensitive")
    if name.startswith(("formsite_", "freshbooks_")) and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": required secondary Formsite and Freshbooks credentials remain hidden")
    if name.startswith("fmfw_") and (len(actual) != 2 or len(expected) != 2 or any(row["RawV2"] for row in actual + expected)):
        raise AssertionError(name + ": independent FMFW grammars produce two keys with one hidden required ID, including its self-pair")
    if name.startswith("formbucket_") and any("\0" not in row["Raw"] for row in actual + expected):
        raise AssertionError(name + ": FormBucket's first separator is a wildcard and must preserve the original NUL byte")
    if name.startswith(("formio_missing_suffix_", "formio_tab_suffix_")) and (actual or expected):
        raise AssertionError(name + ": FormIO requires one immediate space, CR or LF; EOF and HTAB do not qualify")
    if name.startswith("flyio_filtered_") and (actual or expected):
        raise AssertionError(name + ": lowercase aaaaaa does not bypass FlyIO's default false-positive fallback")
    if name.startswith("flowflu_") and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": FlowFlu keeps its required account hidden from RawV2")
    if name.startswith("flightstats_") and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": Flightstats keeps its required application ID hidden from RawV2")
    if name.startswith("fibery_") and any(row["RawV2"] for row in actual + expected):
        raise AssertionError(name + ": Fibery keeps its required domain hidden from RawV2")
    if name.startswith("figma_v") and any(row.get("ExtraData") != {"version": name.split("_")[1][1:]} for row in actual + expected):
        raise AssertionError(name + ": Figma retains its version metadata without verification")
    if name.startswith("flexport_") and any(row.get("ExtraData") != {"rotation_guide": "https://howtorotate.com/docs/tutorials/flexport/"} for row in actual + expected):
        raise AssertionError(name + ": Flexport retains its rotation guide without verification")
    if name.startswith("eraser_") and any(row.get("ExtraData") != {"rotation_guide": "https://howtorotate.com/docs/tutorials/eraser/"} for row in actual + expected):
        raise AssertionError(name + ": Eraser retains its rotation guide without verification")
    if name in ("everhour_bad_upper_stdin", "everhour_bad_upper_filesystem") and (actual or expected):
        raise AssertionError(name + ": Everhour allows uppercase A, not uppercase B through F, in the first group")
    if name in ("denodeploy_stdin", "denodeploy_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": both direct Deno token prefixes must dispatch without a provider name")
    if name in ("databrickstoken_products_stdin", "databrickstoken_products_filesystem") and (len(actual) != 6 or len(expected) != 6):
        raise AssertionError(name + ": unique token/domain sets must retain six products, including optional-suffix fallback")
    if name in ("datadogapikey_no_dispatch_stdin", "datadogapikey_no_dispatch_filesystem") and (actual or expected):
        raise AssertionError(name + ": extraction prefix alone must not replace the detector dispatch keywords")
    if name in ("customerio_products_stdin", "customerio_products_filesystem") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": two distinct occurrences must retain all four CustomerIO products")
    if name in ("currencycloud_no_email_stdin", "currencycloud_no_email_filesystem") and (actual or expected):
        raise AssertionError(name + ": missing required email must produce no finding")
    if name.startswith("couchbase_"):
        count = 0 if name.startswith(("couchbase_filtered_", "couchbase_retained_unicode16_upper_rejected_", "couchbase_retained_unicode16_lower_rejected_")) else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": source transformations and pinned Unicode15 validation must not be vacuous")
    if name in ("companyhub_stdin", "companyhub_filesystem") and (len(actual) != 2 or len(expected) != 2):
        raise AssertionError(name + ": key must self-pair and also pair with the separate symbol-bearing ID")
    if name in ("cexio_products_stdin", "cexio_products_filesystem") and (len(actual) != 4 or len(expected) != 4):
        raise AssertionError(name + ": both keys and both secrets must retain all four products")
    if name in ("checkout_sandbox_filtered_stdin", "checkout_sandbox_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": default wordlist must filter sk_test_ credentials")
    if name in ("clinchpad_filtered_stdin", "clinchpad_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": default wordlist must filter the safe substring")
    if name in ("convertkit_filtered_stdin", "convertkit_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": default wordlist must filter the original sign substring")
    if name in ("column_test_filtered_stdin", "column_test_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": default wordlist must filter test_ Column credentials")
    if name in ("coinbase_filtered_stdin", "coinbase_filtered_filesystem") and (actual or expected):
        raise AssertionError(name + ": default wordlist must filter PRIVATE in Coinbase Raw")
    if name.startswith("coinbase_retained_"):
        empty = name.startswith(("coinbase_retained_crlf_", "coinbase_retained_no_name_", "coinbase_retained_zero_scalar_"))
        count = 0 if empty else 1
        if len(actual) != count or len(expected) != count:
            raise AssertionError(name + ": retained-key validation and normalization must not be vacuous")
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
