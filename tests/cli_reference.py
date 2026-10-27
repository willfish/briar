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
    # Coinbase PRIVATE and Couchbase normalized hostnames match pinned default
    # wordlist terms. Retained cases use an ALREADY supported flag in BOTH CLIs,
    # not output normalization or a detector/filter change. Keep default-zero guards.
    result_types = "filtered_unverified" if name.startswith(("coinbase_retained_", "couchbase_retained_")) else None
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
                "dfuse_stdin", "dfuse_filesystem") and (len(actual) != 1 or len(expected) != 1):
        raise AssertionError(name + ": positive fixture must produce exactly one finding")
    if name in ("deputy_no_host_stdin", "deputy_no_host_filesystem") and (actual or expected):
        raise AssertionError(name + ": the hidden Deputy host is still a required credential component")
    if name in ("dfuse_no_dispatch_stdin", "dfuse_no_dispatch_filesystem") and (actual or expected):
        raise AssertionError(name + ": direct token extraction must not bypass the Dfuse dispatch keyword")
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
