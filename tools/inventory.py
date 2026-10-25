#!/usr/bin/env python3
"""Inventory the pinned reference without executing it or reading credentials.

This is source bookkeeping, not a declaration of detector parity. Registry-list
membership does not mean enabled by default: feature filters run afterwards.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
METHOD = re.compile(r"(?m)^func\s*\(\s*(?:[A-Za-z_]\w*\s+)?\*?([A-Za-z_]\w*)\s*\)\s*([A-Za-z_]\w*)\s*\(")
FROM_DATA = re.compile(r"(?m)^func\s*\([^)]*\)\s*FromData\s*\(")
MODULE = "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(reference):
    upstream = json.loads((ROOT / "UPSTREAM.json").read_text())
    defaults = reference / "pkg/engine/defaults/defaults.go"
    registry = defaults.read_text()
    # Constructor lines in this pinned file are plain Go expressions. Refuse a
    # block-comment change rather than silently counting commented constructors.
    if "/*" in registry:
        raise ValueError("registry block comments require inventory parser review")
    registry = re.sub(r"//[^\n]*", "", registry)
    aliases = {}
    for alias, package in re.findall(r'^\s*(?:(\w+)\s+)?"' + re.escape(MODULE) + r'([^\"]+)"', registry, re.M):
        aliases[alias or package.rsplit("/", 1)[-1]] = package
    listed = {}
    for alias, receiver in re.findall(r"(?m)^\s*&([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\{", registry):
        if alias not in aliases:
            raise ValueError(f"unresolved registry constructor alias: {alias}")
        listed[f"{aliases[alias]}/{receiver}"] = f"{alias}.{receiver}"

    detectors = {}
    source_count = 0
    for path in sorted((reference / "pkg/detectors").rglob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        source_count += 1
        text = path.read_text()
        methods = list(METHOD.finditer(text))
        from_data = [method for method in methods if method.group(2) == "FromData"]
        if len(from_data) != len(FROM_DATA.findall(text)):
            raise ValueError(f"unsupported receiver declaration in {path.relative_to(reference)}")
        package = str(path.parent.relative_to(reference / "pkg/detectors"))
        for method in from_data:
            receiver = method.group(1)
            key = f"{package}/{receiver}"
            if key in detectors:
                raise ValueError(f"duplicate FromData implementation: {key}")
            receiver_methods = set()
            for sibling in path.parent.glob("*.go"):
                if not sibling.name.endswith("_test.go"):
                    receiver_methods.update(m.group(2) for m in METHOD.finditer(sibling.read_text()) if m.group(1) == receiver)
            detectors[key] = {
                "id": key,
                "package": package,
                "receiver": receiver,
                "source": str(path.relative_to(reference)),
                "source_sha256": digest(path),
                "source_line": text.count("\n", 0, method.start()) + 1,
                "methods": sorted(receiver_methods),
                "registry_constructor": listed.get(key),
                "listed_in_registry": key in listed,
                "test_files": [str(p.relative_to(reference)) for p in sorted(path.parent.glob("*_test.go"))],
            }
    unresolved = sorted(set(listed) - set(detectors))
    if unresolved:
        # Some constructors can inherit FromData. Such cases must be explicitly
        # represented rather than disappearing from the completion denominator.
        for key in unresolved:
            package, receiver = key.rsplit("/", 1)
            detectors[key] = {
                "id": key, "package": package, "receiver": receiver,
                "source": None, "source_sha256": None, "source_line": None,
                "methods": [], "registry_constructor": listed[key],
                "listed_in_registry": True, "test_files": [],
                "requires_manual_resolution": True,
            }

    components = []
    for package in sorted((reference / "pkg").iterdir()):
        if not package.is_dir() or package.name == "detectors":
            continue
        files = sorted(p for p in package.rglob("*") if p.is_file() and not p.name.endswith("_test.go"))
        components.append({
            "id": package.name,
            "source_directory": str(package.relative_to(reference)),
            "source_files": [{"path": str(p.relative_to(reference)), "sha256": digest(p)} for p in files],
        })
    root_runtime = [p for p in sorted(reference.glob("*.go")) if not p.name.endswith("_test.go")]
    components.append({"id": "cli", "source_directory": ".", "source_files": [{"path": p.name, "sha256": digest(p)} for p in root_runtime]})
    distribution = ["Dockerfile", "Dockerfile.goreleaser", "action.yml", "entrypoint.sh", "PreCommit.md"]
    components.append({"id": "distribution", "source_directory": ".", "source_files": [{"path": name, "sha256": digest(reference / name)} for name in distribution if (reference / name).is_file()]})
    return {
        "upstream_version": upstream["version"], "upstream_commit": upstream["commit"],
        "detector_source_files": source_count,
        "detector_implementations": len(detectors),
        "registry_constructor_candidates": len(listed),
        "unresolved_registry_constructors": unresolved,
        "registry_note": "List membership only; feature gating and disabled/versioned behavior require separate parity evidence.",
        "detectors": [detectors[key] for key in sorted(detectors)],
        "components": components,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, default=ROOT / ".reference/trufflehog")
    parser.add_argument("--check", action="store_true", help="compare the committed inventory with the pinned source")
    args = parser.parse_args()
    inventory = generate(args.reference)
    destination = ROOT / "upstream-inventory.json"
    rendered = json.dumps(inventory, indent=2) + "\n"
    if args.check:
        if not destination.is_file() or destination.read_text() != rendered:
            raise SystemExit("inventory does not match the pinned reference")
    else:
        destination.write_text(rendered)
    print(f'{inventory["detector_implementations"]} detector implementations; '
          f'{inventory["registry_constructor_candidates"]} registry candidates; '
          f'{len(inventory["components"])} supporting components; '
          f'{len(inventory["unresolved_registry_constructors"])} unresolved constructors')


if __name__ == "__main__":
    main()
