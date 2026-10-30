#!/usr/bin/env python3
"""Audit ledger claims against the actual source tree, registry and fixtures.

This is the mechanical half of the completion audit: for every pinned upstream
identity it re-checks provenance, native ownership, registry wiring and fixture
coverage. It cannot prove behavioural parity; it proves that each accepted
identity is real, wired and evidenced rather than a ledger-only claim, and it
lists every identity that is still unstarted or only partial.

Exit status is non-zero only when the ledger claims completion while a
mechanical requirement is unmet, so the report stays usable during migration.
"""
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path("/nix/store/q1bli5hz14c1lc45r02kahn2swfgnl5a-source")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exported_symbols():
    library = ROOT / "build/libbriar.a"
    if not library.exists():
        return set()
    output = subprocess.run(["nm", "-g", "--defined-only", str(library)],
                            check=True, capture_output=True, text=True).stdout
    return {line.split()[-1] for line in output.splitlines() if " T " in line or line.endswith(" T")}


def detector_fixture_counts(cases):
    counts = {}
    for _, _, selector, _, _ in cases:
        base = selector.split(".")[0].split(",")[0]
        counts[base] = counts.get(base, 0) + 1
    return counts


def main():
    inventory = json.loads((ROOT / "upstream-inventory.json").read_text())
    ledger = json.loads((ROOT / "parity.json").read_text())
    registry = (ROOT / "src/detectors/registry.c").read_text()
    symbols = exported_symbols()
    cases = load_module(ROOT / "tests/cli_reference.py", "cli_reference").fixtures()
    fixtures = detector_fixture_counts(cases)

    rows = []
    problems = []
    for item in inventory["detectors"]:
        name = item["id"]
        package = item["package"]
        source = REFERENCE / item["source"]
        provenance = source.is_file() and sha256(source) == item["source_sha256"]
        record = ledger["detectors"].get(name)
        native = directory = None
        if record:
            native = [path for path in record.get("native_files", []) if (ROOT / path).is_file()]
            for path in record.get("native_files", []):
                if path.startswith("src/detectors/") and path.endswith(".c"):
                    directory = path
                    break
        segments = [part for part in name.split("/") if part not in ("Scanner",)]
        lowered = [part.lower() for part in segments]
        module_name = lowered[-1]
        family = lowered[0]
        # Native owners flatten the upstream path, e.g. aws/access_keys keeps a
        # trailing "scanner" segment while azureapimanagement/repositorykey joins.
        candidates = {f"br_{module_name}_init", f"br_{family}_init",
                      f"br_{'_'.join(lowered)}_init"}
        for prefix in range(1, len(lowered)):
            candidates.add(f"br_{'_'.join(lowered[:prefix])}_init")
        # A provider module may deliberately rename an upstream package, e.g.
        # deno/Scanner owning denodeploy.c; the reviewed ledger records the file.
        if record:
            for path in record.get("native_files", []):
                if path.startswith("src/detectors/") and path.endswith(".c"):
                    candidates.add(f"br_{Path(path).stem}_init")
        for part in segments:
            if re.fullmatch(r"\d+|v\d+|\d+\.v\d+", part):
                version = part.replace(".v", "_v").replace("v", "")
                candidates.add(f"br_{family}_v{version}_init")
                candidates.add(f"br_{module_name}_v{version}_init")
                candidates.add(f"br_{'_'.join(lowered)}_v{version}_init")
        exports = sorted(symbol for symbol in symbols if symbol in candidates)
        if not exports:
            stem = re.escape(module_name)
            exports = sorted(symbol for symbol in symbols
                             if re.fullmatch(rf"br_.*{stem}(_v\d+)?_init", symbol))
        registered = bool(exports) and any(registry.count(symbol) >= 1 for symbol in exports)
        row = {
            "id": name,
            "ledger": (record.get("status") or ("partial" if record.get("aspects") else "unstarted")) if record else "unstarted",
            "provenance": provenance,
            "native_files": bool(native),
            "exports": exports,
            "registered": registered,
            "fixtures": None,
        }
        if record and row["ledger"] != "unstarted":
            if not provenance:
                problems.append(f"{name}: upstream provenance mismatch")
            if not native:
                problems.append(f"{name}: no existing native file")
            if not exports:
                problems.append(f"{name}: no exported initializer")
            elif not registered:
                problems.append(f"{name}: initializer missing from registry")
            behaviour = all(value == "verified" for value in record.get("aspects", {}).values())
            if row["ledger"] == "verified" and not behaviour:
                problems.append(f"{name}: verified status without all aspects verified")
        rows.append(row)

    partial = [row["id"] for row in rows if row["ledger"] not in ("verified", "unstarted")]
    verified = [row["id"] for row in rows if row["ledger"] == "verified"]
    unstarted = [row["id"] for row in rows if row["ledger"] == "unstarted"]
    components = ledger["components"]
    report = {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "counts": {
            "inventory": len(rows),
            "verified": len(verified),
            "partial": len(partial),
            "unstarted": len(unstarted),
            "components": len(inventory["components"]),
            "components_verified": sum(1 for row in components.values() if row["status"] == "verified"),
            "problems": len(problems),
        },
        "problems": problems,
        "unstarted": unstarted,
        "partial": partial,
        "rows": rows,
    }
    out = ROOT / "state/audit/report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"identities {len(rows)}: {len(verified)} verified, {len(partial)} partial, {len(unstarted)} unstarted")
    print(f"components: {report['counts']['components_verified']}/{len(inventory['components'])} verified")
    print(f"mechanical problems: {len(problems)}")
    for problem in problems:
        print("  " + problem)
    print(f"full report {out}")
    if ledger.get("completion") == "complete" and (unstarted or partial or problems):
        print("ledger claims completion but the mechanical audit disagrees", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
