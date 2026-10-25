#!/usr/bin/env python3
"""Report full-goal coverage without silently removing unfinished entries."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    inventory = json.loads((ROOT / "upstream-inventory.json").read_text())
    ledger = json.loads((ROOT / "parity.json").read_text())
    if ledger["upstream_commit"] != inventory["upstream_commit"]:
        raise SystemExit("ledger/reference commit mismatch")
    ids = {row["id"] for row in inventory["detectors"]}
    component_ids = {row["id"] for row in inventory["components"]}
    if set(ledger["detectors"]) - ids or set(ledger["components"]) - component_ids:
        raise SystemExit("ledger contains entries outside the pinned inventory")
    complete = []
    partial = []
    aspects = ledger["rules"]["detector_required_aspects"]
    for name, record in ledger["detectors"].items():
        if all(record.get("aspects", {}).get(aspect) == "verified" for aspect in aspects):
            for source in record.get("native_files", []):
                if not (ROOT / source).is_file():
                    raise SystemExit(f"missing native source: {source}")
            if not record.get("native_files") or not record.get("evidence"):
                raise SystemExit(f"unsubstantiated complete detector record: {name}")
            complete.append(name)
        else:
            partial.append(name)
    components_complete = [name for name, record in ledger["components"].items() if record.get("status") == "verified"]
    missing = len(ids) - len(complete) - len(partial)
    print(f"Detectors: {len(complete)}/{len(ids)} verified; {len(partial)} partial; {missing} not started")
    print(f"Supporting components: {len(components_complete)}/{len(component_ids)} verified")
    print(f"Registry: {inventory['registry_constructor_candidates']} constructor candidates; disabled and feature-gated behavior still needs individual evidence")
    print("Goal remains incomplete" if len(complete) != len(ids) or len(components_complete) != len(component_ids) else "Ledger fully populated; independent full-scope completion audit still required")
    if ledger.get("completion") == "complete":
        raise SystemExit("do not assert completion from the ledger alone; use the full goal audit")


if __name__ == "__main__":
    main()
