#!/usr/bin/env python3
"""Regressions for omissions observed while checking the upstream registry."""

from pathlib import Path
import unittest

import inventory

ROOT = Path(__file__).resolve().parents[1]


class PinnedRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = inventory.generate(ROOT / ".reference/trufflehog")
        cls.detectors = {item["id"]: item for item in cls.catalogue["detectors"]}

    def test_aws_factories_are_not_lost(self):
        for package in ("access_keys", "session_keys"):
            item = self.detectors[f"aws/{package}/scanner"]
            self.assertTrue(item["listed_in_registry"])
            self.assertEqual(item["registry_kind"], "factory")
            self.assertEqual(item["registry_constructor"], f"aws_{package}.New()")
        self.assertEqual(self.catalogue["registry_factory_candidates"], 2)

    def test_disabled_implementations_stay_in_denominator(self):
        item = self.detectors["abstract/Scanner"]
        self.assertFalse(item["listed_in_registry"])
        self.assertIsNone(item["registry_constructor"])
        self.assertIn("FromData", item["methods"])

    def test_reference_totals_and_resolution(self):
        self.assertEqual(self.catalogue["detector_implementations"], 921)
        self.assertEqual(self.catalogue["registry_composite_candidates"], 890)
        self.assertEqual(self.catalogue["registry_constructor_candidates"], 892)
        self.assertEqual(self.catalogue["unresolved_registry_constructors"], [])
        self.assertEqual(len(self.catalogue["components"]), 34)

    def test_all_production_go_files_have_an_owner(self):
        reference = ROOT / ".reference/trufflehog"
        assigned = {item["source"] for item in self.catalogue["detectors"] if item["source"]}
        assigned.update(source["path"] for component in self.catalogue["components"] for source in component["source_files"])
        actual = {str(path.relative_to(reference)) for path in (reference / "pkg").rglob("*.go") if not path.name.endswith("_test.go")}
        self.assertEqual(actual - assigned, set())
        self.assertIn("pkg/detectors/detectors.go", assigned)
        self.assertIn("pkg/detectors/falsepositives.go", assigned)
        self.assertIn("pkg/detectors/aws/common.go", assigned)


if __name__ == "__main__":
    unittest.main()
