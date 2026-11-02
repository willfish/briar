#!/usr/bin/env python3
"""Regressions for child-specific latency measurement, not scanner benchmarks."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import latency


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        (latency.ROOT / "state").mkdir(exist_ok=True)
        self.home = tempfile.TemporaryDirectory(prefix="latency-test-", dir=latency.ROOT / "state")
        self.addCleanup(self.home.cleanup)

    def measure(self, code, timeout=30):
        return latency.measure([sys.executable, "-c", code], self.home.name, timeout)

    def test_memory_peak_belongs_to_each_child(self):
        large = self.measure('data = bytearray(64 * 1024 * 1024); print("large")')
        small = self.measure('print("small")')
        self.assertEqual(large["exit"], 0)
        self.assertEqual(small["exit"], 0)
        self.assertEqual(large["stdout"], b"large\n")
        self.assertEqual(small["stdout"], b"small\n")
        self.assertLess(small["peak_rss_kib"], large["peak_rss_kib"] - 32 * 1024)

    def test_output_and_unsuccessful_exit_are_preserved(self):
        result = self.measure('import sys; print("out"); print("err", file=sys.stderr); sys.exit(7)')
        self.assertEqual((result["stdout"], result["stderr"], result["exit"]), (b"out\n", b"err\n", 7))
        self.assertGreater(result["wall_ms"], 0)
        self.assertGreater(result["peak_rss_kib"], 0)

    def test_timeout_stops_the_child(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.measure('import time; time.sleep(30)', timeout=0.05)

    def test_each_invocation_has_a_fresh_home(self):
        code = ('import os; from pathlib import Path; home = Path(os.environ["HOME"]); '
                'print(len(list(home.iterdir()))); (home / "marker").touch()')
        for _ in range(2):
            result = self.measure(code)
            self.assertEqual(result["exit"], 0)
            self.assertEqual(result["stdout"], b"0\n")
        self.assertEqual(list(Path(self.home.name).iterdir()), [])

    def test_complete_findings_not_just_counts_must_match(self):
        one = b'{"DetectorType":239,"Raw":"synthetic-one"}\n'
        two = b'{"DetectorType":239,"Raw":"synthetic-two"}\n'
        self.assertNotEqual(latency.findings(one), latency.findings(two))
        self.assertEqual(latency.findings(one + two), latency.findings(two + one))


if __name__ == "__main__":
    unittest.main()
