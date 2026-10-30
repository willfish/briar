#!/usr/bin/env python3
"""Regressions for child-specific latency measurement, not scanner benchmarks."""
import subprocess
import sys
import tempfile
import unittest

import latency


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory(prefix="latency-test-", dir=latency.ROOT / "state")
        self.addCleanup(self.home.cleanup)

    def measure(self, code, timeout=30):
        return latency.measure([sys.executable, "-c", code], self.home.name, timeout)

    def test_memory_peak_belongs_to_each_child(self):
        large = self.measure('data = bytearray(64 * 1024 * 1024); print("large")')
        small = self.measure('print("small")')
        self.assertEqual(large[-1], 0)
        self.assertEqual(small[-1], 0)
        self.assertEqual(large[2], b"large\n")
        self.assertEqual(small[2], b"small\n")
        self.assertLess(small[1], large[1] - 32 * 1024)

    def test_output_and_unsuccessful_exit_are_preserved(self):
        result = self.measure('import sys; print("out"); print("err", file=sys.stderr); sys.exit(7)')
        self.assertEqual(result[2:5], (b"out\n", b"err\n", 7))
        self.assertGreater(result[0], 0)
        self.assertGreater(result[1], 0)

    def test_timeout_stops_the_child(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.measure('import time; time.sleep(30)', timeout=0.05)


if __name__ == "__main__":
    unittest.main()
