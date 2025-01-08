import unittest

from luminaut import models


class TestModels(unittest.TestCase):
    def test_scan_finding_bool(self):
        self.assertFalse(bool(models.ScanFindings(tool="foo")))
        self.assertTrue(bool(models.ScanFindings(tool="foo", resources=["bar"])))  # type: ignore
        self.assertTrue(bool(models.ScanFindings(tool="foo", services=["bar"])))  # type: ignore
        self.assertTrue(bool(models.ScanFindings(tool="foo", events=["bar"])))  # type: ignore


if __name__ == "__main__":
    unittest.main()
