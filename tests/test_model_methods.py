import unittest
from datetime import UTC, datetime

from luminaut import models


class TestModels(unittest.TestCase):
    def test_scan_finding_bool(self):
        self.assertFalse(bool(models.ScanFindings(tool="foo")))
        self.assertTrue(bool(models.ScanFindings(tool="foo", resources=["bar"])))  # type: ignore
        self.assertTrue(bool(models.ScanFindings(tool="foo", services=["bar"])))  # type: ignore
        self.assertTrue(bool(models.ScanFindings(tool="foo", events=["bar"])))  # type: ignore

    def test_load_timeframes_for_aws(self):
        config = {
            "enabled": True,
            "start_time": "2025-01-01T00:00:00Z",
            "end_time": "2025-01-02T00:00:00Z",
        }
        config_model = models.LuminautConfigtoolAwsEvents.from_dict(config)
        self.assertEqual(config_model.start_time, datetime(2025, 1, 1, 0, 0, 0, 0, UTC))
        self.assertEqual(config_model.end_time, datetime(2025, 1, 2, 0, 0, 0, 0, UTC))


if __name__ == "__main__":
    unittest.main()
