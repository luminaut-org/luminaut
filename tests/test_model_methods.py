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
            "start_time": datetime(2025, 1, 1, 0, 0, 0, 0, UTC),
            "end_time": datetime(2025, 1, 2, 0, 0, 0, 0, UTC),
        }
        config_model = models.LuminautConfigtoolAwsEvents.from_dict(config)
        self.assertIsInstance(config_model.start_time, datetime)
        self.assertIsInstance(config_model.end_time, datetime)


if __name__ == "__main__":
    unittest.main()
