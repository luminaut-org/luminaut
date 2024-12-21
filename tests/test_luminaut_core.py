import unittest

from luminaut import Luminaut, LuminautConfig, models


class LuminautCore(unittest.TestCase):
    def setUp(self):
        self.config = LuminautConfig()
        self.luminaut = Luminaut(self.config)

    def test_discover_public_ips_only_runs_if_aws_enabled(self):
        self.config.aws = models.LuminautConfigToolAws(enabled=False)
        scan_results = self.luminaut.discover_public_ips()
        self.assertEqual([], scan_results)

        expected_result = models.ScanResult(ip="1.1.1.1", findings=[])
        self.luminaut.scanner.aws_fetch_public_enis = lambda: [expected_result]
        self.config.aws.enabled = True

        scan_results = self.luminaut.discover_public_ips()
        self.assertEqual(expected_result, scan_results[0])
