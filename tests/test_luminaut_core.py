import unittest

from luminaut import Luminaut, LuminautConfig, models


class LuminautCore(unittest.TestCase):
    def test_discover_public_ips_only_runs_if_aws_enabled(self):
        config = LuminautConfig(aws=models.LuminautConfigToolAws(enabled=False))
        luminaut = Luminaut(config)
        scan_results = luminaut.discover_public_ips()
        self.assertEqual([], scan_results)

        expected_result = models.ScanResult(ip="1.1.1.1", findings=[])
        luminaut.scanner.aws_fetch_public_enis = lambda: [expected_result]
        config.aws.enabled = True
        scan_results = luminaut.discover_public_ips()
        self.assertEqual(expected_result, scan_results[0])
