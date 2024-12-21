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

    def test_nmap_only_runs_if_enabled(self):
        self.config.nmap = models.LuminautConfigTool(enabled=False)
        empty_scan_results = models.ScanResult(ip="10.0.0.1", findings=[])
        scan_findings = [models.ScanFindings(tool="unittest")]
        self.luminaut.scanner.nmap = lambda ip: models.ScanResult(
            ip="10.0.0.1", findings=scan_findings
        )

        nmap_findings = self.luminaut.run_nmap(empty_scan_results)

        self.assertEqual([], nmap_findings)

        self.config.nmap.enabled = True

        nmap_findings = self.luminaut.run_nmap(empty_scan_results)
        self.assertEqual(scan_findings, nmap_findings)

    def test_aws_config_only_runs_if_enabled(self):
        self.luminaut.scanner.aws_get_config_history_for_resource = (
            lambda *args: models.ScanResult(
                ip="10.0.0.1",
                findings=[models.ScanFindings(tool="unittest")],
            )
        )

        self.config.aws = models.LuminautConfigToolAws(enabled=False)
        self.config.aws.config = models.LuminautConfigTool(enabled=True)

        scan_result = self.luminaut.gather_aws_config_history(
            models.ScanResult(ip="10.0.0.1", findings=[])
        )

        self.assertEqual([], scan_result.findings)
