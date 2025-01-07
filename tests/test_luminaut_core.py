import unittest
from unittest.mock import Mock, patch

from luminaut import Luminaut, LuminautConfig, models


class LuminautCore(unittest.TestCase):
    def setUp(self):
        self.config = LuminautConfig()

        # Disable during unittests
        self.config.report.console = False

        self.luminaut = Luminaut(self.config)

    @patch("luminaut.core.console")
    def test_report_to_console_only_if_enabled(self, mock_console: Mock):
        self.config.report.console = True
        self.luminaut.report([models.ScanResult(ip="10.0.0.1", findings=[])])
        mock_console.print.assert_called_once()

        mock_console.print.reset_mock()

        self.config.report.console = False
        self.luminaut.report([models.ScanResult(ip="10.0.0.1", findings=[])])
        mock_console.print.assert_not_called()

    @patch("luminaut.core.write_jsonl_report")
    def test_report_to_jsonl_only_if_enabled(self, mock_write_jsonl_report: Mock):
        self.config.report.json = True
        self.luminaut.report([models.ScanResult(ip="10.0.0.1", findings=[])])
        mock_write_jsonl_report.assert_called_once()

        mock_write_jsonl_report.reset_mock()

        self.config.report.json = False
        self.luminaut.report([models.ScanResult(ip="10.0.0.1", findings=[])])
        mock_write_jsonl_report.assert_not_called()

    def test_discover_public_ips_only_runs_if_aws_enabled(self):
        self.config.aws.enabled = False
        scan_results = self.luminaut.discover_public_ips()
        self.assertEqual([], scan_results)

        expected_result = models.ScanResult(ip="10.1.1.1", findings=[])
        self.luminaut.scanner.aws = lambda: [expected_result]
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
