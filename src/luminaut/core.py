import logging
import sys

from luminaut import models
from luminaut.report import (
    console,
    write_csv_timeline,
    write_html_report,
    write_jsonl_report,
)
from luminaut.scanner import Scanner

logger = logging.getLogger(__name__)


class Luminaut:
    def __init__(self, config: models.LuminautConfig | None = None):
        self.config = config if config else models.LuminautConfig()
        self.scanner = Scanner(config=self.config)

    def run(self):
        scan_results = self.discover_public_ips()
        scan_results = self.gather_public_ip_context(scan_results)
        self.report(scan_results)

    def report(self, scan_results: list[models.ScanResult]) -> None:
        if self.config.report.json:
            if self.config.report.json_file:
                with self.config.report.json_file.open("w") as target:
                    write_jsonl_report(scan_results, target)
                logger.info("Saved scan results to %s", self.config.report.json_file)
            else:
                write_jsonl_report(scan_results, sys.stdout)

        if self.config.report.timeline and self.config.report.timeline_file:
            with self.config.report.timeline_file.open(
                "w", encoding="utf-8", newline=""
            ) as target:
                write_csv_timeline(scan_results, target)
            logger.info("Saved timeline to %s", self.config.report.timeline_file)

        if self.config.report.console:
            for scan_result in scan_results:
                title, text = scan_result.build_rich_panel()
                console.rule(title, align="left")
                console.print(text)

        if self.config.report.html and self.config.report.html_file:
            write_html_report(self.config.report.html_file)

    def discover_public_ips(self) -> list[models.ScanResult]:
        return self.scanner.aws()

    def gather_public_ip_context(
        self, scan_results: list[models.ScanResult]
    ) -> list[models.ScanResult]:
        updated_scan_results = []

        for scan_result in scan_results:
            scan_result.findings += self.run_nmap(scan_result)
            scan_result.findings += self.query_shodan(scan_result)
            scan_result.findings += self.run_whatweb(scan_result)

            updated_scan_results.append(scan_result)

        return updated_scan_results

    def run_nmap(self, scan_result: models.ScanResult) -> list[models.ScanFindings]:
        if self.config.nmap.enabled:
            return self.scanner.nmap(scan_result.ip).findings
        return []

    def query_shodan(self, scan_result: models.ScanResult) -> list[models.ScanFindings]:
        if self.config.shodan.enabled:
            return [self.scanner.shodan(scan_result.ip)]
        return []

    def run_whatweb(self, scan_result: models.ScanResult) -> list[models.ScanFindings]:
        if self.config.whatweb.enabled:
            targets = scan_result.generate_ip_port_targets()
            if targets and (whatweb_findings := self.scanner.whatweb(targets)):
                return [whatweb_findings]
        return []
