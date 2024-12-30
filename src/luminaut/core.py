import logging
import sys

from rich import progress

from luminaut import models
from luminaut.report import TaskProgress, console, write_jsonl_report
from luminaut.scanner import Scanner

logger = logging.getLogger(__name__)
default_progress_columns = [
    progress.TextColumn("{task.description}"),
    progress.SpinnerColumn(),
    progress.TimeElapsedColumn(),
]


class Luminaut:
    def __init__(self, config: models.LuminautConfig | None = None):
        self.config = config if config else models.LuminautConfig()
        self.scanner = Scanner(config=self.config)
        self.task_progress = None

    def run(self):
        with progress.Progress(
            *default_progress_columns, transient=True
        ) as task_progress:
            self.task_progress = task_progress
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

        if self.config.report.console:
            for scan_result in scan_results:
                panel = scan_result.build_rich_panel()
                console.print(panel)

    def discover_public_ips(self) -> list[models.ScanResult]:
        task_description = "Enumerating AWS ENIs with public IPs"
        with TaskProgress(self.task_progress, task_description):
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
            task_description = f"Scanning {scan_result.ip} with nmap"
            with TaskProgress(self.task_progress, task_description):
                return self.scanner.nmap(scan_result.ip).findings
        return []

    def query_shodan(self, scan_result: models.ScanResult) -> list[models.ScanFindings]:
        if self.config.shodan.enabled:
            task_description = f"Querying Shodan for {scan_result.ip}"
            with TaskProgress(self.task_progress, task_description):
                return [self.scanner.shodan(scan_result.ip)]
        return []

    def run_whatweb(self, scan_result: models.ScanResult) -> list[models.ScanFindings]:
        if self.config.whatweb.enabled:
            task_description = f"Running Whatweb for {scan_result.ip}"
            with TaskProgress(self.task_progress, task_description):
                targets = scan_result.generate_ip_port_targets()
                if targets and (whatweb_findings := self.scanner.whatweb(targets)):
                    return [whatweb_findings]

        return []
