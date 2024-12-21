from rich import progress

from luminaut import models
from luminaut.console import TaskProgress, console
from luminaut.scanner import Scanner

default_progress_columns = [
    *progress.Progress.get_default_columns(),
    progress.TimeElapsedColumn(),
]


class Luminaut:
    def __init__(self, config: models.LuminautConfig):
        self.config = config
        self.scanner = Scanner()
        self.task_progress = None

    def run(self):
        with progress.Progress(
            *default_progress_columns,
            transient=True,
        ) as task_progress:
            self.task_progress = task_progress
            scan_results = self.discover_public_ips()

            scan_results = self.gather_public_ip_context(scan_results)

            self.report(scan_results)

    def report(self, scan_results):
        for scan_result in scan_results:
            panel = scan_result.build_rich_panel()
            console.print(panel)

    def discover_public_ips(self) -> list[models.ScanResult]:
        scan_results = []

        if self.config.aws.enabled:
            task_description = "Enumerating AWS ENIs with public IPs"
            with TaskProgress(self.task_progress, task_description):
                scan_results = self.scanner.aws_fetch_public_enis()

        return scan_results

    def gather_public_ip_context(
        self, scan_results: list[models.ScanResult]
    ) -> list[models.ScanResult]:
        updated_scan_results = []

        for scan_result in scan_results:
            scan_result.findings += self.run_nmap(scan_result)
            scan_result = self.gather_aws_config_history(scan_result)

            updated_scan_results.append(scan_result)

        return updated_scan_results

    def run_nmap(self, scan_result: models.ScanResult) -> list[models.ScanFindings]:
        if self.config.nmap.enabled:
            task_description = f"Scanning {scan_result.ip} with nmap"
            with TaskProgress(self.task_progress, task_description):
                return self.scanner.nmap(scan_result.ip).findings
        return []

    def gather_aws_config_history(
        self, scan_result: models.ScanResult
    ) -> models.ScanResult:
        if self.config.aws.enabled is False or self.config.aws.config.enabled is False:
            return scan_result

        task_description = f"Checking AWS Config for {scan_result.eni_id}"

        with TaskProgress(self.task_progress, task_description):
            aws_config_results = self.scanner.aws_get_config_history_for_resource(
                models.ResourceType.EC2_NetworkInterface,
                scan_result.eni_id,
                scan_result.ip,
            )
            scan_result.findings.extend(aws_config_results.findings)

        for eni_resource in scan_result.get_eni_resources():
            # Scan for AWS config changes related to EC2 instances associated with an ENI
            if not eni_resource.ec2_instance_id:
                continue

            task_description = f"Checking AWS Config for {eni_resource.ec2_instance_id}"

            with TaskProgress(self.task_progress, task_description):
                aws_config_results = self.scanner.aws_get_config_history_for_resource(
                    models.ResourceType.EC2_Instance,
                    eni_resource.ec2_instance_id,
                    scan_result.ip,
                )
                scan_result.findings.extend(aws_config_results.findings)

        return scan_result
