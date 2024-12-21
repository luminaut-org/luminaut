from dataclasses import dataclass

from rich import progress

from luminaut import models
from luminaut.console import console
from luminaut.scanner import Scanner


@dataclass
class LuminautConfig:
    pass


default_progress_columns = [
    *progress.Progress.get_default_columns(),
    progress.TimeElapsedColumn(),
]


class Luminaut:
    def __init__(self, config: LuminautConfig):
        self.config = config
        self.scanner = Scanner()
        self.task_progress = None

    def run(self):
        # Step 1: Enumerate ENIs with public IPs
        with progress.Progress(
            *default_progress_columns,
            transient=True,
        ) as task_progress:
            self.task_progress = task_progress
            task_id = self.task_progress.add_task(
                "Enumerating ENIs with public IPs", total=None
            )
            scan_results = self.scanner.aws_fetch_public_enis()
            self.task_progress.stop_task(task_id)

            scan_results = self.gather_eni_context(scan_results)

            for scan_result in scan_results:
                panel = scan_result.build_rich_panel()
                console.print(panel)

    def gather_eni_context(self, scan_results: list[models.ScanResult]):
        updated_scan_results = []
        for scan_result in scan_results:
            # Step 2: Run the various tools that depend on the IP address
            scan_result = self.run_nmap(scan_result)

            scan_result = self.gather_aws_config_history(scan_result)
            updated_scan_results.append(scan_result)

        return updated_scan_results

    def run_nmap(self, scan_result: models.ScanResult):
        task_id = self.task_progress.add_task(
            f"Scanning {scan_result.ip} with nmap", total=None
        )
        nmap_results = self.scanner.nmap(scan_result.ip)
        scan_result.findings.extend(nmap_results.findings)
        self.task_progress.stop_task(task_id)
        return scan_result

    def gather_aws_config_history(
        self, scan_result: models.ScanResult
    ) -> models.ScanResult:
        task_id = self.task_progress.add_task(
            f"Checking AWS Config for {scan_result.eni_id}",
            total=None,
        )
        aws_config_results = self.scanner.aws_get_config_history_for_resource(
            models.ResourceType.EC2_NetworkInterface,
            scan_result.eni_id,
            scan_result.ip,
        )
        scan_result.findings.extend(aws_config_results.findings)
        self.task_progress.stop_task(task_id)

        for eni_resource in scan_result.get_eni_resources():
            # Scan for AWS config changes related to EC2 instances associated with an ENI
            if not eni_resource.ec2_instance_id:
                continue

            task_id = self.task_progress.add_task(
                f"Checking AWS Config for {eni_resource.ec2_instance_id}",
                total=None,
            )
            aws_config_results = self.scanner.aws_get_config_history_for_resource(
                models.ResourceType.EC2_Instance,
                eni_resource.ec2_instance_id,
                scan_result.ip,
            )
            scan_result.findings.extend(aws_config_results.findings)
            self.task_progress.stop_task(task_id)
        return scan_result
