from dataclasses import dataclass

from rich import progress

from perimeter_scanner import models
from perimeter_scanner.console import console
from perimeter_scanner.scanner import Scanner


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

    def run(self):
        scanner = Scanner()
        # Step 1: Enumerate ENIs with public IPs
        with progress.Progress(
            *default_progress_columns,
            transient=True,
        ) as task_progress:
            task_progress.add_task("Enumerating ENIs with public IPs", total=None)
            scan_results = scanner.aws_fetch_public_enis()

        for scan_result in scan_results:
            # Step 2: Run the various tools that depend on the IP address
            with progress.Progress(
                *default_progress_columns,
                transient=True,
            ) as task_progress:
                task_progress.add_task(
                    f"Scanning {scan_result.ip} with nmap", total=None
                )
                nmap_results = scanner.nmap(scan_result.ip)
                scan_result.findings.extend(nmap_results.findings)

            with progress.Progress(
                *default_progress_columns,
                transient=True,
            ) as task_progress:
                task = task_progress.add_task(
                    f"Checking AWS Config for {scan_result.eni_id}",
                    total=None,
                )
                aws_config_results = scanner.aws_get_config_history_for_resource(
                    models.ResourceType.EC2_NetworkInterface,
                    scan_result.eni_id,
                    scan_result.ip,
                )
                scan_result.findings.extend(aws_config_results.findings)
                task_progress.stop_task(task)

                for eni_resource in scan_result.get_eni_resources():
                    # Scan for AWS config changes related to EC2 instances associated with an ENI
                    if not eni_resource.ec2_instance_id:
                        continue

                    task_progress.add_task(
                        f"Checking AWS Config for {eni_resource.ec2_instance_id}",
                        total=None,
                    )
                    aws_config_results = scanner.aws_get_config_history_for_resource(
                        models.ResourceType.EC2_Instance,
                        eni_resource.ec2_instance_id,
                        scan_result.ip,
                    )
                    scan_result.findings.extend(aws_config_results.findings)

            panel = scan_result.build_rich_panel()
            console.print(panel)
