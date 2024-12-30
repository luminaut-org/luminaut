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
            scan_result.findings.append(self.gather_security_group_rules(scan_result))
            scan_result.findings += self.run_nmap(scan_result)
            scan_result.findings += self.query_shodan(scan_result)
            scan_result.findings += self.run_whatweb(scan_result)
            scan_result.findings.append(self.gather_aws_config_history(scan_result))

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

    def gather_aws_config_history(
        self, scan_result: models.ScanResult
    ) -> models.ScanFindings:
        findings = models.ScanFindings(tool="AWS Config", resources=[])
        if self.config.aws.enabled is False or self.config.aws.config.enabled is False:
            return findings

        task_description = f"Checking AWS Config for {scan_result.eni_id}"

        with TaskProgress(self.task_progress, task_description):
            aws_config_results = self.scanner.aws_get_config_history_for_resource(
                models.ResourceType.EC2_NetworkInterface,
                scan_result.eni_id,
            )
            findings.resources.extend(aws_config_results)

        for eni_resource in scan_result.get_eni_resources():
            # Scan for AWS config changes related to EC2 instances associated with an ENI
            if not eni_resource.ec2_instance_id:
                continue

            task_description = f"Checking AWS Config for {eni_resource.ec2_instance_id}"

            with TaskProgress(self.task_progress, task_description):
                aws_config_results = self.scanner.aws_get_config_history_for_resource(
                    models.ResourceType.EC2_Instance,
                    eni_resource.ec2_instance_id,
                )
                findings.resources.extend(aws_config_results)

        return findings

    def gather_security_group_rules(
        self, scan_result: models.ScanResult
    ) -> models.ScanFindings | None:
        if not self.config.aws.enabled:
            return None

        security_group_findings = []
        for eni_resource in scan_result.get_eni_resources():
            if not eni_resource.security_groups:
                continue

            task_description = (
                f"Checking security group rules for {eni_resource.network_interface_id}"
            )

            with TaskProgress(
                self.task_progress,
                task_description,
                total=len(eni_resource.security_groups),
            ):
                for security_group in eni_resource.security_groups:
                    security_group = self.scanner.aws_populate_permissive_ingress_security_group_rules(
                        security_group
                    )

                    if security_group.rules:
                        security_group_findings.append(security_group)

        return models.ScanFindings(
            tool="AWS Security Groups",
            emoji_name="lock",
            resources=security_group_findings,
        )
