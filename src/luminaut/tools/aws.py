from typing import Any

import boto3

from luminaut import models


class Aws:
    def __init__(self, config: models.LuminautConfig | None = None):
        config = config if config else models.LuminautConfig()
        self.config = config
        self.ec2_client = boto3.client("ec2")
        self.config_client = boto3.client("config")

    def explore_region(self, region: str) -> list[models.ScanResult]:
        self.setup_client_region(region)

        aws_exploration_results = []
        for eni in self._fetch_enis_with_public_ips():
            findings = []
            eni_finding = models.ScanFindings(
                tool="AWS Elastic Network Interfaces",
                emoji_name="cloud",
                resources=[eni],
            )
            findings.append(eni_finding)

            findings.append(self.explore_security_groups(eni.security_groups))

            if self.config.aws.config.enabled:
                findings.append(self.explore_config_history(eni))

            eni_exploration = models.ScanResult(
                ip=eni.public_ip,
                region=region,
                eni_id=eni.network_interface_id,
                findings=findings,
            )
            aws_exploration_results.append(eni_exploration)

        return aws_exploration_results

    def explore_security_groups(
        self, security_groups: list[models.SecurityGroup]
    ) -> models.ScanFindings:
        sg_finding = models.ScanFindings(
            tool="AWS Security Groups",
            emoji_name="lock",
        )
        for security_group in security_groups:
            security_group = self.populate_permissive_ingress_security_group_rules(
                security_group
            )
            sg_finding.resources.append(security_group)

        return sg_finding

    def explore_config_history(self, eni: models.AwsEni) -> models.ScanFindings:
        resource_history = self.get_config_history_for_resource(
            models.ResourceType.EC2_NetworkInterface, eni.network_interface_id
        )
        if eni.ec2_instance_id:
            ec2_instance_history = self.get_config_history_for_resource(
                models.ResourceType.EC2_Instance, eni.ec2_instance_id
            )
            resource_history += ec2_instance_history

        return models.ScanFindings(
            tool="AWS Config",
            emoji_name="gear",
            resources=resource_history,
        )

    def setup_client_region(self, region: str) -> None:
        self.ec2_client = boto3.client("ec2", region_name=region)
        self.config_client = boto3.client("config", region_name=region)

    def fetch_enis_with_public_ips(self) -> list[models.ScanResult]:
        scans = []
        for eni in self._fetch_enis_with_public_ips():
            finding = models.ScanFindings(
                tool="AWS Elastic Network Interfaces",
                emoji_name="cloud",
                resources=[eni],
            )
            scan = models.ScanResult(
                ip=eni.public_ip,
                eni_id=eni.network_interface_id,
                findings=[finding],
            )
            scans.append(scan)
        return scans

    def _fetch_enis_with_public_ips(self) -> list[models.AwsEni]:
        paginator = self.ec2_client.get_paginator("describe_network_interfaces")
        results = paginator.paginate(
            Filters=[
                {
                    "Name": "association.public-ip",
                    "Values": ["*"],
                },
            ],
        )
        scan_results = []

        for enis in results:
            for eni in enis["NetworkInterfaces"]:
                eni_model = self._build_eni_scan_finding(eni)
                scan_results.append(eni_model)
        return scan_results

    @staticmethod
    def _build_eni_scan_finding(eni: dict[str, Any]) -> models.AwsEni:
        association = eni.get("Association", {})
        public_ip = association.get("PublicIp")
        attachment = eni.get("Attachment", {})
        security_groups = [
            models.SecurityGroup(x["GroupId"], x["GroupName"])
            for x in eni.get("Groups", [])
        ]

        return models.AwsEni(
            network_interface_id=eni["NetworkInterfaceId"],
            public_ip=public_ip,
            private_ip=eni["PrivateIpAddress"],
            ec2_instance_id=attachment.get("InstanceId"),
            public_dns_name=association.get("PublicDnsName"),
            private_dns_name=eni.get("PrivateDnsName"),
            attachment_id=attachment.get("AttachmentId"),
            attachment_time=attachment.get("AttachTime"),
            attachment_status=attachment.get("Status"),
            availability_zone=eni["AvailabilityZone"],
            security_groups=security_groups,
            status=eni["Status"],
            vpc_id=eni["VpcId"],
        )

    def get_config_history_for_resource(
        self,
        resource_type: models.ResourceType,
        resource_id: str,
    ) -> list[models.AwsConfigItem]:
        pagination_client = self.config_client.get_paginator(
            "get_resource_config_history"
        )
        pages = pagination_client.paginate(
            resourceType=str(resource_type),
            resourceId=resource_id,
        )

        resources = []
        for page in pages:
            for config_item in page.get("configurationItems", []):
                resources.append(models.AwsConfigItem.from_aws_config(config_item))

        return resources

    def populate_permissive_ingress_security_group_rules(
        self, security_group: models.SecurityGroup
    ) -> models.SecurityGroup:
        aws_client = self.ec2_client.get_paginator("describe_security_group_rules")

        paginator = aws_client.paginate(
            Filters=[{"Name": "group-id", "Values": [security_group.group_id]}]
        )

        for page in paginator:
            for rule in page["SecurityGroupRules"]:
                sg_rule = models.SecurityGroupRule.from_describe_rule(rule)
                if (
                    sg_rule.direction == models.Direction.INGRESS
                    and sg_rule.is_permissive()
                ):
                    security_group.rules.append(sg_rule)

        return security_group
