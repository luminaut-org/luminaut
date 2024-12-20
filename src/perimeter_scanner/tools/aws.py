import boto3
from rich.emoji import Emoji

from perimeter_scanner import models


class Aws:
    def __init__(self):
        self.ec2_client = boto3.client("ec2")
        self.aws_client = boto3.client("config")

    def fetch_enis_with_public_ips(self) -> list[models.ScanResult]:
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
                attachment = eni.get("Attachment", {})
                association = eni.get("Association", {})
                security_groups = [
                    models.SecurityGroup(x["GroupId"], x["GroupName"])
                    for x in eni.get("Groups", [])
                ]
                public_ip = association.get("PublicIp")

                scan_results.append(
                    models.ScanResult(
                        ip=public_ip,
                        eni_id=eni["NetworkInterfaceId"],
                        findings=[
                            models.ScanFindings(
                                tool="AWS Elastic Network Interfaces",
                                emoji=Emoji("cloud"),
                                resources=[
                                    models.AwsEni(
                                        network_interface_id=eni["NetworkInterfaceId"],
                                        public_ip=public_ip,
                                        private_ip=eni["PrivateIpAddress"],
                                        ec2_instance_id=attachment.get("InstanceId"),
                                        public_dns_name=association.get(
                                            "PublicDnsName"
                                        ),
                                        private_dns_name=eni.get("PrivateDnsName"),
                                        attachment_id=attachment.get("AttachmentId"),
                                        attachment_time=attachment.get("AttachTime"),
                                        attachment_status=attachment.get("Status"),
                                        availability_zone=eni["AvailabilityZone"],
                                        security_groups=security_groups,
                                        status=eni["Status"],
                                        vpc_id=eni["VpcId"],
                                    )
                                ],
                            )
                        ],
                    )
                )

        return scan_results

    def get_config_history_for_resource(
        self,
        resource_type: models.ResourceType,
        resource_id: str,
        ip: models.IPAddress,
    ) -> models.ScanResult:
        pagination_client = self.aws_client.get_paginator("get_resource_config_history")
        pages = pagination_client.paginate(
            resourceType=str(resource_type),
            resourceId=resource_id,
        )

        resources = []
        for page in pages:
            for config_item in page.get("configurationItems", []):
                resources.append(models.ConfigItem.from_aws_config(config_item))

        scan_result = models.ScanResult(
            ip=ip,
            eni_id=resource_id,
            findings=[
                models.ScanFindings(
                    tool="AWS Config",
                    emoji=Emoji("cloud"),
                    resources=resources,
                )
            ],
        )

        return scan_result
