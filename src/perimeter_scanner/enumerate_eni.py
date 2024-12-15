from dataclasses import dataclass
from datetime import datetime

import boto3

from perimeter_scanner.aws_config import SecurityGroup


@dataclass
class AwsEni:
    network_interface_id: str
    public_ip: str
    private_ip: str
    attachment_id: str
    attachment_time: datetime
    attachment_status: str
    availability_zone: str
    security_groups: list[SecurityGroup]
    status: str
    vpc_id: str
    ec2_instance_id: str | None = None
    public_dns_name: str | None = None
    private_dns_name: str | None = None


class ENI:
    def __init__(self):
        self.ec2_client = boto3.client("ec2")

    def fetch_enis_with_public_ips(self) -> list[AwsEni]:
        paginator = self.ec2_client.get_paginator("describe_network_interfaces")
        results = paginator.paginate(
            Filters=[
                {
                    "Name": "association.public-ip",
                    "Values": ["*"],
                },
            ],
        )
        for enis in results:
            for eni in enis["NetworkInterfaces"]:
                attachment = eni.get("Attachment", {})
                association = eni.get("Association", {})
                security_groups = [
                    SecurityGroup(x["GroupId"], x["GroupName"])
                    for x in eni.get("Groups", [])
                ]
                yield AwsEni(
                    network_interface_id=eni["NetworkInterfaceId"],
                    public_ip=association.get("PublicIp"),
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
