from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import boto3

from perimeter_scanner import models


class ENI:
    def __init__(self):
        self.ec2_client = boto3.client("ec2")

    def fetch_enis_with_public_ips(self) -> list[models.AwsEni]:
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
                    models.SecurityGroup(x["GroupId"], x["GroupName"])
                    for x in eni.get("Groups", [])
                ]
                yield models.AwsEni(
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


class AwsConfig:
    def __init__(self):
        self.aws_client = boto3.client("config")

    def get_config_history_for_resource(
        self,
        resource_type: models.ResourceType,
        resource_id: str,
    ) -> models.ConfigItem | None:
        pagination_client = self.aws_client.get_paginator("get_resource_config_history")
        pages = pagination_client.paginate(
            resourceType=str(resource_type),
            resourceId=resource_id,
        )

        for page in pages:
            # get the first item, if any
            config_items = page.get("configurationItems")
            if not config_items or len(config_items) == 0:
                return None

            for config_item in config_items:
                yield models.ConfigItem.from_aws_config(config_item)


@dataclass
class QueryResult:
    source: str
    data: list[models.AwsEni | dict[str, Any]]


class Query(ABC):
    @abstractmethod
    def run(self, **kwargs) -> QueryResult:
        pass


class QueryPublicAwsEni(Query):
    def __init__(self):
        self.eni = ENI()

    def run(self, **kwargs) -> QueryResult:
        data = []
        for eni in self.eni.fetch_enis_with_public_ips():
            data.append(eni)
        return QueryResult(source="Public AWS ENI", data=data)
