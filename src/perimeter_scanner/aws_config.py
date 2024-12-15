import argparse
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from pprint import pprint
from typing import Any, Self

import boto3

from perimeter_scanner import models

IPAddress = IPv4Address | IPv6Address


class ResourceType(StrEnum):
    EC2_Instance = "AWS::EC2::Instance"
    EC2_NetworkInterface = "AWS::EC2::NetworkInterface"


@dataclass
class NetworkInterface:
    network_interface_id: str
    association_public_ip: IPAddress
    association_public_dns_name: str
    association_ip_owner_id: str
    attachment_time: datetime
    attachment_id: str
    attachment_status: str
    description: str
    security_groups: list[models.SecurityGroup | dict[str, Any]]
    interface_type: str
    private_dns_name: str
    private_ip_address: IPAddress
    status: str
    subnet_id: str
    vpc_id: str


@dataclass
class Ec2Configuration:
    instance_id: str
    image_id: str
    launch_time: datetime
    tags: dict[str, str]
    platform_details: str
    private_dns_name: str
    private_ip_address: IPAddress
    public_dns_name: str
    public_ip_address: IPAddress
    network_interfaces: list[NetworkInterface | dict[str, Any]]
    security_groups: list[models.SecurityGroup | dict[str, Any]]
    state: dict[str, Any]
    state_reason: str
    usage_operation: str
    usage_operation_update_time: datetime
    subnet_id: str
    vpc_id: str

    @classmethod
    def from_aws_config(cls, configuration: dict[str, Any]) -> Self:
        return cls(
            instance_id=configuration["instanceId"],
            image_id=configuration["imageId"],
            launch_time=datetime.fromisoformat(configuration["launchTime"]),
            tags=configuration["tags"],
            platform_details=configuration["platformDetails"],
            private_dns_name=configuration["privateDnsName"],
            private_ip_address=ip_address(configuration["privateIpAddress"]),
            public_dns_name=configuration["publicDnsName"],
            public_ip_address=ip_address(configuration["publicIpAddress"]),
            network_interfaces=configuration["networkInterfaces"],
            security_groups=configuration["securityGroups"],
            state=configuration["state"],
            state_reason=configuration["stateReason"],
            usage_operation=configuration["usageOperation"],
            usage_operation_update_time=datetime.fromisoformat(
                configuration["usageOperationUpdateTime"]
            ),
            subnet_id=configuration["subnetId"],
            vpc_id=configuration["vpcId"],
        )


@dataclass
class ConfigItem:
    resource_type: ResourceType
    resource_id: str
    resource_creation_time: datetime
    account: str
    region: str
    arn: str
    config_capture_time: datetime
    config_status: str
    configuration: Ec2Configuration | str
    tags: dict[str, str]

    @staticmethod
    def build_configuration(
        resource_type: ResourceType,
        configuration: str,
    ) -> Ec2Configuration | str:
        try:
            configuration = json.loads(configuration)
        except json.JSONDecodeError:
            return configuration

        if resource_type == ResourceType.EC2_Instance:
            return Ec2Configuration.from_aws_config(configuration)
        return configuration

    @classmethod
    def from_aws_config(cls, aws_config: Mapping[str, Any]) -> Self:
        config_resource_type = ResourceType(aws_config["resourceType"])

        return cls(
            resource_type=config_resource_type,
            resource_id=aws_config["resourceId"],
            resource_creation_time=aws_config["resourceCreationTime"],
            account=aws_config["accountId"],
            region=aws_config["awsRegion"],
            arn=aws_config["arn"],
            config_capture_time=aws_config["configurationItemCaptureTime"],
            config_status=aws_config["configurationItemStatus"],
            configuration=cls.build_configuration(
                config_resource_type,
                aws_config["configuration"],
            ),
            tags=aws_config["tags"],
        )


class AwsConfig:
    def __init__(self):
        self.aws_client = boto3.client("config")

    def get_config_history_for_resource(
        self,
        resource_type: ResourceType,
        resource_id: str,
    ) -> ConfigItem | None:
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
                yield ConfigItem.from_aws_config(config_item)


if __name__ == "__main__":
    cli_args = argparse.ArgumentParser()
    cli_args.add_argument(
        "RESOURCE_TYPE",
        type=ResourceType,
        choices=list(ResourceType),
    )
    cli_args.add_argument(
        "RESOURCE_ID",
        type=str,
    )
    args = cli_args.parse_args()

    aws_config = AwsConfig()
    config_history = config_item = aws_config.get_config_history_for_resource(
        args.RESOURCE_TYPE,
        args.RESOURCE_ID,
    )
    for config_item in config_history:
        pprint(config_item)
