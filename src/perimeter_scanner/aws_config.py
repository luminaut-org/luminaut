import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

import boto3

IPAddress = IPv4Address | IPv6Address


class ResourceType(StrEnum):
    EC2_Instance = "AWS::EC2::Instance"
    EC2_NetworkInterface = "AWS::EC2::NetworkInterface"


@dataclass
class SecurityGroup:
    group_id: str
    group_name: str


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
    security_groups: list[SecurityGroup | dict[str, Any]]
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
    security_groups: list[SecurityGroup | dict[str, Any]]
    state: dict[str, Any]
    state_reason: str
    usage_operation: str
    usage_operation_update_time: datetime
    subnet_id: str
    vpc_id: str


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


class AwsConfig:
    def __init__(self):
        self.aws_client = boto3.client("config")

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
            return Ec2Configuration(
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
        return configuration

    def get_current_config_for_resource(
        self,
        resource_type: ResourceType,
        resource_id: str,
    ) -> ConfigItem | None:
        resp = self.aws_client.get_resource_config_history(
            resourceType=str(resource_type),
            resourceId=resource_id,
        )

        # get the first item, if any
        config_items = resp.get("configurationItems")
        if not config_items or len(config_items) == 0:
            return None

        config_item = config_items[0]

        config_resource_type = ResourceType(config_item["resourceType"])
        return ConfigItem(
            resource_type=config_resource_type,
            resource_id=config_item["resourceId"],
            resource_creation_time=config_item["resourceCreationTime"],
            account=config_item["accountId"],
            region=config_item["awsRegion"],
            arn=config_item["arn"],
            config_capture_time=config_item["configurationItemCaptureTime"],
            config_status=config_item["configurationItemStatus"],
            configuration=self.build_configuration(
                config_resource_type,
                config_item["configuration"],
            ),
            tags=config_item["tags"],
        )
