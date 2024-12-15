import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Self

from rich.panel import Panel

IPAddress = IPv4Address | IPv6Address


@dataclass
class SecurityGroup:
    group_id: str
    group_name: str


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

    def build_rich_panel(self) -> Panel:
        rich_text = "[bold underline]AWS Elastic Network Interface[/bold underline]\n"
        rich_text += f"[orange1]{self.network_interface_id}[/orange1] in [cyan]{self.vpc_id} ({self.availability_zone})[/cyan]\n"
        if self.ec2_instance_id:
            rich_text += f"EC2: [orange1]{self.ec2_instance_id}[/orange1] attached at [none]{self.attachment_time}\n"
        if self.security_groups:
            security_group_list = ", ".join(
                [
                    f"[orange1]{sg.group_name}[/orange1] ({sg.group_id})"
                    for sg in self.security_groups
                ]
            )
            rich_text += f"Security Groups: {security_group_list}\n"
        return Panel(
            rich_text,
            title=self.public_ip,
            title_align="left",
        )


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


class Protocol(StrEnum):
    TCP = auto()
    UDP = auto()
    ICMP = auto()


@dataclass
class NmapPortServices:
    port: int
    protocol: Protocol
    name: str
    product: str
    version: str
    state: str

    def build_rich_text(self) -> str:
        return f"[green]{self.protocol}/{self.port}[/green] {self.name} {self.product} {self.version} {self.state}"


@dataclass
class ScanFindings:
    tool: str
    services: list[NmapPortServices]


@dataclass
class ScanResult:
    ip: str
    findings: list[ScanFindings]
