import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, BinaryIO, Self

from rich.emoji import Emoji
from rich.panel import Panel

IPAddress = IPv4Address | IPv6Address
QUAD_ZERO_ADDRESSES = (IPv4Address("0.0.0.0"), IPv6Address("::"))


@dataclass
class LuminautConfigTool:
    enabled: bool = True
    timeout: int | None = None

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> Self:
        return cls(
            enabled=config.get("enabled", True),
            timeout=config.get("timeout"),
        )


@dataclass
class LuminautConfigToolShodan(LuminautConfigTool):
    api_key: str | None = None

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> Self:
        shodan_config = super().from_dict(config)
        shodan_config.api_key = config.get("api_key")
        return shodan_config


@dataclass
class LuminautConfigToolAws(LuminautConfigTool):
    aws_profile: str | None = None
    aws_regions: list[str] | None = None
    config: LuminautConfigTool = field(
        default_factory=lambda: LuminautConfigTool(enabled=True)
    )

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> Self:
        aws_config = super().from_dict(config)

        aws_config.aws_profile = config.get("aws_profile")
        aws_config.aws_regions = config.get("aws_regions")
        aws_config.config = LuminautConfigTool.from_dict(config.get("config", {}))

        return aws_config


@dataclass
class LuminautConfigReport:
    console: bool = True
    json: bool = False


@dataclass
class LuminautConfig:
    report: LuminautConfigReport = field(default_factory=LuminautConfigReport)
    aws: LuminautConfigToolAws = field(default_factory=LuminautConfigToolAws)
    nmap: LuminautConfigTool = field(default_factory=LuminautConfigTool)
    shodan: LuminautConfigToolShodan = field(default_factory=LuminautConfigToolShodan)

    @classmethod
    def from_toml(cls, toml_file: BinaryIO) -> Self:
        toml_data = tomllib.load(toml_file)

        luminaut_config = cls(
            report=LuminautConfigReport(**toml_data.get("report", {}))
        )

        if tool_config := toml_data.get("tool"):
            luminaut_config.aws = LuminautConfigToolAws.from_dict(
                tool_config.get("aws", {})
            )
            luminaut_config.nmap = LuminautConfigTool.from_dict(
                tool_config.get("nmap", {})
            )
            luminaut_config.shodan = LuminautConfigToolShodan.from_dict(
                tool_config.get("shodan", {})
            )
        return luminaut_config


class Direction(StrEnum):
    INGRESS = auto()
    EGRESS = auto()


class SecurityGroupRuleTargetType(StrEnum):
    CIDR = auto()
    SECURITY_GROUP = auto()
    PREFIX_LIST = auto()


@dataclass
class SecurityGroupRule:
    direction: Direction
    protocol: "Protocol"
    from_port: int
    to_port: int
    rule_id: str
    description: str | None = None
    # Target is a CIDR block or a security group ID
    target: str | None = None
    target_type: SecurityGroupRuleTargetType | None = None

    def build_rich_text(self) -> str:
        return f"  [green]{self.target}[/green] {self.direction} [blue]{self.from_port}[/blue] to [blue]{self.to_port}[/blue] [magenta]{self.protocol}[/magenta] ({self.rule_id}: {self.description})\n"

    def is_permissive(self) -> bool:
        if self.target_type == SecurityGroupRuleTargetType.CIDR:
            ip = ip_address(self.target.split("/")[0])
            return ip.is_global or ip in QUAD_ZERO_ADDRESSES

        # Prefix lists, security groups, and non-global IPs are
        # not considered permissive in the context of the individual rule.
        # Prefix lists and security group targets require further
        # inspection for overall service permissiveness in the context
        # of the environment.
        return False

    @classmethod
    def from_describe_rule(cls, rule: dict[str, Any]) -> Self:
        # Parse the result from calling boto3.ec2.client.describe_security_group_rules

        if pl_id := rule.get("PrefixListId"):
            target = pl_id
            target_type = SecurityGroupRuleTargetType.PREFIX_LIST
        elif target_group_id := rule.get("ReferencedGroupInfo", {}).get("GroupId"):
            target = target_group_id
            target_type = SecurityGroupRuleTargetType.SECURITY_GROUP
        elif ip_range := (rule.get("CidrIpv4") or rule.get("CidrIpv6")):
            target = ip_range
            target_type = SecurityGroupRuleTargetType.CIDR
        else:
            raise NotImplementedError(
                f"Unknown target type for rule: {rule.get('SecurityGroupRuleId')}"
            )

        return cls(
            direction=Direction.EGRESS if rule["IsEgress"] else Direction.INGRESS,
            protocol=Protocol(rule["IpProtocol"]),
            from_port=rule["FromPort"],
            to_port=rule["ToPort"],
            rule_id=rule["SecurityGroupRuleId"],
            description=rule.get("Description"),
            target=target,
            target_type=target_type,
        )


@dataclass
class SecurityGroup:
    group_id: str
    group_name: str
    rules: list[SecurityGroupRule] = field(default_factory=list)

    def build_rich_text(self):
        rich_text = f"[orange1]{self.group_name}[/orange1] ({self.group_id})\n"
        for rule in self.rules:
            if hasattr(rule, "build_rich_text"):
                rich_text += rule.build_rich_text()
        return rich_text


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

    def build_rich_text(self) -> str:
        rich_text = f"[orange1]{self.network_interface_id}[/orange1] in [cyan]{self.vpc_id} ({self.availability_zone})[/cyan]\n"
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
        return rich_text


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
class Ec2InstanceStateReason:
    # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_StateReason.html
    code: int | None = None
    message: str | None = None

    def __bool__(self) -> bool:
        return isinstance(self.message, str) and len(self.message) > 0

    @classmethod
    def from_aws_config(cls, state: dict[str, Any]) -> Self:
        if not state:
            return cls()
        return cls(
            code=state.get("code"),
            message=state.get("message"),
        )


@dataclass
class Ec2InstanceState:
    # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceState.html
    code: int | None = None
    name: str | None = None

    def __bool__(self) -> bool:
        return isinstance(self.name, str) and len(self.name) > 0

    @classmethod
    def from_aws_config(cls, state: dict[str, Any]) -> Self:
        if not state:
            return cls()
        return cls(
            code=state.get("code"),
            name=state.get("name"),
        )


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
    network_interfaces: list[NetworkInterface | dict[str, Any]]
    security_groups: list[SecurityGroup | dict[str, Any]]
    state: Ec2InstanceState | None
    state_reason: Ec2InstanceStateReason | None
    usage_operation: str
    usage_operation_update_time: datetime
    subnet_id: str
    vpc_id: str
    public_ip_address: IPAddress | None = None

    @classmethod
    def from_aws_config(cls, configuration: dict[str, Any]) -> Self:
        public_ip_address = (
            ip_address(configuration["publicIpAddress"])
            if configuration.get("publicIpAddress")
            else None
        )
        return cls(
            instance_id=configuration["instanceId"],
            image_id=configuration["imageId"],
            launch_time=datetime.fromisoformat(configuration["launchTime"]),
            tags=configuration["tags"],
            platform_details=configuration["platformDetails"],
            private_dns_name=configuration["privateDnsName"],
            private_ip_address=ip_address(configuration["privateIpAddress"]),
            public_dns_name=configuration["publicDnsName"],
            public_ip_address=public_ip_address,
            network_interfaces=configuration["networkInterfaces"],
            security_groups=configuration["securityGroups"],
            state=Ec2InstanceState.from_aws_config(configuration["state"]),
            state_reason=Ec2InstanceStateReason.from_aws_config(
                configuration["stateReason"]
            ),
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
    account: str
    region: str
    arn: str
    config_capture_time: datetime
    config_status: str
    configuration: Ec2Configuration | str
    tags: dict[str, str]
    resource_creation_time: datetime | None = None

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
            resource_creation_time=aws_config.get("resourceCreationTime"),
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
    ICMPv6 = auto()
    ALL = "-1"


@dataclass
class NmapPortServices:
    port: int
    protocol: Protocol
    name: str
    product: str
    version: str
    state: str

    def build_rich_text(self) -> str:
        return f"[green]{self.protocol}/{self.port}[/green] Status: {self.state} Service: {self.name} {self.product} {self.version}\n"


@dataclass
class ScanFindings:
    tool: str
    services: list[NmapPortServices] = field(default_factory=list)
    resources: list[AwsEni | ConfigItem | SecurityGroup] = field(default_factory=list)
    emoji_name: str | None = "mag"

    def build_rich_text(self) -> str:
        rich_title = f"[bold underline]{Emoji(self.emoji_name) if self.emoji_name else ''} {self.tool}[/bold underline]\n"
        rich_text = ""
        other_resources = 0
        for resource in self.resources:
            if hasattr(resource, "build_rich_text"):
                rich_text += resource.build_rich_text()
            else:
                other_resources += 1

        if other_resources:
            rich_text += f"  {other_resources} additional resources discovered."

        other_services = 0
        for service in self.services:
            if hasattr(service, "build_rich_text"):
                rich_text += service.build_rich_text()
            else:
                other_services += 1

        if other_services:
            rich_text += f"  {other_services} additional services discovered."

        if rich_text:
            return rich_title + rich_text

        return (
            rich_title
            + "No findings to report to the console. See JSON report for full details."
        )


@dataclass
class ScanResult:
    ip: str
    findings: list[ScanFindings]
    eni_id: str | None = None

    def build_rich_panel(self) -> Panel:
        rich_text = "\n".join(finding.build_rich_text() for finding in self.findings)
        return Panel(rich_text, title=self.ip, title_align="left")

    def get_eni_resources(self) -> list[AwsEni]:
        eni_resources = []
        for finding in self.findings:
            for resource in finding.resources:
                if isinstance(resource, AwsEni):
                    eni_resources.append(resource)
        return eni_resources
