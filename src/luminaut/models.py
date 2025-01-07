import json
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Any, BinaryIO, Self

from rich.emoji import Emoji

IPAddress = IPv4Address | IPv6Address
QUAD_ZERO_ADDRESSES = (IPv4Address("0.0.0.0"), IPv6Address("::"))


def convert_tag_set_to_dict(tag_set: Iterable[dict[str, str]]) -> dict[str, str]:
    tags = {}
    for tag in tag_set:
        if (key := tag.get("key")) and (value := tag.get("value")):
            tags[key] = value
    return tags


@dataclass
class ConfigDiff:
    added: dict[str, Any] = field(default_factory=dict)
    removed: dict[str, Any] = field(default_factory=dict)
    changed: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return any([self.added, self.removed, self.changed])


def generate_config_diff(
    first: type[dataclass] | dict[str, Any], second: type[dataclass] | dict[str, Any]
) -> ConfigDiff:
    diff = ConfigDiff()

    if not isinstance(first, dict):
        first = asdict(first)
    if not isinstance(second, dict):
        second = asdict(second)

    first_keys = set(first.keys())
    second_keys = set(second.keys())
    common_keys = first_keys & second_keys

    diff.added = {key: second[key] for key in second_keys - common_keys}
    diff.removed = {key: first[key] for key in first_keys - common_keys}
    diff.changed = {
        key: {"old": first[key], "new": second[key]}
        for key in common_keys
        if first[key] != second[key]
    }

    return diff


class Direction(StrEnum):
    INGRESS = auto()
    EGRESS = auto()


class Protocol(StrEnum):
    TCP = auto()
    UDP = auto()
    ICMP = auto()
    ICMPv6 = auto()
    ALL = "-1"


class ResourceType(StrEnum):
    EC2_Instance = "AWS::EC2::Instance"
    EC2_NetworkInterface = "AWS::EC2::NetworkInterface"
    EC2_SecurityGroup = "AWS::EC2::SecurityGroup"
    ELB_LoadBalancer = "AWS::ElasticLoadBalancingV2::LoadBalancer"


class SecurityGroupRuleTargetType(StrEnum):
    CIDR = auto()
    SECURITY_GROUP = auto()
    PREFIX_LIST = auto()


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
class LuminautConfigAwsAllowedResource:
    type: ResourceType | None = None
    id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        if resource_type := data.get("type"):
            resource_type = ResourceType(resource_type)

        return cls(
            type=resource_type,
            id=data.get("id"),
            tags=data.get("tags", {}),
        )


@dataclass
class LuminautConfigToolAws(LuminautConfigTool):
    aws_profile: str | None = None
    aws_regions: list[str] | None = field(default_factory=lambda: ["us-east-1"])
    config: LuminautConfigTool = field(
        default_factory=lambda: LuminautConfigTool(enabled=True)
    )
    cloudtrail: LuminautConfigTool = field(
        default_factory=lambda: LuminautConfigTool(enabled=True)
    )
    allowed_resources: list[LuminautConfigAwsAllowedResource] = field(
        default_factory=list
    )

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> Self:
        aws_config = super().from_dict(config)

        aws_config.aws_profile = config.get("aws_profile")

        # Don't override defaults
        if aws_regions := config.get("aws_regions"):
            aws_config.aws_regions = aws_regions
        if config_dict := config.get("config"):
            aws_config.config = LuminautConfigTool.from_dict(config_dict)

        aws_config.allowed_resources = [
            LuminautConfigAwsAllowedResource.from_dict(x)
            for x in config.get("allowed_resources", [])
        ]

        return aws_config


@dataclass
class LuminautConfigReport:
    console: bool = True
    json: bool = False
    json_file: Path | None = None
    html: bool = False
    html_file: Path | None = None
    timeline: bool = False
    timeline_file: Path | None = None

    @classmethod
    def from_toml(cls, config: dict[str, Any]) -> Self:
        def path_or_none(value: str | None) -> Path | None:
            return Path(value) if value else None

        json_file_path = path_or_none(config.get("json_file"))
        html_file_path = path_or_none(config.get("html_file"))
        timeline_file_path = path_or_none(config.get("timeline_file"))

        return cls(
            console=config.get("console", True),
            json=config.get("json", False),
            json_file=json_file_path,
            html=config.get("html", False),
            html_file=html_file_path,
            timeline=config.get("timeline", False),
            timeline_file=timeline_file_path,
        )


@dataclass
class LuminautConfig:
    report: LuminautConfigReport = field(default_factory=LuminautConfigReport)
    aws: LuminautConfigToolAws = field(default_factory=LuminautConfigToolAws)
    nmap: LuminautConfigTool = field(default_factory=LuminautConfigTool)
    shodan: LuminautConfigToolShodan = field(default_factory=LuminautConfigToolShodan)
    whatweb: LuminautConfigTool = field(default_factory=LuminautConfigTool)

    @classmethod
    def from_toml(cls, toml_file: BinaryIO) -> Self:
        toml_data = tomllib.load(toml_file)

        luminaut_config = cls(
            report=LuminautConfigReport.from_toml(toml_data.get("report", {}))
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
class AwsLoadBalancerListener:
    resource_id: str
    arn: str
    port: int
    protocol: str

    def build_rich_text(self):
        return f"[blue]{self.port}[/blue]/[magenta]{self.protocol}[/magenta]"

    @classmethod
    def from_describe_listener(cls, listener: dict[str, Any]) -> Self:
        return cls(
            resource_id=listener["ListenerArn"],
            arn=listener["ListenerArn"],
            port=listener["Port"],
            protocol=listener["Protocol"],
        )


@dataclass
class AwsLoadBalancer:
    resource_id: str
    name: str
    arn: str
    dns_name: str
    type: str
    vpc_id: str
    state: str
    scheme: str
    created_time: datetime
    security_groups: list[SecurityGroup] = field(default_factory=list)
    subnets: list[str] = field(default_factory=list)
    listeners: list[AwsLoadBalancerListener] = field(default_factory=list)

    def build_rich_text(self) -> str:
        headline = f"[orange1]{self.resource_id}[/orange1] {self.scheme} ({self.state}) Created: {self.created_time}\n"
        listener_details = []
        for listener in self.listeners:
            listener_details.append(listener.build_rich_text())

        if listener_details:
            return headline + "  Listeners: " + ", ".join(listener_details) + "\n"
        return headline

    @classmethod
    def from_describe_elb(cls, elb: dict[str, Any]) -> Self:
        security_groups = [
            SecurityGroup(group_id=sg_id, group_name="")
            for sg_id in elb["SecurityGroups"]
        ]
        subnets = [az["SubnetId"] for az in elb["AvailabilityZones"]]

        return cls(
            resource_id=elb["LoadBalancerName"],
            name=elb["LoadBalancerName"],
            arn=elb["LoadBalancerArn"],
            dns_name=elb["DNSName"],
            type=elb["Type"],
            vpc_id=elb["VpcId"],
            state=elb["State"]["Code"],
            scheme=elb["Scheme"],
            created_time=elb["CreatedTime"],
            security_groups=security_groups,
            subnets=subnets,
        )


@dataclass
class AwsNetworkInterface:
    resource_id: str
    public_ip: str
    private_ip: str
    attachment_id: str
    attachment_time: datetime
    attachment_status: str
    availability_zone: str
    status: str
    vpc_id: str
    security_groups: list[SecurityGroup] = field(default_factory=list)
    ec2_instance_id: str | None = None
    public_dns_name: str | None = None
    private_dns_name: str | None = None
    description: str | None = None
    interface_type: str | None = None
    subnet_id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    resource_type: ResourceType = ResourceType.EC2_NetworkInterface

    def get_aws_tags(self) -> dict[str, str]:
        return self.tags

    def build_rich_text(self) -> str:
        rich_text = f"[orange1]{self.resource_id}[/orange1] in [cyan]{self.vpc_id} ({self.availability_zone})[/cyan]\n"
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


@dataclass
class AwsEc2InstanceStateReason:
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
class AwsEc2InstanceState:
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
class AwsEc2Instance:
    resource_id: str
    image_id: str
    launch_time: datetime
    tags: dict[str, str]
    platform_details: str
    private_dns_name: str
    private_ip_address: str
    public_dns_name: str
    network_interfaces: list[AwsNetworkInterface | dict[str, Any]]
    security_groups: list[SecurityGroup | dict[str, Any]]
    state: AwsEc2InstanceState | None
    state_reason: AwsEc2InstanceStateReason | None
    usage_operation: str
    usage_operation_update_time: datetime
    subnet_id: str
    vpc_id: str
    public_ip_address: str | None = None
    resource_type: ResourceType = ResourceType.EC2_Instance

    def get_aws_tags(self) -> dict[str, str]:
        return self.tags

    @classmethod
    def from_aws_config(cls, configuration: dict[str, Any]) -> Self:
        tags = convert_tag_set_to_dict(configuration["tags"])

        return cls(
            resource_id=configuration["instanceId"],
            image_id=configuration["imageId"],
            launch_time=datetime.fromisoformat(configuration["launchTime"]),
            tags=tags,
            platform_details=configuration["platformDetails"],
            private_dns_name=configuration["privateDnsName"],
            private_ip_address=configuration["privateIpAddress"],
            public_dns_name=configuration["publicDnsName"],
            public_ip_address=configuration.get("publicIpAddress"),
            network_interfaces=configuration["networkInterfaces"],
            security_groups=configuration["securityGroups"],
            state=AwsEc2InstanceState.from_aws_config(configuration["state"]),
            state_reason=AwsEc2InstanceStateReason.from_aws_config(
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
class AwsConfigItem:
    resource_type: ResourceType
    resource_id: str
    account: str
    region: str
    arn: str
    config_capture_time: datetime
    config_status: str
    configuration: AwsEc2Instance | str
    tags: dict[str, str]
    resource_creation_time: datetime | None = None
    diff_to_prior: ConfigDiff | None = None

    def get_aws_tags(self) -> dict[str, str]:
        return self.tags

    @staticmethod
    def build_configuration(
        resource_type: ResourceType,
        configuration: str,
    ) -> AwsEc2Instance | str:
        try:
            configuration = json.loads(configuration)
        except json.JSONDecodeError:
            return configuration

        if resource_type == ResourceType.EC2_Instance:
            return AwsEc2Instance.from_aws_config(configuration)
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


@dataclass
class NmapPortServices:
    port: int
    protocol: Protocol
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None

    def build_rich_text(self) -> str:
        rich_text = f"[green]{self.protocol}/{self.port}[/green] Status: [cyan]{self.state}[/cyan]"

        service_details = ""
        for attr in ["name", "product", "version"]:
            if value := getattr(self, attr):
                service_details += f"{attr.capitalize()}: [cyan]{value}[/cyan] "

        if service_details:
            rich_text += f" {service_details}"

        if not rich_text.endswith("\n"):
            rich_text += "\n"

        return rich_text


@dataclass
class ShodanService:
    timestamp: datetime
    port: int | None = None
    protocol: Protocol | None = None
    product: str | None = None
    data: str | None = None
    operating_system: str | None = None
    cpe: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    http_server: str | None = None
    http_title: str | None = None
    opt_heartbleed: str | None = None
    opt_vulnerabilities: list["Vulnerability"] = field(default_factory=list)

    def build_rich_text(self) -> str:
        rich_text = ""
        if self.protocol and self.port:
            rich_text = f"[green]{self.protocol}/{self.port}[/green]"
        if self.product:
            rich_text += f" {self.product}"

        if rich_text:
            # Add newline after title line
            rich_text += "\n"

        http_information = ""
        if self.http_server:
            http_information += f"HTTP Server: {self.http_server}"
        if self.http_title:
            if http_information:
                http_information += " "
            http_information += f"HTTP Title: {self.http_title}"

        if http_information:
            rich_text += "  " + http_information + "\n"

        if self.opt_vulnerabilities:
            rich_text += "".join(
                x.build_rich_text() for x in self.opt_vulnerabilities[:5]
            )
            if len(self.opt_vulnerabilities) > 5:
                rich_text += f"  {len(self.opt_vulnerabilities)} total vulnerabilities found. See JSON for full report.\n"

        return rich_text

    @classmethod
    def from_shodan_host(cls, service: Mapping[str, Any]) -> Self:
        vulns = []
        for cve, vuln_data in service.get("vulns", {}).items():
            vulns.append(
                Vulnerability.from_shodan(
                    cve,
                    vuln_data,
                    datetime.fromisoformat(service["timestamp"]),
                )
            )

        return cls(
            timestamp=datetime.fromisoformat(service["timestamp"]),
            port=service.get("port"),
            protocol=Protocol(service["transport"])
            if service.get("transport")
            else None,
            product=service.get("product"),
            data=service.get("data"),
            operating_system=service.get("os"),
            cpe=service.get("cpe", []),
            tags=service.get("tags", []),
            http_server=service.get("http", {}).get("server"),
            http_title=service.get("http", {}).get("title"),
            opt_heartbleed=service.get("opts", {}).get("heartbleed"),
            opt_vulnerabilities=vulns,
        )


@dataclass
class Hostname:
    name: str
    timestamp: datetime | None = None

    def build_rich_text(self) -> str:
        return f"  Hostname: [orange1]{self.name}[/orange1] ({self.timestamp})\n"


@dataclass
class Vulnerability:
    cve: str
    cvss: float | None = None
    cvss_version: int | None = None
    summary: str | None = None
    references: list[str] = field(default_factory=list)
    timestamp: datetime | None = None

    def build_rich_text(self) -> str:
        emphasis = self.cve
        if self.cvss:
            emphasis += f" (CVSS: {self.cvss})"

        return f"  Vulnerability: [red]{emphasis}[/red]\n"

    @classmethod
    def from_shodan(
        cls, cve: str, shodan_data: Mapping[str, Any], timestamp: datetime
    ) -> Self:
        return cls(
            cve=cve,
            cvss=shodan_data.get("cvss"),
            cvss_version=shodan_data.get("cvss_version"),
            summary=shodan_data.get("summary"),
            references=shodan_data.get("references", []),
            timestamp=timestamp,
        )


@dataclass
class Whatweb:
    summary_text: str
    json_data: list[dict[str, Any]]

    def __bool__(self):
        return bool(self.summary_text) or bool(self.json_data)

    def build_rich_text(self):
        rich_text = ""
        for item in self.json_data:
            if target := item.get("target"):
                rich_text += f"- [green]{target}[/green]"
                if value_text := self.build_value_rich_text(item):
                    rich_text += f"\n{value_text}\n"
        return rich_text

    @staticmethod
    def build_value_rich_text(item: dict[str, Any]) -> str:
        plugins_to_skip = [
            "Cookies",
            "Country",
            "HttpOnly",
            "IP",
            "Meta-Refresh-Redirect",
            "Script",
            "PasswordField",
            "X-Frame-Options",
        ]
        item_text = ""
        for key, value in item.get("plugins").items():
            if key in plugins_to_skip:
                continue
            item_text += f"  [orange1]{key}[/orange1]"
            value_text = ""
            if value:
                if strings := value.get("string", []):
                    value_text += ", ".join(strings)
                if versions := value.get("version", []):
                    value_text += ", ".join(versions)
            if value_text:
                escaped_value_text = value_text.replace("[", "\\[")
                item_text += f": {escaped_value_text}"
            item_text += "\n"
        return item_text


class TimelineEventType(StrEnum):
    COMPUTE_INSTANCE_STATE_CHANGE = "Instance state changed"
    COMPUTE_INSTANCE_CREATED = "Instance created"
    COMPUTE_INSTANCE_TERMINATED = "Instance terminated"
    COMPUTE_INSTANCE_LAUNCH_TIME_UPDATED = "Instance launch time updated"
    COMPUTE_INSTANCE_NETWORKING_CHANGE = "Instance networking change"
    SECURITY_GROUP_ASSOCIATION_CHANGE = "Security group changed"
    SECURITY_GROUP_RULE_CHANGE = "Security group rule changed"
    RESOURCE_CREATED = "Resource created"


@dataclass
class TimelineEvent:
    timestamp: datetime
    source: str
    event_type: TimelineEventType
    resource_id: str
    resource_type: ResourceType
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def build_rich_text(self) -> str:
        return f"[green]{self.timestamp.astimezone(UTC)}[/green] {self.event_type}: [magenta]{self.message}[/magenta] ({self.resource_type} {self.resource_id})\n"


FindingServices = list[NmapPortServices | ShodanService | Whatweb]
FindingResources = list[AwsNetworkInterface | AwsConfigItem | SecurityGroup | Hostname]


@dataclass
class ScanFindings:
    tool: str
    services: FindingServices = field(default_factory=list)
    resources: FindingResources = field(default_factory=list)
    events: list[TimelineEvent] = field(default_factory=list)
    emoji_name: str | None = "mag"

    def build_rich_text(self) -> str:
        rich_title = f"[bold underline]{Emoji(self.emoji_name) if self.emoji_name else ''} {self.tool}[/bold underline]\n"

        rich_text = self.build_rich_text_for_attributes()

        if rich_text:
            return rich_title + rich_text

        return (
            rich_title
            + "No findings to report to the console. See JSON report for full details.\n"
        )

    def build_rich_text_for_attributes(self) -> str:
        rich_text = ""
        for attribute in ["services", "resources", "events"]:
            attribute_title = f"[bold]{attribute.title()}[/bold]:\n"
            items = getattr(self, attribute)
            attribute_text = [
                item.build_rich_text()
                for item in items
                if hasattr(item, "build_rich_text")
            ]

            if attribute_text:
                rich_text += attribute_title + "".join(attribute_text)

            other_items = len(items) - len(attribute_text)
            if other_items:
                other_text = f"  {other_items} {'additional ' if len(attribute_text) else ''}{attribute} discovered.\n"
                if not len(rich_text):
                    rich_text += attribute_title
                rich_text += other_text

        return rich_text


@dataclass
class ScanResult:
    ip: str
    findings: list[ScanFindings]
    region: str | None = None
    eni_id: str | None = None

    def build_rich_panel(self) -> tuple[str, str]:
        rich_text = "\n".join(finding.build_rich_text() for finding in self.findings)
        title = self.ip
        if self.region:
            title += f" | {self.region}"
        return title, rich_text

    def get_eni_resources(self) -> list[AwsNetworkInterface]:
        eni_resources = []
        for finding in self.findings:
            for resource in finding.resources:
                if isinstance(resource, AwsNetworkInterface):
                    eni_resources.append(resource)
        return eni_resources

    def get_security_group_rules(self) -> list[SecurityGroupRule]:
        sg_rules = []
        for finding in self.findings:
            for resource in finding.resources:
                if isinstance(resource, SecurityGroup):
                    sg_rules.extend(resource.rules)
        return sg_rules

    def generate_ip_port_targets(self) -> list[str]:
        ports = set()
        default_ports = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888}
        if security_group_rules := self.get_security_group_rules():
            for sg_rule in security_group_rules:
                if sg_rule.protocol in (Protocol.ICMP, Protocol.ICMPv6):
                    continue
                elif sg_rule.protocol == Protocol.ALL:
                    ports.update(default_ports)
                ports.update({x for x in range(sg_rule.from_port, sg_rule.to_port + 1)})

        targets = [f"{self.ip}:{port}" for port in ports]
        return targets
