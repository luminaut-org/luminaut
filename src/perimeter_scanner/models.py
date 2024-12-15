from dataclasses import dataclass
from datetime import datetime


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
