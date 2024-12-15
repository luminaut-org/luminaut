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
