import boto3


class ENI:
    def __init__(self):
        self.ec2_client = boto3.client('ec2')

    def fetch_enis_with_public_ips(self):
        paginator = self.ec2_client.get_paginator('describe_network_interfaces')
        results = paginator.paginate(
            Filters=[
                {
                    'Name': 'association.public-ip',
                    'Values': ['*'],
                },
            ],
        )
        for enis in results:
            for eni in enis['NetworkInterfaces']:
                yield (
                    eni['NetworkInterfaceId'],
                    eni['Association']['PublicIp'],
                )
