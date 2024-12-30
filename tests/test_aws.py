import unittest
from datetime import datetime

import boto3
from moto import mock_aws

from luminaut import models
from luminaut.tools.aws import Aws


class MockDescribeEniPaginator:
    @staticmethod
    def paginate(*args, **kwargs):
        return [
            {
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-1234567890abcdef0",
                        "Association": {"PublicIp": "10.0.0.1"},
                    },
                ]
            }
        ]


class AwsTool(unittest.TestCase):
    def setUp(self):
        self.sample_sg = models.SecurityGroup(
            group_id="sg-1234567890abcdef0",
            group_name="unittest",
            rules=[],
        )
        self.sample_eni = models.AwsEni(
            network_interface_id="eni-1234567890abcdef0",
            public_ip="10.0.0.1",
            private_ip="10.0.0.1",
            attachment_id="eni-attach-1234567890abcdef0",
            attachment_time=datetime.today(),
            attachment_status="attached",
            availability_zone="us-west-2a",
            status="available",
            vpc_id="vpc-1234567890abcdef0",
            security_groups=[self.sample_sg],
        )

    def test_explore_region(self):
        aws = Aws()
        aws._fetch_enis_with_public_ips = lambda: [self.sample_eni]
        aws.populate_permissive_ingress_security_group_rules = lambda x: [
            self.sample_sg
        ]

        exploration = aws.explore_region("us-east-1")

        self.assertIsInstance(exploration, list)
        self.assertEqual(1, len(exploration))
        self.assertIsInstance(exploration[0], models.ScanResult)
        self.assertEqual(2, len(exploration[0].findings))

    @mock_aws()
    def test_setup_client_region(self):
        aws = Aws()
        self.assertEqual("us-east-1", aws.ec2_client.meta.region_name)
        self.assertEqual("us-east-1", aws.config_client.meta.region_name)

        aws.setup_client_region("us-east-2")

        self.assertEqual("us-east-2", aws.ec2_client.meta.region_name)
        self.assertEqual("us-east-2", aws.config_client.meta.region_name)

    @mock_aws()
    def test_fetch_enis_with_public_ips(self):
        aws = Aws()
        aws._build_eni_scan_finding = lambda x: self.sample_eni
        aws.ec2_client.get_paginator = lambda x: MockDescribeEniPaginator()

        scan_results = aws.fetch_enis_with_public_ips()
        self.assertIsInstance(scan_results, list)
        self.assertIsInstance(scan_results[0], models.ScanResult)
        self.assertIsInstance(scan_results[0].findings[0], models.ScanFindings)

    @mock_aws()
    def test_list_security_group_rules(self):
        ec2_client = boto3.client("ec2")
        group_name = "unittest"
        sg = ec2_client.create_security_group(
            GroupName=group_name, Description=group_name
        )

        public_ingress_response = ec2_client.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[
                {
                    "FromPort": 54321,
                    "ToPort": 54321,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )
        ec2_client.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[
                {
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "10.2.0.0/16"}],
                },
            ],
        )

        security_group = models.SecurityGroup(sg["GroupId"], group_name)
        security_group = Aws().populate_permissive_ingress_security_group_rules(
            security_group
        )
        rules = security_group.rules

        self.assertEqual(1, len(rules))
        self.assertEqual(models.Direction.INGRESS, rules[0].direction)
        self.assertEqual(
            public_ingress_response["SecurityGroupRules"][0]["CidrIpv4"],
            rules[0].target,
        )
        self.assertEqual(models.Protocol.TCP, rules[0].protocol)
