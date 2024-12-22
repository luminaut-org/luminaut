import unittest

import boto3
from moto import mock_aws

from luminaut import models
from luminaut.tools.aws import Aws


class AwsTool(unittest.TestCase):
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
