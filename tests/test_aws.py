import unittest
from dataclasses import asdict
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
        self.sample_eni = models.AwsNetworkInterface(
            resource_id="eni-1234567890abcdef0",
            public_ip="10.0.0.1",
            private_ip="10.0.0.1",
            attachment_id="eni-attach-1234567890abcdef0",
            attachment_time=datetime.today(),
            attachment_status="attached",
            availability_zone="us-west-2a",
            status="available",
            vpc_id="vpc-1234567890abcdef0",
            security_groups=[self.sample_sg],
            ec2_instance_id="i-1234567890abcdef0",
        )
        self.sample_config_eni = models.AwsConfigItem(
            resource_type=models.ResourceType.EC2_NetworkInterface,
            resource_id="eni-1234567890abcdef0",
            account="123456789012",
            region="us-west-2",
            arn="arn",
            config_capture_time=datetime.today(),
            config_status="OK",
            configuration="",
            tags={},
            resource_creation_time=None,
        )
        self.sample_config_ec2 = models.AwsConfigItem(
            resource_type=models.ResourceType.EC2_Instance,
            resource_id="i-1234567890abcdef0",
            account="123456789012",
            region="us-west-2",
            arn="arn",
            config_capture_time=datetime.today(),
            config_status="OK",
            configuration="",
            tags={},
            resource_creation_time=None,
        )

    def aws_client_mock_setup(self, config=None) -> Aws:
        def mock_get_config_history_for_resource(
            resource_type: models.ResourceType, *args, **kwargs
        ) -> (list[models.AwsConfigItem], list[models.TimelineEvent]):
            if resource_type == models.ResourceType.EC2_NetworkInterface:
                return [self.sample_config_eni], []
            elif resource_type == models.ResourceType.EC2_Instance:
                return [self.sample_config_ec2], []

        aws = Aws(config)
        aws._fetch_enis_with_public_ips = lambda: [self.sample_eni]
        aws.populate_permissive_ingress_security_group_rules = lambda x: self.sample_sg
        aws.get_config_history_for_resource = mock_get_config_history_for_resource
        return aws

    def test_explore_region(self):
        aws = self.aws_client_mock_setup()

        exploration = aws.explore_region("us-east-1")

        self.assertIsInstance(exploration, list)
        self.assertEqual(1, len(exploration))
        self.assertIsInstance(exploration[0], models.ScanResult)
        self.assertEqual(3, len(exploration[0].findings))

        self.assertIn(self.sample_eni, exploration[0].findings[0].resources)
        self.assertIn(self.sample_sg, exploration[0].findings[1].resources)
        self.assertIn(self.sample_config_eni, exploration[0].findings[2].resources)
        self.assertIn(self.sample_config_ec2, exploration[0].findings[2].resources)

    def test_explore_region_no_config(self):
        config = models.LuminautConfig()
        config.aws.config.enabled = False
        aws = self.aws_client_mock_setup(config)

        exploration = aws.explore_region("us-east-1")

        self.assertIsInstance(exploration, list)
        self.assertEqual(1, len(exploration))
        self.assertIsInstance(exploration[0], models.ScanResult)
        self.assertEqual(2, len(exploration[0].findings))

        self.assertIn(self.sample_eni, exploration[0].findings[0].resources)
        self.assertIn(self.sample_sg, exploration[0].findings[1].resources)

    def test_explore_region_no_aws(self):
        config = models.LuminautConfig()
        config.aws.enabled = False
        aws = self.aws_client_mock_setup(config)

        exploration = aws.explore_region("us-east-1")

        self.assertIsInstance(exploration, list)
        self.assertEqual(0, len(exploration))

    def test_skip_resource_by_tags(self):
        config = models.LuminautConfig()
        config.aws.allowed_resources = [
            models.LuminautConfigAwsAllowedResource(tags={"foo": "bar"})
        ]
        aws = Aws(config)

        self.assertFalse(aws.skip_resource(self.sample_config_eni))
        self.sample_config_eni.tags = {"foo": "bar"}
        self.assertTrue(aws.skip_resource(self.sample_config_eni))

    def test_skip_resource_by_id(self):
        config = models.LuminautConfig()
        config.aws.allowed_resources = [
            models.LuminautConfigAwsAllowedResource(
                type=self.sample_eni.resource_type, id=self.sample_eni.resource_id
            )
        ]
        aws = Aws(config)

        self.assertFalse(aws.skip_resource(self.sample_config_ec2))
        self.assertTrue(aws.skip_resource(self.sample_config_eni))

    def test_convert_tag_set_to_dict(self):
        tag_set = [
            {"key": "Name", "value": "test"},
            {"key": "Owner", "value": "unittest"},
        ]
        tag_dict = {
            "Name": "test",
            "Owner": "unittest",
        }
        actual = models.convert_tag_set_to_dict(tag_set)
        self.assertEqual(tag_dict, actual)

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

    def test_generate_config_diff(self):
        old_config = {"foo": "bar", "bar": "baz", "baz": "foo"}
        new_config = {"foo": ["baz"], "aaa": {"a": "A"}, "bbb": "ccc"}
        diff = models.generate_config_diff(old_config, new_config)

        self.assertEqual(
            diff.added,
            {"aaa": {"a": "A"}, "bbb": "ccc"},
        )
        self.assertEqual(
            diff.removed,
            {"bar": "baz", "baz": "foo"},
        )
        self.assertEqual(
            diff.changed,
            {"foo": {"old": "bar", "new": ["baz"]}},
        )

    def test_generate_event_for_diff(self):
        resource_type = models.ResourceType.EC2_Instance
        resource_id = "i-1"
        config_capture_time = datetime.now()
        diff_to_prior = models.ConfigDiff(
            changed={"state": {"old": {"name": "running"}, "new": {"name": "stopping"}}}
        )

        expected_event = models.TimelineEvent(
            timestamp=config_capture_time,
            event_type=models.TimelineEventType.AWS_EC2_INSTANCE_STATE_CHANGE,
            resource_type=resource_type,
            resource_id=resource_id,
            message="AWS EC2 Instance state changed from running to stopping.",
            details=asdict(diff_to_prior),
        )

        actual_events = Aws.generate_events_for_diff(
            resource_type, resource_id, config_capture_time, diff_to_prior
        )

        self.assertEqual(1, len(actual_events))
        self.assertEqual(expected_event, actual_events[0])
