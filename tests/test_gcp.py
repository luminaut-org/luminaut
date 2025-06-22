import datetime
from io import BytesIO
from textwrap import dedent
from unittest import TestCase
from unittest.mock import Mock

from luminaut import models
from luminaut.tools.gcp import Gcp


class TestGcpAccessConfig:
    nat_i_p = "1.2.3.4"


class FakeGcpNetworkInterface:
    access_configs = [TestGcpAccessConfig()]
    name = "nic0"
    network_i_p = "10.0.0.1"
    network = "https://www.googleapis.com/compute/v1/projects/luminaut/global/networks/default"
    network_attachment = ""
    alias_ip_ranges = []


class FakeGcpInstance:
    id = "abc123"
    name = "test-instance"
    network_interfaces = [FakeGcpNetworkInterface()]
    creation_timestamp = "2025-05-19T05:35:09.886-07:00"
    zone = "https://www.googleapis.com/compute/v1/projects/luminaut/zones/us-central1-c"
    status = "RUNNING"
    description = "Test instance"


class TestGCP(TestCase):
    def test_initialize_class(self):
        config = BytesIO(
            dedent(
                """
            [gcp]
            enabled = true
            project_id = ["test-project-1", "test-project-2"]
            compute_zones = ["us-central1-a", "us-central1-b", "us-central1-c"]
            """
            ).encode("utf-8")
        )
        config = models.LuminautConfig.from_toml(config)
        gcp_client = Mock()

        gcp = Gcp(config, gcp_client=gcp_client)

        self.assertEqual(gcp.config, config)
        self.assertEqual(gcp.gcp_client, gcp_client)

    def test_enumerate_instances_with_public_ips(self):
        expected_nic = models.GcpNetworkInterface(
            resource_id=FakeGcpNetworkInterface.name,
            public_ip=TestGcpAccessConfig.nat_i_p,
            internal_ip=FakeGcpNetworkInterface.network_i_p,
            network=FakeGcpNetworkInterface.network,
            network_attachment=FakeGcpNetworkInterface.network_attachment,
            alias_ip_ranges=FakeGcpNetworkInterface.alias_ip_ranges,
        )
        expected_instance = models.GcpInstance(
            resource_id=FakeGcpInstance.id,
            name=FakeGcpInstance.name,
            network_interfaces=[expected_nic],
            creation_time=datetime.datetime(
                2025,
                5,
                19,
                5,
                35,
                9,
                886000,
                tzinfo=datetime.timezone(datetime.timedelta(hours=-7)),
            ),
            zone="us-central1-c",
            status=FakeGcpInstance.status,
            description=FakeGcpInstance.description,
        )
        gcp_client = Mock()
        gcp_client.list.return_value = [FakeGcpInstance()]
        config = models.LuminautConfig(
            gcp=models.LuminautConfigToolGcp(
                enabled=True,
                projects=["test-project-1"],
                compute_zones=["us-central1-c"],
            )
        )

        instances = Gcp(config, gcp_client=gcp_client).fetch_instances(
            project=config.gcp.projects[0],
            zone=config.gcp.compute_zones[0],
        )

        # Calls the list command
        gcp_client.list.assert_called_once()

        self.assertEqual(
            len(instances),
            1,
            f"Expected one instance, found {len(instances)}",
        )

        actual_instance = instances[0]
        actual_nic = instances[0].network_interfaces[0]

        self.assertEqual(actual_nic.resource_id, expected_nic.resource_id)
        self.assertEqual(actual_nic.public_ip, expected_nic.public_ip)
        self.assertEqual(actual_instance.resource_id, expected_instance.resource_id)
