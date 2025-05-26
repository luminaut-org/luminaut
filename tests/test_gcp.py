from unittest import TestCase
from unittest.mock import Mock

from luminaut.models import GcpNetworkInterface
from luminaut.tools.gcp import fetch_network_interfaces


class TestGcpAccessConfig:
    nat_ip = "1.2.3.4"


class FakeGcpNetworkInterface:
    access_configs = [TestGcpAccessConfig()]
    name = "nic0"


class FakeGcpInstance:
    id = "abc123"
    name = "test-instance"
    network_interfaces = [FakeGcpNetworkInterface()]


class TestGCP(TestCase):
    def test_enumerate_public_ips(self):
        expected_nic = GcpNetworkInterface(
            resource_id="nic0", public_ip="1.2.3.4", compute_instance_id="abc123"
        )
        gcp_client = Mock()
        gcp_client.list.return_value = [FakeGcpInstance()]

        actual_nics = fetch_network_interfaces(gcp_client, "unittest", "unittest")

        # Calls the list command
        gcp_client.list.assert_called_once()

        self.assertEqual(
            len(actual_nics),
            1,
            f"Expected one network interface, found {len(actual_nics)}",
        )
        self.assertEqual(actual_nics[0].resource_id, expected_nic.resource_id)
        self.assertEqual(actual_nics[0].public_ip, expected_nic.public_ip)
        self.assertEqual(
            actual_nics[0].compute_instance_id, expected_nic.compute_instance_id
        )
