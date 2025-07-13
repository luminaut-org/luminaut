import datetime
from io import BytesIO
from textwrap import dedent
from unittest import TestCase
from unittest.mock import Mock

from google.cloud.compute_v1 import types as gcp_compute_v1_types
from google.cloud.run_v2 import types as run_v2_types
from google.protobuf.timestamp_pb2 import Timestamp

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


class FakeGcpInstanceTags:
    items = ["web-server", "production", "backend"]


class FakeGcpInstance:
    id = "abc123"
    name = "test-instance"
    network_interfaces = [FakeGcpNetworkInterface()]
    creation_timestamp = "2025-05-19T05:35:09.886-07:00"
    zone = "https://www.googleapis.com/compute/v1/projects/luminaut/zones/us-central1-c"
    status = "RUNNING"
    description = "Test instance"
    tags = FakeGcpInstanceTags()


class FakeGcpInternalNetworkInterface:
    access_configs = []
    name = "nic0"
    network_i_p = "10.0.0.1"
    network = "https://www.googleapis.com/compute/v1/projects/luminaut/global/networks/default"
    network_attachment = ""
    alias_ip_ranges = []


class FakeGcpInternalInstanceTags:
    items = ["internal", "database"]


class FakeGcpInternalInstance:
    id = "abc123"
    name = "test-instance"
    network_interfaces = [FakeGcpInternalNetworkInterface()]
    creation_timestamp = "2025-05-19T05:35:09.886-07:00"
    zone = "https://www.googleapis.com/compute/v1/projects/luminaut/zones/us-central1-c"
    status = "RUNNING"
    description = "Test instance"
    tags = FakeGcpInternalInstanceTags()


fake_container = run_v2_types.Container(
    name="test-container",
    image="gcr.io/test-project/test-image",
    command=["python", "app.py"],
    ports=[run_v2_types.ContainerPort(name="http1", container_port=8080)],
)

some_date = datetime.datetime(2025, 5, 19, 5, 35, 9, tzinfo=datetime.UTC)

fake_service = run_v2_types.Service(
    name="test-service",
    uid="12345678-1234-1234-1234-123456789012",
    uri="https://test-service-12345678-uc.a.run.app",
    creator="foo",
    last_modifier="bar",
    template=run_v2_types.RevisionTemplate(containers=[fake_container]),
    ingress=run_v2_types.IngressTraffic.INGRESS_TRAFFIC_ALL,
    urls=["https://test-service-12345678-uc.a.run.app"],
    create_time=Timestamp(seconds=int(some_date.timestamp())),
    update_time=Timestamp(seconds=int(some_date.timestamp())),
)

fake_service_with_no_ingress = run_v2_types.Service(
    name="test-service-ingress-none",
    uid="12345678-1234-1234-1234-123456789013",
    uri="https://test-service-12345678-uc.a.run.app",
    creator="foo",
    last_modifier="bar",
    template=run_v2_types.RevisionTemplate(containers=[fake_container]),
    ingress=run_v2_types.IngressTraffic.INGRESS_TRAFFIC_NONE,
    urls=["https://test-service-12345678-uc.a.run.app"],
    create_time=Timestamp(seconds=int(some_date.timestamp())),
    update_time=Timestamp(seconds=int(some_date.timestamp())),
)


class TestGCP(TestCase):
    def setUp(self):
        config = BytesIO(
            dedent(
                """
            [tool.gcp]
            enabled = true
            projects = ["test-project-1", "test-project-2"]
            regions = ["us-central1", "us-east1"]
            compute_zones = ["us-central1-a", "us-central1-b", "us-central1-c"]
            """
            ).encode("utf-8")
        )
        self.config = models.LuminautConfig.from_toml(config)

    def mock_gcp_clients(
        self,
        gcp: Gcp,
        compute_list_instance_response=None,
        cloud_run_list_service_response=None,
    ) -> dict[str, Mock]:
        clients = {}
        clients["compute_v1"] = Mock()
        clients["compute_v1"].list.return_value = compute_list_instance_response or []
        gcp.get_compute_v1_client = Mock(return_value=clients["compute_v1"])

        clients["run_v2"] = Mock()
        clients["run_v2"].list_services.return_value = (
            cloud_run_list_service_response or []
        )
        gcp.get_run_v2_services_client = Mock(return_value=clients["run_v2"])

        return clients

    def test_explore(self):
        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp,
            compute_list_instance_response=[FakeGcpInstance()],
            cloud_run_list_service_response=[fake_service],
        )
        instances = gcp.explore()

        self.assertEqual(mock_clients["compute_v1"].list.call_count, 6)
        self.assertEqual(mock_clients["run_v2"].list_services.call_count, 4)
        self.assertEqual(len(instances), 10)

    def test_explore_gcp_disabled(self):
        self.config.gcp.enabled = False

        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(gcp)
        instances = gcp.explore()

        self.assertEqual(mock_clients["compute_v1"].list.call_count, 0)
        self.assertEqual(mock_clients["run_v2"].list_services.call_count, 0)
        self.assertEqual(len(instances), 0)

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

        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp, compute_list_instance_response=[FakeGcpInstance()]
        )
        instances = gcp.fetch_instances(
            project=self.config.gcp.projects[0],
            zone=self.config.gcp.compute_zones[0],
        )

        # Calls the list command
        mock_clients["compute_v1"].list.assert_called_once()

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
        self.assertEqual(actual_instance.tags, ["web-server", "production", "backend"])

    def test_enumerate_instances_without_public_ips(self):
        expected_nic = models.GcpNetworkInterface(
            resource_id=FakeGcpInternalNetworkInterface.name,
            public_ip=None,
            internal_ip=FakeGcpInternalNetworkInterface.network_i_p,
            network=FakeGcpInternalNetworkInterface.network,
            network_attachment=FakeGcpInternalNetworkInterface.network_attachment,
            alias_ip_ranges=FakeGcpInternalNetworkInterface.alias_ip_ranges,
        )

        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp,
            compute_list_instance_response=[FakeGcpInternalInstance()],
        )
        instances = gcp.fetch_instances(
            project=self.config.gcp.projects[0],
            zone=self.config.gcp.compute_zones[0],
        )

        mock_clients["compute_v1"].list.assert_called_once()

        self.assertEqual(
            len(instances),
            1,
            f"Expected one instance, found {len(instances)}",
        )

        actual_nic = instances[0].network_interfaces[0]

        self.assertEqual(actual_nic.resource_id, expected_nic.resource_id)
        self.assertIsNone(actual_nic.public_ip)
        self.assertEqual(actual_nic.internal_ip, expected_nic.internal_ip)
        self.assertEqual(instances[0].tags, ["internal", "database"])

    def test_explore_only_returns_instances_with_external_ips(self):
        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp,
            compute_list_instance_response=[FakeGcpInternalInstance()],
        )
        instances = gcp.explore()

        self.assertEqual(mock_clients["compute_v1"].list.call_count, 6)
        self.assertEqual(
            len(instances),
            0,
            f"Expected no instances, found {len(instances)}",
        )

    def test_explore_only_returns_cloud_run_services_with_ingress(self):
        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp,
            cloud_run_list_service_response=[
                fake_service_with_no_ingress,
                fake_service,
            ],
        )
        instances = gcp.explore()

        self.assertEqual(mock_clients["run_v2"].list_services.call_count, 4)
        self.assertEqual(
            len(instances),
            len(self.config.gcp.projects) * len(self.config.gcp.regions),
            f"Expected {len(self.config.gcp.projects) * len(self.config.gcp.regions)} instances, found {len(instances)}",
        )

    def test_get_run_services(self):
        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp,
            cloud_run_list_service_response=[fake_service],
        )
        services = gcp.fetch_run_services(project="unittest", location="unittest")

        self.assertEqual(mock_clients["run_v2"].list_services.call_count, 1)
        self.assertEqual(len(services), 1)

        service = services[0]
        self.assertEqual(service.name, fake_service.name)
        self.assertEqual(service.uri, fake_service.uri)
        self.assertEqual(service.resource_id, fake_service.uid)
        self.assertEqual(service.created_by, fake_service.creator)
        self.assertEqual(service.creation_time, some_date)
        self.assertEqual(service.last_modified_by, fake_service.last_modifier)
        self.assertEqual(service.update_time, some_date)
        self.assertEqual(len(service.containers), 1)
        self.assertEqual(service.containers[0].name, fake_container.name)
        self.assertEqual(service.containers[0].image, fake_container.image)
        self.assertEqual(service.containers[0].command, fake_container.command)
        self.assertEqual(
            service.containers[0].network_ports[0],
            fake_container.ports[0].container_port,
        )
        self.assertEqual(service.ingress, fake_service.ingress.name)
        self.assertEqual(service.urls, fake_service.urls)

    def test_service_allows_ingress(self):
        service = models.GcpService.from_gcp(fake_service)
        self.assertTrue(service.allows_ingress())

        service_no_ingress = models.GcpService.from_gcp(fake_service_with_no_ingress)
        self.assertFalse(service_no_ingress.allows_ingress())


fake_firewall_rule = gcp_compute_v1_types.Firewall(
    id="12345678901234567890",
    name="allow-http-https",
    direction="INGRESS",
    priority=1000,
    network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
    allowed=[gcp_compute_v1_types.Allowed(I_p_protocol="tcp", ports=["80", "443"])],
    source_ranges=["0.0.0.0/0"],
    creation_timestamp="2025-01-01T00:00:00.000-00:00",
    disabled=False,
)


class TestGcpFirewalls(TestCase):
    def setUp(self):
        config = BytesIO(
            dedent(
                """
            [tool.gcp]
            enabled = true
            projects = ["test-project"]
            """
            ).encode("utf-8")
        )
        self.config = models.LuminautConfig.from_toml(config)

    def mock_firewall_client(self, gcp: Gcp, firewall_list_response=None) -> Mock:
        client = Mock()
        client.list.return_value = firewall_list_response or []
        gcp.get_firewall_client = Mock(return_value=client)
        return client

    def test_fetch_firewall_rules(self):
        gcp = Gcp(self.config)
        mock_client = self.mock_firewall_client(
            gcp, firewall_list_response=[fake_firewall_rule]
        )

        firewall_rules = gcp.fetch_firewall_rules(
            project="test-project", network="default"
        )

        expected_request = gcp_compute_v1_types.ListFirewallsRequest(
            project="test-project",
            filter='network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default"',
        )
        mock_client.list.assert_called_once_with(request=expected_request)

        self.assertEqual(len(firewall_rules), 1)

        rule = firewall_rules[0]
        self.assertEqual(rule.resource_id, "12345678901234567890")
        self.assertEqual(rule.name, "allow-http-https")
        self.assertEqual(rule.direction, models.Direction.INGRESS)
        self.assertEqual(rule.priority, 1000)
        self.assertEqual(rule.action, "ALLOW")
        self.assertEqual(rule.source_ranges, ["0.0.0.0/0"])
        self.assertEqual(len(rule.allowed_protocols), 1)
        self.assertEqual(rule.allowed_protocols[0]["IPProtocol"], "tcp")
        self.assertEqual(rule.allowed_protocols[0]["ports"], ["80", "443"])
        self.assertFalse(rule.disabled)


class TestGcpInstanceNetworks(TestCase):
    def test_get_networks_deduplication_and_parsing(self):
        # Test with multiple scenarios: single network, multiple networks, and duplicates
        nic1 = models.GcpNetworkInterface(
            resource_id="nic0",
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
            internal_ip="10.0.0.1",
        )

        nic2 = models.GcpNetworkInterface(
            resource_id="nic1",
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/custom-vpc",
            internal_ip="10.1.0.1",
        )

        nic3 = models.GcpNetworkInterface(
            resource_id="nic2",
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",  # duplicate
            internal_ip="10.0.0.2",
        )

        instance = models.GcpInstance(
            resource_id="instance-123",
            name="test-instance",
            network_interfaces=[nic1, nic2, nic3],
        )

        networks = instance.get_networks()

        # Should return 2 unique networks despite 3 interfaces
        self.assertEqual(len(networks), 2)
        self.assertIn("default", networks)
        self.assertIn("custom-vpc", networks)

    def test_get_networks_no_interfaces(self):
        # Test instance with no network interfaces
        instance = models.GcpInstance(
            resource_id="empty-instance", name="empty-instance", network_interfaces=[]
        )

        networks = instance.get_networks()
        self.assertEqual(len(networks), 0)

    def test_get_networks_none_network_values(self):
        # Test instance with None network values
        nic_with_none_network = models.GcpNetworkInterface(
            resource_id="nic0", network=None, internal_ip="10.0.0.1"
        )

        nic_with_valid_network = models.GcpNetworkInterface(
            resource_id="nic1",
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/valid-network",
            internal_ip="10.1.0.1",
        )

        instance = models.GcpInstance(
            resource_id="mixed-instance",
            name="mixed-instance",
            network_interfaces=[nic_with_none_network, nic_with_valid_network],
        )

        networks = instance.get_networks()
        # Should only return valid network, ignoring None values
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0], "valid-network")

    def test_instance_tags_edge_cases(self):
        # Test instance with no tags
        fake_no_tags = Mock()
        fake_no_tags.items = []

        instance_no_tags = models.GcpInstance(
            resource_id="no-tags-instance", name="no-tags-instance", tags=[]
        )

        self.assertEqual(instance_no_tags.tags, [])

        # Test from_gcp with empty tags
        fake_instance = Mock()
        fake_instance.id = "test-id"
        fake_instance.name = "test-name"
        fake_instance.network_interfaces = []
        fake_instance.creation_timestamp = "2025-01-01T00:00:00.000-00:00"
        fake_instance.zone = (
            "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a"
        )
        fake_instance.status = "RUNNING"
        fake_instance.description = "Test"
        fake_instance.tags = fake_no_tags

        parsed_instance = models.GcpInstance.from_gcp(fake_instance)
        self.assertEqual(parsed_instance.tags, [])
