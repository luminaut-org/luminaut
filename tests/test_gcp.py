import datetime
from io import BytesIO
from textwrap import dedent
from unittest import TestCase
from unittest.mock import Mock

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


class FakeGcpInstance:
    id = "abc123"
    name = "test-instance"
    network_interfaces = [FakeGcpNetworkInterface()]
    creation_timestamp = "2025-05-19T05:35:09.886-07:00"
    zone = "https://www.googleapis.com/compute/v1/projects/luminaut/zones/us-central1-c"
    status = "RUNNING"
    description = "Test instance"


class FakeGcpInternalNetworkInterface:
    access_configs = []
    name = "nic0"
    network_i_p = "10.0.0.1"
    network = "https://www.googleapis.com/compute/v1/projects/luminaut/global/networks/default"
    network_attachment = ""
    alias_ip_ranges = []


class FakeGcpInternalInstance:
    id = "abc123"
    name = "test-instance"
    network_interfaces = [FakeGcpInternalNetworkInterface()]
    creation_timestamp = "2025-05-19T05:35:09.886-07:00"
    zone = "https://www.googleapis.com/compute/v1/projects/luminaut/zones/us-central1-c"
    status = "RUNNING"
    description = "Test instance"


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
