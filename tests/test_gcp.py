import datetime
from collections.abc import Iterable
from io import BytesIO
from textwrap import dedent
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from google.cloud.compute_v1 import types as gcp_compute_v1_types
from google.cloud.run_v2 import types as gcp_run_v2_types
from google.protobuf.timestamp_pb2 import Timestamp

from luminaut import models
from luminaut.tools.gcp import Gcp
from luminaut.tools.gcp_audit_logs import GcpAuditLogs

fake_gcp_access_config = gcp_compute_v1_types.AccessConfig(nat_i_p="1.2.3.4")

fake_gcp_network_interface = gcp_compute_v1_types.NetworkInterface(
    access_configs=[fake_gcp_access_config],
    name="nic0",
    network_i_p="1.2.3.4",
    network="https://www.googleapis.com/compute/v1/projects/luminaut/global/networks/default",
    network_attachment="",
    alias_ip_ranges=[],
)


fake_gcp_instance = gcp_compute_v1_types.Instance(
    id=123,
    name="test-instance",
    network_interfaces=[fake_gcp_network_interface],
    creation_timestamp="2025-05-19T05:35:09.886-07:00",
    zone="https://www.googleapis.com/compute/v1/projects/luminaut/zones/us-central1-c",
    status="RUNNING",
    description="Test instance",
    tags=gcp_compute_v1_types.Tags(items=["web-server", "production", "backend"]),
)

fake_gcp_internal_network_interface = gcp_compute_v1_types.NetworkInterface(
    access_configs=[],
    name="nic0",
    network_i_p="10.0.0.1",
    network="https://www.googleapis.com/compute/v1/projects/luminaut/global/networks/default",
    network_attachment="",
    alias_ip_ranges=[],
)

fake_gcp_internal_instance_tags = gcp_compute_v1_types.Tags(
    items=["internal", "database"]
)


fake_gcp_instance_with_no_public_ip = gcp_compute_v1_types.Instance(
    id=456,
    name="test-instance",
    network_interfaces=[fake_gcp_internal_network_interface],
    creation_timestamp="2025-05-19T05:35:09.886-07:00",
    zone="https://www.googleapis.com/compute/v1/projects/luminaut/zones/us-central1-c",
    status="RUNNING",
    description="Test instance",
    tags=fake_gcp_internal_instance_tags,
)

fake_container = gcp_run_v2_types.Container(
    name="test-container",
    image="gcr.io/test-project/test-image",
    command=["python", "app.py"],
    ports=[gcp_run_v2_types.ContainerPort(name="http1", container_port=8080)],
)

some_date = datetime.datetime(2025, 5, 19, 5, 35, 9, tzinfo=datetime.UTC)

fake_service = gcp_run_v2_types.Service(
    name="projects/test-project/locations/us-central1/services/test-service",
    uid="12345678-1234-1234-1234-123456789012",
    uri="https://test-service-12345678-uc.a.run.app",
    creator="foo",
    last_modifier="bar",
    template=gcp_run_v2_types.RevisionTemplate(containers=[fake_container]),
    ingress=gcp_run_v2_types.IngressTraffic.INGRESS_TRAFFIC_ALL,
    urls=["https://test-service-12345678-uc.a.run.app"],
    create_time=Timestamp(seconds=int(some_date.timestamp())),
    update_time=Timestamp(seconds=int(some_date.timestamp())),
)

fake_service_with_no_ingress = gcp_run_v2_types.Service(
    name="projects/test-project/locations/us-central1/services/test-service-ingress-none",
    uid="12345678-1234-1234-1234-123456789013",
    uri="https://test-service-12345678-uc.a.run.app",
    creator="foo",
    last_modifier="bar",
    template=gcp_run_v2_types.RevisionTemplate(containers=[fake_container]),
    ingress=gcp_run_v2_types.IngressTraffic.INGRESS_TRAFFIC_NONE,
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
        compute_list_instance_response: Iterable[gcp_compute_v1_types.Instance]
        | None = None,
        cloud_run_list_service_response: Iterable[gcp_run_v2_types.Service]
        | None = None,
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
            compute_list_instance_response=[fake_gcp_instance],
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
            resource_id=fake_gcp_network_interface.name,
            public_ip=fake_gcp_access_config.nat_i_p,
            internal_ip=fake_gcp_network_interface.network_i_p,
            network=fake_gcp_network_interface.network,
            network_attachment=fake_gcp_network_interface.network_attachment,
            alias_ip_ranges=[
                str(x) for x in fake_gcp_network_interface.alias_ip_ranges
            ],
        )
        expected_instance = models.GcpInstance(
            resource_id=str(fake_gcp_instance.id),
            name=fake_gcp_instance.name,
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
            status=fake_gcp_instance.status,
            description=fake_gcp_instance.description,
        )

        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp, compute_list_instance_response=[fake_gcp_instance]
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
            resource_id=fake_gcp_internal_network_interface.name,
            public_ip=None,
            internal_ip=fake_gcp_internal_network_interface.network_i_p,
            network=fake_gcp_internal_network_interface.network,
            network_attachment=fake_gcp_internal_network_interface.network_attachment,
            alias_ip_ranges=[
                str(x) for x in fake_gcp_internal_network_interface.alias_ip_ranges
            ],
        )

        gcp = Gcp(self.config)
        mock_clients = self.mock_gcp_clients(
            gcp,
            compute_list_instance_response=[fake_gcp_instance_with_no_public_ip],
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
            compute_list_instance_response=[fake_gcp_instance_with_no_public_ip],
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
        self.assertEqual(
            service.name, GcpAuditLogs._extract_service_name(fake_service.name)
        )
        self.assertEqual(service.uri, fake_service.uri)
        self.assertEqual(service.resource_id, fake_service.name)
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
    target_tags=["web-server", "frontend"],
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

    def mock_firewall_client(
        self,
        gcp: Gcp,
        firewall_list_response: Iterable[gcp_compute_v1_types.Firewall] | None = None,
    ) -> Mock:
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
        self.assertEqual(rule.action, models.FirewallAction.ALLOW)
        self.assertEqual(rule.source_ranges, ["0.0.0.0/0"])
        self.assertEqual(len(rule.allowed_protocols), 1)
        self.assertEqual(rule.allowed_protocols[0]["IPProtocol"], "tcp")
        self.assertEqual(rule.allowed_protocols[0]["ports"], ["80", "443"])
        self.assertFalse(rule.disabled)
        self.assertEqual(rule.target_tags, ["web-server", "frontend"])

    def test_firewall_rule_with_no_target_tags(self):
        # Test firewall rule with no target tags
        fake_rule_no_tags = gcp_compute_v1_types.Firewall(
            id="987654321",
            name="allow-all",
            direction="INGRESS",
            priority=2000,
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
            allowed=[gcp_compute_v1_types.Allowed(I_p_protocol="tcp", ports=["22"])],
            source_ranges=["10.0.0.0/8"],
            creation_timestamp="2025-01-01T00:00:00.000-00:00",
            disabled=False,
            target_tags=[],  # Empty tags
        )

        gcp = Gcp(self.config)
        self.mock_firewall_client(gcp, firewall_list_response=[fake_rule_no_tags])

        firewall_rules = gcp.fetch_firewall_rules(
            project="test-project", network="default"
        )

        self.assertEqual(len(firewall_rules), 1)
        rule = firewall_rules[0]
        self.assertEqual(rule.target_tags, [])

    def test_get_applicable_firewall_rules(self):
        # Test instance with tags that match firewall rules
        instance = models.GcpInstance(
            resource_id="test-instance",
            name="test-instance",
            network_interfaces=[
                models.GcpNetworkInterface(
                    resource_id="nic0",
                    network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                    internal_ip="10.0.0.1",
                )
            ],
            tags=["web-server", "frontend"],
        )

        gcp = Gcp(self.config)
        mock_client = self.mock_firewall_client(
            gcp, firewall_list_response=[fake_firewall_rule]
        )

        firewall_rules = gcp.get_applicable_firewall_rules(instance)

        # Should call fetch_firewall_rules for the default network
        expected_request = gcp_compute_v1_types.ListFirewallsRequest(
            project="test-project",
            filter='network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default"',
        )
        mock_client.list.assert_called_once_with(request=expected_request)

        # Should return GcpInstanceFirewallRules with matching rule
        self.assertIsInstance(firewall_rules, models.GcpFirewallRules)
        self.assertEqual(len(firewall_rules.rules), 1)
        self.assertEqual(firewall_rules.rules[0].name, "allow-http-https")

    def test_get_applicable_firewall_rules_no_matching_tags(self):
        # Test instance with tags that don't match firewall rules
        instance = models.GcpInstance(
            resource_id="test-instance",
            name="test-instance",
            network_interfaces=[
                models.GcpNetworkInterface(
                    resource_id="nic0",
                    network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                    internal_ip="10.0.0.1",
                )
            ],
            tags=["database", "backend"],  # No overlap with rule's target_tags
        )

        gcp = Gcp(self.config)
        self.mock_firewall_client(gcp, firewall_list_response=[fake_firewall_rule])

        firewall_rules = gcp.get_applicable_firewall_rules(instance)

        # Should return empty rules since tags don't match
        self.assertEqual(len(firewall_rules.rules), 0)

    def test_get_applicable_firewall_rules_no_target_tags(self):
        # Test firewall rule with no target tags (applies to all instances)
        rule_no_tags = gcp_compute_v1_types.Firewall(
            id="987654321",
            name="allow-all",
            direction="INGRESS",
            priority=2000,
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
            allowed=[gcp_compute_v1_types.Allowed(I_p_protocol="tcp", ports=["22"])],
            source_ranges=["10.0.0.0/8"],
            creation_timestamp="2025-01-01T00:00:00.000-00:00",
            disabled=False,
            target_tags=[],  # No target tags = applies to all
        )

        instance = models.GcpInstance(
            resource_id="test-instance",
            name="test-instance",
            network_interfaces=[
                models.GcpNetworkInterface(
                    resource_id="nic0",
                    network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                    internal_ip="10.0.0.1",
                )
            ],
            tags=["database"],
        )

        gcp = Gcp(self.config)
        self.mock_firewall_client(gcp, firewall_list_response=[rule_no_tags])

        firewall_rules = gcp.get_applicable_firewall_rules(instance)

        # Should return the rule since it has no target tags
        self.assertEqual(len(firewall_rules.rules), 1)
        self.assertEqual(firewall_rules.rules[0].name, "allow-all")


class TestGcpScanResultsIntegration(TestCase):
    def setUp(self):
        config = BytesIO(
            dedent(
                """
            [tool.gcp]
            enabled = true
            projects = ["test-project"]
            regions = ["us-central1"]
            compute_zones = ["us-central1-a"]
            """
            ).encode("utf-8")
        )
        self.config = models.LuminautConfig.from_toml(config)

    def mock_gcp_and_firewall_clients(
        self,
        gcp: Gcp,
        instance_response: Iterable[gcp_compute_v1_types.Instance] | None = None,
        firewall_response: Iterable[gcp_compute_v1_types.Firewall] | None = None,
        services_response: Iterable[gcp_run_v2_types.Service] | None = None,
    ) -> dict[str, Mock]:
        clients = {}

        # Mock compute client for instances
        clients["compute_v1"] = Mock()
        clients["compute_v1"].list.return_value = instance_response or []
        gcp.get_compute_v1_client = Mock(return_value=clients["compute_v1"])

        # Mock firewall client
        clients["firewall"] = Mock()
        clients["firewall"].list.return_value = firewall_response or []
        gcp.get_firewall_client = Mock(return_value=clients["firewall"])

        # Mock run client (not used in this test)
        clients["run_v2"] = Mock()
        clients["run_v2"].list_services.return_value = services_response or []
        gcp.get_run_v2_services_client = Mock(return_value=clients["run_v2"])

        return clients

    def test_find_instances_includes_firewall_findings(self):
        # Test that find_instances includes firewall findings in scan results
        gcp = Gcp(self.config)
        self.mock_gcp_and_firewall_clients(
            gcp,
            instance_response=[fake_gcp_instance],
            firewall_response=[fake_firewall_rule],
        )

        scan_results = gcp.find_instances(project="test-project", zone="us-central1-a")

        # Should have one scan result for the instance with public IP
        self.assertEqual(len(scan_results), 1)

        scan_result = scan_results[0]
        self.assertEqual(scan_result.ip, fake_gcp_access_config.nat_i_p)

        # Should have one finding with both instance and firewall resources
        self.assertEqual(len(scan_result.findings), 1)

        finding = scan_result.findings[0]
        self.assertEqual(finding.tool, "GCP Instance")

        # Should have two resources: instance + firewall rules
        self.assertEqual(len(finding.resources), 2)

        # Check instance resource
        instance_resource = finding.resources[0]
        self.assertIsInstance(instance_resource, models.GcpInstance)

        # Check firewall rules resource
        firewall_rules_resource = finding.resources[1]
        self.assertIsInstance(firewall_rules_resource, models.GcpFirewallRules)
        self.assertIsInstance(firewall_rules_resource, models.GcpFirewallRules)
        if isinstance(firewall_rules_resource, models.GcpFirewallRules):
            # Though covered by the above assertion, this is to inform the type checker
            self.assertEqual(len(firewall_rules_resource.rules), 1)
            self.assertEqual(firewall_rules_resource.rules[0].name, "allow-http-https")

    def test_find_instances_with_no_firewall_rules(self):
        # Test that find_instances handles instances with no applicable firewall rules
        gcp = Gcp(self.config)
        self.mock_gcp_and_firewall_clients(
            gcp,
            instance_response=[fake_gcp_instance],
            firewall_response=[],  # No firewall rules
        )

        scan_results = gcp.find_instances(project="test-project", zone="us-central1-a")

        # Should still have scan result but with empty firewall rules
        self.assertEqual(len(scan_results), 1)
        scan_result = scan_results[0]

        # Should have one finding (instance only, no firewall rules appended since they're empty)
        self.assertEqual(len(scan_result.findings), 1)

        finding = scan_result.findings[0]
        self.assertEqual(finding.tool, "GCP Instance")

        # Should only have the instance resource (no firewall rules since they're empty)
        self.assertEqual(len(finding.resources), 1)
        instance_resource = finding.resources[0]
        self.assertIsInstance(instance_resource, models.GcpInstance)

    def test_get_applicable_firewall_rules_no_networks(self):
        # Test instance with no network interfaces
        instance = models.GcpInstance(
            resource_id="test-instance",
            name="test-instance",
            network_interfaces=[],  # No network interfaces
            tags=["web-server"],
        )

        gcp = Gcp(self.config)
        firewall_rules = gcp.get_applicable_firewall_rules(instance)

        # Should return empty rules since there are no networks
        self.assertEqual(len(firewall_rules.rules), 0)

    def test_gcp_instance_firewall_rules_bool_behavior(self):
        # Test __bool__ method behavior for GcpInstanceFirewallRules

        # Empty firewall rules should evaluate to False
        empty_rules = models.GcpFirewallRules()
        self.assertFalse(empty_rules)
        self.assertFalse(bool(empty_rules))

        # Firewall rules with content should evaluate to True
        rule = models.GcpFirewallRule(
            resource_id="test-rule",
            name="test-rule",
            direction=models.Direction.INGRESS,
            priority=1000,
            action=models.FirewallAction.ALLOW,
        )
        rules_with_content = models.GcpFirewallRules(rules=[rule])
        self.assertTrue(rules_with_content)
        self.assertTrue(bool(rules_with_content))

    def test_find_instances_with_audit_logs_enabled(self):
        """Test that audit logs are queried when enabled and events are added to scan findings."""
        # Enable audit logs in config
        self.config.gcp.audit_logs.enabled = True

        # Create a mock timeline event
        mock_timeline_event = models.TimelineEvent(
            timestamp=datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.UTC),
            source="GCP Audit Logs",
            event_type=models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
            resource_id=str(fake_gcp_instance.id),
            resource_type=models.ResourceType.GCP_Instance,
            message="Instance created by test@example.com",
        )

        gcp = Gcp(self.config)

        # Mock the compute client
        self.mock_gcp_and_firewall_clients(
            gcp,
            instance_response=[fake_gcp_instance],
        )

        # Mock the audit logs service
        with patch("luminaut.tools.gcp.GcpAuditLogs") as mock_audit_logs_class:
            mock_audit_service = MagicMock()
            mock_audit_logs_class.return_value = mock_audit_service
            mock_audit_service.query_instance_events.return_value = [
                mock_timeline_event
            ]

            # Call find_instances
            scan_results = gcp.find_instances("test-project", "us-central1-a")

            # Verify audit logs service was called
            mock_audit_logs_class.assert_called_once_with(
                "test-project", self.config.gcp.audit_logs
            )
            mock_audit_service.query_instance_events.assert_called_once()

            # Verify scan results contain the audit log event
            self.assertEqual(len(scan_results), 1)
            scan_result = scan_results[0]
            self.assertEqual(len(scan_result.findings), 1)

            scan_finding = scan_result.findings[0]
            self.assertEqual(len(scan_finding.events), 1)
            self.assertEqual(scan_finding.events[0], mock_timeline_event)

    def test_find_instances_with_audit_logs_disabled(self):
        """Test that audit logs are not queried when disabled."""
        # Disable audit logs in config
        self.config.gcp.audit_logs.enabled = False

        gcp = Gcp(self.config)

        # Mock the compute client
        self.mock_gcp_and_firewall_clients(
            gcp,
            instance_response=[fake_gcp_instance],
        )

        # Mock the audit logs service - it should not be called
        with patch("luminaut.tools.gcp.GcpAuditLogs") as mock_audit_logs_class:
            # Call find_instances
            scan_results = gcp.find_instances("test-project", "us-central1-a")

            # Verify audit logs service was NOT called
            mock_audit_logs_class.assert_not_called()

            # Verify scan results don't contain audit log events
            self.assertEqual(len(scan_results), 1)
            scan_result = scan_results[0]
            self.assertEqual(len(scan_result.findings), 1)

            scan_finding = scan_result.findings[0]
            self.assertEqual(len(scan_finding.events), 0)

    def test_find_services_with_audit_logs_enabled(self):
        """Test that Cloud Run service audit logs are queried when enabled and events are added to scan findings."""
        # Enable audit logs in config
        self.config.gcp.audit_logs.enabled = True

        # Create a mock timeline event for a Cloud Run service
        mock_timeline_event = models.TimelineEvent(
            timestamp=datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.UTC),
            source="GCP Audit Logs",
            event_type=models.TimelineEventType.SERVICE_CREATED,
            resource_id=fake_service.name,
            resource_type=models.ResourceType.GCP_Service,
            message="Service created by test@example.com",
        )

        gcp = Gcp(self.config)

        self.mock_gcp_and_firewall_clients(gcp, services_response=[fake_service])

        # Mock the audit logs service
        with patch("luminaut.tools.gcp.GcpAuditLogs") as mock_audit_logs_class:
            mock_audit_service = MagicMock()
            mock_audit_logs_class.return_value = mock_audit_service
            mock_audit_service.query_service_events.return_value = [mock_timeline_event]

            # Call find_services
            scan_results = gcp.find_services("test-project", "us-central1")

            # Verify audit logs service was called
            mock_audit_logs_class.assert_called_once_with(
                "test-project", self.config.gcp.audit_logs
            )
            mock_audit_service.query_service_events.assert_called_once()

            # Verify scan results contain the audit log event
            self.assertEqual(len(scan_results), 1)
            scan_result = scan_results[0]
            self.assertEqual(len(scan_result.findings), 1)

            scan_finding = scan_result.findings[0]
            self.assertEqual(len(scan_finding.events), 1)
            self.assertEqual(scan_finding.events[0], mock_timeline_event)
            self.assertEqual(scan_finding.tool, "GCP Run Service")

    def test_find_services_with_audit_logs_disabled(self):
        """Test that Cloud Run service audit logs are not queried when disabled."""
        # Disable audit logs in config
        self.config.gcp.audit_logs.enabled = False

        gcp = Gcp(self.config)

        self.mock_gcp_and_firewall_clients(gcp, services_response=[fake_service])

        # Mock the audit logs service - it should not be called
        with patch("luminaut.tools.gcp.GcpAuditLogs") as mock_audit_logs_class:
            # Call find_services
            scan_results = gcp.find_services("test-project", "us-central1")

            # Verify audit logs service was NOT called
            mock_audit_logs_class.assert_not_called()

            # Verify scan results don't contain audit log events
            self.assertEqual(len(scan_results), 1)
            scan_result = scan_results[0]
            self.assertEqual(len(scan_result.findings), 1)

            scan_finding = scan_result.findings[0]
            self.assertEqual(len(scan_finding.events), 0)
            self.assertEqual(scan_finding.tool, "GCP Run Service")

    def test_find_services_with_no_ingress_skips_audit_logs(self):
        """Test that services without external ingress are skipped and audit logs are still processed."""
        # Enable audit logs in config
        self.config.gcp.audit_logs.enabled = True

        gcp = Gcp(self.config)

        self.mock_gcp_and_firewall_clients(
            gcp, services_response=[fake_service_with_no_ingress]
        )

        # Mock the audit logs service
        with patch("luminaut.tools.gcp.GcpAuditLogs") as mock_audit_logs_class:
            mock_audit_service = MagicMock()
            mock_audit_logs_class.return_value = mock_audit_service
            mock_audit_service.query_service_events.return_value = []

            # Call find_services
            scan_results = gcp.find_services("test-project", "us-central1")

            # Verify audit logs service was still called (for all services discovered)
            mock_audit_logs_class.assert_called_once_with(
                "test-project", self.config.gcp.audit_logs
            )
            mock_audit_service.query_service_events.assert_called_once()

            # But no scan results should be returned since service has no ingress
            self.assertEqual(len(scan_results), 0)


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


class TestGcpNetworkInterface(TestCase):
    def test_get_project_valid_network_url(self):
        # Test extracting project from valid network URL
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
            internal_ip="10.0.0.1",
        )

        project = nic.get_project_name()
        self.assertEqual(project, "test-project")

    def test_get_project_no_network(self):
        # Test with no network URL
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network=None,
            internal_ip="10.0.0.1",
        )

        project = nic.get_project_name()
        self.assertIsNone(project)

    def test_get_project_invalid_network_url(self):
        # Test with malformed network URL
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network="invalid-url-format",
            internal_ip="10.0.0.1",
        )

        project = nic.get_project_name()
        self.assertIsNone(project)

    def test_get_project_empty_network(self):
        # Test with empty network string
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network="",
            internal_ip="10.0.0.1",
        )

        project = nic.get_project_name()
        self.assertIsNone(project)

    def test_get_network_name_valid_network_url(self):
        # Test extracting network name from valid network URL
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network="https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
            internal_ip="10.0.0.1",
        )

        network_name = nic.get_network_name()
        self.assertEqual(network_name, "default")

    def test_get_network_name_no_network(self):
        # Test with no network URL
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network=None,
            internal_ip="10.0.0.1",
        )

        network_name = nic.get_network_name()
        self.assertIsNone(network_name)

    def test_get_network_name_invalid_network_url(self):
        # Test with malformed network URL
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network="invalid-url-format",
            internal_ip="10.0.0.1",
        )

        network_name = nic.get_network_name()
        self.assertIsNone(network_name)

    def test_get_network_name_empty_network(self):
        # Test with empty network string
        nic = models.GcpNetworkInterface(
            resource_id="nic0",
            network="",
            internal_ip="10.0.0.1",
        )

        network_name = nic.get_network_name()
        self.assertIsNone(network_name)

    def test_firewall_rules_caching(self):
        # Test that firewall rules are cached properly
        config = models.LuminautConfig()
        gcp = Gcp(config)

        # Mock the firewall client
        mock_client = Mock()
        mock_firewall_rule = Mock()
        mock_firewall_rule.id = "rule-123"
        mock_firewall_rule.name = "allow-http"
        mock_firewall_rule.direction = "INGRESS"
        mock_firewall_rule.priority = 1000
        mock_firewall_rule.allowed = [Mock()]
        mock_firewall_rule.allowed[0].I_p_protocol = "tcp"
        mock_firewall_rule.allowed[0].ports = ["80"]
        mock_firewall_rule.source_ranges = ["0.0.0.0/0"]
        mock_firewall_rule.creation_timestamp = "2025-01-01T00:00:00.000Z"
        mock_firewall_rule.disabled = False
        mock_firewall_rule.target_tags = []

        mock_client.list.return_value = [mock_firewall_rule]
        gcp.get_firewall_client = Mock(return_value=mock_client)

        # First call should fetch from API
        rules1 = gcp.fetch_firewall_rules("test-project", "default")
        self.assertEqual(len(rules1), 1)
        self.assertEqual(rules1[0].name, "allow-http")

        # Verify API was called once
        self.assertEqual(mock_client.list.call_count, 1)

        # Second call should use cache
        rules2 = gcp.fetch_firewall_rules("test-project", "default")
        self.assertEqual(len(rules2), 1)
        self.assertEqual(rules2[0].name, "allow-http")

        # Verify API was still only called once (cached result used)
        self.assertEqual(mock_client.list.call_count, 1)

        # Clear cache and verify it works
        gcp.clear_firewall_rules_cache()
        rules3 = gcp.fetch_firewall_rules("test-project", "default")
        self.assertEqual(len(rules3), 1)

        # Verify API was called again after cache clear
        self.assertEqual(mock_client.list.call_count, 2)
