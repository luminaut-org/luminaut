import unittest
from datetime import UTC, datetime, timedelta
from io import BytesIO
from unittest.mock import MagicMock, patch

from luminaut import models
from luminaut.tools.gcp_audit_logs import GcpAuditLogs

sample_toml_config_with_audit_logs = b"""
[tool.gcp]
enabled = true
projects = ["test-project"]
regions = ["us-central1"]

[tool.gcp.audit_logs]
enabled = true
start_time = "2024-01-01T00:00:00Z"
end_time = "2024-01-02T00:00:00Z"
"""

sample_toml_config_with_disabled_audit_logs = b"""
[tool.gcp]
enabled = true
projects = ["test-project"]

[tool.gcp.audit_logs]
enabled = false
"""


class TestGcpAuditLogsConfig(unittest.TestCase):
    def test_audit_logs_config_enabled(self):
        """Test that GCP audit logs configuration is properly parsed when enabled."""
        config = models.LuminautConfig.from_toml(
            BytesIO(sample_toml_config_with_audit_logs)
        )

        self.assertTrue(config.gcp.audit_logs.enabled)
        self.assertEqual(
            config.gcp.audit_logs.start_time, datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        )
        self.assertEqual(
            config.gcp.audit_logs.end_time, datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)
        )

    def test_audit_logs_config_disabled(self):
        """Test that GCP audit logs configuration is properly parsed when disabled."""
        config = models.LuminautConfig.from_toml(
            BytesIO(sample_toml_config_with_disabled_audit_logs)
        )

        self.assertFalse(config.gcp.audit_logs.enabled)
        self.assertIsNone(config.gcp.audit_logs.start_time)
        self.assertIsNone(config.gcp.audit_logs.end_time)

    def test_audit_logs_config_defaults(self):
        """Test that GCP audit logs configuration has proper defaults."""
        config = models.LuminautConfigToolGcp()

        # Should have audit_logs with enabled=True by default
        self.assertTrue(config.audit_logs.enabled)
        self.assertIsNone(config.audit_logs.start_time)
        self.assertIsNone(config.audit_logs.end_time)


class TestGcpAuditLogsService(unittest.TestCase):
    def setUp(self):
        self.config = models.LuminautConfig()
        self.config.gcp.audit_logs.enabled = True
        self.config.gcp.audit_logs.start_time = datetime(
            2024, 1, 1, 0, 0, 0, tzinfo=UTC
        )
        self.config.gcp.audit_logs.end_time = datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)

        self.mock_instance = models.GcpInstance(
            resource_id="123456789",
            name="test-instance",
            creation_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            zone="us-central1-a",
            status="RUNNING",
        )

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_audit_logs_service_initialization(self, mock_logging_client):
        """Test that GcpAuditLogs service initializes correctly."""
        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        self.assertEqual(audit_service.project, "test-project")
        self.assertEqual(audit_service.config, self.config.gcp.audit_logs)

        # Client should not be created until first access (lazy initialization)
        mock_logging_client.assert_not_called()

        # Accessing the client property should create it
        _ = audit_service.client
        mock_logging_client.assert_called_once()

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_query_instance_events_filters(self, mock_logging_client):
        """Test that audit log queries use correct filters for instance events."""
        mock_client = MagicMock()
        mock_logging_client.return_value = mock_client
        mock_client.list_entries.return_value = []

        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        # Mock instances to query
        instances = [self.mock_instance]

        # Call the method we expect to exist
        events = audit_service.query_instance_events(instances)

        # Verify the client was called with proper filters
        mock_client.list_entries.assert_called_once()
        call_args = mock_client.list_entries.call_args

        # Check that filter includes expected components
        filter_str = call_args[1]["filter_"]
        self.assertIn(
            'logName:"projects/test-project/logs/cloudaudit.googleapis.com%2Factivity"',
            filter_str,
        )
        self.assertIn('protoPayload.serviceName="compute.googleapis.com"', filter_str)
        self.assertIn("protoPayload.methodName:", filter_str)
        self.assertIn("compute.instances.insert", filter_str)
        self.assertIn("compute.instances.delete", filter_str)
        self.assertIn("compute.instances.start", filter_str)
        self.assertIn("compute.instances.stop", filter_str)

        # Should return empty list when no log entries
        self.assertEqual(events, [])

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_parse_audit_log_entries_all_instance_events(self, mock_logging_client):
        """Test parsing of all supported instance audit log entries."""
        mock_client = MagicMock()
        mock_logging_client.return_value = mock_client

        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        # Test cases for all supported instance events
        test_cases = [
            {
                "method_name": "beta.compute.instances.insert",
                "principal_email": "test@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
                "expected_message_content": ["created", "test@example.com"],
            },
            {
                "method_name": "v1.compute.instances.delete",
                "principal_email": "admin@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_TERMINATED,
                "expected_message_content": ["deleted", "admin@example.com"],
            },
            {
                "method_name": "v1.compute.instances.start",
                "principal_email": "user@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
                "expected_message_content": ["started", "user@example.com"],
            },
            {
                "method_name": "v1.compute.instances.stop",
                "principal_email": "user@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
                "expected_message_content": ["stopped", "user@example.com"],
            },
            {
                "method_name": "beta.compute.instances.suspend",
                "principal_email": "user@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
                "expected_message_content": ["suspended", "user@example.com"],
            },
            {
                "method_name": "beta.compute.instances.resume",
                "principal_email": "user@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
                "expected_message_content": ["resumed", "user@example.com"],
            },
        ]

        for test_case in test_cases:
            with self.subTest(method_name=test_case["method_name"]):
                # Mock audit log entry
                mock_entry = MagicMock()
                mock_entry.timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
                mock_entry.payload = {
                    "methodName": test_case["method_name"],
                    "resourceName": "projects/test-project/zones/us-central1-a/instances/test-instance",
                    "authenticationInfo": {
                        "principalEmail": test_case["principal_email"]
                    },
                }

                # Create name-to-resource-ID mapping
                name_to_resource_id = {"test-instance": "123456789"}

                # Parse the entry
                timeline_event = audit_service._parse_instance_audit_log_entry(
                    mock_entry, name_to_resource_id
                )

                # Verify common fields
                self.assertIsInstance(timeline_event, models.TimelineEvent)
                if timeline_event is None:
                    # Needed for pyright as it cannot infer this based on the prior assertion.
                    self.fail("Parsed timeline event should not be None")

                self.assertEqual(
                    timeline_event.event_type, test_case["expected_event_type"]
                )
                self.assertEqual(timeline_event.resource_id, "123456789")
                self.assertEqual(
                    timeline_event.resource_type, models.ResourceType.GCP_Instance
                )
                self.assertEqual(timeline_event.timestamp, mock_entry.timestamp)
                self.assertEqual(timeline_event.source, "GCP Audit Logs")

                # Verify message content contains expected strings
                for expected_content in test_case["expected_message_content"]:
                    self.assertIn(expected_content, timeline_event.message.lower())

    def test_extract_resource_name_from_path(self):
        """Test extraction of resource name from GCP resource path."""
        # Create service without triggering client initialization
        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        # Test instance resource path
        resource_path = (
            "projects/test-project/zones/us-central1-a/instances/test-instance"
        )
        resource_name = audit_service._extract_resource_name(resource_path)
        self.assertEqual(resource_name, "test-instance")

        # Test invalid resource path
        invalid_path = "invalid/path"
        resource_name = audit_service._extract_resource_name(invalid_path)
        self.assertEqual(
            resource_name, invalid_path
        )  # Should return original if can't parse

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_disabled_audit_logs(self, mock_logging_client):
        """Test that audit logs service respects disabled configuration."""
        config = models.LuminautConfig()
        config.gcp.audit_logs.enabled = False

        # Should be able to create service even when disabled
        audit_service = GcpAuditLogs("test-project", config.gcp.audit_logs)

        # But querying should return empty list
        events = audit_service.query_instance_events([self.mock_instance])
        self.assertEqual(events, [])

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    @patch("luminaut.tools.gcp_audit_logs.datetime")
    def test_default_time_range_when_none_specified(
        self, mock_datetime, mock_logging_client
    ):
        """Test that a default 30-day time range is applied when no time range is specified."""
        # Mock current time
        mock_now = datetime(2024, 2, 1, 12, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = mock_now
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

        mock_client = MagicMock()
        mock_logging_client.return_value = mock_client
        mock_client.list_entries.return_value = []

        # Create config with no time range specified
        config = models.LuminautConfig()
        config.gcp.audit_logs.enabled = True
        # Explicitly set both to None to test default behavior
        config.gcp.audit_logs.start_time = None
        config.gcp.audit_logs.end_time = None

        audit_service = GcpAuditLogs("test-project", config.gcp.audit_logs)

        # Call query_instance_events
        events = audit_service.query_instance_events([self.mock_instance])

        # Verify the client was called with the default time range
        mock_client.list_entries.assert_called_once()
        call_args = mock_client.list_entries.call_args
        filter_str = call_args[1]["filter_"]

        # Should include both start and end timestamps for 30-day window
        expected_start = mock_now - timedelta(days=30)
        expected_start_str = expected_start.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        expected_end_str = mock_now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        self.assertIn(f'timestamp>="{expected_start_str}"', filter_str)
        self.assertIn(f'timestamp<="{expected_end_str}"', filter_str)

        # Should return empty list when no log entries
        self.assertEqual(events, [])


class TestGcpAuditLogsServiceCloudRun(unittest.TestCase):
    """Test GCP Audit Logs service functionality for Cloud Run services."""

    def setUp(self):
        """Set up test configuration and mock objects."""
        self.config = models.LuminautConfig()
        self.config.gcp.audit_logs.enabled = True
        self.config.gcp.audit_logs.start_time = datetime(
            2024, 1, 1, 0, 0, 0, tzinfo=UTC
        )
        self.config.gcp.audit_logs.end_time = datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)

        # Create mock Cloud Run service
        self.mock_service = models.GcpService(
            resource_id="projects/test-project/locations/us-central1/services/test-service",
            name="test-service",
            uri="https://test-service-123456789-uc.a.run.app",
        )

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_query_service_events_filters(self, mock_logging_client):
        """Test that service audit log filters are properly constructed."""
        mock_client = MagicMock()
        mock_logging_client.return_value = mock_client
        mock_client.list_entries.return_value = []

        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)
        events = audit_service.query_service_events([self.mock_service])

        # Verify the client was called with correct filter
        mock_client.list_entries.assert_called_once()
        call_args = mock_client.list_entries.call_args
        filter_str = call_args[1]["filter_"]

        # Check that Cloud Run service name is used
        self.assertIn('protoPayload.serviceName="run.googleapis.com"', filter_str)

        # Check that Cloud Run method names are included
        self.assertIn("google.cloud.run.v1.Services.CreateService", filter_str)
        self.assertIn("google.cloud.run.v1.Services.DeleteService", filter_str)
        self.assertIn("google.cloud.run.v1.Services.ReplaceService", filter_str)
        self.assertIn("google.cloud.run.v1.Revisions.DeleteRevision", filter_str)

        # Check that service resource name is included (using correct audit log format)
        self.assertIn(
            '"namespaces/test-project/services/test-service"',
            filter_str,
        )

        # Should return empty list when no log entries
        self.assertEqual(events, [])

    def test_parse_service_audit_log_entries_all_events(self):
        """Test parsing of all supported Cloud Run service audit log entries."""
        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)
        name_to_resource_id = {"test-service": self.mock_service.resource_id}

        test_cases = [
            {
                "method_name": "google.cloud.run.v1.Services.CreateService",
                "expected_event_type": models.TimelineEventType.SERVICE_CREATED,
                "expected_message_content": ["service", "created"],
            },
            {
                "method_name": "google.cloud.run.v1.Services.DeleteService",
                "expected_event_type": models.TimelineEventType.SERVICE_DELETED,
                "expected_message_content": ["service", "deleted"],
            },
            {
                "method_name": "google.cloud.run.v1.Services.ReplaceService",
                "expected_event_type": models.TimelineEventType.SERVICE_UPDATED,
                "expected_message_content": ["service", "updated"],
            },
            {
                "method_name": "google.cloud.run.v1.Revisions.DeleteRevision",
                "expected_event_type": models.TimelineEventType.SERVICE_DEFINITION_REVISION_DELETED,
                "expected_message_content": ["service", "revision", "deleted"],
            },
        ]

        for test_case in test_cases:
            with self.subTest(method_name=test_case["method_name"]):
                # Create mock audit log entry
                mock_entry = MagicMock()
                mock_entry.timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
                mock_entry.payload = {
                    "methodName": test_case["method_name"],
                    "resourceName": "namespaces/test-project/services/test-service",
                    "authenticationInfo": {"principalEmail": "user@example.com"},
                }

                timeline_event = audit_service._parse_service_audit_log_entry(
                    mock_entry, name_to_resource_id
                )

                # Verify common fields
                self.assertIsInstance(timeline_event, models.TimelineEvent)
                if timeline_event is None:
                    self.fail("Parsed timeline event should not be None")

                self.assertEqual(
                    timeline_event.event_type, test_case["expected_event_type"]
                )
                self.assertEqual(
                    timeline_event.resource_id, self.mock_service.resource_id
                )
                self.assertEqual(
                    timeline_event.resource_type, models.ResourceType.GCP_Service
                )
                self.assertEqual(timeline_event.timestamp, mock_entry.timestamp)
                self.assertEqual(timeline_event.source, "GCP Audit Logs")

                # Verify message content contains expected strings
                for expected_content in test_case["expected_message_content"]:
                    self.assertIn(expected_content, timeline_event.message.lower())

                # Verify details
                self.assertEqual(
                    timeline_event.details["methodName"], test_case["method_name"]
                )
                self.assertEqual(timeline_event.details["serviceName"], "test-service")
                self.assertEqual(
                    timeline_event.details["principalEmail"], "user@example.com"
                )

    def test_extract_service_name_from_path(self):
        """Test extraction of service name from GCP Cloud Run resource path."""
        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        # Test Cloud Run audit log resource path format
        audit_log_resource_path = "namespaces/test-project/services/test-service"
        service_name = audit_service._extract_service_name(audit_log_resource_path)
        self.assertEqual(service_name, "test-service")

        # Test with more complex service name
        complex_resource_path = (
            "namespaces/my-gcp-project-123/services/my-api-service-v2"
        )
        service_name = audit_service._extract_service_name(complex_resource_path)
        self.assertEqual(service_name, "my-api-service-v2")

        # Test API resource format for backward compatibility
        api_format_path = (
            "projects/test-project/locations/us-central1/services/test-service"
        )
        service_name = audit_service._extract_service_name(api_format_path)
        self.assertEqual(service_name, "test-service")

        # Test invalid resource path
        invalid_path = "invalid/path"
        service_name = audit_service._extract_service_name(invalid_path)
        self.assertEqual(
            service_name, invalid_path
        )  # Should return original if can't parse

        # Test partial path
        partial_path = "namespaces/test-project"
        service_name = audit_service._extract_service_name(partial_path)
        self.assertEqual(
            service_name, partial_path
        )  # Should return original if can't parse

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_disabled_service_audit_logs(self, mock_logging_client):
        """Test that service audit logs respect disabled configuration."""
        config = models.LuminautConfig()
        config.gcp.audit_logs.enabled = False

        audit_service = GcpAuditLogs("test-project", config.gcp.audit_logs)

        # Should return empty list when disabled
        events = audit_service.query_service_events([self.mock_service])
        self.assertEqual(events, [])

        # Should not have called the logging client
        mock_logging_client.assert_not_called()

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_query_service_events_no_services(self, mock_logging_client):
        """Test querying service events with empty service list."""
        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        # Should return empty list when no services provided
        events = audit_service.query_service_events([])
        self.assertEqual(events, [])

        # Should not have called the logging client
        mock_logging_client.assert_not_called()

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_service_audit_logs_exception_handling(self, mock_logging_client):
        """Test that service audit log exceptions are handled gracefully."""
        mock_client = MagicMock()
        mock_logging_client.return_value = mock_client

        # Simulate an exception during log querying
        mock_client.list_entries.side_effect = Exception("API Error")

        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        # Should handle exception gracefully and return empty list
        events = audit_service.query_service_events([self.mock_service])
        self.assertEqual(events, [])

    def test_audit_log_filter_uses_correct_resource_name_format(self):
        """Test that audit log filters use the correct namespaces/project/services/name format."""
        audit_service = GcpAuditLogs("test-project", self.config.gcp.audit_logs)

        # Create a service with the resource_id format that comes from the API
        service = models.GcpService(
            resource_id="projects/test-project/locations/us-central1/services/test-service",
            name="test-service",
            uri="https://test-service-xyz.a.run.app",
        )

        # Build the filter
        filter_str = audit_service._build_service_audit_log_filter([service])

        # Verify the filter uses the correct audit log resource name format
        self.assertIn("run.googleapis.com", filter_str)

        self.assertIn("namespaces/test-project/services/test-service", filter_str)
        self.assertNotIn(
            "projects/test-project/locations/us-central1/services/test-service",
            filter_str,
        )


if __name__ == "__main__":
    unittest.main()
