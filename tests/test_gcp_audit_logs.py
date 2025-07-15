import unittest
from datetime import UTC, datetime
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
                "method_name": "compute.instances.insert",
                "principal_email": "test@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
                "expected_message_content": ["created", "test@example.com"],
            },
            {
                "method_name": "compute.instances.delete",
                "principal_email": "admin@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_TERMINATED,
                "expected_message_content": ["deleted", "admin@example.com"],
            },
            {
                "method_name": "compute.instances.start",
                "principal_email": "user@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
                "expected_message_content": ["started", "user@example.com"],
            },
            {
                "method_name": "compute.instances.stop",
                "principal_email": "user@example.com",
                "expected_event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
                "expected_message_content": ["stopped", "user@example.com"],
            },
        ]

        for test_case in test_cases:
            with self.subTest(method_name=test_case["method_name"]):
                # Mock audit log entry
                mock_entry = MagicMock()
                mock_entry.timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
                mock_entry.proto_payload = {
                    "methodName": test_case["method_name"],
                    "resourceName": "projects/test-project/zones/us-central1-a/instances/test-instance",
                    "authenticationInfo": {
                        "principalEmail": test_case["principal_email"]
                    },
                }

                # Parse the entry
                timeline_event = audit_service._parse_audit_log_entry(mock_entry)

                # Verify common fields
                self.assertIsInstance(timeline_event, models.TimelineEvent)
                if timeline_event is None:
                    # Needed for pyright as it cannot infer this based on the prior assertion.
                    self.fail("Parsed timeline event should not be None")

                self.assertEqual(
                    timeline_event.event_type, test_case["expected_event_type"]
                )
                self.assertEqual(timeline_event.resource_id, "test-instance")
                self.assertEqual(
                    timeline_event.resource_type, models.ResourceType.GCP_Instance
                )
                self.assertEqual(timeline_event.timestamp, mock_entry.timestamp)
                self.assertEqual(timeline_event.source, "GCP Audit Logs")

                # Verify message content contains expected strings
                for expected_content in test_case["expected_message_content"]:
                    self.assertIn(expected_content, timeline_event.message.lower())

    @patch("luminaut.tools.gcp_audit_logs.gcp_logging.Client")
    def test_extract_resource_name_from_path(self, mock_logging_client):
        """Test extraction of resource name from GCP resource path."""
        mock_client = MagicMock()
        mock_logging_client.return_value = mock_client

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


if __name__ == "__main__":
    unittest.main()
