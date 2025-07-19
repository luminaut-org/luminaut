import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from google.cloud import logging as gcp_logging

from luminaut import models

logger = logging.getLogger(__name__)


class GcpAuditLogs:
    """Service for querying Google Cloud Audit Logs for Compute Engine instance events.

    This service queries Cloud Logging API for audit logs related to GCP Compute Engine
    instance lifecycle events (create, delete, start, stop) and converts them into
    TimelineEvent objects for integration with Luminaut's scanning workflow.

    The service supports filtering by:
    - Specific instances (by resource name)
    - Time ranges (start_time and end_time)
    - Event types (only supported instance lifecycle events)

    Example:
        config = LuminautConfigToolGcpAuditLogs(enabled=True)
        service = GcpAuditLogs("my-project", config)
        events = service.query_instance_events(instances)
    """

    # Constants for audit log filtering and parsing
    SOURCE_NAME = "GCP Audit Logs"
    LOG_NAME_TEMPLATE = "projects/{project}/logs/cloudaudit.googleapis.com%2Factivity"
    SERVICE_NAME = "compute.googleapis.com"
    RESOURCE_PATH_TEMPLATE = "projects/{project}/zones/{zone}/instances/{instance}"
    TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

    # Expected resource path format: projects/{project}/zones/{zone}/instances/{instance-name}
    RESOURCE_PATH_PARTS_COUNT = 6
    RESOURCE_PATH_INSTANCES_INDEX = 4
    RESOURCE_PATH_NAME_INDEX = 5

    # Mapping of GCP audit log method names to timeline event types and messages
    SUPPORTED_INSTANCE_EVENTS = {
        "beta.compute.instances.insert": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
            "message": "Instance created",
        },
        "v1.compute.instances.delete": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_TERMINATED,
            "message": "Instance deleted",
        },
        "v1.compute.instances.start": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
            "message": "Instance started",
        },
        "v1.compute.instances.stop": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
            "message": "Instance stopped",
        },
        "beta.compute.instances.suspend": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
            "message": "Instance suspended",
        },
        "beta.compute.instances.resume": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
            "message": "Instance resumed",
        },
    }

    def __init__(self, project: str, config: models.LuminautConfigToolGcpAuditLogs):
        self.project = project
        self.config = config
        self._client: gcp_logging.Client | None = None

    @property
    def client(self) -> gcp_logging.Client:
        """Lazy initialization of the GCP logging client."""
        if self._client is None:
            self._client = gcp_logging.Client()
        return self._client

    def query_instance_events(
        self, instances: list[models.GcpInstance]
    ) -> list[models.TimelineEvent]:
        """Query audit logs for instance lifecycle events.

        Args:
            instances: List of GCP instances to query audit logs for.

        Returns:
            List of timeline events found in audit logs for the given instances.
            Returns empty list if audit logs are disabled, no instances provided,
            or if an error occurs during querying.
        """
        if not self.config.enabled:
            logger.debug("GCP audit logs are disabled, skipping query")
            return []

        if not instances:
            logger.debug("No instances provided for audit log query")
            return []

        # Create a mapping from instance names to resource IDs for exact matching
        name_to_resource_id = {
            instance.name: instance.resource_id for instance in instances
        }

        # Build the filter for audit log queries
        filter_str = self._build_audit_log_filter(instances)
        if not filter_str:
            logger.debug("No valid filter could be built for audit log query")
            return []

        try:
            # Query the audit logs
            log_entries = self.client.list_entries(
                filter_=filter_str, order_by=gcp_logging.ASCENDING
            )

            # Parse the entries into timeline events
            timeline_events = []
            for entry in log_entries:
                if timeline_event := self._parse_audit_log_entry(
                    entry, name_to_resource_id
                ):
                    timeline_events.append(timeline_event)
            return timeline_events

        except Exception as e:
            logger.error(
                f"Error querying GCP audit logs for project {self.project}: {e}"
            )
            return []

    def _build_audit_log_filter(self, instances: list[models.GcpInstance]) -> str:
        """Build the filter string for querying audit logs.

        Args:
            instances: List of GCP instances to build filters for.

        Returns:
            Filter string compatible with Cloud Logging API.
        """
        # Base filter for GCP Compute Engine audit logs
        base_filter = [
            f'logName:"{self.LOG_NAME_TEMPLATE.format(project=self.project)}"',
            f'protoPayload.serviceName="{self.SERVICE_NAME}"',
        ]

        # Add method name filters
        method_names = list(self.SUPPORTED_INSTANCE_EVENTS.keys())
        quoted_methods = [f'"{method}"' for method in method_names]
        method_filter = f"protoPayload.methodName:({' OR '.join(quoted_methods)})"
        base_filter.append(method_filter)

        # Add resource name filters for specific instances
        if instances:
            instance_resources = []
            for instance in instances:
                # Build the full resource path for the instance
                resource_path = self.RESOURCE_PATH_TEMPLATE.format(
                    project=self.project, zone=instance.zone, instance=instance.name
                )
                instance_resources.append(f'"{resource_path}"')

            resource_filter = (
                f"protoPayload.resourceName=({' OR '.join(instance_resources)})"
            )
            base_filter.append(resource_filter)

        # Add time range filters if configured, with default 30-day lookback
        start_time = self.config.start_time
        end_time = self.config.end_time

        # If no time range is specified, default to last 30 days
        if not start_time and not end_time:
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=30)

        if start_time:
            start_time_str = start_time.strftime(self.TIMESTAMP_FORMAT)
            base_filter.append(f'timestamp>="{start_time_str}"')

        if end_time:
            end_time_str = end_time.strftime(self.TIMESTAMP_FORMAT)
            base_filter.append(f'timestamp<="{end_time_str}"')

        return " AND ".join(base_filter)

    def _parse_audit_log_entry(
        self, entry: Any, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        """Parse a GCP audit log entry into a TimelineEvent.

        Args:
            entry: Audit log entry from Cloud Logging API.
            name_to_resource_id: Mapping from instance names to resource IDs.

        Returns:
            TimelineEvent if the entry represents a supported instance event,
            None otherwise.
        """
        try:
            if not entry.payload:
                return None

            # Get method name to determine event type
            method_name = entry.payload.get("methodName", "")
            if method_name not in self.SUPPORTED_INSTANCE_EVENTS:
                return None

            event_config = self.SUPPORTED_INSTANCE_EVENTS[method_name]

            # Extract resource name and instance name
            resource_name = entry.payload.get("resourceName", "")
            instance_name = self._extract_resource_name(resource_name)

            # Get the actual resource ID from the mapping
            resource_id = name_to_resource_id.get(instance_name, instance_name)

            # Extract authentication info for the message
            auth_info = entry.payload.get("authenticationInfo", {})
            principal_email = auth_info.get("principalEmail", "unknown")

            # Build the event message
            base_message = event_config["message"]
            message = f"{base_message} by {principal_email}"

            # Create the timeline event
            timeline_event = models.TimelineEvent(
                timestamp=entry.timestamp.astimezone(UTC),
                source=self.SOURCE_NAME,
                event_type=event_config["event_type"],
                resource_id=resource_id,
                resource_type=models.ResourceType.GCP_Instance,
                message=message,
                details={
                    "methodName": method_name,
                    "resourceName": resource_name,
                    "principalEmail": principal_email,
                    "project": self.project,
                    "instanceName": instance_name,
                },
            )

            return timeline_event

        except Exception as e:
            logger.warning(f"Error parsing audit log entry: {e}")
            return None

    def _extract_resource_name(self, resource_path: str) -> str:
        """Extract the resource name from a GCP resource path.

        Args:
            resource_path: Full GCP resource path (e.g., projects/{project}/zones/{zone}/instances/{name}).

        Returns:
            The resource name (e.g., instance name) or the original path if parsing fails.
        """
        try:
            # Resource path format: projects/{project}/zones/{zone}/instances/{instance-name}
            parts = resource_path.split("/")
            if (
                len(parts) >= self.RESOURCE_PATH_PARTS_COUNT
                and parts[self.RESOURCE_PATH_INSTANCES_INDEX] == "instances"
            ):
                return parts[self.RESOURCE_PATH_NAME_INDEX]
            return resource_path
        except (IndexError, AttributeError):
            return resource_path
