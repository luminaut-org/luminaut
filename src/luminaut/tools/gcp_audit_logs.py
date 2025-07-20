import logging
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from google.cloud import logging as gcp_logging

from luminaut import models

logger = logging.getLogger(__name__)


class GcpAuditLogFilterBuilder:
    """Builder for constructing GCP Audit Log filter strings in a flexible, chainable way."""

    def __init__(self, project: str, log_name_template: str):
        self.project = project
        self.log_name_template = log_name_template
        self.parts: list[str] = []

    def with_log_name(self) -> "GcpAuditLogFilterBuilder":
        self.parts.append(
            f'logName:"{self.log_name_template.format(project=self.project)}"'
        )
        return self

    def with_service_name(self, service_name: str) -> "GcpAuditLogFilterBuilder":
        self.parts.append(f'protoPayload.serviceName="{service_name}"')
        return self

    def with_method_names(
        self, method_names: Iterable[str]
    ) -> "GcpAuditLogFilterBuilder":
        quoted_methods = [f'"{method}"' for method in method_names]
        self.parts.append(f"protoPayload.methodName:({' OR '.join(quoted_methods)})")
        return self

    def with_resource_names(
        self, resource_names: Iterable[str]
    ) -> "GcpAuditLogFilterBuilder":
        if resource_names:
            quoted = [f'"{name}"' for name in resource_names]
            self.parts.append(f"protoPayload.resourceName=({' OR '.join(quoted)})")
        return self

    def with_time_range(
        self,
        start_time: datetime | None,
        end_time: datetime | None,
        timestamp_format: str,
    ) -> "GcpAuditLogFilterBuilder":
        # If no time range is specified, default to last 30 days
        if not start_time and not end_time:
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=30)
        if start_time:
            self.parts.append(f'timestamp>="{start_time.strftime(timestamp_format)}"')
        if end_time:
            self.parts.append(f'timestamp<="{end_time.strftime(timestamp_format)}"')
        return self

    def build(self) -> str:
        return " AND ".join(self.parts)


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
    SERVICE_NAME_COMPUTE = "compute.googleapis.com"
    SERVICE_NAME_RUN = "run.googleapis.com"
    TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

    RESOURCE_PATH_TEMPLATE = "projects/{project}/zones/{zone}/instances/{instance}"
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

    # Mapping of GCP audit log method names to timeline event types and messages for Cloud Run
    SUPPORTED_CLOUD_RUN_EVENTS = {
        "google.cloud.run.v1.Services.CreateService": {
            "event_type": models.TimelineEventType.SERVICE_CREATED,
            "message": "Service created",
        },
        "google.cloud.run.v1.Services.DeleteService": {
            "event_type": models.TimelineEventType.SERVICE_DELETED,
            "message": "Service deleted",
        },
        "google.cloud.run.v1.Services.ReplaceService": {
            "event_type": models.TimelineEventType.SERVICE_UPDATED,
            "message": "Service updated",
        },
        "google.cloud.run.v1.Revisions.DeleteRevision": {
            "event_type": models.TimelineEventType.SERVICE_DEFINITION_REVISION_DELETED,
            "message": "Service revision deleted",
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
        return self._query_audit_events(
            instances,
            self._build_instance_audit_log_filter,
            self._parse_instance_audit_log_entry,
            self._build_resource_name_id_mapping(instances),
        )

    def query_service_events(
        self, services: list[models.GcpService]
    ) -> list[models.TimelineEvent]:
        """Query audit logs for Cloud Run service lifecycle events.

        Args:
            services: List of GCP Cloud Run services to query audit logs for.

        Returns:
            List of timeline events found in audit logs for the given services.
            Returns empty list if audit logs are disabled, no services provided,
            or if an error occurs during querying.
        """
        return self._query_audit_events(
            services,
            self._build_service_audit_log_filter,
            self._parse_service_audit_log_entry,
            self._build_resource_name_id_mapping(services),
        )

    @staticmethod
    def _build_resource_name_id_mapping(
        resources: Sequence[models.GcpInstance | models.GcpService],
    ) -> dict[str, str]:
        """Build a mapping from resource names to their IDs.

        Args:
            resources: List of GCP instances or services.

        Returns:
            Mapping of resource names to their IDs.
        """
        return {resource.name: resource.resource_id for resource in resources}

    def _build_instance_audit_log_filter(
        self, instances: list[models.GcpInstance]
    ) -> str:
        """Build the filter string for querying audit logs for Compute Engine instances."""
        resource_names = []
        for instance in instances:
            resource_path = self.RESOURCE_PATH_TEMPLATE.format(
                project=self.project, zone=instance.zone, instance=instance.name
            )
            resource_names.append(resource_path)
        return (
            GcpAuditLogFilterBuilder(self.project, self.LOG_NAME_TEMPLATE)
            .with_log_name()
            .with_service_name(self.SERVICE_NAME_COMPUTE)
            .with_method_names(self.SUPPORTED_INSTANCE_EVENTS.keys())
            .with_resource_names(resource_names)
            .with_time_range(
                self.config.start_time, self.config.end_time, self.TIMESTAMP_FORMAT
            )
            .build()
        )

    def _parse_instance_audit_log_entry(
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

            if entry.timestamp.tzinfo is None:
                timestamp = entry.timestamp.replace(tzinfo=UTC)
            else:
                timestamp = entry.timestamp.astimezone(UTC)

            # Create the timeline event
            timeline_event = models.TimelineEvent(
                timestamp=timestamp,
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

    def _build_service_audit_log_filter(
        self, services: Sequence[models.GcpService]
    ) -> str:
        """Build the filter string for querying Cloud Run service audit logs."""
        resource_names = []
        for service in services:
            service_name = self._extract_service_name(service.resource_id)
            audit_log_resource_name = (
                f"namespaces/{self.project}/services/{service_name}"
            )
            resource_names.append(audit_log_resource_name)
        return (
            GcpAuditLogFilterBuilder(self.project, self.LOG_NAME_TEMPLATE)
            .with_log_name()
            .with_service_name(self.SERVICE_NAME_RUN)
            .with_method_names(self.SUPPORTED_CLOUD_RUN_EVENTS.keys())
            .with_resource_names(resource_names)
            .with_time_range(
                self.config.start_time, self.config.end_time, self.TIMESTAMP_FORMAT
            )
            .build()
        )

    def _parse_service_audit_log_entry(
        self, entry: Any, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        """Parse a GCP audit log entry into a TimelineEvent for Cloud Run services.

        Args:
            entry: Audit log entry from Cloud Logging API.
            name_to_resource_id: Mapping from service names to resource IDs.

        Returns:
            TimelineEvent if the entry represents a supported service event,
            None otherwise.
        """
        try:
            if not entry.payload:
                return None

            # Get method name to determine event type
            method_name = entry.payload.get("methodName", "")
            if method_name not in self.SUPPORTED_CLOUD_RUN_EVENTS:
                return None

            event_config = self.SUPPORTED_CLOUD_RUN_EVENTS[method_name]

            # Extract resource name and service name
            resource_name = entry.payload.get("resourceName", "")
            service_name = self._extract_service_name(resource_name)

            # Get the actual resource ID from the mapping
            resource_id = name_to_resource_id.get(service_name)
            if not resource_id:
                logger.warning(
                    "Service resource ID not found for resource: %s and service: %s",
                    resource_name,
                    service_name,
                )
                return None

            # Extract authentication info for the message
            auth_info = entry.payload.get("authenticationInfo", {})
            principal_email = auth_info.get("principalEmail", "unknown")

            # Build the event message
            base_message = event_config["message"]
            message = f"{base_message} by {principal_email}"

            if entry.timestamp.tzinfo is None:
                timestamp = entry.timestamp.replace(tzinfo=UTC)
            else:
                timestamp = entry.timestamp.astimezone(UTC)

            # Create the timeline event
            timeline_event = models.TimelineEvent(
                timestamp=timestamp,
                source=self.SOURCE_NAME,
                event_type=event_config["event_type"],
                resource_id=resource_id,
                resource_type=models.ResourceType.GCP_Service,
                message=message,
                details={
                    "methodName": method_name,
                    "resourceName": resource_name,
                    "principalEmail": principal_email,
                    "project": self.project,
                    "serviceName": service_name,
                },
            )

            return timeline_event

        except Exception as e:
            logger.warning(f"Error parsing service audit log entry: {e}")
            return None

    @staticmethod
    def _extract_service_name(resource_path: str) -> str:
        """Extract the service name from a GCP Cloud Run resource path.

        Args:
            resource_path: Full GCP resource path. Can be either:
                - namespaces/{project}/services/{name} (actual audit log format)
                - projects/{project}/locations/{region}/services/{name} (API resource format)

        Returns:
            The service name or the original path if parsing fails.
        """
        try:
            parts = resource_path.split("/")

            # Handle API resource format for backward compatibility: projects/{project}/locations/{region}/services/{service-name}
            if len(parts) >= 6 and parts[4] == "services":
                return parts[5]

            # Handle actual audit log format: namespaces/{project}/services/{service-name}
            if len(parts) >= 4 and parts[0] == "namespaces" and parts[2] == "services":
                return parts[3]

            return resource_path
        except (IndexError, AttributeError):
            return resource_path

    @classmethod
    def _extract_resource_name(cls, resource_path: str) -> str:
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
                len(parts) >= cls.RESOURCE_PATH_PARTS_COUNT
                and parts[cls.RESOURCE_PATH_INSTANCES_INDEX] == "instances"
            ):
                return parts[cls.RESOURCE_PATH_NAME_INDEX]
            return resource_path
        except (IndexError, AttributeError):
            return resource_path

    def _query_audit_events(
        self,
        resources: list[Any],
        filter_builder: Callable,
        entry_parser: Callable,
        name_to_resource_id: dict[str, str],
    ) -> list[models.TimelineEvent]:
        """
        Query GCP audit logs for the given resources using a provided filter builder and entry parser.

        Args:
            items: List of resource objects (instances or services) to query audit logs for.
            filter_builder: Callable that builds the filter string for the audit log query based on the items.
            entry_parser: Callable that parses each audit log entry into a TimelineEvent.
            name_to_resource_id: Mapping from resource names to resource IDs for resolving resource references.

        Returns:
            List of TimelineEvent objects parsed from the audit logs for the given resources.
            Returns an empty list if audit logs are disabled, no items are provided, or if an error occurs during querying.
        """
        if not self.config.enabled:
            logger.debug("GCP audit logs are disabled, skipping query")
            return []
        if not resources:
            logger.debug("No resources provided for audit log query")
            return []
        filter_str = filter_builder(resources)
        if not filter_str:
            logger.debug("No valid filter could be built for audit log query")
            return []
        try:
            log_entries = self.client.list_entries(
                filter_=filter_str, order_by=gcp_logging.ASCENDING
            )
            timeline_events = []
            for entry in log_entries:
                if timeline_event := entry_parser(entry, name_to_resource_id):
                    timeline_events.append(timeline_event)
            return timeline_events
        except Exception as e:
            logger.error(
                f"Error querying GCP audit logs for project {self.project}: {e}"
            )
            return []
