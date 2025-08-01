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

    # Mapping of GCP Firewall events to timeline event types and messages
    SUPPORTED_FIREWALL_EVENTS = {
        "beta.compute.firewalls.insert": {
            "event_type": models.TimelineEventType.FIREWALL_RULE_CREATED,
            "message": "Firewall rule created",
        },
        "v1.compute.firewalls.insert": {
            "event_type": models.TimelineEventType.FIREWALL_RULE_CREATED,
            "message": "Firewall rule created",
        },
        "beta.compute.firewalls.update": {
            "event_type": models.TimelineEventType.FIREWALL_RULE_UPDATED,
            "message": "Firewall rule updated",
        },
        "v1.compute.firewalls.update": {
            "event_type": models.TimelineEventType.FIREWALL_RULE_UPDATED,
            "message": "Firewall rule updated",
        },
        "beta.compute.firewalls.delete": {
            "event_type": models.TimelineEventType.FIREWALL_RULE_DELETED,
            "message": "Firewall rule deleted",
        },
        "v1.compute.firewalls.delete": {
            "event_type": models.TimelineEventType.FIREWALL_RULE_DELETED,
            "message": "Firewall rule deleted",
        },
    }

    def __init__(self, project: str, config: models.LuminautConfigToolGcpAuditLogs):
        self.project = project
        self.config = config
        self.enabled = config.enabled
        self._client: gcp_logging.Client | None = None
        self._compute_parser = ComputeInstanceEventParser(
            self.SUPPORTED_INSTANCE_EVENTS,
            self._extract_resource_name,
            self.SOURCE_NAME,
            self.project,
        )
        self._cloudrun_parser = CloudRunServiceEventParser(
            self.SUPPORTED_CLOUD_RUN_EVENTS,
            self.SOURCE_NAME,
            self.project,
        )
        self._firewall_parser = FirewallEventParser(
            self.SUPPORTED_FIREWALL_EVENTS,
            self.SOURCE_NAME,
            self.project,
        )

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
        if not self.config.enabled:
            logger.debug("GCP audit logs are disabled, skipping query")
            return []
        return self._query_audit_events(
            services,
            self._build_service_audit_log_filter,
            self._parse_service_audit_log_entry,
            self._build_resource_name_id_mapping(services),
        )

    def query_firewall_events(
        self, firewalls: list[models.GcpFirewallRule]
    ) -> list[models.TimelineEvent]:
        """Query audit logs for GCP firewall rule lifecycle events.

        Args:
            firewalls: List of GCP firewall rules to query audit logs for.

        Returns:
            List of timeline events found in audit logs for the given firewalls.
            Returns empty list if audit logs are disabled, no firewalls provided,
            or if an error occurs during querying.
        """
        if not self.config.enabled:
            logger.debug("GCP audit logs are disabled, skipping query")
            return []
        return self._query_audit_events(
            firewalls,
            self._build_firewall_audit_log_filter,
            self._parse_firewall_audit_log_entry,
            self._build_resource_name_id_mapping(firewalls),
        )

    @staticmethod
    def _build_resource_name_id_mapping(
        resources: Sequence[
            models.GcpInstance | models.GcpService | models.GcpFirewallRule
        ],
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
        self, entry: gcp_logging.types.LogEntry, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        """Directly dispatch to the Compute parser for Compute Engine events."""
        method_name = (
            entry.payload.get("methodName", "") if hasattr(entry, "payload") else ""
        )
        if method_name in self.SUPPORTED_INSTANCE_EVENTS:
            return self._compute_parser.parse(entry, name_to_resource_id)
        return None

    def _build_service_audit_log_filter(
        self, services: Sequence[models.GcpService]
    ) -> str:
        """Build the filter string for querying Cloud Run service audit logs."""
        resource_names = []
        for service in services:
            service_name = CloudRunServiceEventParser.extract_service_name(
                service.resource_id
            )
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

    def _build_firewall_audit_log_filter(
        self, firewalls: Sequence[models.GcpFirewallRule]
    ) -> str:
        firewall_resource_path_template = (
            "projects/{project}/global/firewalls/{firewall}"
        )
        resource_names = []
        for firewall in firewalls:
            resource_path = firewall_resource_path_template.format(
                project=self.project, firewall=firewall.name
            )
            resource_names.append(resource_path)
        return (
            GcpAuditLogFilterBuilder(self.project, self.LOG_NAME_TEMPLATE)
            .with_log_name()
            .with_service_name(self.SERVICE_NAME_COMPUTE)
            .with_method_names(self.SUPPORTED_FIREWALL_EVENTS.keys())
            .with_resource_names(resource_names)
            .with_time_range(
                self.config.start_time, self.config.end_time, self.TIMESTAMP_FORMAT
            )
            .build()
        )

    def _parse_firewall_audit_log_entry(
        self, entry: gcp_logging.types.LogEntry, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        """Directly dispatch to the Firewall parser for Firewall events."""
        method_name = (
            entry.payload.get("methodName", "") if hasattr(entry, "payload") else ""
        )
        if method_name in self.SUPPORTED_FIREWALL_EVENTS:
            return self._firewall_parser.parse(entry, name_to_resource_id)
        return None

    def _parse_service_audit_log_entry(
        self, entry: gcp_logging.types.LogEntry, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        """Directly dispatch to the Cloud Run parser for Cloud Run events."""
        method_name = (
            entry.payload.get("methodName", "") if hasattr(entry, "payload") else ""
        )
        if method_name in self.SUPPORTED_CLOUD_RUN_EVENTS:
            return self._cloudrun_parser.parse(entry, name_to_resource_id)
        return None

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
            return [
                timeline_event
                for entry in log_entries
                if (timeline_event := entry_parser(entry, name_to_resource_id))
            ]
        except Exception as e:
            logger.error(
                f"Error querying GCP audit logs for project {self.project}: {e}"
            )
            return []


class ComputeInstanceEventParser:
    def __init__(
        self,
        supported_events: dict[str, dict[str, Any]],
        extract_resource_name: Callable,
        source_name: str,
        project: str,
    ):
        self.supported_events = supported_events
        self.extract_resource_name = extract_resource_name
        self.source_name = source_name
        self.project = project

    def parse(
        self, entry: gcp_logging.types.LogEntry, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        try:
            method_name = AuditLogParseTools.get_method_name(entry)
            event_config = AuditLogParseTools.get_event_config(
                method_name, self.supported_events
            )
            if not entry.payload or not event_config:
                return None
            resource_name = AuditLogParseTools.get_resource_name(entry)
            instance_name = self.extract_resource_name(resource_name)
            resource_id = AuditLogParseTools.get_resource_id(
                name_to_resource_id, instance_name
            )
            if resource_id is None:
                logger.warning(
                    "Instance resource ID not found for resource: %s and instance: %s",
                    resource_name,
                    instance_name,
                )
                return None
            principal_email = AuditLogParseTools.get_principal_email(entry)
            message = AuditLogParseTools.build_message(
                event_config["message"], principal_email
            )
            if not isinstance(entry.timestamp, datetime):
                logger.warning(
                    "Invalid timestamp format in audit log entry: %s %s",
                    entry.timestamp,
                    type(entry.timestamp),
                )
                return None
            timestamp = AuditLogParseTools.normalize_timestamp(entry.timestamp)
            return models.TimelineEvent(
                timestamp=timestamp,
                source=self.source_name,
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
        except Exception as e:
            logger.warning(f"Error parsing audit log entry: {e}")
            return None


class CloudRunServiceEventParser:
    def __init__(
        self,
        supported_events: dict[str, dict[str, Any]],
        source_name: str,
        project: str,
    ):
        self.supported_events = supported_events
        self.source_name = source_name
        self.project = project

    @staticmethod
    def extract_service_name(resource_path: str) -> str:
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

    def parse(
        self, entry: gcp_logging.types.LogEntry, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        try:
            method_name = AuditLogParseTools.get_method_name(entry)
            event_config = AuditLogParseTools.get_event_config(
                method_name, self.supported_events
            )
            if not entry.payload or not event_config:
                return None
            resource_name = AuditLogParseTools.get_resource_name(entry)
            service_name = self.extract_service_name(resource_name)
            resource_id = AuditLogParseTools.get_resource_id(
                name_to_resource_id, service_name
            )
            if not isinstance(resource_id, str):
                logger.warning(
                    "Service resource ID not found for resource: %s and service: %s",
                    resource_name,
                    service_name,
                )
                return None
            principal_email = AuditLogParseTools.get_principal_email(entry)
            message = AuditLogParseTools.build_message(
                event_config["message"], principal_email
            )
            if not isinstance(entry.timestamp, datetime):
                logger.warning(
                    "Invalid timestamp format in audit log entry: %s %s",
                    entry.timestamp,
                    type(entry.timestamp),
                )
                return None
            timestamp = AuditLogParseTools.normalize_timestamp(entry.timestamp)
            return models.TimelineEvent(
                timestamp=timestamp,
                source=self.source_name,
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
        except Exception as e:
            logger.warning(f"Error parsing service audit log entry: {e}")
            return None


class FirewallEventParser:
    def __init__(
        self,
        supported_events: dict[str, dict[str, Any]],
        source_name: str,
        project: str,
    ):
        self.supported_events = supported_events
        self.source_name = source_name
        self.project = project

    @classmethod
    def extract_resource_name(cls, resource_path: str) -> str:
        # Resource path format: projects/{project}/global/firewalls/{name}
        return resource_path.rsplit("/", 1)[-1]

    def parse(
        self, entry: gcp_logging.types.LogEntry, name_to_resource_id: dict[str, str]
    ) -> models.TimelineEvent | None:
        try:
            method_name = AuditLogParseTools.get_method_name(entry)
            event_config = AuditLogParseTools.get_event_config(
                method_name, self.supported_events
            )
            if not entry.payload or not event_config:
                return None
            resource_name = AuditLogParseTools.get_resource_name(entry)
            firewall_name = self.extract_resource_name(resource_name)
            resource_id = AuditLogParseTools.get_resource_id(
                name_to_resource_id, firewall_name
            )
            if resource_id is None:
                logger.warning(
                    "Firewall resource ID not found for resource: %s and firewall: %s",
                    resource_name,
                    firewall_name,
                )
                return None
            principal_email = AuditLogParseTools.get_principal_email(entry)
            message = AuditLogParseTools.build_message(
                event_config["message"], principal_email
            )
            if not isinstance(entry.timestamp, datetime):
                logger.warning(
                    "Invalid timestamp format in audit log entry: %s %s",
                    entry.timestamp,
                    type(entry.timestamp),
                )
                return None
            timestamp = AuditLogParseTools.normalize_timestamp(entry.timestamp)
            request_parameters = entry.payload.get("request", {})

            return models.TimelineEvent(
                timestamp=timestamp,
                source=self.source_name,
                event_type=event_config["event_type"],
                resource_id=resource_id,
                resource_type=models.ResourceType.GCP_Firewall_Rule,
                message=message,
                details={
                    "methodName": method_name,
                    "resourceName": resource_name,
                    "principalEmail": principal_email,
                    "rule_detail": {
                        "allowed_protocols": [
                            x["IPProtocol"]
                            for x in request_parameters.get("alloweds", [])
                            if "IPProtocol" in x
                        ],
                        "allowed_ports": [
                            port_number
                            for allowed in request_parameters.get("alloweds", [])
                            for port_number in allowed["ports"]
                            if "ports" in allowed
                        ],
                        "sourceRanges": request_parameters.get("sourceRanges", []),
                        "targetTags": request_parameters.get("targetTags", []),
                        "description": request_parameters.get("description", ""),
                        "network": request_parameters.get("network", ""),
                    },
                },
            )
        except Exception as e:
            logger.warning(f"Error parsing firewall audit log entry: {e}")
            raise e


class AuditLogParseTools:
    @staticmethod
    def get_method_name(entry: gcp_logging.types.LogEntry) -> str:
        return entry.payload.get("methodName", "") if hasattr(entry, "payload") else ""

    @staticmethod
    def get_event_config(
        method_name: str, supported_events: dict[str, dict[str, Any]]
    ) -> dict[str, Any] | None:
        return supported_events.get(method_name)

    @staticmethod
    def get_resource_name(entry: gcp_logging.types.LogEntry) -> str:
        return (
            entry.payload.get("resourceName", "") if hasattr(entry, "payload") else ""
        )

    @staticmethod
    def get_resource_id(name_to_resource_id: dict[str, str], name: str) -> str | None:
        return name_to_resource_id.get(name)

    @staticmethod
    def get_principal_email(entry: gcp_logging.types.LogEntry) -> str:
        auth_info = (
            entry.payload.get("authenticationInfo", {})
            if hasattr(entry, "payload")
            else {}
        )
        return auth_info.get("principalEmail", "unknown")

    @staticmethod
    def normalize_timestamp(timestamp: datetime) -> datetime:
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC)

    @staticmethod
    def build_message(base_message: str, principal_email: str) -> str:
        return f"{base_message} by {principal_email}"
