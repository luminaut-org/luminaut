import asyncio
import logging

import google.auth
from google.cloud import compute_v1, run_v2
from google.cloud.compute_v1 import types as gcp_compute_v1_types
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from luminaut import models
from luminaut.tools.gcp_audit_logs import GcpAuditLogs

logger = logging.getLogger(__name__)


class GcpClients:
    """Manages GCP client instances."""

    def __init__(self):
        self._instances = None
        self._services = None
        self._firewalls = None
        self._regions = None
        self._zones = None

    @property
    def instances(self) -> compute_v1.InstancesClient:
        if self._instances is None:
            self._instances = compute_v1.InstancesClient()
        return self._instances

    @property
    def services(self) -> run_v2.ServicesClient:
        if self._services is None:
            self._services = run_v2.ServicesClient()
        return self._services

    @property
    def firewalls(self) -> compute_v1.FirewallsClient:
        if self._firewalls is None:
            self._firewalls = compute_v1.FirewallsClient()
        return self._firewalls

    @property
    def regions(self) -> compute_v1.RegionsClient:
        if self._regions is None:
            self._regions = compute_v1.RegionsClient()
        return self._regions

    @property
    def zones(self) -> compute_v1.ZonesClient:
        if self._zones is None:
            self._zones = compute_v1.ZonesClient()
        return self._zones


class Gcp:
    def __init__(self, config: models.LuminautConfig):
        self.config = config
        self.clients = GcpClients()
        # Cache for firewall rules by (project, network) tuple
        self._firewall_rules_cache: dict[
            tuple[str, str], list[models.GcpFirewallRule]
        ] = {}

    def get_compute_v1_client(self) -> compute_v1.InstancesClient:
        return compute_v1.InstancesClient()

    def get_run_v2_services_client(self) -> run_v2.ServicesClient:
        return run_v2.ServicesClient()

    def get_firewall_client(self) -> compute_v1.FirewallsClient:
        return compute_v1.FirewallsClient()

    def clear_firewall_rules_cache(self) -> None:
        """Clear the firewall rules cache."""
        self._firewall_rules_cache.clear()
        logger.debug("Cleared firewall rules cache")

    def get_projects(self) -> list[str]:
        if self.config.gcp.projects is not None and len(self.config.gcp.projects) > 0:
            return self.config.gcp.projects

        (_default_creds, default_project) = google.auth.default()
        if default_project:
            logger.warning(
                "No GCP projects specified in the configuration. Using default project '%s'.",
                default_project,
            )
            self.config.gcp.projects = [default_project]
            return [default_project]

        logger.error(
            "No GCP projects specified in the configuration and no default project found."
        )
        return []

    def get_regions(self, project: str) -> list[str]:
        if self.config.gcp.regions:
            return self.config.gcp.regions
        try:
            logger.warning(
                "No GCP compute regions specified in the configuration. Using all available regions for the project %s.",
                project,
            )
            regions_client = compute_v1.RegionsClient()
            all_regions = regions_client.list(project=project)
            return [region.name for region in all_regions]
        except Exception as e:
            logger.error(
                "Failed to fetch regions for project %s: %s",
                project,
                str(e),
            )
            return []

    def get_zones(self, project: str) -> list[str]:
        if self.config.gcp.compute_zones:
            return self.config.gcp.compute_zones
        try:
            logger.warning(
                "No GCP compute zones specified in the configuration. Using all available zones for the project %s.",
                project,
            )
            zones_client = compute_v1.ZonesClient()
            all_zones = zones_client.list(project=project)
            return [zone.name for zone in all_zones]
        except Exception as e:
            logger.error(
                "Failed to fetch zones for project %s: %s",
                project,
                str(e),
            )
            return []

    def explore(self) -> list[models.ScanResult]:
        return asyncio.run(self.explore_async())

    async def explore_async(self) -> list[models.ScanResult]:
        if not self.config.gcp.enabled:
            return []

        tasks = []
        for project in self.get_projects():
            tasks.extend(
                asyncio.to_thread(self.find_instances, project, zone)
                for zone in self.get_zones(project)
            )
            tasks.extend(
                asyncio.to_thread(self.find_services, project, region)
                for region in self.get_regions(project)
            )

        scan_results = []
        with logging_redirect_tqdm():
            for coro in tqdm(
                asyncio.as_completed(tasks), total=len(tasks), desc="Scanning GCP"
            ):
                r = await coro
                scan_results.extend(r)
        logger.info("Completed scanning GCP")
        return scan_results

    def find_instances(self, project: str, zone: str) -> list[models.ScanResult]:
        scan_results = []
        instances = self.fetch_instances(project, zone)

        # Query audit logs for all discovered instances if enabled
        audit_log_events = []
        if self.config.gcp.audit_logs.enabled and instances:
            try:
                logger.info(
                    f"Querying GCP audit logs for {len(instances)} instances in project {project}/{zone}"
                )
                audit_service = GcpAuditLogs(project, self.config.gcp.audit_logs)
                audit_log_events = audit_service.query_instance_events(instances)
                logger.info(
                    f"Found {len(audit_log_events)} audit log events for {len(instances)} instances in {project}/{zone}"
                )
            except Exception as e:
                logger.error(f"Error querying audit logs for project {project}: {e}")

        for gcp_instance in instances:
            for public_ip in gcp_instance.get_public_ips():
                scan_finding = models.ScanFindings(
                    tool="GCP Instance",
                    emoji_name="cloud",
                    resources=[gcp_instance],
                )

                firewall_rules = self.get_applicable_firewall_rules(gcp_instance)
                if firewall_rules:
                    scan_finding.resources.append(firewall_rules)

                # Add audit log events for this specific instance
                instance_events = [
                    event
                    for event in audit_log_events
                    if str(event.resource_id) == gcp_instance.resource_id
                ]
                if instance_events:
                    scan_finding.events.extend(instance_events)

                scan_results.append(
                    models.ScanResult(
                        ip=public_ip,
                        findings=[scan_finding],
                        region=zone,
                    )
                )
        return scan_results

    def fetch_instances(self, project: str, zone: str) -> list[models.GcpInstance]:
        try:
            instances = self.clients.instances.list(
                project=project,
                zone=zone,
            )
            return [models.GcpInstance.from_gcp(instance) for instance in instances]
        except Exception as e:
            logger.error(
                "Failed to fetch GCP instances for project %s in zone %s: %s",
                project,
                zone,
                str(e),
            )
            return []

    def find_services(self, project: str, location: str) -> list[models.ScanResult]:
        scan_results = []
        services = self.fetch_run_services(project, location)

        # Query audit logs for all discovered services if enabled
        audit_log_events = []
        if self.config.gcp.audit_logs.enabled and services:
            try:
                logger.info(
                    f"Querying GCP audit logs for {len(services)} Cloud Run services in project {project}/{location}"
                )
                audit_service = GcpAuditLogs(project, self.config.gcp.audit_logs)
                audit_log_events = audit_service.query_service_events(services)
                logger.info(
                    f"Found {len(audit_log_events)} audit log events for {len(services)} services in {project}/{location}"
                )
            except Exception as e:
                logger.error(
                    f"Error querying service audit logs for project {project}: {e}"
                )

        for service in services:
            if not service.allows_ingress():
                logger.debug(
                    "Skipping GCP Run Service %s as it does not have external ingress",
                    service.name,
                )
                continue
            scan_finding = models.ScanFindings(
                tool="GCP Run Service",
                emoji_name="cloud",
                resources=[service],
            )

            # Add audit log events for this specific service
            service_events = [
                event
                for event in audit_log_events
                if event.resource_id == service.resource_id
            ]
            if service_events:
                scan_finding.events.extend(service_events)

            scan_results.append(
                models.ScanResult(
                    url=service.uri,
                    findings=[scan_finding],
                    region=location,
                )
            )
        return scan_results

    def fetch_run_services(
        self, project: str, location: str
    ) -> list[models.GcpService]:
        try:
            client = self.clients.services
            services = client.list_services(
                parent=f"projects/{project}/locations/{location}"
            )
            return [models.GcpService.from_gcp(service) for service in services]
        except Exception as e:
            logger.error(
                "Failed to fetch GCP Run services for project %s in location %s: %s",
                project,
                location,
                str(e),
            )
            return []

    def fetch_firewall_rules(
        self, project: str, network: str
    ) -> list[models.GcpFirewallRule]:
        """Fetch firewall rules for a given project and network."""
        # Check cache first
        cache_key = (project, network)
        if cache_key in self._firewall_rules_cache:
            return self._firewall_rules_cache[cache_key]

        network_url = f"https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}"
        filter_expression = f'network="{network_url}"'

        request = gcp_compute_v1_types.ListFirewallsRequest(
            project=project, filter=filter_expression
        )
        try:
            client = self.get_firewall_client()
            firewall_rules = client.list(request=request)
            rules = [models.GcpFirewallRule.from_gcp(rule) for rule in firewall_rules]

            # Cache the results
            self._firewall_rules_cache[cache_key] = rules
            return rules
        except Exception as e:
            logger.error(
                "Failed to fetch GCP firewall rules for project %s network %s: %s",
                project,
                network,
                str(e),
            )
            return []

    def get_applicable_firewall_rules(
        self, instance: models.GcpInstance
    ) -> models.GcpFirewallRules:
        """Get firewall rules that apply to a given GCP instance."""
        applicable_rules = {}
        for nic in instance.network_interfaces:
            project_name = nic.get_project_name()
            network_name = nic.get_network_name()

            if not project_name or not network_name:
                continue

            firewall_rules = self.fetch_firewall_rules(project_name, network_name)

            # Filter rules based on target tags
            for rule in firewall_rules:
                if (
                    rule.resource_id not in applicable_rules
                    and self._rule_applies_to_instance(rule, instance)
                ):
                    applicable_rules[rule.resource_id] = rule

        return models.GcpFirewallRules(rules=list(applicable_rules.values()))

    def _rule_applies_to_instance(
        self, rule: models.GcpFirewallRule, instance: models.GcpInstance
    ) -> bool:
        """Check if a firewall rule applies to an instance based on target tags."""
        # If rule has no target tags, it applies to all instances in the network
        if not rule.target_tags:
            return True

        # Rule applies if there's any overlap between instance tags and rule target tags
        return bool(set(instance.tags) & set(rule.target_tags))
