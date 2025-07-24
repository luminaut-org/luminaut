import asyncio
import logging
from typing import Any

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


class GcpResourceDiscovery:
    """Handles discovery of GCP resources like projects, regions, and zones.

    This class is responsible for discovering GCP projects, regions, and zones
    based on configuration settings or by querying the GCP APIs. It supports
    both configuration-driven discovery and automatic discovery via API calls.

    The class follows the following precedence:
    1. Use explicitly configured resources from luminaut.toml
    2. Fall back to API discovery for regions/zones
    3. Fall back to default project authentication for projects

    Attributes:
        config: The Luminaut configuration object
        clients: The GCP clients manager for API access
    """

    def __init__(self, config: models.LuminautConfig, clients: GcpClients) -> None:
        """Initialize the GCP resource discovery instance.

        Args:
            config: The Luminaut configuration object containing GCP settings
            clients: The GCP clients manager for accessing GCP APIs
        """
        self.config = config
        self.clients = clients

    def get_projects(self) -> list[str]:
        """Get the list of GCP projects to scan.

        Returns the configured projects from the configuration file, or falls back
        to the default project from the authenticated Google Cloud SDK.

        Returns:
            List of GCP project IDs to scan. Empty list if no projects are found.

        Side Effects:
            May modify self.config.gcp.projects if using default project fallback.
        """
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
        """Get the list of GCP compute regions to scan for a given project.

        Returns the configured regions from the configuration file, or queries
        the GCP Compute Engine API to get all available regions for the project.

        Args:
            project: The GCP project ID to get regions for

        Returns:
            List of GCP region names to scan. Empty list if API call fails.
        """
        if self.config.gcp.regions:
            return self.config.gcp.regions
        try:
            logger.warning(
                "No GCP compute regions specified in the configuration. Using all available regions for the project %s.",
                project,
            )
            regions_client = self.clients.regions
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
        """Get the list of GCP compute zones to scan for a given project.

        Returns the configured zones from the configuration file, or queries
        the GCP Compute Engine API to get all available zones for the project.

        Args:
            project: The GCP project ID to get zones for

        Returns:
            List of GCP zone names to scan. Empty list if API call fails.
        """
        if self.config.gcp.compute_zones:
            return self.config.gcp.compute_zones
        try:
            logger.warning(
                "No GCP compute zones specified in the configuration. Using all available zones for the project %s.",
                project,
            )
            zones_client = self.clients.zones
            all_zones = zones_client.list(project=project)
            return [zone.name for zone in all_zones]
        except Exception as e:
            logger.error(
                "Failed to fetch zones for project %s: %s",
                project,
                str(e),
            )
            return []


class GcpFirewallManager:
    """Manages GCP firewall rules including caching and instance matching."""

    def __init__(self, clients: GcpClients) -> None:
        """Initialize the GCP firewall manager.

        Args:
            clients: The GCP clients manager for accessing GCP APIs
        """
        self.clients = clients
        # Cache for firewall rules by (project, network) tuple
        self._firewall_rules_cache: dict[
            tuple[str, str], list[models.GcpFirewallRule]
        ] = {}

    def clear_cache(self) -> None:
        """Clear the firewall rules cache."""
        self._firewall_rules_cache.clear()
        logger.debug("Cleared firewall rules cache")

    async def fetch_firewall_rules_async(
        self, project: str, network: str
    ) -> list[models.GcpFirewallRule]:
        """Fetch firewall rules for a given project and network asynchronously."""
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
            client = self.clients.firewalls
            # Run the blocking GCP API call in a thread pool
            firewall_rules = await asyncio.to_thread(client.list, request=request)
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

    def fetch_firewall_rules(
        self, project: str, network: str
    ) -> list[models.GcpFirewallRule]:
        """Fetch firewall rules for a given project and network."""
        return asyncio.run(self.fetch_firewall_rules_async(project, network))

    async def get_applicable_firewall_rules_async(
        self, instance: models.GcpInstance
    ) -> models.GcpFirewallRules:
        """Get firewall rules that apply to a given GCP instance asynchronously."""
        applicable_rules = {}

        # Collect all unique (project, network) combinations
        network_queries = set()
        for nic in instance.network_interfaces:
            project_name = nic.get_project_name()
            network_name = nic.get_network_name()
            if project_name and network_name:
                network_queries.add((project_name, network_name))

        # Fetch firewall rules concurrently for all networks
        firewall_tasks = [
            self.fetch_firewall_rules_async(project, network)
            for project, network in network_queries
        ]

        if firewall_tasks:
            firewall_results: list[Any] = await asyncio.gather(
                *firewall_tasks, return_exceptions=True
            )

            # Process results and handle any exceptions
            for i, result in enumerate(firewall_results):
                if isinstance(result, Exception):
                    project, network = list(network_queries)[i]
                    logger.error(
                        "Error fetching firewall rules for %s/%s: %s",
                        project,
                        network,
                        str(result),
                    )
                else:
                    # Filter rules based on target tags
                    # result is guaranteed to be list[models.GcpFirewallRule] here
                    rules: list[models.GcpFirewallRule] = result
                    for rule in rules:
                        if (
                            rule.resource_id not in applicable_rules
                            and self._rule_applies_to_instance(rule, instance)
                        ):
                            applicable_rules[rule.resource_id] = rule

        return models.GcpFirewallRules(rules=list(applicable_rules.values()))

    def get_applicable_firewall_rules(
        self, instance: models.GcpInstance
    ) -> models.GcpFirewallRules:
        """Get firewall rules that apply to a given GCP instance."""
        return asyncio.run(self.get_applicable_firewall_rules_async(instance))

    def _rule_applies_to_instance(
        self, rule: models.GcpFirewallRule, instance: models.GcpInstance
    ) -> bool:
        """Check if a firewall rule applies to an instance based on target tags."""
        # If rule has no target tags, it applies to all instances in the network
        if not rule.target_tags:
            return True

        # Rule applies if there's any overlap between instance tags and rule target tags
        return bool(set(instance.tags) & set(rule.target_tags))


class GcpInstanceDiscovery:
    """Handles discovery of GCP compute instances."""

    def __init__(
        self,
        config: models.LuminautConfig,
        clients: GcpClients,
        firewall_manager: GcpFirewallManager,
    ) -> None:
        """Initialize the GCP instance discovery.

        Args:
            config: The Luminaut configuration object containing GCP settings
            clients: The GCP clients manager for accessing GCP APIs
            firewall_manager: The firewall manager for retrieving firewall rules
        """
        self.config = config
        self.clients = clients
        self.firewall_manager = firewall_manager

    async def find_resources_async(
        self, project: str, location: str
    ) -> list[models.ScanResult]:
        """Find GCP compute instances in the specified project and zone asynchronously.

        Args:
            project: The GCP project ID
            location: The GCP zone name

        Returns:
            List of scan results for discovered instances with public IPs
        """
        scan_results = []
        instances = await self.fetch_resources_async(project, location)

        # Query audit logs for all discovered instances if enabled
        audit_log_events = []
        if self.config.gcp.audit_logs.enabled and instances:
            try:
                logger.info(
                    f"Querying GCP audit logs for {len(instances)} instances in project {project}/{location}"
                )
                audit_service = GcpAuditLogs(project, self.config.gcp.audit_logs)
                # Use async audit log querying when available
                audit_log_events = await asyncio.to_thread(
                    audit_service.query_instance_events, instances
                )
                logger.info(
                    f"Found {len(audit_log_events)} audit log events for {len(instances)} instances in {project}/{location}"
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

                # Use async firewall rule fetching
                firewall_rules = (
                    await self.firewall_manager.get_applicable_firewall_rules_async(
                        gcp_instance
                    )
                )
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
                        region=location,
                    )
                )
        return scan_results

    def find_resources(self, project: str, location: str) -> list[models.ScanResult]:
        """Find GCP compute instances in the specified project and zone.

        Args:
            project: The GCP project ID
            location: The GCP zone name

        Returns:
            List of scan results for discovered instances with public IPs
        """
        return asyncio.run(self.find_resources_async(project, location))

    async def fetch_resources_async(
        self, project: str, location: str
    ) -> list[models.GcpInstance]:
        """Fetch GCP compute instances from the specified project and zone asynchronously.

        Args:
            project: The GCP project ID
            location: The GCP zone name

        Returns:
            List of GCP compute instances
        """
        try:
            instances = await asyncio.to_thread(
                self.clients.instances.list,
                project=project,
                zone=location,
            )
            return [models.GcpInstance.from_gcp(instance) for instance in instances]
        except Exception as e:
            logger.error(
                "Failed to fetch GCP instances for project %s in zone %s: %s",
                project,
                location,
                str(e),
            )
            return []

    def fetch_resources(self, project: str, location: str) -> list[models.GcpInstance]:
        """Fetch GCP compute instances from the specified project and zone.

        Args:
            project: The GCP project ID
            location: The GCP zone name

        Returns:
            List of GCP compute instances
        """
        return asyncio.run(self.fetch_resources_async(project, location))


class GcpServiceDiscovery:
    """Handles discovery of GCP Cloud Run services."""

    def __init__(self, config: models.LuminautConfig, clients: GcpClients) -> None:
        """Initialize the GCP service discovery.

        Args:
            config: The Luminaut configuration object containing GCP settings
            clients: The GCP clients manager for accessing GCP APIs
        """
        self.config = config
        self.clients = clients

    async def find_resources_async(
        self, project: str, location: str
    ) -> list[models.ScanResult]:
        """Find GCP Cloud Run services in the specified project and region asynchronously.

        Args:
            project: The GCP project ID
            location: The GCP region name

        Returns:
            List of scan results for discovered services with external ingress
        """
        scan_results = []
        services = await self.fetch_resources_async(project, location)

        # Query audit logs for all discovered services if enabled
        audit_log_events = []
        if self.config.gcp.audit_logs.enabled and services:
            try:
                logger.info(
                    f"Querying GCP audit logs for {len(services)} Cloud Run services in project {project}/{location}"
                )
                audit_service = GcpAuditLogs(project, self.config.gcp.audit_logs)
                # Use async audit log querying when available
                audit_log_events = await asyncio.to_thread(
                    audit_service.query_service_events, services
                )
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

    def find_resources(self, project: str, location: str) -> list[models.ScanResult]:
        """Find GCP Cloud Run services in the specified project and region.

        Args:
            project: The GCP project ID
            location: The GCP region name

        Returns:
            List of scan results for discovered services with external ingress
        """
        return asyncio.run(self.find_resources_async(project, location))

    async def fetch_resources_async(
        self, project: str, location: str
    ) -> list[models.GcpService]:
        """Fetch GCP Cloud Run services from the specified project and region asynchronously.

        Args:
            project: The GCP project ID
            location: The GCP region name

        Returns:
            List of GCP Cloud Run services
        """
        try:
            client = self.clients.services
            services = await asyncio.to_thread(
                client.list_services, parent=f"projects/{project}/locations/{location}"
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

    def fetch_resources(self, project: str, location: str) -> list[models.GcpService]:
        """Fetch GCP Cloud Run services from the specified project and region.

        Args:
            project: The GCP project ID
            location: The GCP region name

        Returns:
            List of GCP Cloud Run services
        """
        return asyncio.run(self.fetch_resources_async(project, location))


class Gcp:
    def __init__(
        self, config: models.LuminautConfig, clients: GcpClients | None = None
    ):
        self.config = config
        self.clients = clients if clients is not None else GcpClients()
        self.resource_discovery = GcpResourceDiscovery(self.config, self.clients)
        self.firewall_manager = GcpFirewallManager(self.clients)
        self.instance_discovery = GcpInstanceDiscovery(
            self.config, self.clients, self.firewall_manager
        )
        self.service_discovery = GcpServiceDiscovery(self.config, self.clients)

    def explore(self) -> list[models.ScanResult]:
        return asyncio.run(self.explore_async())

    async def explore_async(self) -> list[models.ScanResult]:
        if not self.config.gcp.enabled:
            return []

        tasks = []
        for project in self.resource_discovery.get_projects():
            tasks.extend(
                asyncio.to_thread(self.instance_discovery.find_resources, project, zone)
                for zone in self.resource_discovery.get_zones(project)
            )
            tasks.extend(
                asyncio.to_thread(
                    self.service_discovery.find_resources, project, region
                )
                for region in self.resource_discovery.get_regions(project)
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
