import asyncio
import logging

import google.auth
from google.cloud import compute_v1, run_v2

from luminaut import models

logger = logging.getLogger(__name__)


class Gcp:
    def __init__(self, config: models.LuminautConfig):
        self.config = config

    def get_compute_v1_client(self) -> compute_v1.InstancesClient:
        return compute_v1.InstancesClient()

    def get_run_v2_services_client(self) -> run_v2.ServicesClient:
        return run_v2.ServicesClient()

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
            all_regions = compute_v1.RegionsClient().list(project=project)
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
            all_zones = compute_v1.ZonesClient().list(project=project)
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
            for zone in self.get_zones(project):
                tasks.append(asyncio.to_thread(self.find_instances, project, zone))
            for region in self.get_regions(project):
                tasks.append(asyncio.to_thread(self.find_services, project, region))
        results = await asyncio.gather(*tasks)

        scan_results = []
        for r in results:
            scan_results.extend(r)
        logger.info("Completed scanning GCP")
        return scan_results

    def find_instances(self, project: str, zone: str) -> list[models.ScanResult]:
        scan_results = []
        for gcp_instance in self.fetch_instances(project, zone):
            for public_ip in gcp_instance.get_public_ips():
                scan_finding = models.ScanFindings(
                    tool="GCP Instance",
                    emoji_name="cloud",
                    resources=[gcp_instance],
                )
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
            instances = self.get_compute_v1_client().list(
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
        for service in self.fetch_run_services(project, location):
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
            client = self.get_run_v2_services_client()
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
