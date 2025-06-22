import logging

import google.auth
from google.cloud import compute_v1

from luminaut import models

logger = logging.getLogger(__name__)


class Gcp:
    def __init__(
        self,
        config: models.LuminautConfig,
        *,
        gcp_client: compute_v1.InstancesClient | None = None,
    ):
        self.config = config

    def get_compute_v1_client(self) -> compute_v1.InstancesClient:
        return compute_v1.InstancesClient()

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
        if not self.config.gcp.enabled:
            return []

        scan_results = []
        for project in self.get_projects():
            for zone in self.get_zones(project):
                logger.info(
                    "Scanning GCP project %s in zone %s",
                    project,
                    zone,
                )
                scan_results += self.find_instances(project, zone)
        logger.info("Completed scanning GCP projects")
        return scan_results

    def find_instances(self, project: str, zone: str) -> list[models.ScanResult]:
        scan_results = []
        for gcp_instance in self.fetch_instances(project, zone):
            if gcp_instance.has_public_ip():
                for network_interface in gcp_instance.network_interfaces:
                    if network_interface.public_ip is None:
                        continue  # To assist with type checking

                    scan_finding = models.ScanFindings(
                        tool="GCP Instance",
                        emoji_name="cloud",
                        resources=[gcp_instance],
                    )
                    scan_results.append(
                        models.ScanResult(
                            ip=network_interface.public_ip,
                            findings=[scan_finding],
                            region=zone,
                        )
                    )
        return scan_results

    def fetch_instances(self, project: str, zone: str) -> list[models.GcpInstance]:
        instances = self.get_compute_v1_client().list(
            project=project,
            zone=zone,
        )
        return [models.GcpInstance.from_gcp(instance) for instance in instances]
