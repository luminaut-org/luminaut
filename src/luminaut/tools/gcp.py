import logging

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
        self.gcp_client = gcp_client or compute_v1.InstancesClient()

    def explore(self) -> list[models.ScanResult]:
        if not self.config.gcp.enabled:
            return []

        if not self.config.gcp.projects:
            logger.warning("No GCP projects specified in the configuration.")
            return []
        if not self.config.gcp.compute_zones:
            logger.warning("No GCP compute zones specified in the configuration.")
            return []

        scan_results = []
        for project in self.config.gcp.projects:
            for zone in self.config.gcp.compute_zones:
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
        instances = self.gcp_client.list(
            project=project,
            zone=zone,
        )
        return [models.GcpInstance.from_gcp(instance) for instance in instances]
