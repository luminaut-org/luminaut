import logging
import subprocess

import nmap3
import nmap3.exceptions

from luminaut import models
from luminaut.tools.aws import Aws

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, *, config: models.LuminautConfig):
        self.config = config

    def nmap(self, ip_address: models.IPAddress) -> models.ScanResult:
        nmap = nmap3.Nmap()
        try:
            result = nmap.nmap_version_detection(
                target=ip_address,
                args="--version-light -Pn",
                timeout=self.config.nmap.timeout,
            )
        except nmap3.exceptions.NmapNotInstalledError as e:
            logger.warning(f"Skipping nmap, not found: {e}")
            return models.ScanResult(ip=ip_address, findings=[])
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap scan for {ip_address} timed out")
            return models.ScanResult(ip=ip_address, findings=[])

        port_services = []
        for port in result[ip_address]["ports"]:
            port_services.append(
                models.NmapPortServices(
                    port=int(port["portid"]),
                    protocol=models.Protocol(port["protocol"]),
                    name=port["service"]["name"],
                    product=port["service"]["product"],
                    version=port["service"]["version"],
                    state=port["state"],
                )
            )

        nmap_findings = models.ScanFindings(tool="nmap", services=port_services)
        return models.ScanResult(ip=ip_address, findings=[nmap_findings])

    @staticmethod
    def aws_fetch_public_enis() -> list[models.ScanResult]:
        return Aws().fetch_enis_with_public_ips()

    @staticmethod
    def aws_get_config_history_for_resource(
        resource_type: models.ResourceType,
        resource_id: str,
    ) -> list[models.ConfigItem]:
        return Aws().get_config_history_for_resource(resource_type, resource_id)

    @staticmethod
    def aws_populate_permissive_ingress_security_group_rules(
        security_group: models.SecurityGroup,
    ) -> models.SecurityGroup:
        return Aws().populate_permissive_ingress_security_group_rules(security_group)
