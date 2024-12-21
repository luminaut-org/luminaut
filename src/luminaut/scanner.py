import nmap3

from luminaut import models
from luminaut.tools.aws import Aws


class Scanner:
    def __init__(self, *, timeout: int = 30, **kwargs):
        self.timeout = timeout

    def nmap(self, ip_address: models.IPAddress) -> models.ScanResult:
        nmap = nmap3.Nmap()
        result = nmap.nmap_version_detection(
            target=ip_address,
            args="--version-light -Pn",
            timeout=self.timeout,
        )

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
        ip_address: models.IPAddress,
    ) -> models.ScanResult:
        return Aws().get_config_history_for_resource(
            resource_type, resource_id, ip_address
        )
