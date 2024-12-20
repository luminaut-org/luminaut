from abc import ABC, abstractmethod

import nmap3

from perimeter_scanner import models


class Scanner(ABC):
    def __init__(self, *, timeout: int = 30, **kwargs):
        self.timeout = timeout

    @abstractmethod
    def run(self, ip_address: models.IPAddress) -> models.ScanResult:
        pass


class NmapScanner(Scanner):
    def run(self, ip_address: models.IPAddress) -> models.ScanResult:
        return self.nmap(ip_address)

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
