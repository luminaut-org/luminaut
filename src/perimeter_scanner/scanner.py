from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

import nmap3

IPAddressType = IPv4Address | IPv6Address


@dataclass
class NmapPortServices:
    port: int
    protocol: str
    name: str
    product: str
    version: str
    state: str


@dataclass
class ScanFindings:
    tool: str
    services: list[NmapPortServices]


@dataclass
class ScanResult:
    ip: str
    findings: list[ScanFindings]


class Scanner:
    @classmethod
    def nmap(cls, ip_address: IPAddressType) -> ScanResult:
        nmap = nmap3.Nmap()
        result = nmap.nmap_version_detection(ip_address, timeout=30)

        port_services = []
        for port in result[ip_address]["ports"]:
            port_services.append(
                NmapPortServices(
                    port=int(port["portid"]),
                    protocol=port["protocol"],
                    name=port["service"]["name"],
                    product=port["service"]["product"],
                    version=port["service"]["version"],
                    state=port["state"],
                )
            )

        nmap_findings = ScanFindings(tool="nmap", services=port_services)
        return ScanResult(ip=ip_address, findings=[nmap_findings])
