from dataclasses import dataclass
from enum import StrEnum, auto
from ipaddress import IPv4Address, IPv6Address

import nmap3

IPAddressType = IPv4Address | IPv6Address


class Protocol(StrEnum):
    TCP = auto()
    UDP = auto()
    ICMP = auto()


@dataclass
class NmapPortServices:
    port: int
    protocol: Protocol
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
    def __init__(self, *, timeout: int = 30):
        self.timeout = timeout

    def nmap(self, ip_address: IPAddressType) -> ScanResult:
        nmap = nmap3.Nmap()
        result = nmap.nmap_version_detection(
            target=ip_address,
            args=["--version-light"],
            timeout=self.timeout,
        )

        port_services = []
        for port in result[ip_address]["ports"]:
            port_services.append(
                NmapPortServices(
                    port=int(port["portid"]),
                    protocol=Protocol(port["protocol"]),
                    name=port["service"]["name"],
                    product=port["service"]["product"],
                    version=port["service"]["version"],
                    state=port["state"],
                )
            )

        nmap_findings = ScanFindings(tool="nmap", services=port_services)
        return ScanResult(ip=ip_address, findings=[nmap_findings])
