from dataclasses import dataclass

from rich.emoji import Emoji

from perimeter_scanner.console import console
from perimeter_scanner.query import QueryPublicAwsEni
from perimeter_scanner.scanner import NmapScanner


@dataclass
class LuminautConfig:
    pass


class Luminaut:
    def __init__(self, config: LuminautConfig):
        self.config = config

    def run(self):
        # Step 1: Enumerate ENIs with public IPs
        enis_with_public_ips = QueryPublicAwsEni().run()
        for eni in enis_with_public_ips.data:
            panel = eni.build_rich_panel()

            nmap_results = []
            scan_results = NmapScanner().run(eni.public_ip)
            for scan_finding in scan_results.findings:
                for service in scan_finding.services:
                    nmap_results.append(service.build_rich_text())

            if nmap_results:
                panel.renderable += f"\n[bold underline]{Emoji('mag')} Nmap Scan Results[/bold underline]\n"
                panel.renderable += "\n".join(nmap_results)

            console.print(panel)
