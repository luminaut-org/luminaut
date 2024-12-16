from dataclasses import dataclass

from perimeter_scanner.console import console
from perimeter_scanner.query import Aws
from perimeter_scanner.scanner import NmapScanner


@dataclass
class LuminautConfig:
    pass


class Luminaut:
    def __init__(self, config: LuminautConfig):
        self.config = config

    def run(self):
        # Step 1: Enumerate ENIs with public IPs
        scan_results = Aws().fetch_enis_with_public_ips()
        for scan_result in scan_results:
            # Step 2: Run the various tools that depend on the IP address
            nmap_results = NmapScanner().run(scan_result.ip)
            scan_result.findings.extend(nmap_results.findings)

            panel = scan_result.build_rich_panel()
            console.print(panel)
