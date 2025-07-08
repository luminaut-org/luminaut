import logging
import subprocess
from ipaddress import ip_address

import nmap3
import nmap3.exceptions
import shodan

from luminaut import models
from luminaut.tools.aws import Aws
from luminaut.tools.gcp import Gcp
from luminaut.tools.whatweb import Whatweb

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, *, config: models.LuminautConfig):
        self.config = config

    def aws(self) -> list[models.ScanResult]:
        aws = Aws(self.config)

        scan_results = []
        regions = self.config.aws.aws_regions

        try:
            if regions:
                for region in regions:
                    scan_results.extend(aws.explore_region(region))
            else:
                scan_results.extend(aws.explore_region())
        except Exception as e:
            logger.error("Failed to explore AWS regions: %s", e)
            return []
        return scan_results

    def gcp(self) -> list[models.ScanResult]:
        try:
            return Gcp(self.config).explore()
        except Exception as e:
            logger.error("Failed to explore GCP: %s", e)
            return []

    def nmap(self, target: str, ports: list[str] | None = None) -> models.ScanResult:
        port_list = ",".join(ports) if ports else None
        logger.info("Running nmap against %s with ports: %s", target, port_list)

        nmap = nmap3.Nmap()
        nmap_args = "--version-light -Pn"
        if port_list:
            nmap_args += f" -p {port_list}"
        try:
            result = nmap.nmap_version_detection(
                target=target,
                args=nmap_args,
                timeout=self.config.nmap.timeout,
            )
        except nmap3.exceptions.NmapNotInstalledError as e:
            logger.warning(f"Skipping nmap, not found: {e}")
            return self._create_scan_result(target, [])
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap scan for {target} timed out")
            return self._create_scan_result(target, [])

        port_services = []
        for port in result[target]["ports"]:
            port_services.append(
                models.NmapPortServices(
                    port=int(port["portid"]),
                    protocol=models.Protocol(port["protocol"]),
                    name=port["service"].get("name"),
                    product=port["service"].get("product"),
                    version=port["service"].get("version"),
                    state=port["state"],
                )
            )
        logger.info("Nmap found %s services on %s", len(port_services), target)

        nmap_findings = models.ScanFindings(tool="nmap", services=port_services)
        return self._create_scan_result(target, [nmap_findings])

    def shodan(self, ip_addr: str) -> models.ScanFindings:
        shodan_findings = models.ScanFindings(
            tool="Shodan.io", emoji_name="globe_with_meridians"
        )

        if not self.config.shodan.api_key:
            logger.warning("Skipping Shodan scan, missing API key")
            return shodan_findings

        shodan_client = shodan.Shodan(self.config.shodan.api_key)
        try:
            host = shodan_client.host(ip_addr)
        except shodan.APIError as e:
            logger.warning("Incomplete Shodan finding due to API error: %s", e)
            return shodan_findings

        for service in host["data"]:
            shodan_findings.services.append(
                models.ShodanService.from_shodan_host(service)
            )

        logger.info(
            "Shodan found %s services on %s", len(shodan_findings.services), ip_addr
        )

        for domain in host["domains"]:
            shodan_findings.resources.append(
                models.Hostname(
                    name=domain,
                    timestamp=host["last_update"],
                )
            )

        logger.info(
            "Shodan found %s domains on %s", len(shodan_findings.resources), ip_addr
        )

        return shodan_findings

    def whatweb(self, targets: list[str]) -> models.ScanFindings | None:
        logger.info("Running Whatweb against %s", ", ".join(targets))

        finding = models.ScanFindings(tool="Whatweb", emoji_name="spider_web")
        for target in targets:
            try:
                result = Whatweb(self.config).run(target)
                if result:
                    finding.services.append(result)
            except RuntimeError as e:
                logger.warning(f"Skipping Whatweb, not found: {e}")
                return None
            except subprocess.TimeoutExpired:
                logger.warning(f"Whatweb scan for {target} timed out")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Whatweb scan for {target} failed: {e}")

        logger.info("Whatweb found %s services across targets", len(finding.services))

        return finding

    def _create_scan_result(
        self, target: str, findings: list[models.ScanFindings]
    ) -> models.ScanResult:
        """Helper to create ScanResult with correct field based on target type."""
        try:
            ip_address(target)
            return models.ScanResult(ip=target, findings=findings)
        except ValueError:
            return models.ScanResult(url=target, findings=findings)
