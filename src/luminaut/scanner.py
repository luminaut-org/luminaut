import logging
import subprocess

import nmap3
import nmap3.exceptions
import shodan

from luminaut import models
from luminaut.tools.aws import Aws
from luminaut.tools.whatweb import Whatweb

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, *, config: models.LuminautConfig):
        self.config = config

    def aws(self) -> list[models.ScanResult]:
        aws = Aws(self.config)

        scan_results = []
        logger.info("Scanning AWS regions: %s", ", ".join(self.config.aws.aws_regions))

        for region in self.config.aws.aws_regions:
            scan_results.extend(aws.explore_region(region))

        logger.info("Completed AWS scan of all specified regions.")
        return scan_results

    def nmap(self, ip_address: str) -> models.ScanResult:
        logger.info("Running nmap against %s", ip_address)
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
                    name=port["service"].get("name"),
                    product=port["service"].get("product"),
                    version=port["service"].get("version"),
                    state=port["state"],
                )
            )
        logger.info("Nmap found %s services on %s", len(port_services), ip_address)

        nmap_findings = models.ScanFindings(tool="nmap", services=port_services)
        return models.ScanResult(ip=ip_address, findings=[nmap_findings])

    def shodan(self, ip_address: str) -> models.ScanFindings:
        shodan_findings = models.ScanFindings(
            tool="Shodan.io", emoji_name="globe_with_meridians"
        )

        if not self.config.shodan.api_key:
            logger.warning("Skipping Shodan scan, missing API key")
            return shodan_findings

        shodan_client = shodan.Shodan(self.config.shodan.api_key)
        try:
            host = shodan_client.host(ip_address)
        except shodan.APIError as e:
            logger.warning("Incomplete Shodan finding due to API error: %s", e)
            return shodan_findings

        for service in host["data"]:
            shodan_findings.services.append(
                models.ShodanService.from_shodan_host(service)
            )

        logger.info(
            "Shodan found %s services on %s", len(shodan_findings.services), ip_address
        )

        for domain in host["domains"]:
            shodan_findings.resources.append(
                models.Hostname(
                    name=domain,
                    timestamp=host["last_update"],
                )
            )

        logger.info(
            "Shodan found %s domains on %s", len(shodan_findings.resources), ip_address
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
