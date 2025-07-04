import logging
import subprocess

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

    def nmap(
        self, ip_address: str, ports: list[str] | None = None
    ) -> models.ScanResult:
        port_list = ",".join(ports) if ports else None
        logger.info("Running nmap against %s with ports: %s", ip_address, port_list)

        nmap = nmap3.Nmap()
        nmap_args = "--version-light -Pn"
        if port_list:
            nmap_args += f" -p {port_list}"
        try:
            result = nmap.nmap_version_detection(
                target=ip_address,
                args=nmap_args,
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

    def nmap_targets(
        self, scan_targets: list[models.ScanTarget]
    ) -> list[models.ScanResult]:
        if not scan_targets:
            return []

        # Build target list and port list for nmap
        target_list = []
        port_set = set()

        for scan_target in scan_targets:
            target_list.append(scan_target.target)
            port_set.add(str(scan_target.port))

        targets_str = ",".join(target_list)
        ports_str = ",".join(sorted(port_set))

        logger.info(
            "Running nmap against targets %s with ports: %s", targets_str, ports_str
        )

        nmap = nmap3.Nmap()
        nmap_args = "--version-light -Pn"
        if ports_str:
            nmap_args += f" -p {ports_str}"

        try:
            result = nmap.nmap_version_detection(
                target=targets_str,
                args=nmap_args,
                timeout=self.config.nmap.timeout,
            )
        except nmap3.exceptions.NmapNotInstalledError as e:
            logger.warning(f"Skipping nmap, not found: {e}")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap scan for {targets_str} timed out")
            return []

        # Process results for each target
        scan_results = []
        for scan_target in scan_targets:
            target = scan_target.target
            if target in result:
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

                nmap_findings = models.ScanFindings(tool="nmap", services=port_services)

                # Create ScanResult based on target type
                if scan_target.target_type == models.TargetType.IP:
                    scan_result = models.ScanResult(ip=target, findings=[nmap_findings])
                else:
                    scan_result = models.ScanResult(
                        url=self._build_url(scan_target), findings=[nmap_findings]
                    )

                scan_results.append(scan_result)
                logger.info("Nmap found %s services on %s", len(port_services), target)
            else:
                # Target not found in results
                if scan_target.target_type == models.TargetType.IP:
                    scan_result = models.ScanResult(ip=target, findings=[])
                else:
                    scan_result = models.ScanResult(
                        url=self._build_url(scan_target), findings=[]
                    )
                scan_results.append(scan_result)
                logger.warning("No nmap results found for target %s", target)

        return scan_results

    def _build_url(self, scan_target: models.ScanTarget) -> str:
        """Build URL from ScanTarget for hostname targets."""
        if scan_target.schema:
            return f"{scan_target.schema}://{scan_target.target}:{scan_target.port}"
        return f"http://{scan_target.target}:{scan_target.port}"

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
