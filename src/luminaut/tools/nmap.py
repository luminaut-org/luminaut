import logging
import subprocess
from typing import Any

import nmap3
import nmap3.exceptions

from luminaut import models

logger = logging.getLogger(__name__)


class Nmap:
    def __init__(self, config: models.LuminautConfig):
        self.config = config

    def scan_targets(
        self, scan_targets: list[models.ScanTarget]
    ) -> list[models.ScanResult]:
        """Scan multiple targets with nmap and return results."""
        if not scan_targets:
            return []

        targets_str, ports_str = self._build_command_args(scan_targets)
        nmap_result = self._execute_scan(targets_str, ports_str)

        if nmap_result is None:  # Error occurred
            return []

        return self._parse_results(scan_targets, nmap_result)

    def _build_command_args(
        self, scan_targets: list[models.ScanTarget]
    ) -> tuple[str, str]:
        """Build target list and port list for nmap command."""
        target_list = []
        port_set = set()

        for scan_target in scan_targets:
            target_list.append(scan_target.target)
            port_set.add(str(scan_target.port))

        targets_str = ",".join(target_list)
        ports_str = ",".join(sorted(port_set))

        return targets_str, ports_str

    def _execute_scan(self, targets_str: str, ports_str: str) -> dict[str, Any] | None:
        """Execute nmap scan and handle errors."""
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
            return result
        except nmap3.exceptions.NmapNotInstalledError as e:
            logger.warning(f"Skipping nmap, not found: {e}")
            return None
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap scan for {targets_str} timed out")
            return None

    def _parse_results(
        self, scan_targets: list[models.ScanTarget], result: dict[str, Any]
    ) -> list[models.ScanResult]:
        """Parse nmap results and create ScanResult objects."""
        scan_results = []

        for scan_target in scan_targets:
            target = scan_target.target
            if target in result:
                port_services = self._parse_port_services(result[target]["ports"])
                nmap_findings = models.ScanFindings(
                    tool="nmap", services=list(port_services)
                )
                scan_result = self._build_scan_result(scan_target, [nmap_findings])
                scan_results.append(scan_result)
                logger.info("Nmap found %s services on %s", len(port_services), target)
            else:
                # Target not found in results
                scan_result = self._build_scan_result(scan_target, [])
                scan_results.append(scan_result)
                logger.warning("No nmap results found for target %s", target)

        return scan_results

    def _parse_port_services(
        self, ports: list[dict[str, Any]]
    ) -> list[models.NmapPortServices]:
        """Parse port information from nmap results."""
        port_services = []
        for port in ports:
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
        return port_services

    def _build_scan_result(
        self, scan_target: models.ScanTarget, findings: list[models.ScanFindings]
    ) -> models.ScanResult:
        """Build ScanResult based on target type."""
        if scan_target.target_type == models.TargetType.IP:
            return models.ScanResult(ip=scan_target.target, findings=findings)
        else:
            return models.ScanResult(
                url=self._build_url(scan_target), findings=findings
            )

    def _build_url(self, scan_target: models.ScanTarget) -> str:
        """Build URL from ScanTarget for hostname targets."""
        if scan_target.schema:
            return f"{scan_target.schema}://{scan_target.target}:{scan_target.port}"
        return f"http://{scan_target.target}:{scan_target.port}"
