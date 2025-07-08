from unittest.mock import patch

from luminaut import models
from luminaut.scanner import Scanner


def test_nmap():
    ip_addr = "127.0.0.1"
    service_name = "foo"
    service_product = "bar"
    service_version = "1.0"
    nmap_response = {
        ip_addr: {
            "ports": [
                {
                    "portid": "1",
                    "protocol": models.Protocol.TCP,
                    "reason": "syn-ack",
                    "service": {
                        "name": service_name,
                        "product": service_product,
                        "version": service_version,
                    },
                    "state": "open",
                }
            ]
        }
    }

    with patch("luminaut.scanner.nmap3") as mocked_nmap3:
        mocked_nmap3.Nmap().nmap_version_detection.return_value = nmap_response
        nmap_results = Scanner(config=models.LuminautConfig()).nmap(ip_addr)

    assert mocked_nmap3.Nmap().nmap_version_detection.called_once()
    assert ip_addr == nmap_results.ip
    assert "nmap" == nmap_results.findings[0].tool
    assert isinstance(nmap_results.findings[0].services[0], models.NmapPortServices)
    assert "foo" == nmap_results.findings[0].services[0].name


def test_nmap_hostname():
    hostname = "example.com"
    service_name = "http"
    service_product = "nginx"
    service_version = "1.20.1"
    nmap_response = {
        hostname: {
            "ports": [
                {
                    "portid": "80",
                    "protocol": models.Protocol.TCP,
                    "reason": "syn-ack",
                    "service": {
                        "name": service_name,
                        "product": service_product,
                        "version": service_version,
                    },
                    "state": "open",
                }
            ]
        }
    }

    with patch("luminaut.scanner.nmap3") as mocked_nmap3:
        mocked_nmap3.Nmap().nmap_version_detection.return_value = nmap_response
        nmap_results = Scanner(config=models.LuminautConfig()).nmap(hostname)

    assert mocked_nmap3.Nmap().nmap_version_detection.called_once()
    assert hostname == nmap_results.url  # Hostname should be in url field
    assert nmap_results.ip is None  # IP field should be None for hostname scans
    assert "nmap" == nmap_results.findings[0].tool
    assert isinstance(nmap_results.findings[0].services[0], models.NmapPortServices)
    assert "http" == nmap_results.findings[0].services[0].name
    assert "nginx" == nmap_results.findings[0].services[0].product
    assert "1.20.1" == nmap_results.findings[0].services[0].version


def test_url_scan_target_generation():
    """Test that ScanResult can generate proper scan targets from URLs for nmap scanning."""
    # Test URL with explicit port
    scan_result = models.ScanResult(url="https://example.com:8443")
    targets = scan_result.generate_scan_targets()

    expected_target = models.ScanTarget(target="example.com", port=8443, schema="https")
    assert expected_target in targets
    assert len(targets) == 1

    # Test URL without explicit port (should use default ports)
    scan_result = models.ScanResult(url="https://api.example.com")
    targets = scan_result.generate_scan_targets()

    # Should generate default ports for the hostname
    assert (
        len(targets) == 8
    )  # Default ports: 80, 443, 3000, 5000, 8000, 8080, 8443, 8888
    hostnames = {target.target for target in targets}
    assert hostnames == {"api.example.com"}

    # Verify some expected ports are present
    ports = {target.port for target in targets}
    expected_ports = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888}
    assert ports == expected_ports

    # Test URL with just hostname (no scheme)
    scan_result = models.ScanResult(url="web.example.com")
    targets = scan_result.generate_scan_targets()

    # Should still generate default ports
    assert len(targets) == 8
    hostnames = {target.target for target in targets}
    assert hostnames == {"web.example.com"}


def test_nmap_with_url_scan_targets():
    """Test that nmap can use scan targets generated from URLs."""
    url = "https://example.com:8080"
    hostname = "example.com"
    port = "8080"

    # Create a ScanResult with URL
    scan_result = models.ScanResult(url=url)
    targets = scan_result.generate_scan_targets()

    # Extract ports for nmap scanning (similar to how core.py would do it)
    port_list = [str(target.port) for target in targets]

    # Mock nmap response
    nmap_response = {
        hostname: {
            "ports": [
                {
                    "portid": port,
                    "protocol": models.Protocol.TCP,
                    "reason": "syn-ack",
                    "service": {
                        "name": "http-proxy",
                        "product": "nginx",
                        "version": "1.20.1",
                    },
                    "state": "open",
                }
            ]
        }
    }

    with patch("luminaut.scanner.nmap3") as mocked_nmap3:
        mocked_nmap3.Nmap().nmap_version_detection.return_value = nmap_response
        nmap_results = Scanner(config=models.LuminautConfig()).nmap(
            hostname, ports=port_list
        )

    assert mocked_nmap3.Nmap().nmap_version_detection.called_once()
    assert hostname == nmap_results.url  # Hostname should be in url field
    assert nmap_results.ip is None  # IP field should be None for hostname scans
    assert "nmap" == nmap_results.findings[0].tool
    assert isinstance(nmap_results.findings[0].services[0], models.NmapPortServices)
    assert "http-proxy" == nmap_results.findings[0].services[0].name
    assert "nginx" == nmap_results.findings[0].services[0].product
    assert "1.20.1" == nmap_results.findings[0].services[0].version
