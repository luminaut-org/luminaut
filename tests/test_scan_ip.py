from unittest.mock import Mock, patch

from luminaut import models
from luminaut.core import Luminaut
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


def test_nmap_passes_hostname_not_full_url():
    """Test that nmap receives only the hostname, not the full URL with schema."""
    expected_hostname = "example.com"

    # Mock nmap response using hostname's IP as key (which is what happens in real life)
    nmap_response = {
        "10.1.2.3": {
            "ports": [
                {
                    "portid": "8080",
                    "protocol": models.Protocol.TCP,
                    "reason": "syn-ack",
                    "service": {
                        "name": "http-alt",
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
            expected_hostname, ports=["8080"]
        )

        # Verify that nmap was called with just the hostname, not the full URL
        mocked_nmap3.Nmap().nmap_version_detection.assert_called_once_with(
            target=expected_hostname,  # Should be hostname only
            args="--version-light -Pn -p 8080",
            timeout=None,
        )

        # Verify the result contains the hostname in the url field
        assert expected_hostname == nmap_results.url
        assert nmap_results.ip is None
        assert len(nmap_results.findings) == 1
        assert nmap_results.findings[0].tool == "nmap"
        assert len(nmap_results.findings[0].services) == 1
        assert isinstance(nmap_results.findings[0].services[0], models.NmapPortServices)
        assert nmap_results.findings[0].services[0].name == "http-alt"


def test_core_extracts_hostname_from_url():
    """Test that core.py extracts hostname from URL before passing to nmap."""
    full_url = "https://api.example.com:8443/v1/endpoint"
    expected_hostname = "api.example.com"

    # Create a scan result with the full URL
    scan_result = models.ScanResult(url=full_url)

    # Mock the scanner's nmap method to capture what target it receives
    config = models.LuminautConfig()
    config.nmap.enabled = True
    luminaut = Luminaut(config)

    # Create a mock that returns a proper ScanResult and tracks calls
    mock_nmap = Mock(
        return_value=models.ScanResult(
            url=expected_hostname, findings=[models.ScanFindings(tool="nmap")]
        )
    )
    luminaut.scanner.nmap = mock_nmap

    # Run the nmap scan
    findings = luminaut.run_nmap(scan_result)

    # Verify that the hostname (not full URL) was passed to nmap
    mock_nmap.assert_called_once()
    call_args = mock_nmap.call_args
    assert (
        call_args[0][0] == expected_hostname
    )  # First positional argument should be hostname
    assert call_args[1]["ports"] is not None  # ports keyword argument should exist
    assert "8443" in call_args[1]["ports"]  # Should include the port from the URL
    assert len(findings) == 1
    assert findings[0].tool == "nmap"


def test_scan_result_ip_without_aws_metadata_uses_default_targets():
    """Test that ScanResult can generate default scan targets for IPs without AWS metadata."""
    # Test IP without any AWS metadata should use default ports
    scan_result = models.ScanResult(ip="192.168.1.1")
    targets = scan_result.generate_scan_targets()

    # Should generate default ports for the IP
    assert (
        len(targets) == 8
    )  # Default ports: 80, 443, 3000, 5000, 8000, 8080, 8443, 8888
    ips = {target.target for target in targets}
    assert ips == {"192.168.1.1"}

    # Verify some expected ports are present
    ports = {target.port for target in targets}
    assert 80 in ports
    assert 443 in ports
    assert 8080 in ports
    assert 8443 in ports
