from unittest import TestCase
from unittest.mock import Mock, patch

from luminaut import models
from luminaut.core import Luminaut
from luminaut.scanner import Scanner


class TestScanner(TestCase):
    def test_nmap(self):
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

        mocked_nmap3.Nmap().nmap_version_detection.assert_called_once()
        self.assertEqual(ip_addr, nmap_results.ip)
        self.assertEqual("nmap", nmap_results.findings[0].tool)
        self.assertIsInstance(
            nmap_results.findings[0].services[0], models.NmapPortServices
        )
        if isinstance(nmap_results.findings[0].services[0], models.NmapPortServices):
            # Though proven in the prior assertion, this proves it to pyright
            self.assertEqual("foo", nmap_results.findings[0].services[0].name)

    def test_nmap_hostname(self):
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

        mocked_nmap3.Nmap().nmap_version_detection.assert_called_once()
        self.assertEqual(hostname, nmap_results.url)  # Hostname should be in url field
        self.assertIsNone(nmap_results.ip)  # IP field should be None for hostname scans
        self.assertEqual("nmap", nmap_results.findings[0].tool)
        self.assertIsInstance(
            nmap_results.findings[0].services[0], models.NmapPortServices
        )

        if isinstance(nmap_results.findings[0].services[0], models.NmapPortServices):
            # Though proven in the prior assertion, this proves it to pyright
            self.assertEqual("http", nmap_results.findings[0].services[0].name)
            self.assertEqual("nginx", nmap_results.findings[0].services[0].product)
            self.assertEqual("1.20.1", nmap_results.findings[0].services[0].version)

    def test_url_scan_target_generation(self):
        """Test that ScanResult can generate proper scan targets from URLs for nmap scanning."""
        # Test URL with explicit port
        scan_result = models.ScanResult(url="https://example.com:8443")
        targets = scan_result.generate_scan_targets()

        expected_target = models.ScanTarget(
            target="example.com", port=8443, schema="https"
        )
        self.assertIn(expected_target, targets)
        self.assertEqual(len(targets), 1)

        # Test URL without explicit port (should use default ports)
        scan_result = models.ScanResult(url="https://api.example.com")
        targets = scan_result.generate_scan_targets()

        # Should generate default ports for the hostname
        self.assertEqual(len(targets), 8)
        hostnames = {target.target for target in targets}
        self.assertEqual(hostnames, {"api.example.com"})

        # Verify some expected ports are present
        ports = {target.port for target in targets}
        expected_ports = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888}
        self.assertEqual(ports, expected_ports)

        # Test URL with just hostname (no scheme)
        scan_result = models.ScanResult(url="web.example.com")
        targets = scan_result.generate_scan_targets()

        # Should still generate default ports
        self.assertEqual(len(targets), 8)
        hostnames = {target.target for target in targets}
        self.assertEqual(hostnames, {"web.example.com"})

    def test_nmap_with_url_scan_targets(self):
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

        mocked_nmap3.Nmap().nmap_version_detection.assert_called_once()
        self.assertEqual(hostname, nmap_results.url)  # Hostname should be in url field
        self.assertIsNone(nmap_results.ip)  # IP field should be None for hostname scans
        self.assertEqual("nmap", nmap_results.findings[0].tool)
        self.assertIsInstance(
            nmap_results.findings[0].services[0], models.NmapPortServices
        )

        if isinstance(nmap_results.findings[0].services[0], models.NmapPortServices):
            # Though proven in the prior assertion, this proves it to pyright
            self.assertEqual("http-proxy", nmap_results.findings[0].services[0].name)
            self.assertEqual("nginx", nmap_results.findings[0].services[0].product)
            self.assertEqual("1.20.1", nmap_results.findings[0].services[0].version)

    def test_nmap_passes_hostname_not_full_url(self):
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
        self.assertEqual(expected_hostname, nmap_results.url)
        self.assertIsNone(nmap_results.ip)
        self.assertEqual(1, len(nmap_results.findings))
        self.assertEqual("nmap", nmap_results.findings[0].tool)
        self.assertEqual(1, len(nmap_results.findings[0].services))
        self.assertIsInstance(
            nmap_results.findings[0].services[0], models.NmapPortServices
        )
        if isinstance(nmap_results.findings[0].services[0], models.NmapPortServices):
            # Though proven in the prior assertion, this proves it to pyright
            self.assertEqual("http-alt", nmap_results.findings[0].services[0].name)

    def test_core_extracts_hostname_from_url(self):
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
        self.assertEqual(
            call_args[0][0], expected_hostname
        )  # First positional argument should be hostname
        self.assertIsNotNone(
            call_args[1]["ports"]
        )  # ports keyword argument should exist
        self.assertIn(
            "8443", call_args[1]["ports"]
        )  # Should include the port from the URL
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].tool, "nmap")

    def test_scan_result_ip_without_aws_metadata_uses_default_targets(self):
        """Test that ScanResult can generate default scan targets for IPs without AWS metadata."""
        # Test IP without any AWS metadata should use default ports
        scan_result = models.ScanResult(ip="192.168.1.1")
        targets = scan_result.generate_scan_targets()

        # Should generate default ports for the IP
        self.assertEqual(len(targets), 8)
        ips = {target.target for target in targets}
        self.assertEqual(ips, {"192.168.1.1"})

        # Verify some expected ports are present
        ports = {target.port for target in targets}
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(8080, ports)
        self.assertIn(8443, ports)

    def test_nmap_port_state_filtering(self):
        """Test that nmap only includes ports with states: open, closed, and unfiltered."""
        ip_addr = "192.168.1.1"

        # Mock nmap response with various port states
        nmap_response = {
            ip_addr: {
                "ports": [
                    {
                        "portid": "22",
                        "protocol": models.Protocol.TCP,
                        "reason": "syn-ack",
                        "service": {
                            "name": "ssh",
                            "product": "OpenSSH",
                            "version": "8.9",
                        },
                        "state": "open",  # Should be included
                    },
                    {
                        "portid": "23",
                        "protocol": models.Protocol.TCP,
                        "reason": "reset",
                        "service": {"name": "telnet", "product": "", "version": ""},
                        "state": "closed",  # Should be included
                    },
                    {
                        "portid": "80",
                        "protocol": models.Protocol.TCP,
                        "reason": "no-response",
                        "service": {"name": "http", "product": "", "version": ""},
                        "state": "filtered",  # Should be excluded
                    },
                    {
                        "portid": "443",
                        "protocol": models.Protocol.TCP,
                        "reason": "no-response",
                        "service": {
                            "name": "https",
                            "product": "nginx",
                            "version": "1.20.1",
                        },
                        "state": "unfiltered",  # Should be included
                    },
                    {
                        "portid": "8080",
                        "protocol": models.Protocol.TCP,
                        "reason": "host-unreach",
                        "service": {"name": "http-proxy", "product": "", "version": ""},
                        "state": "open|filtered",  # Should be excluded
                    },
                    {
                        "portid": "3306",
                        "protocol": models.Protocol.TCP,
                        "reason": "reset",
                        "service": {
                            "name": "mysql",
                            "product": "MySQL",
                            "version": "8.0",
                        },
                        "state": "closed|filtered",  # Should be excluded
                    },
                ]
            }
        }

        with patch("luminaut.scanner.nmap3") as mocked_nmap3:
            mocked_nmap3.Nmap().nmap_version_detection.return_value = nmap_response
            nmap_results = Scanner(config=models.LuminautConfig()).nmap(ip_addr)

        # Verify the scan was executed
        mocked_nmap3.Nmap().nmap_version_detection.assert_called_once()

        # Verify only ports with allowed states are included
        services = nmap_results.findings[0].services
        self.assertEqual(len(services), 3)  # Only open, closed, and unfiltered ports

        # Check specific ports and their states
        states = {service.state for service in services}  # type: ignore
        expected_states = {"open", "closed", "unfiltered"}
        self.assertEqual(states, expected_states)
