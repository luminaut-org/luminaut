from unittest.mock import patch

import pytest

from luminaut import models
from luminaut.scanner import Scanner


@pytest.fixture
def scanner() -> Scanner:
    return Scanner(config=models.LuminautConfig())


def create_nmap_response(
    target: str,
    port: int,
    service_name: str,
    service_product: str,
    service_version: str,
) -> dict[str, dict[str, list[dict[str, str | dict[str, str]]]]]:
    return {
        target: {
            "ports": [
                {
                    "portid": str(port),
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


def assert_scan_result(
    result: models.ScanResult,
    expected_ip: str | None = None,
    expected_url: str | None = None,
    expected_service_name: str | None = None,
) -> None:
    assert result.ip == expected_ip
    assert result.url == expected_url
    assert len(result.findings) == 1
    assert result.findings[0].tool == "nmap"
    assert len(result.findings[0].services) == 1
    if expected_service_name:
        service = result.findings[0].services[0]
        assert isinstance(service, models.NmapPortServices)
        assert service.name == expected_service_name


def test_nmap() -> None:
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


@pytest.mark.parametrize(
    "target,port,schema,expected_ip,expected_url,service_name",
    [
        ("192.168.1.1", 80, None, "192.168.1.1", None, "http"),
        ("example.com", 443, "https", None, "https://example.com:443", "https"),
    ],
)
def test_nmap_targets_single(
    scanner: Scanner,
    target: str,
    port: int,
    schema: str | None,
    expected_ip: str | None,
    expected_url: str | None,
    service_name: str,
) -> None:
    scan_target = models.ScanTarget(target=target, port=port, schema=schema)
    nmap_response = create_nmap_response(target, port, service_name, "nginx", "1.20")

    with patch("luminaut.tools.nmap.nmap3") as mocked_nmap3:
        mocked_nmap3.Nmap().nmap_version_detection.return_value = nmap_response
        results = scanner.nmap_targets([scan_target])

    assert len(results) == 1
    assert_scan_result(results[0], expected_ip, expected_url, service_name)


def test_nmap_targets_multiple_mixed(scanner: Scanner) -> None:
    ip_addr = "10.0.0.1"
    hostname = "test.example.com"
    port1 = 80
    port2 = 443

    scan_targets = [
        models.ScanTarget(target=ip_addr, port=port1),
        models.ScanTarget(target=hostname, port=port2, schema="https"),
    ]

    nmap_response = {
        **create_nmap_response(ip_addr, port1, "http", "nginx", "1.18"),
        **create_nmap_response(hostname, port2, "https", "Apache", "2.4"),
    }

    with patch("luminaut.tools.nmap.nmap3") as mocked_nmap3:
        mocked_nmap3.Nmap().nmap_version_detection.return_value = nmap_response
        results = scanner.nmap_targets(scan_targets)

    assert len(results) == 2

    # Find IP result
    ip_result = next(r for r in results if r.ip == ip_addr)
    assert_scan_result(
        ip_result, expected_ip=ip_addr, expected_url=None, expected_service_name="http"
    )

    # Find hostname result
    hostname_result = next(
        r for r in results if r.url == "https://test.example.com:443"
    )
    assert_scan_result(
        hostname_result,
        expected_ip=None,
        expected_url="https://test.example.com:443",
        expected_service_name="https",
    )
