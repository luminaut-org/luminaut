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
    assert (
        hostname == nmap_results.ip
    )  # Currently expecting IP field to contain hostname
    assert "nmap" == nmap_results.findings[0].tool
    assert isinstance(nmap_results.findings[0].services[0], models.NmapPortServices)
    assert "http" == nmap_results.findings[0].services[0].name
    assert "nginx" == nmap_results.findings[0].services[0].product
    assert "1.20.1" == nmap_results.findings[0].services[0].version
