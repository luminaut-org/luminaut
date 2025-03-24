#!/usr/bin/env python
"""Query Shodan for a given IP address and save the results to a file.

## Usage

```text
query_shodan.py <config> <IP>

<config> is the path to the config file.
<IP> is the IP address to query.
```

## Description

This script will query Shodan for the given IP address and save the results to a file,
using the Luminaut framework. The intention of this script is to demonstrate how to
use the Luminaut framework as a Python library to integrate with other tools.

The `LuminautConfig` object is used to configure the Luminaut framework, and does
not need to be constructed from a TOML file. It is possible to configure the object
manually or to omit it to use the default configuration. In this
example, the configuration is required as we need to provide the Shodan API key.

The `query_shodan` method provides the functionality to query Shodan for a given IP
address. It requires a `ScanResult` object as an argument, which contains the IP
address to query. The method then returns a list of `ScanResult` objects, which
contain the results of the query.

The `report` method is used to then provide the results, based on the configuration
provided in the `LuminautConfig` object.

It is possible to use the `ScanResult` object to construct a custom report of the
findings, using the data available in the `ScanResult` object. The model definitions
are available in the `luminaut.models` module. Luminaut does provide a JSON report
format, which includes all available data in the `ScanResult` object.

## Example

Config file:

```toml
[report]
console = true
json = true
json_file = "shodan_example.json"

[tool.shodan]
enabled = true
api_key = "your_shodan_api_key"
```

Command execution:

```bash
python query_shodan.py shodan.toml 1.1.1.1
```

This will query Shodan for the IP address `1.1.1.1` and save the results to a file,
using the Luminaut framework.

Trimmed example of the terminal output:

```text
1.1.1.1 ────────────────────────────────────────────────────────────────────────────────────────
🌐 Shodan.io
Services:
tcp/53 (as of 2025-03-23 09:00:08.034606)
udp/53 (as of 2025-03-24 06:57:25.058305)
tcp/80 CloudFlare (as of 2025-03-24 03:39:30.769480)
  HTTP Server: cloudflare HTTP Title: Edge IP Restricted | www.live.schoolloop.com | Cloudflare
udp/161 (as of 2025-03-09 22:25:36.422962)
tcp/443 CloudFlare (as of 2025-03-24 06:57:18.638182)
  HTTP Server: cloudflare HTTP Title: 403 Forbidden
[... more services ...]
Resources:
 Hostname: one.one (as of 2025-03-24T06:57:34.011262)
```

Trimmed example of the JSON report:

```json
{
    "ip": "1.1.1.1",
    "findings": [
        {
            "tool": "Shodan.io",
            "services": [
                {
                    "timestamp": "2025-03-23T09:00:08.034606",
                    "port": 53,
                    "protocol": "tcp",
                    "product": null,
                    "data": "\nRecursion: enabled\nResolver ID: EWR",
                    "operating_system": null,
                    "cpe": [],
                    "tags": [],
                    "http_server": null,
                    "http_title": null,
                    "opt_heartbleed": null,
                    "opt_vulnerabilities": []
                },
                {
                    "timestamp": "2025-03-24T06:57:25.058305",
                    "port": 53,
                    "protocol": "udp",
                    "product": null,
                    "data": "\nRecursion: enabled\nResolver ID: SOF",
                    "operating_system": null,
                    "cpe": [],
                    "tags": [],
                    "http_server": null,
                    "http_title": null,
                    "opt_heartbleed": null,
                    "opt_vulnerabilities": []
                },
                {
                    "timestamp": "2025-03-24T03:39:30.769480",
                    "port": 80,
                    "protocol": "tcp",
                    "product": "CloudFlare",
                    "data": "HTTP/1.1 403 Forbidden\r\nDate: Mon, 24 Mar 2025 03:39:30 GMT [... more data ...]",
                    "operating_system": null,
                    "cpe": [],
                    "tags": [],
                    "http_server": "cloudflare",
                    "http_title": "Edge IP Restricted | www.live.schoolloop.com | Cloudflare",
                    "opt_heartbleed": null,
                    "opt_vulnerabilities": []
                },
                {
                    "timestamp": "2025-03-09T22:25:36.422962",
                    "port": 161,
                    "protocol": "udp",
                    "product": null,
                    "data": "SNMP:\n  Versions:\n    3\n  Engineid Format: mac\n [... more data ...]",
                    "operating_system": null,
                    "cpe": [],
                    "tags": [],
                    "http_server": null,
                    "http_title": null,
                    "opt_heartbleed": null,
                    "opt_vulnerabilities": []
                },
                {
                    "timestamp": "2025-03-24T06:57:18.638182",
                    "port": 443,
                    "protocol": "tcp",
                    "product": "CloudFlare",
                    "data": "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nDate: Mon, 24 Mar 2025 06:57:18 GMT\r\n [... more data ...]",
                    "operating_system": null,
                    "cpe": [],
                    "tags": [],
                    "http_server": "cloudflare",
                    "http_title": "403 Forbidden",
                    "opt_heartbleed": "2025/03/24 06:57:28 1.1.1.1:443 - SAFE\n",
                    "opt_vulnerabilities": []
                },
                {
                    "...": "...more services ..."
                }
            ],
            "resources": [
                {
                    "name": "one.one",
                    "timestamp": "2025-03-24T06:57:34.011262"
                }
            ],
            "events": [],
            "emoji_name": "globe_with_meridians"
        }
    ],
    "region": null,
    "eni_id": null
}
```
"""

import argparse
from pathlib import Path

from luminaut import Luminaut, LuminautConfig
from luminaut.models import ScanResult

if __name__ == "__main__":
    cli_args = argparse.ArgumentParser()
    cli_args.add_argument("config", type=Path)
    cli_args.add_argument("IP", type=str)
    args = cli_args.parse_args()

    config = LuminautConfig.from_toml(args.config.open("rb"))
    luminaut = Luminaut(config)

    scan = ScanResult(ip=args.IP, findings=[])
    scan.findings += luminaut.query_shodan(scan)
    luminaut.report([scan])
