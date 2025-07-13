---
title: Features
layout: single
toc: true
---

# AWS

- Enumerate ENIs with public IPs.
- Gather information about associated EC2 instances and Elastic load balancers.
- Identify permissive rules for attached security groups.
- Scan CloudTrail history for related events to answer who, what, and when.
  - Supports querying for activity related to discovered ENI, EC2, ELB, and Security Group resources.
  - Optionally specify a time frame to limit the scan to a specific time period.
- Query AWS Config for resource configuration changes over time.
  - Supports scanning AWS Config history for the discovered ENI and EC2 Instance associated with the ENI.
  - Optionally specify a time frame to limit the scan to a specific time period.
- Skip scanning and reporting on resources based on the resource id or tag values
  - Supports skipping based on the resource id of the ENI.
  - Supports tag-based filtering using key-value pairs.
  - Only applies to AWS resources (ENIs), not GCP resources.

# GCP

- Enumerate Compute Engine instances with public IPs.
- Enumerate Cloud Run services with public URIs.
- Identify permissive firewall rules that allow external access to instances.

# Active scanning

- [nmap](https://nmap.org/) to scan ports and services against identified IP addresses.
  - nmap will scan ports associated with permissive firewall rules (allowing traffic from a public IP address) or load balancer listeners.
  - If no permissive rules or listeners are found, nmap will scan default ports (such as 80, 443, 8080, etc.).
- [whatweb](https://github.com/urbanadventurer/WhatWeb) to identify services running on exposed ports.
  - whatweb will scan ports associated with permissive firewall rules (allowing traffic from a public IP address) or load balancer listeners.
  - If no permissive rules or listeners are found, whatweb will scan default ports (such as 80, 443, 8080, etc.).

# Passive sources

- [shodan](https://www.shodan.io/) to gather information about exposed services and vulnerabilities.

# Advanced Features

## Security Rule Analysis
- **Permissive Rule Detection**: Only considers security group rules allowing ingress from public IPs as permissive
- **Protocol Filtering**: Excludes ICMP/ICMPv6 protocols from port scanning
- **Port Range Expansion**: Automatically expands security group port ranges into individual scan targets

## Concurrent Processing
- **Async Architecture**: External tools (nmap, Shodan, whatweb) run concurrently for each discovered IP
- **Parallel Cloud Scanning**: GCP projects, zones, and regions are scanned in parallel
- **Performance Optimization**: Uses asyncio to maximize scanning efficiency for large environments

# Reporting

- Console output with rich formatting, displaying key information.
- HTML capture of console output to preserve prior executions.
- CSV Timeline of events from CloudTrail and other sources.
- JSON lines output with full event information for parsing and integration with other tools.
