---
title: Features
layout: default
---

# Features

## AWS

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

## Active scanning

- [nmap](https://nmap.org/) to scan common ports and services against identified IP addresses.
  - nmap will only scan ports associated with permissive security group rules or a load balancer listener.
- [whatweb](https://github.com/urbanadventurer/WhatWeb) to identify services running on ports associated with exposed security group ports.
  - whatweb will only scan ports associated with permissive security group rules or a load balancer listener.

## Passive sources

- [shodan](https://www.shodan.io/) to gather information about exposed services and vulnerabilities.

## Reporting

- Console output with rich formatting, displaying key information.
- HTML capture of console output to preserve prior executions.
- CSV Timeline of events from CloudTrail and other sources.
- JSON lines output with full event information for parsing and integration with other tools.
