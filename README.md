# Luminaut

Casting light on shadow cloud deployments. Detect exposure of resources deployed in AWS.

![Luminaut Picture](https://raw.githubusercontent.com/luminaut-org/luminaut/refs/heads/main/.github/images/luminaut_readme_300.png)

![Under Development](https://img.shields.io/badge/Status-Under%20Development-orange)
![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Fluminaut-org%2Fluminaut%2Frefs%2Fheads%2Fmain%2Fpyproject.toml)
[![Test](https://github.com/luminaut-org/luminaut/actions/workflows/test.yml/badge.svg)](https://github.com/luminaut-org/luminaut/actions/workflows/test.yml)
[![Build artifacts](https://github.com/luminaut-org/luminaut/actions/workflows/build.yml/badge.svg)](https://github.com/luminaut-org/luminaut/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=luminaut-org_luminaut&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=luminaut-org_luminaut)
![PyPI - Downloads](https://img.shields.io/pypi/dm/luminaut)
![PyPI - Version](https://img.shields.io/pypi/v/luminaut)
![GitHub License](https://img.shields.io/github/license/luminaut-org/luminaut)

## Introduction

Luminaut is a utility to scope cloud environment exposure for triage. The goal is to quickly identify exposed resources and collect information to start an investigation.

Starting from the public IP addresses of AWS Elastic Network Interfaces (ENIs), Luminaut gathers information about the associated EC2 instances, load balancers, security groups, and related events. The framework also includes active scanning tools like nmap and whatweb, to identify services running on exposed ports, and passive sources like Shodan.

By combining cloud configuration data with external sources, Luminaut provides context to guide the next steps of an investigation.

While focused on AWS, Luminaut can be extended to support other cloud providers and services. The framework is designed to be modular, allowing for the addition of new tools and services as needed.

## Features

### AWS

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

### Active scanning

- [nmap](https://nmap.org/) to scan common ports and services against identified IP addresses.
  - nmap will only scan ports associated with permissive security group rules or a load balancer listener.
- [whatweb](https://github.com/urbanadventurer/WhatWeb) to identify services running on ports associated with exposed security group ports.
  - whatweb will only scan ports associated with permissive security group rules or a load balancer listener.

### Passive sources

- [shodan](https://www.shodan.io/) to gather information about exposed services and vulnerabilities.

### Reporting

- Console output with rich formatting, displaying key information.
- HTML capture of console output to preserve prior executions.
- CSV Timeline of events from CloudTrail and other sources.
- JSON lines output with full event information for parsing and integration with other tools.

## Installation

### via python

Luminaut is available on PyPI and can be installed with pip:

```bash
pip install luminaut
```

You can also download a release artifact from the [GitHub releases page](https://github.com/luminaut-org/luminaut/releases) and install it with pip.

Once installed, you can run luminaut from the command line.

```bash
luminaut --help
```

**Note:** Luminaut requires Python 3.11 or later. If you would like to leverage nmap or whatweb, you will need to install these tools separately.

### via docker

The docker image is available on GitHub, you can pull it locally by running: 

```bash
docker pull ghcr.io/luminaut-org/luminaut
```

If you would like to run it locally with just the name `luminaut`, you can then run:

```bash
docker tag ghcr.io/luminaut-org/luminaut luminaut:latest
```

For development, clone the repository and run `docker build --tag luminaut:latest` to build the container.

You can then run the container with:
 
```bash
docker run -it luminaut --help
```


## Usage

Luminaut requires access to AWS. The commands in this documentation assumes that your shell is already configured with the necessary AWS credentials. You can confirm your credential configuration by running `aws sts get-caller-identity`. For additional information on configuring AWS credentials, see the [AWS CLI documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html).

No arguments are required to run luminaut. The default is to look for a `luminaut.toml` file in the same directory
and run available tools to start detecting resources.

The default configuration options are shown in the [Configuration](#configuration) section.

Luminaut help is available with the argument `--help`.

```bash
$ luminaut --help                       
usage: luminaut [-h] [--config CONFIG] [--log LOG] [--verbose]

Luminaut: Casting light on shadow cloud deployments. 

options:
  -h, --help       show this help message and exit
  --config CONFIG  Configuration file. (default: luminaut.toml)
  --log LOG        Log file. (default: luminaut.log)
  --verbose        Verbose output in the log file. (default: False)
```

### Example

By default, Luminaut will run all available tools. It requires your AWS profile to be configured with the necessary permissions, otherwise the first step of public IP detection on ENIs will fail.

```bash
luminaut
```

The AWS Config scanner takes at least 50 seconds to run per resource type. If you would like to disable this, you can do so as shown in the provided `configs/disable_aws_config.toml` configuration file. You can provide this configuration with `-c configs/disable_aws_config.toml`.

```bash
luminaut -c configs/disable_aws_config.toml
```

Similarly, if you'd like to enable Shodan, you will need to specify a configuration file that includes the Shodan API key. See the [Configuration](#configuration) section for more information on the configuration file specification.

### Usage with docker

When running with docker, we need to supply a few arguments:
1. `-it` to run the container interactively and display the output in the terminal.
2. `-v ~/.aws:/home/app/.aws` to mount the AWS credentials from your host machine to the container.
3. `-e AWS_PROFILE=profile-name` to set the AWS profile to use in the container. Replace `profile-name` with the name of your AWS profile.
4. `-v $(pwd)/configs:/app/configs` to mount the configuration file from your host machine to the container.
5. `luminaut` to select the luminaut container.
6. `--help` to display the help message, though replace this with your desired arguments (ie `-c disable_aws_config.toml`).

Note that saved files, such as the log file and JSON reports, will be saved within the container. You may want to mount another volume to save the report files.

Example commands for...

Bash, zsh, and similar terminals:
```bash
docker run -it -v ~/.aws:/home/app/.aws -e AWS_PROFILE=profile-name -v $(pwd)/configs:/app/configs luminaut --help
```

Powershell:
```powershell
docker run -it -v $env:USERPROFILE\.aws:/home/app/.aws -e AWS_PROFILE=profile-name -v ${PWD}\configs:/app/configs luminaut --help
```

## Configuration

Luminaut uses a configuration file to define the tools and services to use. The default configuration will run with all tools enabled, though during runtime any tool not found will be skipped. The default reporting uses console output with JSON reporting disabled.

The configuration files are merged with the default configuration, meaning that you can omit any default values from your configuration file.

The configuration file is a TOML file with the following structure and defaults:

```toml
[report]
console = true  # Rich STDOUT console output

html = false  # Save the console output to an HTML file. Disabled by default.
html_file = "luminaut.html"  # Path is required if html is true

json = false  # JSON lines output, written to STDOUT. Disabled by default.
json_file = "luminaut.json"  # JSON lines output, written to a file. If omitted will write to stdout

timeline = false  # Timeline output, written to a CSV file. Disabled by default.
timeline_file = "luminaut_timeline.csv"  # Path is required if timeline is true

[tool.aws]
enabled = true  # Enable the AWS tool, requires the configuration of AWS credentials.
# aws_regions = ["us-east-1"] # The AWS regions to scan. Defaults to the region set in your AWS profile if none is supplied.

[tool.aws.config]
enabled = false  # Enables the scanning of AWS config. This can take a long time to run, as it scans all resource history. Disabled by default.

# The below dates must be specified as offset aware timestamps in RFC-3339 format, per https://toml.io/en/v1.0.0#offset-date-time.
# You can specify either the start, end, both, or None to influence the time period of the scan as desired.

# start_time = 2025-01-01T00:00:00Z  # The start time for the AWS Config scan. Defaults to no start time
# end_time = 2025-01-02T00:00:00Z  # The end time for the AWS Config scan. Defaults to no end time

[tool.aws.cloudtrail]
enabled = true  # Enables the collection of CloudTrail events related to discovered resources.

# The below dates must be specified as offset aware timestamps in RFC-3339 format, per https://toml.io/en/v1.0.0#offset-date-time
# You can specify either the start, end, both, or None to influence the time period of the scan as desired.

# start_time = 2025-01-01T00:00:00Z  # The start time for the AWS Config scan. Defaults to no start time
# end_time = 2025-01-02T00:00:00Z  # The end time for the AWS Config scan. Defaults to no end time

[[tool.aws.allowed_resources]]
# This configuration allows you to skip resources based on their type, ID, or tags.
# If an `id` is provided, the associated `type` is also required. Tags may be provided independently of the id and resource type.
# These settings only support skipping ENIs at the moment and applies across all scanned regions.

type = "AWS::EC2::NetworkInterface"  # The resource type, as specified by AWS
id = "eni-1234567890abcdef0"  # The resource ID

# Skip resources that match any of the specified tags. The key and value are case-sensitive.
# This is applied before, and separately from, the checks of a type and id. This is also applied across all scanned regions.
tags = { "luminaut" = "ignore", "reviewed" = "true" }

[tool.nmap]
enabled = true  # Enable the nmap tool, requires the nmap utility installed and on the system path. Enabled by default but will not run if nmap is not found on the path.

[tool.shodan]
enabled = true  # Enable the shodan tool, requires the shodan API key to be set in the configuration. Enabled by default, but will not run without an API key.
api_key = ""  # Shodan API key. If this is populated, treat the configuration file as a secret.

[tool.whatweb]
enabled = true  # Enable the whatweb tool, requires the whatweb utility installed and on the system path. Enabled by default, but will not run if whatweb is not found on the path.
```

The source of truth for the luminaut configuration is located in `luminaut.models.LuminautConfig`.

### AWS IAM Permissions

Luminaut requires the following minimum permissions to run:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LuminautReadResourcePermissions",
      "Action": [
        "cloudtrail:LookupEvents",
        "config:GetResourceConfigHistory",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroupRules",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTags"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

## Contributing

If you would like to contribute to Luminaut, please follow the guidelines in the [CONTRIBUTING.md](.github/CONTRIBUTING.md) file.
