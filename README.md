# Luminaut

Casting light on shadow cloud deployments. Detect exposure of resources deployed in AWS.

```text
          _..._                                          
        .'     '.                   .--.                 
       /    .-""-\               .-(    ).               
     .-|   /:.   |              (___.__)__)              
     |  \  |:.   /.-'-.                                  
     | .-'-;:__.'    =/                                  
     .'=  *=|     _.='                           .--.    
    /   _.  |    ;                            .-(    ).  
   ;-.-'|    \   |                           (___.__)__) 
  /   | \    _\  _\                                      
  \__/'._;.  ==' ==\                                     
           \    \   |                    .--.            
           /    /   /                 .-(    ).          
           /-._/-._/                 (___.__)__)         
           \   `\  \                                     
            `-._/._/                                     
```
![Under Development](https://img.shields.io/badge/Status-Under%20Development-orange)
![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Fluminaut-org%2Fluminaut%2Frefs%2Fheads%2Fmain%2Fpyproject.toml)
[![Test](https://github.com/luminaut-org/luminaut/actions/workflows/test.yml/badge.svg)](https://github.com/luminaut-org/luminaut/actions/workflows/test.yml)
[![Build artifacts](https://github.com/luminaut-org/luminaut/actions/workflows/build.yml/badge.svg)](https://github.com/luminaut-org/luminaut/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=luminaut-org_luminaut&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=luminaut-org_luminaut)


## Introduction

Luminaut is a framework that assembles tools and APIs commonly used to understand the scope of exposure for triage. This includes:
- Querying AWS for the active and historic configurations and events associated with exposed resources. Specifically focused on:
  - Enumerating ENIs with public IPs, along with associated EC2 instances and security groups.
  - Cataloging permissive security group rules.
  - Populating a timeline of related CloudTrail events.
  - Detecting changes to resource configuration through AWS Config history.
- Scanning the site with service detection tools like [nmap](https://nmap.org/) and [whatweb](https://github.com/urbanadventurer/WhatWeb).
- Gathering knowledge from network security scanning services like [shodan](https://www.shodan.io/).


## Installation

### Using docker

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

### For development

For development, install the following tools:
- [uv](https://docs.astral.sh/uv/) - package manager
- [pre-commit](https://pre-commit.com/) - code quality tool
- [nmap](https://nmap.org/) - port and service scanning utility
- [whatweb](https://github.com/urbanadventurer/WhatWeb) - web service scanning utility

Once installed, clone this repository and run: `uv sync` to install and configure your environment.

If that completed successfully, you should be able to run tests with `uv run pytest` or show the help information with `uv run luminaut --help`.

Before contributing code, run `pre-commit install` to install the pre-commit tools.

## Usage

No arguments are required to run luminaut. The default is to look for a `luminaut.toml` file in the same directory
and run available tools to start detecting resources.

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

You may run luminaut with docker by mounting the configuration file and running the container. Replace `--help` with any other arguments you would like to pass to luminaut. Note that saved files, such as the log file and JSON reports, will be saved within the container. You may want to mount another volume to save the report files.

Bash, zsh, and similar terminals:
```bash
docker run -it -v ~/.aws:/home/app/.aws -v $(pwd)/configs:/app/configs luminaut --help
```

Powershell:
```powershell
docker run -it -v $env:USERPROFILE\.aws:/home/app/.aws -v ${PWD}\configs:/app/configs luminaut --help
```

## Configuration

Luminaut uses a configuration file to define the tools and services to use. The default configuration will run with all tools enabled, though during runtime any tool not found will be skipped. The default reporting uses console output with JSON reporting disabled.

The configuration files are merged with the default configuration, meaning that you can omit any default values from your configuration file.

The configuration file is a TOML file with the following structure and defaults:

```toml
[report]
console = true  # Rich STDOUT console output
json = false  # JSON lines output, written to STDOUT.
json_file = "luminaut.json"  # JSON lines output, written to a file. If omitted will write to stdout
html = false  # HTML output, written to a file. Disabled by default.
html_file = "luminaut.html"  # Path is required if html is true

[tool.aws]
enabled = true  # Enable the AWS tool, requires the configuration of AWS credentials.
config.enabled = true  # Enables the scanning of AWS config. This can take a long time to run, as it scans all resource history.
cloudtrail.enabled = true  # Enables the collection of CloudTrail events related to discovered resources.

[[tool.aws.allowed_resources]]
# This configuration allows you to skip resources based on their type, ID, or tags.
# If an `id` is provided, the associated `type` is also required. Tags may be provided independently of the id and resource type.
# These settings only support skipping ENIs at the moment and applies across all scanned regions.

type = "AWS::EC2::NetworkInterface"  # The resource type, as specified by AWS
id = "eni-1234567890abcdef0"  # The resource ID

# Skip resources that match any of the specified tags. The key and value are case-sensitive.
# This is applied before, and separately from, the checks of a type and id.
tags = { "luminaut" = "ignore", "reviewed" = "true" }

[tool.nmap]
enabled = true  # Enable the nmap tool, requires the nmap utility installed and on the system path.

[tool.shodan]
enabled = false  # Enable the shodan tool, requires the shodan API key to be set in the configuration.
api_key = ""  # Shodan API key. If this is populated, treat the configuration file as a secret.

[tool.whatweb]
enabled = true  # Enable the whatweb tool, requires the whatweb utility installed and on the system path.
```

The source of truth for the luminaut configuration is located in `luminaut.models.LuminautConfig`.
