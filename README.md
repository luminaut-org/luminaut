# Luminaut

Casting light on shadow cloud deployments. Detect exposure of resources deployed in AWS.

```text
          _..._
        .'     '.
       /    .-""-\
     .-|   /:.   |
     |  \  |:.   /.-'-.
     | .-'-;:__.'    =/
     .'=  *=|     _.='
    /   _.  |    ;
   ;-.-'|    \   |
  /   | \    _\  _\
  \__/'._;.  ==' ==\
           \    \   |
           /    /   /
           /-._/-._/
           \   `\  \
            `-._/._/
```

## Introduction

Luminaut is a framework that assembles tools and APIs commonly used to understand the scope of exposure for triage. This includes:
- Fetching configurations from AWS
- Scanning the site with service detection tools like [nmap](https://nmap.org/) and [whatweb](https://github.com/urbanadventurer/WhatWeb).
- Gathering knowledge from common services like [shodan](https://www.shodan.io/)


## Installation

### Using docker

Run `docker build --tag luminaut:latest` to build the container.

You can then run the container with `docker run luminaut --help`

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

```
$ luminaut --help                       
usage: luminaut [-h] [--config CONFIG] [--log LOG] [--verbose]

Luminaut: Casting light on shadow cloud deployments. 

options:
  -h, --help       show this help message and exit
  --config CONFIG  Configuration file. (default: luminaut.toml)
  --log LOG        Log file. (default: luminaut.log)
  --verbose        Verbose output in the log file. (default: False)
```

### Usage with docker

You may run luminaut with docker by mounting the configuration file and running the container. Replace `--help` with any other arguments you would like to pass to luminaut. Note that saved files, such as the log file and JSON reports, will be saved within the container. You may want to mount another volume to save the report files.

Bash, zsh, and similar terminals:
```bash
$ docker run -it -v ~/.aws:/root/aws -v $(pwd)/configs:/app/configs luminaut --help
```

Powershell:
```powershell
$ docker run -it -v $env:USERPROFILE\.aws:/root/aws -v ${PWD}\configs:/app/configs luminaut --help
```

## Configuration

Luminaut uses a configuration file to define the tools and services to use. The default configuration will run with all tools enabled, though during runtime any tool not found will be skipped. The default reporting uses console output with JSON reporting disabled.

The configuration file is a TOML file with the following structure and defaults:

```toml
[report]
console = true  # Rich STDOUT console output
json = false  # JSON lines output, written to STDOUT.

[tools.aws]
enabled = true  # Enable the AWS tool, requires the configuration of AWS credentials.
config.enabled = true  # Enables the scanning of AWS config. This can take a long time to run, as it scans all resource history.

[tools.nmap]
enabled = true  # Enable the nmap tool, requires the nmap utility installed and on the system path.
```

The source of truth for the luminaut configuration is located in `luminaut.models.LuminautConfig`.

