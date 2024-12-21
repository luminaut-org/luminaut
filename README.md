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
