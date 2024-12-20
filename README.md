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

### For development

For development, install the following tools:
- [uv](https://docs.astral.sh/uv/) - package manager
- [pre-commit](https://pre-commit.com/) - code quality tool
- [nmap](https://nmap.org/) - port and service scanning utility
- [whatweb](https://github.com/urbanadventurer/WhatWeb) - web service scanning utility

Once installed, clone this repository and run: `uv sync` to install and configure your environment.

If that completed successfully, you should be able to run tests with `uv run pytest` or show the help information with `uv run luminaut --help`.
