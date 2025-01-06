# Contributing to Luminaut

## Guidelines

Please follow these guidelines when contributing to Luminaut:

- Ensure your code follows the existing style and conventions.
- Write clear, concise commit messages.
- Include tests for any new features or bug fixes.
- Update documentation as necessary.
- Review and test your code before submitting a pull request.

Contributions are welcome, though we ask that you open an issue outlining your idea and plan so that we (and others) can collaborate with you early in the process. This significantly helps when it comes to reviewing and merging your work and avoiding duplicated efforts.

## Installation

### For development

For development, install the following tools:
- [uv](https://docs.astral.sh/uv/) - package manager
- [pre-commit](https://pre-commit.com/) - code quality tool
- [nmap](https://nmap.org/) - port and service scanning utility
- [whatweb](https://github.com/urbanadventurer/WhatWeb) - web service scanning utility

Once installed, clone this repository and run: `uv sync` to install and configure your environment.

If that completed successfully, you should be able to run tests with `uv run pytest` or show the help information with `uv run luminaut --help`.

Before contributing code, run `pre-commit install` to install the pre-commit tools.
