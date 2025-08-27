# Luminaut - Cloud Security Scanning Tool

Luminaut is a Python CLI security tool for detecting exposed resources in AWS and GCP cloud environments. It uses external security tools (nmap, whatweb, shodan) to scan for vulnerabilities and misconfigurations.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Coding standards
- Use Python best practices
- Use unittest format for tests

### Prerequisites and System Dependencies
- System dependencies:
  - Verify: `nmap --version` and `whatweb --version`
- Python package manager:
  - Verify: `uv --version`

### Bootstrap, Build, and Test
- Set up development environment:
  - `uv sync` -- takes 30+ seconds on first run. NEVER CANCEL. Set timeout to 180+ seconds.
- Build the package:
  - `uv build` -- takes ~3 seconds. Creates wheel and source distribution.
- Run tests:
  - `uv run pytest` -- takes 3+ minutes. NEVER CANCEL. Set timeout to 600+ seconds.
  - **EXPECTED**: all tests pass

### Code Quality and Linting
- Fix formatting: `uv run ruff format`
- Fix linting: `uv run ruff check --fix`
- Type checking: `uv run pyright` -- takes 15+ seconds

### Run the Application
- Show help: `uv run luminaut --help`
- Run with a configuration file: `uv run luminaut -c configs/no_console.toml`

## Validation

### End-to-End Scenarios
Test these scenarios when making changes:
1. **Unit tests**: `uv run pytest` to run all tests and all tests should pass.
2. **Basic CLI**: `uv run luminaut --help` should display help with ASCII art
3. **Code quality**: All ruff and pyright checks should pass

## Common Tasks

### Repo Structure
```
repository/
├── .github/workflows/         # CI/CD pipelines (test.yml, build.yml)
├── configs/                   # Sample configuration files
├── docs/                      # Documentation (installation, usage, etc.)
├── examples/                  # Python library usage examples
├── src/luminaut/              # Main source code
├── tests/                     # Test suite
├── pyproject.toml             # Main project configuration
├── uv.lock                    # Dependency lock file
└── README.md                  # Main documentation
```

### Key Source Files
- `src/luminaut/core.py` - Main application logic
- `src/luminaut/models.py` - Data models and configuration
- `src/luminaut/tools/aws.py` - AWS integration
- `src/luminaut/tools/gcp.py` - GCP integration
- `src/luminaut/tools/whatweb.py` - WhatWeb integration
- `src/luminaut/scanner.py` - IP scanning logic
- `src/luminaut/report.py` - Report generation

### Configuration Files
- `configs/no_console.toml` - Disable console output
- `configs/disable_aws_config.toml` - Disable AWS Config scanner
- `configs/allow_list.toml` - Allow list configuration

### Frequent Commands Output
```bash
# Help command shows ASCII art logo and options
$ uv run luminaut --help
usage: luminaut [-h] [-c CONFIG] [--log LOG] [--verbose] [--version]

Luminaut: Casting light on shadow cloud deployments.
# ... (ASCII art continues)

# Build creates distribution files
$ uv build
Building source distribution...
Building wheel from source distribution...
Successfully built dist/luminaut-0.13.2.tar.gz
Successfully built dist/luminaut-0.13.2-py3-none-any.whl

# Version check
$ uv run luminaut --version
luminaut 0.13.2
```

## Development Workflow

### Making Changes
1. **Setup**: `uv sync` (first time only)
2. **Write tests**: Edit files in `tests/` to define expected behavior
2. **Code**: Edit files in `src/luminaut/`
3. **Test**: `uv run pytest` to confirm tests are working
4. **Lint**: `uv run ruff check && uv run ruff format`
5. **Type check**: `uv run pyright`

### Adding Dependencies
- Use `uv add <package-name>` to add dependencies.
- Use `uv add --dev <package-name>` to add development dependencies.

### Docker Usage (if network allows)
- Build: `docker build . --tag luminaut:latest` 
- Run: `docker run -it luminaut --help`
- **NOTE**: May fail in sandboxed environments due to network restrictions

## Troubleshooting

### Common Issues
- **"No region specified"**: Tests failing due to missing AWS_DEFAULT_REGION
- **uv not found**: Install with `python3 -m pip install uv`

Always validate that any changes maintain the tool's core functionality: scanning cloud resources for security exposures and generating comprehensive reports.