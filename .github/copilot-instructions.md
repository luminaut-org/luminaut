# Luminaut - Cloud Security Scanning Tool

Luminaut is a Python 3.11+ CLI security tool for detecting exposed resources in AWS and GCP cloud environments. It uses external security tools (nmap, whatweb, shodan) to scan for vulnerabilities and misconfigurations.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Prerequisites and System Setup
- Install system dependencies first:
  - `sudo apt-get update && sudo apt-get install -y nmap whatweb`
  - Verify: `nmap --version` and `whatweb --version`
- Install uv package manager:
  - `python3 -m pip install uv`
  - Verify: `uv --version`

### Bootstrap, Build, and Test
- Set up development environment:
  - `uv sync` -- takes 30+ seconds on first run. NEVER CANCEL. Set timeout to 180+ seconds.
- Build the package:
  - `uv build` -- takes ~3 seconds. Creates wheel and source distribution.
- Run tests:
  - `uv run pytest` -- takes 3+ minutes. NEVER CANCEL. Set timeout to 600+ seconds.
  - **EXPECTED**: 9 tests fail due to missing AWS credentials/region (this is normal)
  - **EXPECTED**: 112+ tests pass

### Code Quality and Linting
- Check code formatting: `uv run ruff format --check` -- takes <1 second
- Fix formatting: `uv run ruff format`
- Run linting: `uv run ruff check` -- takes <1 second
- Fix linting: `uv run ruff check --fix`
- Type checking: `uv run pyright` -- takes 15+ seconds

### Run the Application
- Show help: `uv run luminaut --help`
- Run with configuration: `uv run luminaut -c configs/no_console.toml`
- **REQUIRES**: AWS/GCP credentials for full functionality
  - AWS: `aws configure` or `aws sts get-caller-identity` to verify
  - GCP: `gcloud auth list` to verify

## Validation

### Manual Testing Requirements
- **ALWAYS** test the CLI help command after making changes: `uv run luminaut --help`
- **ALWAYS** verify the package builds successfully: `uv build`
- **ALWAYS** run linting before committing: `uv run ruff check && uv run ruff format --check`
- Test with sample config files in `configs/` directory

### End-to-End Scenarios
Test these scenarios when making changes:
1. **Basic CLI**: `uv run luminaut --help` should display help with ASCII art
2. **Configuration loading**: `uv run luminaut -c configs/no_console.toml --help` should work
3. **Package building**: `uv build` should create dist/ files without errors
4. **Code quality**: All ruff and pyright checks should pass

### CI Validation
Always run these commands before committing (matches .github/workflows/):
- `uv run pytest` -- full test suite 
- `uv run ruff check`
- `uv run ruff format --check`
- `uv run pyright`

## Important Warnings

### NEVER CANCEL Operations
- **uv sync**: Takes 30+ seconds on first run (downloads Python). Set timeout to 180+ seconds.
- **uv run pytest**: Takes 3+ minutes. Set timeout to 600+ seconds.
- **uv run pyright**: Takes 15+ seconds for type checking.

### Expected Test Failures
- 9 AWS-related tests fail without proper AWS credentials/region setup
- This is EXPECTED behavior - do not try to fix these tests
- Focus only on new test failures related to your changes

### Network/Environment Limitations
- Docker builds may fail due to certificate issues (expected in sandboxed environments)
- Pre-commit hooks may fail due to network timeouts (expected in sandboxed environments)
- Shodan integration requires API key (not available in test environment)

## Common Tasks

### Repo Structure
```
/home/runner/work/luminaut/luminaut/
├── .github/workflows/          # CI/CD pipelines (test.yml, build.yml)
├── configs/                    # Sample configuration files
├── docs/                       # Documentation (installation, usage, etc.)
├── examples/                   # Python library usage examples
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
          _..._
        .'     '.
       /    .-""-\
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
2. **Code**: Edit files in `src/luminaut/`
3. **Test**: `uv run pytest` (expect some AWS failures)
4. **Lint**: `uv run ruff check && uv run ruff format`
5. **Type check**: `uv run pyright`
6. **Build**: `uv build`
7. **Manual test**: `uv run luminaut --help`

### Adding Dependencies
- Add to `pyproject.toml` in the `dependencies` section
- Run `uv sync` to install
- For dev dependencies, add to `dependency-groups.dev`

### Docker Usage (if network allows)
- Build: `docker build . --tag luminaut:latest` 
- Run: `docker run -it luminaut --help`
- **NOTE**: May fail in sandboxed environments due to network restrictions

## Troubleshooting

### Common Issues
- **"No region specified"**: Tests failing due to missing AWS_DEFAULT_REGION (expected)
- **"whatweb not found"**: Install with `sudo apt-get install whatweb`
- **uv not found**: Install with `python3 -m pip install uv`
- **Permission denied**: Use `sudo` for system package installation
- **Network timeouts**: Expected in sandboxed environments for Docker/pre-commit

### Performance Notes
- Initial `uv sync` downloads Python interpreter (~30 seconds)
- Subsequent `uv sync` runs are much faster (~2-3 seconds)
- Tests take ~3 minutes due to GCP API calls in test suite
- Build process is very fast (~3 seconds)

Always validate that any changes maintain the tool's core functionality: scanning cloud resources for security exposures and generating comprehensive reports.