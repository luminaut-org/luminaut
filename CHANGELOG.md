# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### GCP Support

- Luminaut now supports Google Cloud Platform (GCP) with comprehensive resource discovery and scanning capabilities for compute instances, Cloud Run services, and firewall rules.
- GCP Audit Logs: Extract events related to compute instances, Cloud Run services, and firewall rules with 30-day default history
- GCP Firewall Rules: Enhanced firewall rule discovery and analysis with instance targeting, permissive rule detection, and audit log tracking
- GCP Performance: Async/concurrent processing for GCP resource discovery across projects, zones, and regions

#### Scanning Capabilities
- URL Scanning: Support for scanning URLs with nmap, including hostname resolution and URL-based targets
- Progress Indicators: Added `tqdm` progress bars for scanning operations
- Error Resilience: Improved error handling and logging for AWS and GCP resource enumeration failures
- Default Port Scanning: Enhanced nmap scanning with default ports for IP targets
- Port Filtering: Show only open, closed, and unfiltered ports in scan results
- Target Unification: Unified IP and URL scanning workflows

#### Code Quality

- Linting: Adopted more linting rules via ruff with comprehensive code quality improvements
- FindingResource: Standardized resource types with improved type hinting
- Async Processing: Concurrent execution of context gathering tasks (nmap, Shodan, whatweb)
