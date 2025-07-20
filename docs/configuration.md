---
title: Configuration
layout: single
toc: true
---

Luminaut uses a configuration file to define the tools and services to use. The default configuration will run with all tools enabled, though during runtime any tool not found will be skipped. The default reporting uses console output with JSON reporting disabled.

The configuration files are merged with the default configuration, meaning that you can omit any default values from your configuration file.

The configuration file is a TOML file with the following structure and defaults:

```toml
[report]
console = true  # Rich STDOUT console output

html = false  # Save the console output to an HTML file. Disabled by default.
html_file = "luminaut.html"  # Example path. Required if html is true. Default is null.

json = false  # JSON lines output, written to STDOUT. Disabled by default.
json_file = "luminaut.json"  # Example path. If omitted will write to stdout. Default is null.

timeline = false  # Timeline output, written to a CSV file. Disabled by default.
timeline_file = "luminaut_timeline.csv"  # Example path. Required if timeline is true. Default is null.

[tool.aws]
enabled = true  # Enable the AWS tool, requires the configuration of AWS credentials.
# aws_regions = ["us-east-1"] # The AWS regions to scan. Defaults to the region set in your AWS profile if none is supplied.

[tool.aws.config]
enabled = true  # Enables the scanning of AWS config. This can take a long time to run, as it scans all resource history. Enabled by default.

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

[tool.gcp]
# Enable the GCP tool, requires the configuration of GCP credentials.
enabled = true

# The GCP projects to scan. Defaults to the project set in your GCP profile if none are supplied.
projects = []

# The GCP regions to scan. Defaults to all regions available for the GCP project if none are supplied.
regions = []

# The GCP compute zones to scan. Defaults to all zones available for the GCP project if none are supplied.
compute_zones = []

[tool.gcp.audit_logs]
enabled = true  # Enables the collection of GCP audit log events related to discovered compute instances.

# The below dates must be specified as offset aware timestamps in RFC-3339 format, per https://toml.io/en/v1.0.0#offset-date-time
# You can specify either the start, end, both, or None to influence the time period of the scan as desired.
# If no time range is specified, defaults to the last 30 days.

# start_time = 2025-01-01T00:00:00Z  # The start time for the GCP audit logs scan. Defaults to 30 days ago if no time range specified
# end_time = 2025-01-02T00:00:00Z  # The end time for the GCP audit logs scan. Defaults to current time if no time range specified

[tool.nmap]
enabled = true  # Enable the nmap tool, requires the nmap utility installed and on the system path. Enabled by default but will not run if nmap is not found on the path.
timeout = 300  # Timeout in seconds for nmap scans. Default is null (no timeout).

[tool.shodan]
enabled = true  # Enable the shodan tool, requires the shodan API key to be set in the configuration. Enabled by default, but will not run without an API key.
api_key = ""  # Shodan API key. If this is populated, treat the configuration file as a secret.

[tool.whatweb]
enabled = true  # Enable the whatweb tool, requires the whatweb utility installed and on the system path. Enabled by default, but will not run if whatweb is not found on the path.
timeout = 120  # Timeout in seconds for whatweb scans. Default is null (no timeout).
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

### GCP IAM Permissions

Luminaut requires the following minimum permissions to run:

```yaml
title: "Luminaut Minimal"
description: "Minimal permissions required for Luminaut"
stage: "GA"
includedPermissions:
  - compute.instances.list
  - compute.zones.list
  - compute.regions.list
  - compute.firewalls.list
  - run.services.list
  - logging.logEntries.list
```

**Note:** The `logging.logEntries.list` permission is only required when the audit logs feature is enabled in the configuration.
