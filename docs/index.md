---
title: Luminaut Documentation
layout: default
---

# Luminaut

Casting light on shadow cloud deployments. Detect exposure of resources deployed in AWS.

![Luminaut Picture](https://raw.githubusercontent.com/luminaut-org/luminaut/refs/heads/main/.github/images/luminaut_readme_300.png)

<h2>{{ site.data.navigation.title }}</h2>

<ul>
   {% for page in site.data.navigation.pages %}
      <li><a href="{{ site.github.url }}{{ page.url }}">{{ page.title }}</a></li>
   {% endfor %}
</ul>

## Introduction

Luminaut is a utility to scope cloud environment exposure for triage. The goal is to quickly identify exposed resources and collect information to start an investigation.

Starting from the public IP addresses of AWS Elastic Network Interfaces (ENIs), Luminaut gathers information about the associated EC2 instances, load balancers, security groups, and related events. The framework also includes active scanning tools like nmap and whatweb, to identify services running on exposed ports, and passive sources like Shodan.

By combining cloud configuration data with external sources, Luminaut provides context to guide the next steps of an investigation.

While focused on AWS, Luminaut can be extended to support other cloud providers and services. The framework is designed to be modular, allowing for the addition of new tools and services as needed. Support for Google Cloud is in progress.

![Luminaut execution](https://raw.githubusercontent.com/luminaut-org/luminaut/refs/heads/main/.github/images/luminaut_execution.png)
![Luminaut result - IP address 1](https://raw.githubusercontent.com/luminaut-org/luminaut/refs/heads/main/.github/images/luminaut_result_ip_1.png)
![Luminaut result - IP address 2](https://raw.githubusercontent.com/luminaut-org/luminaut/refs/heads/main/.github/images/luminaut_result_ip_2.png)
