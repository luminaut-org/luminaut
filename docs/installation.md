---
title: Installation
layout: default
---

# Installation

<h2>{{ site.data.navigation.title }}</h2>

<ul>
   {% for page in site.data.navigation.pages %}
      <li><a href="{{ page.url }}">{{ page.title }}</a></li>
   {% endfor %}
</ul>

## With Python

Luminaut is available on PyPI and can be installed with pip:

```bash
pip install luminaut
```

You can also download a release artifact from the [GitHub releases page](https://github.com/luminaut-org/luminaut/releases) and install it with pip.

Once installed, you can run luminaut from the command line.

```bash
luminaut --help
```

**Note:** Luminaut requires Python 3.11 or later. If you would like to leverage nmap or whatweb, you will need to install these tools separately.

## With Docker

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
