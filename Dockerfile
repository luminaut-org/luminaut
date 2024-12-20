FROM python:3.12-slim-bookworm

# TODO Add WhatWeb

RUN apt-get update &&\
    apt-get install -y curl git nmap && \
    rm -rf /var/lib/apt/lists/* && \
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh

WORKDIR /app
COPY uv.lock pyproject.toml README.md src /app/
RUN uv sync

ENTRYPOINT [ "uv", "run", "luminaut"]
