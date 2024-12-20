FROM python:3.12-slim-bookworm AS base

# TODO Add WhatWeb

RUN apt-get update &&\
    apt-get install -y --no-install-recommends curl git && \
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app
COPY uv.lock pyproject.toml README.md src /app/
RUN uv build

FROM python:3.12-slim-bookworm AS final

COPY --from=base /app/dist /app/dist
RUN pip install /app/dist/*.whl && \
    apt-get update &&\
    apt-get install -y --no-install-recommends nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["luminaut"]
