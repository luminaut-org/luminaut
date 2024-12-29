FROM fedora:41 AS base

RUN dnf install -y python3.12 curl && \
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh && \
    dnf clean all && \
    rm -rf /var/cache/dnf /tmp/* /var/tmp/*

WORKDIR /app
COPY uv.lock pyproject.toml README.md /app/
COPY src /app/src
RUN uv build

FROM fedora:41 AS final

RUN dnf install -y nmap python3 python3-pip whatweb which && \
    dnf clean all && \
    rm -rf /var/cache/dnf /tmp/* /var/tmp/* && \
    mkdir /app && \
    useradd -m -s /bin/bash app

COPY --from=base /app/dist /app/dist
RUN pip install --no-cache-dir /app/dist/*.whl && \
    chown -R app:app /app

USER app:app
WORKDIR /app

# Copy in default configs to the working directory
COPY configs /app/

ENTRYPOINT ["luminaut"]