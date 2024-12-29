FROM fedora:41 AS base

# Install Python 3.12 and other dependencies
RUN dnf install -y python3.12 curl && \
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh && \
    dnf clean all && \
    rm -rf /var/cache/dnf /tmp/* /var/tmp/*

WORKDIR /app
COPY uv.lock pyproject.toml README.md /app/
COPY src /app/src
RUN uv build

FROM fedora:41 AS final

COPY --from=base /app/dist /app/dist
RUN dnf install -y nmap python3.12 python3-pip whatweb && \
    ln -sf /usr/bin/python3.12 /usr/bin/python && \
    pip install --no-cache-dir /app/dist/*.whl && \
    dnf clean all && \
    rm -rf /var/cache/dnf /tmp/* /var/tmp/* && \
    useradd -m -s /bin/bash app && \
    chown -R app:app /app

USER app:app

ENTRYPOINT ["luminaut"]