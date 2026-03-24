# fors33-verifier hardened runtime image.
# Multi-stage build keeps final image minimal and strips build tooling.

FROM python:3.13-alpine AS builder

ENV VENV_PATH=/opt/venv
ENV PATH="${VENV_PATH}/bin:${PATH}"

RUN apk update \
    && apk upgrade \
    && rm -rf /var/cache/apk/*

RUN python -m venv "${VENV_PATH}"
WORKDIR /app

COPY requirements-release.txt .

# Pin and upgrade build tools, then install hash-locked runtime deps.
RUN python -m pip install --upgrade pip==26.0 wheel==0.46.2 setuptools==78.1.1 \
    && pip install --require-hashes -r requirements-release.txt

COPY . .

# Install this package from source using locked dependencies.
RUN pip install --no-deps . \
    && pip install --no-cache-dir flask==3.1.3

FROM python:3.13-alpine

ENV VENV_PATH=/opt/venv
ENV PATH="${VENV_PATH}/bin:${PATH}"
WORKDIR /app

# Pull latest Alpine security updates at build time.
RUN apk update \
    && apk upgrade \
    && rm -rf /var/cache/apk/*

COPY --from=builder /opt/venv /opt/venv
COPY entrypoint.sh /entrypoint.sh
COPY server_url_only.py /app/server_url_only.py
COPY serve /usr/local/bin/serve

RUN /opt/venv/bin/pip uninstall -y pip setuptools wheel \
    && chmod +x /entrypoint.sh \
    && chmod +x /usr/local/bin/serve

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
