# fors33-verifier: CLI-only image for CI/CD and URL-based verification.
# No file uploads; zero-trust. Use for GitHub Action and App Platform (--url flow only).
FROM python:3.11-slim-bookworm

# Install verifier + optional Flask server, then remove build tooling
RUN pip install --no-cache-dir fors33-verifier \
    && pip install --no-cache-dir flask \
    && pip uninstall -y pip setuptools wheel

COPY entrypoint.sh /entrypoint.sh
COPY server_url_only.py /app/server_url_only.py
# Executable "serve" for platforms that run it as the main process (e.g. DigitalOcean App Platform).
COPY serve /usr/local/bin/serve

RUN chmod +x /entrypoint.sh \
    && chmod +x /usr/local/bin/serve

ENTRYPOINT ["/entrypoint.sh"]
# Default: CLI. For App Platform URL-only API, override CMD to: ["python", "/app/server_url_only.py"]
CMD ["--help"]
