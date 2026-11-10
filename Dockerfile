# Runs HostProof as a non-root user with hash-verified dependencies.
FROM python:3.15-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 hostproof

WORKDIR /app
COPY pyproject.toml README.md requirements.txt ./
COPY src ./src

RUN pip install --require-hashes -r requirements.txt \
    && pip install --no-deps .

USER hostproof

# A one-shot command line tool, so this confirms it can start rather than monitoring a service.
HEALTHCHECK --interval=1m --timeout=5s CMD ["hostproof", "--version"]

ENTRYPOINT ["hostproof"]
CMD ["--help"]
