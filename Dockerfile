# syntax=docker/dockerfile:1.7
ARG UPSTREAM_IMAGE=ghcr.io/openhands/agent-server@sha256:163c9d8b0d9ec48d4936d10ce9f109fc380a7a417d83a83c4ba4fe9a4a8efdcb
FROM ${UPSTREAM_IMAGE}
ARG UPSTREAM_IMAGE
ARG UPSTREAM_DIGEST=sha256:163c9d8b0d9ec48d4936d10ce9f109fc380a7a417d83a83c4ba4fe9a4a8efdcb
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="OpenHands Agent with PostgreSQL 17" \
      org.opencontainers.image.source="https://github.com/Skulldorom/OpenHands-Agent-Image" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.base.name="${UPSTREAM_IMAGE}" \
      org.opencontainers.image.base.digest="${UPSTREAM_DIGEST}" \
      io.openhands.agent-server.version="1.62.0"
USER root
# Debian trixie supplies PostgreSQL 17 through signed official repositories.
RUN test "$(. /etc/os-release; printf '%s' "$VERSION_CODENAME")" = trixie \
    && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && mkdir -p /etc/postgresql-common \
    && printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get install -y --no-install-recommends postgresql-17 postgresql-client-17 \
    && test ! -d /var/lib/postgresql/17/main \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 scripts/init-git.sh /usr/local/bin/init-git
ENV PATH="/usr/lib/postgresql/17/bin:${PATH}"
USER openhands
ENTRYPOINT ["/usr/local/bin/init-git"]
