# syntax=docker/dockerfile:1
ARG UPSTREAM_IMAGE=ghcr.io/openhands/agent-server:latest-python
FROM ${UPSTREAM_IMAGE}

USER root
# Policy 101 prevents package scripts from starting services during installation.
RUN set -eu; \
    . /etc/os-release; \
    if [ "$ID:${VERSION_CODENAME:-}" != debian:trixie ]; then \
        echo "Expected Debian trixie for PostgreSQL 17; review the new upstream base" >&2; exit 1; \
    fi; \
    if [ -e /usr/sbin/policy-rc.d ]; then mv /usr/sbin/policy-rc.d /tmp/upstream-policy-rc.d; fi; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; \
    chmod 0755 /usr/sbin/policy-rc.d; \
    mkdir -p /etc/postgresql-common; \
    printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf; \
    apt-get -o Acquire::Retries=3 update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-17 postgresql-client-17; \
    rm -f /usr/sbin/policy-rc.d /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem; \
    if [ -e /tmp/upstream-policy-rc.d ]; then mv /tmp/upstream-policy-rc.d /usr/sbin/policy-rc.d; fi; \
    test ! -d /var/lib/postgresql/17/main; \
    rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 scripts/init-git.sh /usr/local/bin/init-git
ENV PATH="/usr/lib/postgresql/17/bin:${PATH}"
USER openhands
ENTRYPOINT ["/usr/local/bin/init-git"]
