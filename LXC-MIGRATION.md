# LXC migration guide — operator actions only

No commands in this guide have been executed on the OpenHands LXC. Do not deploy until the release CI is green and the package is publicly pullable.

## 1. Record the working deployment

Record the current Agent Canvas/Agent Server version, service definition, configuration location, image ID/digest and existing free space. Keep `openhands-agent-skulldorom:latest` and all running conversation containers. Back up configuration through your existing protected procedure; do not upload secrets to this repository.

```sh
df -h
docker system df
docker image inspect openhands-agent-skulldorom:latest --format '{{.Id}}'
```

Confirm the host is compatible with Agent Server **1.62.0**. Other versions are not approved by this repository. Budget for both old and new image layers, compressed downloads, extraction and writable layers. A 25 GB filesystem may be insufficient. Do not use `docker system prune`, volume pruning, or workspace deletion to make room.

## 2. Validate the published artifact

Read the latest release's `state.json` and CI run. Compare its `image_digest` with:

```sh
docker buildx imagetools inspect ghcr.io/skulldorom/openhands-agent:latest
```

Use the complete digest, not the literal placeholder below:

```sh
docker pull ghcr.io/skulldorom/openhands-agent@sha256:RELEASE_DIGEST
docker run --rm \
  -e GIT_USER_NAME='Example Developer' \
  -e GIT_USER_EMAIL='developer@example.com' \
  ghcr.io/skulldorom/openhands-agent@sha256:RELEASE_DIGEST \
  --exec git var GIT_AUTHOR_IDENT
docker run --rm ghcr.io/skulldorom/openhands-agent@sha256:RELEASE_DIGEST \
  --exec psql --version
```

These temporary identities are not credentials. Keep real GitHub authentication in the existing secret-management path.

## 3. Configure identity forwarding separately

Replace the examples with your own desired attribution in the protected environment source actually loaded by your **host Agent Server process**:

```env
GIT_USER_NAME=Your Git Name
GIT_USER_EMAIL=your-address@example.com
```

This alone does **not** forward values into conversation containers. Agent Server 1.62.0 has an explicit Docker environment allowlist. In a separately reviewed host application change, locate the Docker conversation environment allowlist for the deployed Agent Server version. Add only `GIT_USER_NAME` and `GIT_USER_EMAIL` to that existing explicit mapping, taking values from the host process environment only when present. Do not forward the whole environment. Keep the change in the host application source/configuration, not an ad-hoc edit to installed packages. Stage-test a new conversation with real commits, then apply during normal host maintenance. If the deployed version exposes no supported configuration hook, maintain a small reviewed source patch pinned to that version. This repository does not supply or execute a host patch. Neither the image nor updater applies that host change. Do not assume `.agent-canvas.env` is read by every launcher. Never add arbitrary environment forwarding or tokens to the allowlist.

Runtime defaults intentionally do not override existing global/repository-local Git identities. Inspect those in a new conversation if attribution differs. The public image contains no personal identity; your values are supplied at runtime only.

## 4. Select the new image

During your normal host maintenance procedure change the existing configuration's image setting:

```env
OH_CONVERSATION_RUNTIME=docker
OH_CONVERSATION_IMAGE=ghcr.io/skulldorom/openhands-agent:latest
```

For safer production pinning, replace `:latest` with `@sha256:RELEASE_DIGEST`. Reload/restart only the host service through its established deployment procedure when safe. This guide deliberately does not guess its service name or run a restart. Do not restart or remove active conversation containers. New conversations use the newly configured image; existing conversations retain their original image.

## 5. Verify a fresh conversation

Run `git var GIT_AUTHOR_IDENT`, `git var GIT_COMMITTER_IDENT`, a real commit in a temporary repository, and all seven PostgreSQL version commands from the task. Confirm no automatic PostgreSQL process exists. If an independently configured external database is used, verify it through its protected settings without printing secrets. Confirm browser, terminal, persistence and workspace behavior. The old PostgreSQL provisioning manager has already been removed. Do not reinstall it. Preserve any separately managed data volumes and cleanup protections.

## 6. Optional pull-only staging updater

Review `scripts/update-image.sh` and both `systemd/` units before installing. The updater never builds locally or activates the host configuration. It checks capacity, preserves the previous image, validates candidates and writes a staged environment fragment. It does not restart agents, delete conversations, prune images, touch workspaces or PostgreSQL volumes.

Install only after explicit operator review, using the executable location referenced in the supplied service. Inspect `scripts/update-image.sh --help` for configuration and rollback options before enabling the timer. Systemd logs are available through:

```sh
journalctl -u openhands-image-update.service
systemctl list-timers openhands-image-update.timer
```

From a reviewed checkout, optional operator installation commands are:

```sh
sudo install -d -m 0755 /usr/local/lib/openhands-image-update
sudo install -m 0755 scripts/update-image.sh /usr/local/lib/openhands-image-update/update-image.sh
sudo install -m 0644 systemd/openhands-image-update.service systemd/openhands-image-update.timer /etc/systemd/system/
sudo install -d -m 0700 /var/lib/openhands-image-update
# After the first successful manual migration, record its complete validated digest:
printf '%s\n' 'ghcr.io/skulldorom/openhands-agent@sha256:RELEASE_DIGEST' | sudo tee /var/lib/openhands-image-update/current.ref >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now openhands-image-update.timer
```

Review `/var/lib/openhands-image-update/pending.env`; select its digest in the existing host configuration only during operator-controlled activation. After successful activation copy `pending.ref` to `current.ref` in that state directory. Run `/usr/local/lib/openhands-image-update/update-image.sh rollback` as administrator to stage the saved previous digest. The service requires local Docker Engine and Buildx. Docker access is administrator-equivalent; the hardening directives do not sandbox the daemon.

Installing/enabling units and selecting the staged digest are separate operator actions. Do not copy secrets-bearing host files into public directories. Do not treat a successful manifest check as proof that extraction will fit.

## 7. Rollback

Before activation retain the old image reference and protected configuration. If new-conversation validation fails, restore the prior `OH_CONVERSATION_IMAGE` value (initially `openhands-agent-skulldorom:latest`, later the previous successful GHCR digest) using the normal host deployment procedure. Do not delete failed or active conversations automatically. They require independent lifecycle handling under your existing workspace-protection policy.

The updater's rollback mode stages its saved previous validated digest; it does not restart services. Always inspect that fragment before applying it. Full version tags and release digest records remain available for manual rollback. Embedded ephemeral PostgreSQL clusters are not durable databases and cannot replace your external PostgreSQL backup/restore plan.
