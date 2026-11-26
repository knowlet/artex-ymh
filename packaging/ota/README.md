# Docker OTA deployment

This is an opt-in update path for an existing single-host ARTEX Compose
deployment. After one host setup, an administrator can check a channel, review
the pinned image and request an update from **System → Settings → Docker OTA**.
The existing binary self-update installation policy remains disabled.

## Supported deployment

- Linux `amd64`, systemd and a local rootful Docker Engine.
- Python **3.11 or newer**, Docker CLI with **Compose v2** and **Buildx**, and
  Cosign **v3.1.6**.
- One running `artex` service and one running `postgres` service in the same
  explicitly named Compose project. PostgreSQL keeps its existing major version
  and named `/var/lib/postgresql/data` volume.
- The standard application layout: `/app/artex`, `/app/data`, persistent
  `/app/data` storage, and `ARTEX_PG_DSN` pointing to that Compose `postgres`.
  The normal image listens on `:8787`. If a custom deployment disables the gate
  by listening only on loopback, set `ARTEX_GATE=off` explicitly.
- Host access to GHCR and Sigstore. The application container receives no
  registry credentials and no Docker socket. For a private GHCR package, log
  into GHCR as the host account running the updater, for example
  `sudo docker login ghcr.io --username YOUR_GITHUB_LOGIN`.

ARM images are not published by this workflow: the current application tool
bundle includes x64 runtime dependencies. Existing source deployment remains
available. This updater does not update Docker, PostgreSQL, Traefik, itself, or
the operator's Compose/environment files.

Existing bind mounts are retained. In particular, a host `./skills:/app/skills`
mount continues to override the skills packaged in the new image; update that
operator-managed directory separately when needed.

## One-time bootstrap

Perform this on the deployment host after reviewing and checking out the OTA
changes. Keep an independent database and data-directory backup before the first
recreation. The commands below assume the checkout is `/opt/artex-ymh`; substitute
the real absolute path and preserve the existing Compose project name.

1. Install the host helper and sample configuration:

   ```sh
   cd /opt/artex-ymh
   sudo install -d -m 0755 /usr/local/libexec
   sudo install -d -m 0700 /etc/artex-updater /var/lib/artex-updater
   sudo install -d -m 0750 /run/artex-updater
   sudo install -m 0755 scripts/docker_ota.py /usr/local/libexec/artex-updater
   sudo install -m 0600 packaging/ota/config.example.json /etc/artex-updater/config.json
   sudo install -m 0644 packaging/ota/artex-updater.service /etc/systemd/system/artex-updater.service
   ```

2. Edit `/etc/artex-updater/config.json`. List **every** currently used Compose
   file, in its original order, then append `packaging/ota/compose.ota.yml`.
   Include local Traefik/port/volume overrides; do not substitute the repository
   defaults for the deployment's current settings. Match `project_name` to the
   existing containers' `com.docker.compose.project` label. Set `env_file` to the
   existing `.env`, or `null` if the deployment has no environment file.
   The example overlay and service use the default state/socket directories;
   update those files together if choosing other paths.

3. Install the pinned Cosign binary, if not already installed. The digest below
   is the official `v3.1.6` Linux amd64 release asset SHA-256:

   ```sh
   (
   set -eu
   ota_cosign=$(mktemp)
   trap 'rm -f -- "$ota_cosign"' EXIT
   curl --fail --location --proto '=https' --tlsv1.2 \
     https://github.com/sigstore/cosign/releases/download/v3.1.6/cosign-linux-amd64 \
     --output "$ota_cosign"
   printf '%s  %s\n' \
     318a99ade4156a0c4113aa983b46c0a0830fa7896a096c63121ee47b610a94c6 \
     "$ota_cosign" | sha256sum --check -
   sudo install -m 0755 "$ota_cosign" /usr/local/bin/cosign
   )
   ```

4. While the **old application container still exists and is running**, preserve
   its signing/encryption keys and any explicit application configuration:

   ```sh
   sudo /usr/local/libexec/artex-updater prepare
   ```

   This copies the existing `jwt.key`, applicable `gate.key`, and application
   configuration into private host storage. It creates an initial Compose
   overlay containing only retained file mounts. It does not replace the
   application image or generate new keys. The command refuses an already
   managed deployment. Do not remove the old container before this succeeds.

5. Build the OTA-capable application from this checkout, then recreate **only**
   `artex` using the managed Compose command. This also enables the socket/state
   mounts. Set an accurate fingerprint for the locally built bootstrap image:

   ```sh
   ota_revision=$(git rev-parse HEAD)
   ota_schema=$(python3 scripts/ota_release_metadata.py schema)
   sudo /usr/local/libexec/artex-updater compose build \
     --build-arg "ARTEX_BUILD_REVISION=$ota_revision" \
     --build-arg "ARTEX_BUILD_VERSION=bootstrap-$ota_revision" \
     --build-arg "ARTEX_OTA_SCHEMA=$ota_schema" artex
   sudo /usr/local/libexec/artex-updater compose up -d --no-deps --no-build artex
   sudo systemctl daemon-reload
   sudo systemctl enable --now artex-updater.service
   ```

   An image label is not a signature. Bootstrap is an explicit local source
   build; subsequent remote installation requires the fixed fork's signature.
   If the old image has no migration fingerprint, an update can still proceed
   with backups, but a failure after candidate startup requires host recovery.

6. Confirm the application starts with the existing login/configuration. Open
   System → Settings and check the Docker OTA status. The readiness endpoint
   uses a mode-`0600` Unix socket inside the container and does not bypass or
   expose the public anti-mapping gate.

After bootstrap, run future Compose operations through
`sudo /usr/local/libexec/artex-updater compose ...`. This includes the managed
image/key overlay. Running only the original Compose files can revert the image
or omit the retained keys. Use `--no-deps` when changing only ARTEX; database
major upgrades remain separate operations.

## Channels and image trust

The fixed image repository is `ghcr.io/knowlet/artex-ymh`.

| Channel | Publication trigger |
| --- | --- |
| `main` | A tested push to `main`, or manual dispatch from `main` |
| `nightly` | Daily at 20:23 UTC / 04:23 Taiwan, or manual dispatch from `main` |
| `stable` | Manual dispatch from `main` with a published, non-draft, non-prerelease `vMAJOR.MINOR.PATCH` tag whose commit is in `main` history |

Stable promotion requires an OTA-capable release; historical tags without the
OTA tests/protocol cannot pass the publishing gates. A stable publisher can
explicitly choose an older published release. Clients review the resulting
target before installation; this service does not schedule unattended updates.

The publishing workflow tests the backend, frontend, real Docker recovery, and
the packaged application with PostgreSQL 16/17. It builds an amd64 image with
SBOM/provenance attestations, signs the immutable index digest, verifies it, then
advances the channel alias. A slow main/nightly run cannot promote after `main`
has advanced. The updater resolves a channel once and retains its immutable
digest in a plan valid for 15 minutes. Apply verifies the signature again.

Trusted certificate identity:

```text
https://github.com/knowlet/artex-ymh/.github/workflows/docker-ota.yml@refs/heads/main
issuer: https://token.actions.githubusercontent.com
```

There is no arbitrary image/repository/ref input and no signature-skip flag.
GitHub initially creates new GHCR packages as private. A maintainer may choose
to make the package public after its first publication, or configure the host's
registry authentication. Package visibility is not changed by this workflow.

## Update behavior and rollback boundaries

An administrator checks a channel and reviews the target, then requests the
update. Running tasks, conversations, reviews and other tracked work must first
finish or be stopped through their normal controls. Update does not forcibly
interrupt a running exercise. A durable maintenance marker blocks admission
while the host downloads/verifies, checks deployment identity, stops ARTEX,
backs up data, replaces only the application container, and checks readiness.
The application has a short service interruption; this is not zero downtime.

Backups under `/var/lib/artex-updater/backups/<job-id>/` include a custom-format
PostgreSQL dump, an application data tar archive, deployment/configuration
snapshots, preserved keys and checksums. Private state contains credentials and
must remain host-only. Backup retention/space management is currently manual;
do not delete files used by the active retained-key mounts.

Before a candidate starts, failures restart the exact previous container. After
candidate startup, automatic image rollback is allowed only if both images have
the same nonempty migration fingerprint. The fingerprint conservatively covers
database/schema code, on-disk traffic/provider formats, configuration and server
startup writers, plus other migration/DDL/seed sources. A changed fingerprint
does not prove an incompatible migration, but prevents assuming reversibility.
The updater never automatically restores a database dump or downgrades a
PostgreSQL cluster. An incompatible failure or interrupted operation leaves
maintenance enabled and reports `recovery_required`.

For host recovery:

1. Stop `artex-updater.service` and inspect its local status, job backups and the
   actual containers. Select a recorded source/target image from the failed job.
2. Restore the appropriate application/database/data state deliberately. Use the
   retained `previous-compose.json` only when its database compatibility has
   been established. It contains resolved secrets; keep it private. A database
   restore can discard subsequent writes and is not performed by this helper.
3. Start the chosen application, then acknowledge the **exact recorded local
   image ID**, for example:

   ```sh
   sudo /usr/local/libexec/artex-updater recover --image sha256:REPLACE_WITH_RECORDED_64_HEX_IMAGE_ID
   sudo systemctl start artex-updater.service
   ```

   Recovery verifies the running image, deployment and readiness before clearing
   maintenance. It does not restore data or start a container. Do not manually
   delete the maintenance marker as a shortcut.

## Trust boundary

Only the host helper controls Docker. The Web API requires ARTEX's administrator
authentication, and the helper accepts a small fixed set of update operations.
Its socket is mounted into the application container: read-only mounting prevents
filesystem changes to the mount, **not socket connections**. This trusts the
application container as a whole; it does not provide operating-system isolation
between the backend and tools running with the same container identity. The
host independently checks application readiness/idle state before stopping it.
Do not claim this design prevents every compromised in-container process from
requesting an update. The helper, its configuration and the publishing workflow
remain trusted deployment components.

The helper has no self-update mechanism. Upgrade it as an explicit host
maintenance operation and restart the service after reviewing the change.

## Sources

- [Docker Compose service recreation](https://docs.docker.com/reference/cli/docker/compose/up/)
- [Docker manifest copying and digest preservation](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/)
- [Sigstore GitHub Actions identity verification](https://docs.sigstore.dev/quickstart/quickstart-ci/)
- [GitHub Container Registry authentication and visibility](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Cosign v3.1.6 release](https://github.com/sigstore/cosign/releases/tag/v3.1.6)
