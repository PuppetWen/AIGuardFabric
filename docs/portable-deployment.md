# Cross-platform Docker deployment

This deploys the self-hosted core (API, Web, ingest, scheduler, PostgreSQL/TimescaleDB,
Redis, NATS and MinIO). It does not install Docker, a model, GPU drivers, security
devices or cloud resources. Core health is not a model, performance or security-quality
acceptance result.

## Requirements and platform limits

- Windows: Docker Desktop in **Linux containers** mode and Windows PowerShell 5.1+.
- Linux/Ubuntu: Docker Engine, Docker Compose **2.24+**, and Bash.
- macOS: Docker Desktop and the built-in Bash are sufficient for the launcher.
- Every service explicitly uses **linux/amd64**. The existing server Dockerfile uses
  an amd64 UPX tool. Apple Silicon therefore needs Docker's amd64 emulation. Native
  arm64 builds, macOS GPU acceleration and an actual Apple Silicon deployment have
  not been verified. This is a Linux-container deployment, not a native host build.
- Allow approximately 8 GiB of Docker memory for the core stack. Building the full
  source is substantially heavier: allow tens of GiB of free disk and preferably
  24 GiB of Docker memory. First compilation can take a long time; no fixed completion
  time or throughput is promised. A verified release image archive avoids compilation.

## One command after cloning or extracting the complete source

### Keep dependencies and data off the Windows system drive

Place the repository on a data drive such as `D:\Projects\AIGuardFabric`.
The launcher keeps its secrets and application data under that repository.
Docker images and BuildKit dependency/build caches live in **Docker's storage**,
not in the Git repository: on a new Windows machine, set Docker Desktop's disk
image location to the data drive before building. Merely cloning to D: does not
move Docker's existing system-drive storage. The launcher does not relocate an
existing Docker installation or change global storage settings.
See [Docker Desktop settings](https://docs.docker.com/desktop/settings-and-maintenance/settings/).

### Start the core

Windows PowerShell, from the repository directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1
```

Linux, Ubuntu or macOS:

```bash
bash ./deploy.sh
```

The default is to **build the four application images from source**, then wait up
to five minutes for startup health. Docker also obtains the infrastructure images
on first use. No local Rust, Node, Python or PowerShell installation is needed on
Linux/macOS. Network access is needed for a source build and any missing images.

The scripts use a separate Compose project, `aiguardfabric-portable`, and create:

- `.env.portable`: random database/object-store/JWT/master/admin secrets; never
  printed, committed or regenerated on a repeat run. Unix mode is 0600; the Windows
  initializer restricts the new file to the current user, SYSTEM and Administrators.
- `data/portable/`: persistent database, object storage, queue and application data.
  A narrow initializer sets application ownership to UID/GID 10001 and creates
  the existing audit-witness ownership marker without replacing witness contents.

No demo fixtures are seeded. Application libraries/rules come from the images.
Database, Redis, NATS and MinIO ports are not published to the host. API, Web,
ingest and syslog bind to **127.0.0.1** by default. Defaults are Web 8081, API 8080,
ingest 8090 and syslog 5514; edit `.env.portable` before starting if those ports
are already used. Use `AGF_BIND_ADDRESS=0.0.0.0` only when you intend LAN exposure
and have configured the host firewall/TLS as appropriate.

Open `http://localhost:8081`. Login user is `agfadmin`; read
`AGF_BOOTSTRAP_ADMIN_PASSWORD` from your local `.env.portable`. The console requires
a password change. The bootstrap password does not reset an existing administrator
when you run the scripts again.

## Explicit model state

By default `AGF_ENV=dev` and `AGF_MOCK_MODE=1`. This is clearly reported as **MOCK**, not a real-model
deployment. No model weights are downloaded and no GPU is claimed.

For a fresh live-mode installation, pass `-Live` (PowerShell) or `--live` (Bash).
This creates `.env.portable` with `AGF_ENV=dev` and `AGF_MOCK_MODE=0`; it still does not install or
claim a working model. Configure an authorized OpenAI-compatible model endpoint
and its credentials in the console and verify the intended model functions.
Container `localhost` is the container itself: a host model needs a reachable host
address, or use a model service on a reachable network. macOS GPU support is not
provided by this Compose file.

For an existing installation, explicitly edit `AGF_MOCK_MODE=0` (keeping `AGF_ENV=dev`) in `.env.portable`
and rerun with `-NoBuild` or `--no-build`. `-Live`/`--live` refuses an existing MOCK
file rather than silently rewriting it. A config created by an older launcher without `AGF_ENV` or the non-default
`AGF_BOOTSTRAP_ADMIN_USER=agfadmin` field is refused until those fields are explicitly
added; no automatic rewrite or secret reset occurs. Existing secrets, data, endpoint permissions
and classifications remain authoritative. Do not upload your local `.env.portable`.

## Existing images and future offline release packs

For images already loaded with the tags selected in `.env.portable`:

```powershell
.\deploy.ps1 -NoBuild
```

```bash
bash ./deploy.sh --no-build
```

For a verified Docker image archive supplied with the matching release:

```powershell
.\deploy.ps1 -ImageArchive .\aiguardfabric-images.tar
```

```bash
bash ./deploy.sh --image-archive ./aiguardfabric-images.tar
```

This runs `docker image load`, never compiles, and uses `--pull never` for startup.
The archive must include **all ten service images** selected by the Compose file:
the four applications, PostgreSQL, Redis, NATS, MinIO, MinIO client and Alpine
initializer. The complete source/configuration files must still accompany it.
Verify the publisher's archive SHA256 before loading it. This document does not
claim that such an archive has already been published or that arbitrary archives
are trustworthy. Override image tags in `.env.portable` to match a supplied pack;
the current source defaults are tags, not an immutable multi-platform release lock.

## Checks, restarts and failures

`-Check` / `--check` initializes a missing local `.env.portable` and validates Compose
with `config --quiet`, without starting containers. It never prints expanded secrets.
`-InitOnly` / `--init-only` runs only the data-directory initializer; an image may
be downloaded if it is not present. It starts no application or database service.

Repeated normal execution starts the same Compose project. Existing secrets and
database/audit contents are preserved; unknown nonempty data roots or mismatching
ownership markers are refused. Containers use `unless-stopped`, but Docker itself
must already be installed/running. No Windows startup task is installed. Host reboot
recovery and all four host OS combinations have not been tested by these scripts.

On failure, keep `.env.portable` and `data/portable`, fix the reported cause, and
inspect the specific service logs. Do not delete the database/audit directory to
make an error disappear. Do not post `.env.portable`, expanded `compose config`,
Docker Env or unredacted application logs in an issue.

To inspect or stop **this** project explicitly, from the repository root:

```bash
docker compose --project-directory . --env-file .env.portable -f deploy/portable/compose.yaml ps
docker compose --project-directory . --env-file .env.portable -f deploy/portable/compose.yaml down
```

`down` stops this project's services; it does not erase bind-mounted data. Do not
remove `data/portable` or the secrets file unless you intentionally discard the
installation. Existing machine-specific `deploy/runtime/start.ps1` and older
Compose projects are separate and are not changed by this portable launcher.

The portable stack is explicitly **local self-hosting in `AGF_ENV=dev`**, including
live-model mode. Its internal PostgreSQL is not configured with production TLS.
The Rust production policy remains unchanged: `prod` requires verified database
TLS. For a production deployment use the separate production Compose setup with
an appropriate TLS-enabled database and trust configuration. Do not relabel this
local stack as production to bypass or misrepresent those requirements.

## Validation scope of this source snapshot

On 2026-10-17 UTC, a clean isolated core installation on a Windows-hosted Docker
Linux daemon passed: Web, API health and API readiness returned HTTP 200, and
22 SQL migrations were applied. The original running deployment was unchanged;
all temporary test containers, network, generated secrets and database data were
removed afterwards. Public receipt SHA256:
`DCE77B724F60EE984692A079D93EE62C539D1B8AFED8048E4C4ECDFD9855BB75`.

This check reused accepted cached amd64 application/infrastructure images and a
cached Redis/Alpine-based image for the initializer. It did **not** recompile the
entire source Dockerfile, verify anonymous pulls of the default Alpine tag, invoke
a model, or exercise macOS/Ubuntu hosts or native ARM64 hardware. PowerShell
configuration/secret-preservation checks, initializer repeat checks and Bash syntax
checks are separate evidence; they do not establish those untested outcomes.
