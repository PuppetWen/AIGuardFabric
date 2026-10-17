#!/usr/bin/env bash
# Linux/Ubuntu/macOS bootstrap. The applications run in Docker Linux containers.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ENV_FILE="$ROOT/.env.portable"
COMPOSE_FILE="$ROOT/deploy/portable/compose.yaml"
BUILD=1
CHECK=0
INIT_ONLY=0
LIVE=0
ARCHIVE=''
usage() {
    printf '%s\n' 'Usage: bash deploy.sh [--build | --no-build | --image-archive FILE] [--live] [--check | --init-only]'
    printf '%s\n' 'Default: build source, then start the core stack in explicit MOCK mode.'
    printf '%s\n' '--live selects live mode only when creating a NEW .env.portable; it never changes an existing file.'
}
fail() { printf '%s\n' "$1" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --build) BUILD=1 ;;
        --no-build) BUILD=0 ;;
        --image-archive) shift; [ "$#" -gt 0 ] || fail '--image-archive needs a file'; ARCHIVE=$1; BUILD=0 ;;
        --live) LIVE=1 ;;
        --check) CHECK=1 ;;
        --init-only) INIT_ONLY=1 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; fail "Unknown option: $1" ;;
    esac
    shift
done
[ "$CHECK" -eq 0 ] || [ "$INIT_ONLY" -eq 0 ] || fail 'Choose --check or --init-only.'
[ -f "$COMPOSE_FILE" ] && [ -f "$ROOT/Cargo.lock" ] || fail 'Run this script from the complete source distribution.'
command -v docker >/dev/null 2>&1 || fail 'Install Docker Engine + Compose v2 (Linux), or Docker Desktop (macOS/Windows), and start it first.'
[ "$(docker info --format '{{.OSType}}')" = linux ] || fail 'A Linux-container Docker daemon is required.'
version=$(docker compose version --short)
version=${version#v}
major=${version%%.*}; rest=${version#*.}; minor=${rest%%.*}
[[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || fail 'Cannot determine Docker Compose version.'
[ "$major" -gt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -ge 24 ]; } || fail 'Docker Compose 2.24+ is required.'
umask 077
if [ -e "$ENV_FILE" ] || [ -L "$ENV_FILE" ]; then
    [ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || fail '.env.portable must be a regular file, not a link.'
else
    random_hex() { od -An -N32 -tx1 /dev/urandom | tr -d ' \r\n'; }
    random_admin() {
        while :; do
            candidate=$(random_hex)
            case "$candidate" in *abc123*|*123456*|*000000*|*111111*) continue ;; esac
            printf 'Ag7!%s' "$candidate"; break
        done
    }
    pg=$(random_hex); s3=$(random_hex); jwt=$(random_hex); admin=$(random_admin)
    master=$(head -c 32 /dev/urandom | base64 | tr -d '\r\n')
    [ "${#pg}" -eq 64 ] && [ "${#s3}" -eq 64 ] && [ "${#jwt}" -eq 64 ] && [ "${#admin}" -eq 68 ] && [ "${#master}" -eq 44 ] || fail 'Secure random generation failed.'
    mode=1; environment=dev
    if [ "$LIVE" -eq 1 ]; then mode=0; fi
    temporary=$(mktemp "$ROOT/.env.portable.tmp.XXXXXX")
    cleanup() { [ -z "${temporary:-}" ] || rm -f -- "$temporary"; }
    trap cleanup EXIT HUP INT TERM
    chmod 600 "$temporary"
    cat > "$temporary" <<EOF
# Generated locally. Do not publish or delete this file when upgrading.
AGF_PG_PASSWORD=$pg
AGF_S3_SECRET_KEY=$s3
AGF_JWT_SECRET=$jwt
AGF_MASTER_KEY_BASE64=$master
AGF_BOOTSTRAP_ADMIN_PASSWORD=$admin
AGF_MOCK_MODE=$mode
AGF_ENV=$environment
AGF_BOOTSTRAP_ADMIN_USER=agfadmin
AGF_BIND_ADDRESS=127.0.0.1
AGF_WEB_PORT=8081
AGF_SERVER_PORT=8080
AGF_INGEST_PORT=8090
AGF_SYSLOG_PORT=5514
AGF_IMAGE_PREFIX=aiguardfabric
AGF_IMAGE_TAG=portable
EOF
    # Hard-link creation is atomic and refuses to overwrite a concurrent initializer.
    ln "$temporary" "$ENV_FILE" || fail 'Another initializer created .env.portable; existing bytes were preserved.'
    rm -f -- "$temporary"; temporary=''
    trap - EXIT HUP INT TERM
    unset pg s3 jwt admin master
    printf '%s\n' 'Created .env.portable with random secrets; admin password is stored there (not printed).'
fi
mode=$(sed -n 's/^AGF_MOCK_MODE=\([01]\)$/\1/p' "$ENV_FILE")
[[ "$mode" = 0 || "$mode" = 1 ]] || fail '.env.portable must contain exactly one AGF_MOCK_MODE=0 or 1 line.'
if [ "$LIVE" -eq 1 ] && [ "$mode" != 0 ]; then
    fail 'Existing .env.portable is in MOCK mode. Set AGF_MOCK_MODE=0 explicitly; existing secrets were preserved.'
fi
environment=$(sed -n 's/^AGF_ENV=//p' "$ENV_FILE")
admin_user=$(sed -n 's/^AGF_BOOTSTRAP_ADMIN_USER=\([A-Za-z0-9_-]*\)$/\1/p' "$ENV_FILE")
[ "$admin_user" = agfadmin ] || fail 'Existing .env.portable requires AGF_BOOTSTRAP_ADMIN_USER=agfadmin; add it explicitly without replacing secrets.'
[ "$environment" = dev ] || fail 'Portable local self-hosting requires AGF_ENV=dev even for live models. Production TLS deployment is separate; correct the field explicitly without replacing secrets.'
chmod 600 "$ENV_FILE"
for path in "$ROOT/data" "$ROOT/data/portable"; do
    [ ! -L "$path" ] || fail 'Data directory links are refused.'
    if [ -e "$path" ]; then [ -d "$path" ] || fail 'Data path must be a directory.'; else mkdir "$path"; fi
done
dc=(docker compose --project-directory "$ROOT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE")
# Prevent an inherited terminal variable from overriding a key in this file.
while IFS='=' read -r key value; do
    case "$key" in
        AGF_*|POSTGRES_IMAGE|REDIS_IMAGE|NATS_IMAGE|MINIO_IMAGE|MINIO_MC_IMAGE)
            [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] && unset "$key" ;;
    esac
done < "$ENV_FILE"
# Do not print `compose config`: its expanded output contains secrets.
"${dc[@]}" config --quiet
if [ "$mode" = 1 ]; then
    printf '%s\n' 'MODEL MODE: MOCK. No real model, GPU or cloud service has been configured or verified.'
else
    printf '%s\n' 'MODEL MODE: LIVE, but no model is installed. Configure an authorized OpenAI-compatible endpoint in the console.'
fi
printf '%s\n' 'Container platform: linux/amd64. Apple Silicon uses emulation; native arm64 and GPU-on-macOS are not claimed.'
if [ "$CHECK" -eq 1 ]; then printf '%s\n' 'Compose configuration is valid. No container was started.'; exit 0; fi
if [ -n "$ARCHIVE" ]; then
    [ -f "$ARCHIVE" ] && [ ! -L "$ARCHIVE" ] || fail 'Image archive must be an existing regular file.'
    docker image load --input "$ARCHIVE"
fi
init=(run --rm --no-deps)
if [ -n "$ARCHIVE" ]; then init+=(--pull never); fi
init+=(init-data)
# Compose creates every bind directory before starting dependencies. Initialize
# first so that its later create phase cannot produce an unowned nonempty root.
"${dc[@]}" "${init[@]}"
if [ "$INIT_ONLY" -eq 1 ]; then
    printf '%s\n' 'Data initializer completed. No application service was started.'
    exit 0
fi
if [ "$BUILD" -eq 1 ]; then
    printf '%s\n' 'Building source: this can take a long time and tens of GiB. A release image archive avoids compilation.'
    "${dc[@]}" build agf-server agf-ingest agf-scheduler agf-web
fi
if [ -n "$ARCHIVE" ]; then
    "${dc[@]}" up -d --no-build --pull never --wait --wait-timeout 300
else
    "${dc[@]}" up -d --no-build --wait --wait-timeout 300
fi
port=$(sed -n 's/^AGF_WEB_PORT=\([0-9][0-9]*\)$/\1/p' "$ENV_FILE")
printf 'Core stack is healthy. Console: http://localhost:%s\n' "$port"
printf '%s\n' 'Login user: agfadmin. Read AGF_BOOTSTRAP_ADMIN_PASSWORD from .env.portable; the console requires a password change.'
printf '%s\n' 'Rerunning preserves .env.portable and data/portable. Model functionality is not implied by core health.'
