#!/bin/sh
# Only this deployment's bind directory is writable. No existing data is removed.
set -eu
umask 077
root=/portable-data
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ -d "$root" ] && [ ! -L "$root" ] || fail 'PORTABLE_DATA_MUST_BE_A_REAL_DIRECTORY'
if [ -e "$root/.owner" ] || [ -L "$root/.owner" ]; then
    [ -f "$root/.owner" ] && [ ! -L "$root/.owner" ] || fail 'PORTABLE_OWNER_TYPE'
    printf 'AIGuardFabric portable data v1\n' | cmp -s - "$root/.owner" || fail 'PORTABLE_DATA_NOT_OWNED'
else
    [ -z "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail 'REFUSE_TO_ADOPT_NONEMPTY_DATA'
    (set -C; printf 'AIGuardFabric portable data v1\n' > "$root/.owner")
fi
for name in app postgres redis nats minio; do
    path=$root/$name
    [ ! -L "$path" ] || fail 'DATA_CHILD_LINK_REFUSED'
    if [ -e "$path" ]; then
        [ -d "$path" ] || fail 'DATA_CHILD_MUST_BE_DIRECTORY'
    else
        mkdir "$path"
    fi
    if [ "$name" != postgres ]; then
        chown 10001:10001 "$path"
        chmod 700 "$path"
    fi
done
for name in evidence reports archive audit-witnesses-v1; do
    path=$root/app/$name
    [ ! -L "$path" ] || fail 'APP_DATA_CHILD_LINK_REFUSED'
    if [ -e "$path" ]; then
        [ -d "$path" ] || fail 'APP_DATA_CHILD_MUST_BE_DIRECTORY'
    else
        mkdir "$path"
    fi
    chown 10001:10001 "$path"
    chmod 700 "$path"
done
marker=$root/app/audit-witnesses-v1/.owner
if [ -e "$marker" ] || [ -L "$marker" ]; then
    [ -f "$marker" ] && [ ! -L "$marker" ] || fail 'AUDIT_OWNER_TYPE'
    printf 'AIGuardFabric durable audit witnesses v1\n' | cmp -s - "$marker" || fail 'AUDIT_OWNER_MISMATCH'
else
    # Existing witnesses without an ownership marker must not be adopted.
    [ -z "$(find "$root/app/audit-witnesses-v1" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail 'AUDIT_OWNER_MISSING'
    (set -C; printf 'AIGuardFabric durable audit witnesses v1\n' > "$marker")
fi
chown 10001:10001 "$marker"
chmod 600 "$marker"
printf 'Portable data ready; existing secrets, database and audit witness contents preserved.\n'
