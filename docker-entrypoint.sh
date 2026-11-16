#!/bin/sh
# Make /data writable for the app user, then drop root.
set -e
PUID="${PUID:-99}"
PGID="${PGID:-100}"
if [ "$(id -u)" = "0" ]; then
  mkdir -p "${DATA_DIR:-/data}"
  chown -R "$PUID:$PGID" "${DATA_DIR:-/data}" 2>/dev/null || echo "warning: could not chown ${DATA_DIR:-/data}"
  exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups "$@"
fi
exec "$@"
