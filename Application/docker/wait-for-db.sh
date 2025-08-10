#!/usr/bin/env bash
set -euo pipefail

host="${DB_HOST:-db}"
port="${DB_PORT:-3306}"

echo "Waiting for MariaDB at ${host}:${port} ..."
for i in {1..60}; do
  (echo > /dev/tcp/${host}/${port}) >/dev/null 2>&1 && break || true
  sleep 1
done
(echo > /dev/tcp/${host}/${port}) >/dev/null 2>&1 || { echo "DB not reachable"; exit 1; }
echo "MariaDB reachable."