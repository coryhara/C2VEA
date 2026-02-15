#!/bin/sh

echo "Setting permissions for /var/lib/mysql"
chown -R 999:999 /var/lib/mysql
chmod -R 755 /var/lib/mysql

exec docker-entrypoint.sh mariadbd
