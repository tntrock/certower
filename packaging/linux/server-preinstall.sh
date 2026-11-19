#!/bin/sh
# Creates the unprivileged account the server runs as.
set -e
if ! getent group certower >/dev/null 2>&1; then
	groupadd --system certower
fi
if ! getent passwd certower >/dev/null 2>&1; then
	nologin=$(command -v nologin || echo /bin/false)
	useradd --system --gid certower --home-dir /var/lib/certower --no-create-home \
		--shell "$nologin" --comment "Certower server" certower
fi
