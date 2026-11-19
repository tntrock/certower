#!/bin/sh
# Stops the service on removal (deb: remove, rpm: 0), not on upgrade.
# The data in /var/lib/certower is kept.
set -e
case "$1" in
remove | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now certower.service || true
	fi
	;;
esac
