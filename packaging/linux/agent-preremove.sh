#!/bin/sh
# Stops the agent on removal, not on upgrade. Its state (keys and
# enrollment) in /var/lib/certower-agent is kept.
set -e
case "$1" in
remove | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now certower-agent.service || true
	fi
	;;
esac
