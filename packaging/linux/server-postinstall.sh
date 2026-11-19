#!/bin/sh
# deb: $1 = configure, $2 = previous version (empty on first install).
# rpm: $1 = number of installed versions (1 on first install).
set -e
first=0
case "$1" in
configure) [ -z "$2" ] && first=1 ;;
1) first=1 ;;
esac

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
	if [ "$first" = 1 ]; then
		systemctl enable --now certower.service
	elif systemctl is-active --quiet certower.service; then
		systemctl restart certower.service
	fi
fi

if [ "$first" = 1 ]; then
	cat <<'EOF'

Certower is running at http://localhost:8080
Create the first administrator:
  sudo -u certower certower bootstrap -config /etc/certower/certower.env -email you@example.com

Settings: /etc/certower/certower.env
Back up /var/lib/certower/certower.kek: stored keys cannot be decrypted without it.
Guide: https://github.com/tntrock/certower/blob/main/docs/admin-guide.md
EOF
fi
