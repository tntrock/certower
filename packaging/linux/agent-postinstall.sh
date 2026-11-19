#!/bin/sh
set -e
first=0
case "$1" in
configure) [ -z "$2" ] && first=1 ;;
1) first=1 ;;
esac

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
	systemctl enable certower-agent.service >/dev/null 2>&1 || true
	if [ "$first" = 0 ] && systemctl is-active --quiet certower-agent.service; then
		systemctl restart certower-agent.service
	fi
fi

if [ "$first" = 1 ]; then
	cat <<'EOF'

Enroll this host with the command shown in Certower (Agents > Add agent), e.g.
  sudo certower-agent enroll -server https://certower.example.com:8443 -token cwe_... -ca-sha256 ...
then start the agent:
  sudo systemctl start certower-agent
EOF
fi
