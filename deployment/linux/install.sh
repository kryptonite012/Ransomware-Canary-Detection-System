#!/usr/bin/env bash
# PROJECT SENTINEL - Linux installer (systemd).
# Installs the agent + API under /opt/sentinel with a dedicated service account.
set -euo pipefail

PREFIX=/opt/sentinel
CONFDIR=/etc/sentinel
STATEDIR=/var/lib/sentinel
LOGDIR=/var/log/sentinel
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ $EUID -ne 0 ]]; then echo "run as root" >&2; exit 1; fi

echo "[*] creating service account 'sentinel'"
id sentinel &>/dev/null || useradd --system --home "$STATEDIR" --shell /usr/sbin/nologin sentinel

echo "[*] creating directories"
install -d -o sentinel -g sentinel -m 0750 "$PREFIX" "$STATEDIR" "$LOGDIR" "$STATEDIR/secrets"
install -d -m 0755 "$CONFDIR"

echo "[*] copying application"
cp -r "$REPO"/agent "$REPO"/backend "$PREFIX"/
[[ -d "$REPO/frontend/dist" ]] && { install -d "$PREFIX/frontend"; cp -r "$REPO/frontend/dist" "$PREFIX/frontend/"; }

echo "[*] creating virtualenv and installing dependencies"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet -r "$REPO/requirements.txt"
chown -R sentinel:sentinel "$PREFIX"

if [[ ! -f "$CONFDIR/sentinel.yaml" ]]; then
  echo "[*] installing default configuration to $CONFDIR/sentinel.yaml"
  sed "s#./data#$STATEDIR#; s#log_file: null#log_file: $LOGDIR/agent.log#" \
      "$REPO/config/sentinel.yaml" > "$CONFDIR/sentinel.yaml"
fi

echo "[*] initializing database and control-plane keys"
sudo -u sentinel SENTINEL_CONFIG="$CONFDIR/sentinel.yaml" "$PREFIX/venv/bin/python" -m agent init
sudo -u sentinel SENTINEL_CONFIG="$CONFDIR/sentinel.yaml" "$PREFIX/venv/bin/python" -m backend init-keys

echo "[*] installing systemd units"
cp "$REPO/deployment/linux/sentinel-agent.service" "$REPO/deployment/linux/sentinel-api.service" \
   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentinel-agent.service sentinel-api.service

echo "[+] installed. Create an admin user with:"
echo "    sudo -u sentinel SENTINEL_CONFIG=$CONFDIR/sentinel.yaml $PREFIX/venv/bin/python -m backend create-user admin admin@example.com --role admin"
