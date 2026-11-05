# Linux Deployment (systemd)

## Automated install

```bash
sudo deployment/linux/install.sh
```

This creates a dedicated `sentinel` service account, installs the app under
`/opt/sentinel`, state under `/var/lib/sentinel`, config at
`/etc/sentinel/sentinel.yaml`, builds a virtualenv, initialises the database and
control-plane keys, and enables two systemd units.

Then create an admin user:

```bash
sudo -u sentinel SENTINEL_CONFIG=/etc/sentinel/sentinel.yaml \
  /opt/sentinel/venv/bin/python -m backend create-user admin admin@example.com --role admin
```

## Services

| Unit | Purpose |
| --- | --- |
| `sentinel-agent.service` | the endpoint detection agent (`Type=notify`, watchdog) |
| `sentinel-api.service` | the control plane / dashboard API |

```bash
systemctl status sentinel-agent sentinel-api
journalctl -u sentinel-agent -f        # structured JSON logs
systemctl restart sentinel-agent
```

The agent starts on boot and restarts on failure (`Restart=on-failure`). It
integrates with the systemd watchdog, so a hung monitor is restarted.

## Monitoring (inotify)

The agent uses inotify. For large trees you may need to raise the watch limit:

```bash
echo 'fs.inotify.max_user_watches=524288' | sudo tee /etc/sysctl.d/90-sentinel.conf
sudo sysctl --system
```

The agent reports inotify watch-limit errors (`ENOSPC`) in each directory's status
and in the endpoint health, rather than failing silently.

## Privilege

By default the units run as the unprivileged `sentinel` user with a hardened
sandbox (`ProtectSystem=strict`, `NoNewPrivileges`, empty `CapabilityBoundingSet`,
syscall filtering). The service account needs **read** access to the directories you
protect and **write** access to its own state dir (for canary deployment inside
monitored dirs it also needs write there).

For privileged process attribution (fanotify/audit) edit `sentinel-agent.service`:

```ini
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
```

Prefer the least privilege that still lets the agent read the protected trees.

## TLS

Terminate TLS at the API (set `SENTINEL_API_TLS_CERTFILE`/`KEYFILE` in the unit) or
behind a reverse proxy. Keep the API bound to `127.0.0.1` when a proxy fronts it.

## Upgrades

```bash
sudo systemctl stop sentinel-agent sentinel-api
# replace /opt/sentinel/{agent,backend,frontend}; migrations run automatically on start
sudo systemctl start sentinel-agent sentinel-api
```
