# Windows Deployment

## Automated install (PowerShell, Administrator)

```powershell
powershell -ExecutionPolicy Bypass -File deployment\windows\install.ps1
```

This installs the app under `C:\Program Files\Sentinel`, state under
`C:\ProgramData\Sentinel`, creates a virtualenv (including `pywin32`), initialises
the database and control-plane keys, installs the **SentinelAgent** Windows Service
and starts it.

Create an admin user:

```powershell
& 'C:\Program Files\Sentinel\venv\Scripts\python.exe' -m backend create-user admin admin@example.com --role admin
```

Run the API (control plane / dashboard):

```powershell
& 'C:\Program Files\Sentinel\venv\Scripts\python.exe' -m backend run
```

(Install the API as a service with your preferred wrapper, e.g. NSSM, or run it on
a management host.)

## The Windows Service

The agent runs as a Windows Service via `agent/service/windows_service.py`
(pywin32). Manage it with:

```powershell
python -m agent.service.windows_service install   # or: start | stop | remove
sc.exe query SentinelAgent
```

The service starts automatically at boot (`--startup auto`) and reads
`SENTINEL_CONFIG` (set as a machine environment variable by the installer).

## Monitoring

On Windows the agent uses `ReadDirectoryChangesW` via watchdog. Process attribution
falls back to I/O correlation; for richer attribution an ETW/minifilter adapter can
be added. Run the service as a low-privilege account with read access to the
protected directories where possible; LocalSystem is only needed for privileged
telemetry.

## Logs

Structured logs go to the configured `log_file` (set `log_file` in
`C:\ProgramData\Sentinel\sentinel.yaml`) and service start/stop events to the
Windows Event Log.

## Uninstall

```powershell
python -m agent.service.windows_service stop
python -m agent.service.windows_service remove
```
