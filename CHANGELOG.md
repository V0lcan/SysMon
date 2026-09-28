# Changelog

## 1.0.0 (not released yet)

First release.

- Live system view for Windows and Linux: CPU with clock speed, power and every
  core, memory, GPUs, disks (space, speed, temperature, health, wear), network,
  battery, and temperatures and fans.
- Process table (F1 / P): sort by any column, group by program, end processes.
- Graphs (F2 / G): overview, CPU cores, GPU, disks, network and temperatures,
  over 1 to 60 minutes.
- `--once` and `--json` print a snapshot; `--log` records every update to a CSV
  file; `sysmon.ini` sets which sections show, their thresholds and colors.
- `sysmon_server.py` shows every machine started with `--connect` on one web
  page and as JSON for monitoring tools, optionally behind a password and over
  HTTPS (`--cert` / `--key` on the server, `--server-cert` for sysmon).
- Needs Python 3.8 or newer (3.11 or newer recommended) and psutil.
