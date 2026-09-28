# Changelog

## 1.0.1

- Process table (F1) can now be shown as tree view.
- Process table (F1) is now searchable with /.
- `--once` and `--json` print a snapshot and `--svg` saves it as a picture;
  `--log` records every update to a CSV file and `--report` turns that into an
  HTML page of graphs; `sysmon.ini` sets which sections show, their thresholds
  and colors.

## 1.0.0

First release.

- Live system view for Windows and Linux: CPU with clock speed, power and every
  core, memory, GPUs, disks (space, speed, temperature, health, wear), network,
  battery, and temperatures and fans.
- Graphs (F2 / G): overview, CPU cores, GPU, disks, network and temperatures,
  over 1 to 60 minutes.
- `sysmon_server.py` shows every machine started with `--connect` on one web
  page and as JSON for monitoring tools, optionally behind a password and over
  HTTPS (`--cert` / `--key` on the server, `--server-cert` for sysmon).
- Needs Python 3.8 or newer (3.11 or newer recommended) and psutil.
