#!/usr/bin/env python3
"""
sysmon.py - live system monitor for the terminal, for Windows and Linux.

Continuously shows CPU clock speed, power and per-core load, memory, GPU load and
VRAM, disk space, I/O, temperature and health, network throughput, temperatures,
fan speeds and battery, refreshing once per second by default.

    pip install psutil
    python sysmon.py                  # live view; H shows the keys, Ctrl+C quits
    python sysmon.py -i 0.5           # refresh every 0.5 seconds
    python sysmon.py --once           # print a single snapshot and exit
    python sysmon.py --json           # print a single snapshot as JSON and exit
    python sysmon.py --log usage.csv  # also append every update to a CSV file
    python sysmon.py --report usage.csv  # turn that log into usage.html, a page with graphs
    python sysmon.py --svg sysmon.svg    # save a picture of the screen
    python sysmon.py --connect 192.168.1.10:8765  # also send it to sysmon_server.py

F1 / P opens a process table (sort, filter by name, tree view, end processes), F2 / G
opens usage graphs. Sections, thresholds and colors are set in sysmon.ini next to this script.

Where the data comes from:
    everywhere  psutil (CPU, memory, disks, network, battery, processes) and
                nvidia-smi when installed (NVIDIA load, VRAM, temperature, fan, power)
    Linux       /sys (AMD / Intel GPUs, RAPL CPU power, disk models and
                temperatures, battery wear), hwmon via psutil (temperatures, fans),
                /proc (per-process GPU use; per-process network with packet
                capture, as root) and smartctl (disk health, as root)
    Windows     performance counters (GPU load for any vendor, per-process GPU and
                VRAM, and the real boost-aware CPU clock, as Task Manager shows),
                DXGI (GPU names and VRAM size), storage driver queries (disk names,
                health, temperature), one system call for all processes, TCP
                connection statistics (per-process network, as administrator),
                and LibreHardwareMonitor's web server when running (temperatures,
                fans, CPU power), since Windows has no built-in API for those.
"""

from __future__ import annotations

__version__ = "1.0.0"  # keep equal to sysmon_server.py's

import argparse
import base64
import configparser
import csv
import ctypes
import glob
import html
import itertools
import json
import math
import os
import platform
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from collections import deque, namedtuple
from dataclasses import asdict, dataclass, field

try:
    import psutil
except ImportError:
    sys.exit("psutil is required:  pip install psutil")

SYSTEM = platform.system()  # "Windows", "Linux", "Darwin", ...
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"

if IS_WINDOWS:
    import msvcrt
    # Windows looks for a program in the current directory before PATH, so a nvidia-smi.bat or
    # powershell.exe planted in the folder sysmon is started from would run instead (as
    # administrator, if sysmon is). This switches that off for us and the programs we start.
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
else:
    import select
    import termios
    import tty


def is_admin():
    """Running as administrator (Windows) or root (Linux)."""
    return bool(ctypes.windll.shell32.IsUserAnAdmin()) if IS_WINDOWS else os.geteuid() == 0


# --- Settings ----------------------------------------------------------------

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sysmon.ini")
SECTION_NAMES = ("cpu", "memory", "gpu", "disks", "network", "battery", "sensors")
DEFAULT_SETTINGS = {
    "sections": {name: "yes" for name in SECTION_NAMES},
    "thresholds": {"usage_warn": "60", "usage_high": "85", "temperature_warn": "60",
                   "temperature_high": "80", "battery_warn": "50", "battery_low": "20"},
    # Bright yellow: PowerShell's blue console scheme turns plain yellow into its white text color.
    "colors": {"ok": "green", "warn": "bright_yellow", "high": "red", "accent": "cyan",
               "track": "bright_black"},
}
# Color names -> ANSI text color codes: black..white are 30..37, bright_black..bright_white 90..97.
COLOR_CODES = {name: str(30 + i) for i, name in
               enumerate(("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"))}
COLOR_CODES.update({f"bright_{name}": str(int(code) + 60) for name, code in list(COLOR_CODES.items())})
SHOW, LIMITS, COLOR = {}, {}, {}  # the settings in use, filled in by apply_settings()


def load_settings(path=None):
    """The default settings, overridden by the INI file at `path` if given."""
    config = configparser.ConfigParser()
    config.read_dict(DEFAULT_SETTINGS)
    if path:
        with open(path, encoding="utf-8") as f:
            config.read_file(f)
    return config


def apply_settings(config):
    """Check the settings and make them the current ones; ValueError describes any mistake."""
    unknown = set(config.sections()) - set(DEFAULT_SETTINGS)
    if unknown:  # e.g. [colour]: its settings would be silently ignored
        raise ValueError(f"unknown section {', '.join(f'[{name}]' for name in sorted(unknown))}")
    for section, defaults in DEFAULT_SETTINGS.items():
        unknown = set(config[section]) - set(defaults)
        if unknown:
            raise ValueError(f"unknown setting in [{section}]: {', '.join(sorted(unknown))}")
    colors = {}
    for name in DEFAULT_SETTINGS["colors"]:
        value = config.get("colors", name).strip().lower()
        if value not in COLOR_CODES and not re.fullmatch(r"\d+(;\d+)*", value):
            raise ValueError(f"unknown color '{value}' for {name} in [colors]")
        colors[name] = COLOR_CODES.get(value, value)
    show = {name: config.getboolean("sections", name) for name in SECTION_NAMES}
    limits = {name: config.getfloat("thresholds", name) for name in DEFAULT_SETTINGS["thresholds"]}
    SHOW.update(show)
    LIMITS.update(limits)
    COLOR.update(colors)


apply_settings(load_settings())


# --- Formatting --------------------------------------------------------------

BOLD, DIM, REVERSE = "1", "2", "7"  # ANSI text styles, used like the color codes
USE_COLOR = True  # main() turns it off when the output isn't a terminal (and for --json)
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")  # one escape sequence (color, cursor movement)
COLOR_RE = re.compile(r"\x1b\[[0-9;]*m")  # a color / style code: the only escape codes in sysmon's lines
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")  # control characters, ESC among them
LABEL_W = 8  # width of the row labels: "Usage", "RAM", "VRAM", ...
GRAPH_ROWS = 4  # height of one graph in the graphs pane
# The classic Windows console fonts (Consolas, Lucida Console) only have the half block.
BLOCKS = " ▄█" if IS_WINDOWS else " ▁▂▃▄▅▆▇█"


def paint(text, code):
    """`text` in an ANSI color or style `code` (e.g. "32" green), reset after it."""
    return f"\x1b[{code}m{text}\x1b[0m" if USE_COLOR else str(text)


def level_color(pct):
    """The ok / warn / high color for a usage percentage."""
    return (COLOR["ok"] if pct < LIMITS["usage_warn"] else
            COLOR["warn"] if pct < LIMITS["usage_high"] else COLOR["high"])


def temp_color(celsius):
    """The ok / warn / high color for a temperature."""
    return (COLOR["ok"] if celsius < LIMITS["temperature_warn"] else
            COLOR["warn"] if celsius < LIMITS["temperature_high"] else COLOR["high"])


def bar(pct, width, code=None):
    """A bar `width` characters long, filled to `pct` percent in `code` or the level's color."""
    pct = min(max(pct or 0.0, 0.0), 100.0)
    filled = round(pct / 100 * width)
    # A solid track in its own color (a dim ░ track disappears on PowerShell's blue background);
    # without colors it must be a different character to tell it from the filled part.
    track = "█" if USE_COLOR else "░"
    return paint("█" * filled, code or level_color(pct)) + paint(track * (width - filled), COLOR["track"])


def bar_width(width):
    """Length of the section bars in a window `width` wide: what's left after the label and
    the numbers beside the bar (about 50 characters), between 10 and 40."""
    return max(10, min(40, width - 50))


def fmt_bytes(n):
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    i = 0
    while abs(n) >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"


def fmt_rate(n):
    return fmt_bytes(n) + "/s"


def fmt_bits(bytes_per_second):
    """Link speeds are quoted in bits: 125000000 bytes/s -> "1 Gbit/s"."""
    bits = bytes_per_second * 8
    return f"{bits / 1e9:g} Gbit/s" if bits >= 1e9 else f"{bits / 1e6:g} Mbit/s"


def log_position(value, floor, top):
    """Where `value` sits between `floor` (0) and `top` (1) on a logarithmic scale."""
    if value <= floor:
        return 0.0
    return min(1.0, math.log(value / floor) / math.log(top / floor))


def fmt_mhz(mhz):
    return f"{mhz / 1000:.2f} GHz" if mhz >= 1000 else f"{mhz:.0f} MHz"


def fmt_temp(celsius):
    return paint(f"{celsius:5.1f}°C", temp_color(celsius))


def fmt_duration(seconds):
    """90061 -> "1d 01:01:01"; the days are left out when there are none."""
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    return (f"{days}d " if days else "") + f"{hours:02}:{minutes:02}:{secs:02}"


def visible_len(s):
    """Length of `s` on screen: escape codes take no room."""
    return len(ANSI_RE.sub("", s))


def pad(s, width):
    """`s` padded with spaces to `width` visible characters (ljust, but color-aware)."""
    return s + " " * (width - visible_len(s))


def printable(s):
    """`s` with every control character outside the color codes shown as "?". Process names,
    sensor labels and device names come from outside; on Linux any user can name a process
    with escape codes that would clear the screen, set the window title or fill the clipboard."""
    parts = re.split(f"({COLOR_RE.pattern})", s)  # text and color codes taking turns
    return "".join(part if i % 2 else CONTROL_RE.sub("?", part) for i, part in enumerate(parts))


def truncate(s, width):
    """Cut a string to `width` visible characters without breaking ANSI codes. Every line passes
    through here on its way to the terminal or the web page, so it's also made printable()."""
    s = printable(s)
    if visible_len(s) <= width:
        return s
    out, n = [], 0
    for part in re.split(f"({ANSI_RE.pattern})", s):
        if ANSI_RE.fullmatch(part):
            out.append(part)  # keep escape codes so colors still get reset
        elif n < width:
            out.append(part[: width - n])
            n += len(out[-1])
    return "".join(out)


def grid(cells, width, gap=3):
    """Lay cells out in as many columns as fit, filling column by column."""
    if not cells:
        return []
    cell_w = max(visible_len(c) for c in cells)
    cols = max(1, (width + gap) // (cell_w + gap))  # the last column needs no gap after it
    rows = -(-len(cells) // cols)  # rounded up
    return [(" " * gap).join(pad(cells[i], cell_w) for i in range(r, len(cells), rows)).rstrip()
            for r in range(rows)]


def side_by_side(columns, widths, separator):
    """Join blocks of lines into columns of the given widths."""
    return [separator.join(pad(truncate(line, w), w) for line, w in zip(row, widths)).rstrip()
            for row in itertools.zip_longest(*columns, fillvalue="")]


def chart(values, width, height, top, color):
    """Column chart of the last `width` values, newest on the right, `height` rows tall and
    scaled to `top`; color(value) picks each column's color."""
    values = [0.0] * (width - len(values)) + list(values)[-width:]  # too little history: pad with 0
    steps = len(BLOCKS) - 1  # filled levels per row
    rows = []
    for row in range(height - 1, -1, -1):  # top row first
        cells = []
        for value in values:
            # The column's height in steps, minus the rows below this one: how full this cell is.
            level = min(max(round(value / top * height * steps) - row * steps, 0), steps)
            cells.append(paint(BLOCKS[level], color(value)) if level else " ")
        rows.append("".join(cells))
    return rows


def resample(values, count, width):
    """The last `count` values averaged into `width` columns; missing history counts as 0."""
    values = list(values)[-count:]
    values = [0.0] * (count - len(values)) + values
    columns = []
    for i in range(width):
        low = i * count // width
        chunk = values[low:max(low + 1, (i + 1) * count // width)]
        columns.append(sum(chunk) / len(chunk))
    return columns


def rule(title, width):
    """A section title line, "── CPU ─────...", `width` characters long."""
    head = f"── {title} "
    return paint(head, f"{BOLD};{COLOR['accent']}") + paint("─" * max(0, width - len(head)), COLOR["accent"])


def usage_line(label, pct, used, total, width, label_w=LABEL_W):
    """A labeled bar with amounts: "  RAM      ████░░░░  52.9%  16.9 GiB / 31.9 GiB"."""
    return (f"  {label[:label_w]:<{label_w}} {bar(pct, bar_width(width))} {pct:5.1f}%  "
            f"{fmt_bytes(used)} / {fmt_bytes(total)}")


# --- Small helpers -----------------------------------------------------------

def safe(fn, *args, **kwargs):
    """Call a hardware probe that may fail on some machines; None on failure."""
    try:
        return fn(*args, **kwargs)
    except Exception:  # psutil raises a variety of errors on unusual hardware
        return None


def to_float(value):
    """float(value), or None if it isn't a number (e.g. nvidia-smi's "[N/A]")."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def read_file(path):
    """A (sysfs / proc) file's contents without the trailing newline, or None if unreadable."""
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


class Background:
    """Runs a slow probe in a daemon thread every `every` seconds; .value is the latest result."""

    def __init__(self, fn, every):
        self.value = None

        def loop():
            while True:
                self.value = safe(fn)
                time.sleep(every)

        threading.Thread(target=loop, daemon=True).start()


# --- System description ------------------------------------------------------

def os_description():
    """E.g. "Windows 11 (build 26200)" or "Ubuntu 24.04 LTS (kernel 6.8.0-45-generic)"."""
    if IS_WINDOWS:
        build = sys.getwindowsversion().build
        # Windows 11 still calls itself release "10"; only the build number tells them apart.
        name = "Windows 11" if build >= 22000 else f"Windows {platform.release()}"
        return f"{name} (build {build})"
    if IS_LINUX:
        name = "Linux"
        for line in (read_file("/etc/os-release") or "").splitlines():
            if line.startswith("PRETTY_NAME="):
                name = line.split("=", 1)[1].strip('"')
        return f"{name} (kernel {platform.release()})"
    return f"{SYSTEM} {platform.release()} (not Windows/Linux: showing what psutil provides)"


def cpu_model():
    """The CPU's marketing name; platform.processor() only gives a family code on Windows."""
    if IS_WINDOWS:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    elif IS_LINUX:
        for line in (read_file("/proc/cpuinfo") or "").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or platform.machine()


# --- GPUs --------------------------------------------------------------------

@dataclass
class GpuInfo:
    name: str
    util: float | None = None         # %
    mem_used: float | None = None     # bytes
    mem_total: float | None = None    # bytes
    shared_used: float | None = None  # bytes of system RAM used by the GPU
    temp: float | None = None         # degrees C
    fan: str | None = None            # as shown: "30%" (nvidia-smi) or "1100 RPM" (Linux sysfs)
    power: float | None = None        # W
    clock: float | None = None        # MHz


class NvidiaSmi:
    """Streams NVIDIA GPU stats from one long-running `nvidia-smi -lms` process."""

    FIELDS = ("index,name,utilization.gpu,memory.used,memory.total,"
              "temperature.gpu,fan.speed,power.draw,clocks.gr")

    def __init__(self, interval):
        self.rows = {}  # GPU index -> the other FIELDS as strings, from nvidia-smi's latest line
        self.proc = None
        exe = shutil.which("nvidia-smi")
        if not exe or not os.path.isabs(exe):  # Python < 3.12 ignores the setting above: ".\nvidia-smi"
            return
        try:
            self.proc = subprocess.Popen(
                [exe, f"--query-gpu={self.FIELDS}", "--format=csv,noheader,nounits",
                 "-lms", str(max(100, int(interval * 1000)))],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        except OSError:
            return
        self._first_line = threading.Event()
        threading.Thread(target=self._reader, daemon=True).start()
        self._first_line.wait(timeout=2)  # so the first frame already knows the NVIDIA GPUs

    def _reader(self):
        """Background thread: keep self.rows up to date from nvidia-smi's output."""
        for line in self.proc.stdout:
            index, _, rest = line.partition(",")
            fields = rest.rsplit(",", 7)  # rsplit: a GPU name could contain commas
            if len(fields) == 8:
                self.rows[index.strip()] = [f.strip() for f in fields]
                self._first_line.set()
        self._first_line.set()  # nvidia-smi exited: don't keep __init__ waiting

    def read(self):
        """The latest stats of every NVIDIA GPU as GpuInfo."""
        gpus = []
        # list() takes a copy first: the reader thread may add a GPU while we loop.
        for _, (name, util, used, total, temp, fan, power, clock) in sorted(list(self.rows.items())):
            used, total, fan = to_float(used), to_float(total), to_float(fan)
            gpus.append(GpuInfo(  # nvidia-smi reports memory in MiB
                name, util=to_float(util),
                mem_used=used * 2**20 if used is not None else None,
                mem_total=total * 2**20 if total is not None else None,
                temp=to_float(temp), fan=f"{fan:.0f}%" if fan is not None else None,
                power=to_float(power), clock=to_float(clock)))
        return gpus

    def close(self):
        if self.proc:
            self.proc.terminate()


class LinuxDrmGpus:
    """AMD and Intel GPUs on Linux, read straight from the kernel driver in sysfs."""

    VENDORS = {"0x1002": "AMD", "0x8086": "Intel", "0x10de": "NVIDIA"}  # PCI vendor IDs

    def __init__(self):
        self.cards = []  # (card folder, its device folder, vendor ID, name)
        for card in sorted(glob.glob("/sys/class/drm/card*")):
            if not re.fullmatch(r"card\d+", os.path.basename(card)):
                continue  # skip connectors such as card0-HDMI-A-1
            dev = os.path.join(card, "device")
            vendor = read_file(os.path.join(dev, "vendor"))
            if vendor:
                self.cards.append((card, dev, vendor, self._name(card, dev, vendor)))

    @classmethod
    def _name(cls, card, dev, vendor):
        """The model name from lspci, or e.g. "AMD GPU (card0)" without it."""
        slot = re.search(r"PCI_SLOT_NAME=(\S+)", read_file(os.path.join(dev, "uevent")) or "")
        if slot and shutil.which("lspci"):
            try:
                out = subprocess.run(["lspci", "-s", slot.group(1)], capture_output=True,
                                     text=True, timeout=2).stdout
                if ": " in out:
                    return out.split(": ", 1)[1].strip()
            except (OSError, subprocess.SubprocessError):
                pass
        return f"{cls.VENDORS.get(vendor, vendor)} GPU ({os.path.basename(card)})"

    def read(self, skip_nvidia):
        """Every card as GpuInfo; skip_nvidia when nvidia-smi already covers those."""
        gpus = []
        for card, dev, vendor, name in self.cards:
            if skip_nvidia and vendor == "0x10de":
                continue
            # Reading a sleeping laptop dGPU's sensors would wake it up and drain the battery.
            if read_file(f"{dev}/power/runtime_status") == "suspended":
                gpus.append(GpuInfo(f"{name} (suspended)"))
                continue
            gpu = GpuInfo(name,
                          util=to_float(read_file(f"{dev}/gpu_busy_percent")),
                          mem_used=to_float(read_file(f"{dev}/mem_info_vram_used")),
                          mem_total=to_float(read_file(f"{dev}/mem_info_vram_total")))
            # amdgpu lists its clock levels ("1: 2400Mhz *") and marks the active one with *.
            active_clock = re.search(r"(\d+)\s*Mhz\s*\*", read_file(f"{dev}/pp_dpm_sclk") or "", re.I)
            gpu.clock = (float(active_clock.group(1)) if active_clock
                         else to_float(read_file(f"{card}/gt_act_freq_mhz")))  # Intel i915
            # hwmon units: temperature in millidegrees C, power in microwatts.
            for hwmon in glob.glob(f"{dev}/hwmon/hwmon*"):
                temp = to_float(read_file(f"{hwmon}/temp1_input"))
                fan = to_float(read_file(f"{hwmon}/fan1_input"))
                power = (to_float(read_file(f"{hwmon}/power1_average"))
                         or to_float(read_file(f"{hwmon}/power1_input")))
                if temp is not None:
                    gpu.temp = temp / 1000
                if fan is not None:
                    gpu.fan = f"{fan:.0f} RPM"
                if power:
                    gpu.power = power / 1e6
            gpus.append(gpu)
        return gpus


# --- Windows: performance counters and DXGI ----------------------------------

# The performance counters we read: our key -> counter path. (*) means every instance
# (each core, GPU engine, process, ...); read() returns them by instance name.
PDH_COUNTERS = {
    "cpu_perf": r"\Processor Information(*)\% Processor Performance",
    "cpu_base": r"\Processor Information(_Total)\Processor Frequency",
    "gpu_engine": r"\GPU Engine(*)\Utilization Percentage",
    "gpu_dedicated": r"\GPU Adapter Memory(*)\Dedicated Usage",
    "gpu_shared": r"\GPU Adapter Memory(*)\Shared Usage",
    "gpu_process_vram": r"\GPU Process Memory(*)\Dedicated Usage",
}


class _PdhValue(ctypes.Structure):  # PDH_FMT_COUNTERVALUE
    _fields_ = [("CStatus", ctypes.c_uint32), ("doubleValue", ctypes.c_double)]


class _PdhItem(ctypes.Structure):  # PDH_FMT_COUNTERVALUE_ITEM_W
    _fields_ = [("szName", ctypes.c_wchar_p), ("FmtValue", _PdhValue)]


class Pdh:
    """Minimal wrapper around the Windows performance-counter API (pdh.dll)."""

    FORMAT = 0x200 | 0x8000  # PDH_FMT_DOUBLE | PDH_FMT_NOCAP100 (boost clocks go past 100 %)
    MORE_DATA = 0x800007D2  # PDH_MORE_DATA: the answer to "how big a buffer do you need?"

    def __init__(self, paths):
        self.dll = ctypes.WinDLL("pdh")
        for name in ("PdhOpenQueryW", "PdhAddEnglishCounterW", "PdhCollectQueryData",
                     "PdhGetFormattedCounterArrayW"):
            getattr(self.dll, name).restype = ctypes.c_uint32
        self.query = ctypes.c_void_p()
        if self.dll.PdhOpenQueryW(None, None, ctypes.byref(self.query)):
            raise OSError("PdhOpenQuery failed")
        self.counters = {}
        for key, path in paths.items():
            handle = ctypes.c_void_p()
            if self.dll.PdhAddEnglishCounterW(self.query, path, None, ctypes.byref(handle)) == 0:
                self.counters[key] = handle
        self.dll.PdhCollectQueryData(self.query)  # rate counters need a baseline sample

    def read(self):
        """Take a new sample. Returns {key: {instance name: value}}."""
        self.dll.PdhCollectQueryData(self.query)
        result = {}
        for key, handle in self.counters.items():
            values = result[key] = {}
            # Called twice: first without a buffer to learn the size, then to fill one.
            size, count = ctypes.c_uint32(0), ctypes.c_uint32(0)
            args = (handle, self.FORMAT, ctypes.byref(size), ctypes.byref(count))
            if self.dll.PdhGetFormattedCounterArrayW(*args, None) != self.MORE_DATA:
                continue
            buffer = ctypes.create_string_buffer(size.value)
            if self.dll.PdhGetFormattedCounterArrayW(*args, buffer) != 0:
                continue
            items = ctypes.cast(buffer, ctypes.POINTER(_PdhItem))
            for i in range(count.value):
                if items[i].FmtValue.CStatus in (0, 1):  # PDH_CSTATUS_VALID_DATA / NEW_DATA
                    values[items[i].szName] = items[i].FmtValue.doubleValue
        return result


class _Luid(ctypes.Structure):  # a GPU's locally unique ID; performance counters name GPUs by it
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]


class _AdapterDesc1(ctypes.Structure):  # DXGI_ADAPTER_DESC1
    _fields_ = [("Description", ctypes.c_wchar * 128), ("VendorId", ctypes.c_uint32),
                ("DeviceId", ctypes.c_uint32), ("SubSysId", ctypes.c_uint32),
                ("Revision", ctypes.c_uint32), ("DedicatedVideoMemory", ctypes.c_size_t),
                ("DedicatedSystemMemory", ctypes.c_size_t), ("SharedSystemMemory", ctypes.c_size_t),
                ("AdapterLuid", _Luid), ("Flags", ctypes.c_uint32)]


def _com_method(obj, index, *argtypes):
    """Return a callable for method number `index` of a COM object's vtable."""
    vtable = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)(vtable[index])


def dxgi_adapters():
    """Hardware GPUs as (name, luid, vendor id, dedicated VRAM bytes), via DXGI."""
    iid = ctypes.create_string_buffer(uuid.UUID("770aae78-f26f-4dba-a829-253c83d1b387").bytes_le, 16)  # IDXGIFactory1
    factory = ctypes.c_void_p()
    if ctypes.WinDLL("dxgi").CreateDXGIFactory1(iid, ctypes.byref(factory)) != 0:
        return []
    enum_adapters = _com_method(factory, 12, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p))  # EnumAdapters1
    adapters, index, adapter = [], 0, ctypes.c_void_p()
    while enum_adapters(factory, index, ctypes.byref(adapter)) == 0:  # fails after the last adapter
        desc = _AdapterDesc1()
        _com_method(adapter, 10, ctypes.POINTER(_AdapterDesc1))(adapter, ctypes.byref(desc))  # GetDesc1
        _com_method(adapter, 2)(adapter)  # Release
        # Written the way the GPU performance counters name the adapter, to match them up.
        luid = f"luid_0x{desc.AdapterLuid.HighPart & 0xFFFFFFFF:08x}_0x{desc.AdapterLuid.LowPart:08x}"
        if not desc.Flags & 2 and luid not in [a[1] for a in adapters]:  # 2 = software renderer
            adapters.append((desc.Description, luid, desc.VendorId, desc.DedicatedVideoMemory))
        index += 1
    _com_method(factory, 2)(factory)  # Release
    return adapters


# GPU counter instance names look like "pid_1234_luid_0x00000000_0x0000d2b1_phys_0_eng_3_engtype_Copy":
# the process, the GPU (luid), and which of its engines.
LUID_RE = re.compile(r"luid_0x[0-9a-f]+_0x[0-9a-f]+", re.I)
ENGINE_RE = re.compile(r"(luid_0x[0-9a-f]+_0x[0-9a-f]+)_phys_(\d+)_eng_(\d+)", re.I)


def windows_gpus(adapters, counters, skip_nvidia):
    """GPU load and VRAM for any vendor, computed like Task Manager does: add up
    every process's use of each engine; the GPU's load is its busiest engine."""
    engines = {}
    for instance, value in counters.get("gpu_engine", {}).items():
        m = ENGINE_RE.search(instance)
        if m:
            key = (m.group(1).lower(), m.group(2), m.group(3))
            engines[key] = engines.get(key, 0.0) + value
    load = {}
    for (luid, _, _), value in engines.items():
        load[luid] = max(load.get(luid, 0.0), value)

    def per_adapter(counter):
        totals = {}
        for instance, value in counters.get(counter, {}).items():
            m = LUID_RE.search(instance)
            if m:
                totals[m.group().lower()] = totals.get(m.group().lower(), 0.0) + value
        return totals

    dedicated, shared = per_adapter("gpu_dedicated"), per_adapter("gpu_shared")
    has_load = "gpu_engine" in counters
    return [GpuInfo(name, util=min(load.get(luid, 0.0), 100.0) if has_load else None,
                    mem_used=dedicated.get(luid), mem_total=vram or None,
                    shared_used=shared.get(luid))
            for name, luid, vendor, vram in adapters
            if not (skip_nvidia and vendor == 0x10DE)]


def windows_by_pid(counters, key, combine):
    """Per-pid values of a GPU counter whose instances are named "pid_1234_luid_...". GPU load
    uses max (a process's busiest engine, like Task Manager); VRAM adds up over adapters."""
    usage = {}
    for instance, value in counters.get(key, {}).items():
        m = re.match(r"pid_(\d+)_", instance)
        if m:
            pid = int(m.group(1))
            usage[pid] = combine(usage[pid], value) if pid in usage else value
    return usage


def windows_cpu_clocks(counters):
    """Real CPU clocks including boost, like Task Manager: base clock x '% Processor
    Performance'. Returns (base MHz, current MHz, [per-core MHz])."""
    base = counters.get("cpu_base", {}).get("_Total")
    perf = counters.get("cpu_perf", {})
    if not base or "_Total" not in perf:
        return None, None, []
    # Per-core instances are named "group,core" ("0,5"); "0,_Total" is a group's total.
    cores = sorted((tuple(map(int, name.split(","))), value)
                   for name, value in perf.items() if re.fullmatch(r"\d+,\d+", name))
    return base, base * perf["_Total"] / 100, [base * value / 100 for _, value in cores]


def enable_ansi_on_windows():
    """Turn on escape-code processing in the classic Windows console (conhost)."""
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.GetStdHandle.restype = ctypes.c_void_p
    handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
    mode = ctypes.c_uint32()
    if kernel32.GetConsoleMode(ctypes.c_void_p(handle), ctypes.byref(mode)):
        kernel32.SetConsoleMode(ctypes.c_void_p(handle), mode.value | 0x0004)  # VT processing


# --- Temperatures, fans, power and battery -----------------------------------

def linux_sensors():
    """[(chip, 'temp' | 'fan', label, value)] from the kernel's hwmon drivers."""
    readings = []
    for chip, entries in (safe(psutil.sensors_temperatures) or {}).items():
        for i, entry in enumerate(entries, 1):
            readings.append((chip, "temp", entry.label or f"temp{i}", entry.current))
    for chip, entries in (safe(psutil.sensors_fans) or {}).items():
        for i, entry in enumerate(entries, 1):
            readings.append((chip, "fan", entry.label or f"fan{i}", entry.current))
    return readings


class LibreHardwareMonitor:
    """Temperatures, fans and CPU power from LibreHardwareMonitor's web server (Windows).

    Polled from a background thread: when LHM isn't running, Windows takes ~0.7 s
    to refuse the connection, which would otherwise freeze the display."""

    URL = "http://localhost:8085/data.json"

    def __init__(self, interval):
        self.readings = None  # [(hardware, 'temp' | 'fan', label, value)], None if unreachable
        self.cpu_power = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never via a proxy
        threading.Thread(target=self._poll, args=(interval,), daemon=True).start()

    def _poll(self, interval):
        while True:
            try:
                with self.opener.open(self.URL, timeout=2) as response:
                    tree = json.load(response)
            except (OSError, ValueError):
                self.readings = self.cpu_power = None
                time.sleep(5)  # not running; check again in a few seconds
                continue
            self.readings, self.cpu_power = self.parse(tree)
            time.sleep(interval)

    @classmethod
    def parse(cls, tree):
        """(temperature and fan readings, CPU package power in W or None) from data.json."""
        found = []
        cls._walk(tree, [], found)
        cpu_power = next((value for _, kind, label, value, is_cpu in found
                          if kind == "power" and is_cpu and "package" in label.lower()), None)
        return [reading[:4] for reading in found if reading[1] != "power"], cpu_power

    @classmethod
    def _walk(cls, node, path, out):
        """Collect every sensor under `node` into `out` as (hardware, kind, label, value, is CPU).
        Tree layout: root > computer > hardware (> sub-hardware) > category > sensor."""
        children = node.get("Children") or []
        for child in children:
            cls._walk(child, path + [node], out)
        if children or len(path) < 2:
            return  # only sensors (leaves under a category and hardware) have values
        value = str(node.get("Value", ""))
        number = re.search(r"-?\d+(?:[.,]\d+)?", value)
        if not number:
            return
        number = float(number.group().replace(",", "."))  # values follow the Windows locale
        category, hardware = path[-1].get("Text", ""), path[-2]
        kind = ("fan" if category == "Fans" or value.endswith("RPM") else
                "temp" if category == "Temperatures" or "°C" in value else
                "power" if category == "Powers" or value.endswith(" W") else None)
        if kind:  # LHM gives CPU hardware a cpu icon; its name alone doesn't say it's a CPU
            out.append((hardware.get("Text", ""), kind, node.get("Text", "?"), number,
                        "cpu" in hardware.get("ImageURL", "")))


class LinuxRapl:
    """CPU package power from the kernel's RAPL energy counters (Intel, and AMD since
    Linux 5.8). Current kernels only let root read them."""

    def __init__(self, base="/sys/class/powercap"):
        self.zones = [zone for zone in sorted(glob.glob(f"{base}/intel-rapl:*"))
                      if re.fullmatch(r"intel-rapl:\d+", os.path.basename(zone))]  # packages, not sub-zones
        self.last = None  # each zone's energy counter (microjoules) at the previous read

    def read(self, dt):
        """Watts since the previous call, or None."""
        energy = [to_float(read_file(f"{zone}/energy_uj")) for zone in self.zones]
        if not self.zones or None in energy:
            return None
        last, self.last = self.last, energy
        if last is None:
            return None
        joules = 0.0
        for zone, now, before in zip(self.zones, energy, last):
            if now < before:  # the counter wrapped around
                now += to_float(read_file(f"{zone}/max_energy_range_uj")) or 0.0
            joules += (now - before) / 1e6
        return joules / dt


def linux_battery_wear(base="/sys/class/power_supply"):
    """Capacity lost compared to new, in %, from the first battery that reports it."""
    for battery in sorted(glob.glob(f"{base}/BAT*")):
        for kind in ("energy", "charge"):
            full = to_float(read_file(f"{battery}/{kind}_full"))
            design = to_float(read_file(f"{battery}/{kind}_full_design"))
            if full and design:
                return max(0.0, 100 * (1 - full / design))
    return None


def windows_battery_wear():
    """Capacity lost compared to new, in %, via WMI; slow (PowerShell), so run in the background."""
    script = ("$full = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity)[0];"
              "$design = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData)[0];"
              "\"$($full.FullChargedCapacity) $($design.DesignedCapacity)\"")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True,
                         text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW).stdout
    full, design = map(float, out.split())
    return max(0.0, 100 * (1 - full / design))


# --- Disks -------------------------------------------------------------------

def list_mounts():
    """Mount points worth a usage bar: "C:\\", "D:\\" on Windows; "/", "/home" on Linux."""
    mounts = []
    for part in safe(psutil.disk_partitions) or []:
        if IS_WINDOWS and ("cdrom" in part.opts or not part.fstype):
            continue  # empty optical / card-reader drives
        if IS_LINUX and part.fstype == "squashfs":
            continue  # snap packages
        if part.mountpoint not in mounts:
            mounts.append(part.mountpoint)
    return mounts


def disk_io():
    """Bytes read and written since boot, per disk (and per partition on Linux)."""
    return safe(psutil.disk_io_counters, perdisk=True) or {}


def is_physical_disk(name):
    """Whether a disk_io() name is a whole physical disk."""
    if IS_LINUX:  # drop partitions (sda1), loop devices, device-mapper volumes, etc.
        return (os.path.exists(f"/sys/block/{name}")
                and not name.startswith(("loop", "ram", "zram", "dm-", "sr")))
    return True  # Windows already reports PhysicalDrive0, PhysicalDrive1, ...


def parse_nvme_health(log):
    """(temperature °C, wear %, healthy) from an NVMe SMART / health information log page.
    Byte 0: critical warning flags; bytes 1-2: temperature in kelvin; byte 5: percentage used."""
    kelvin = struct.unpack_from("<H", log, 1)[0]
    return (kelvin - 273 if kelvin else None), log[5], log[0] == 0


def _device_query(path, code, request=b"", size=1024):
    """Send one query ioctl to a device opened without access rights, which is all that
    queries need: no administrator rights. Returns the reply bytes, or None."""
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(path, 0, 3, None, 3, 0, None)  # share read/write, OPEN_EXISTING
    if handle in (None, ctypes.c_void_p(-1).value):
        return None
    try:
        buffer = ctypes.create_string_buffer(request, max(size, len(request)))
        returned = ctypes.c_uint32()
        if kernel32.DeviceIoControl(ctypes.c_void_p(handle), code, buffer, len(request), buffer,
                                    len(buffer), ctypes.byref(returned), None):
            return buffer.raw[:returned.value]
        return None
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def _c_string(data, offset):
    """The NUL-terminated string at `offset` in a driver's reply."""
    end = data.find(b"\0", offset)
    return data[offset:end if end >= 0 else None].decode(errors="replace").strip()


def windows_disk_info(disk_names, mounts):
    """{"PhysicalDrive0": {label, model, temperature, health, wear_percent}} from the storage
    drivers: drive letters, model, and NVMe health log or SMART failure prediction."""
    letters = {}  # "PhysicalDrive0" -> the drive letters on it
    for mount in mounts:
        extents = _device_query(f"\\\\.\\{mount[:2]}", 0x560000)  # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
        # Reply: the number of extents, then from byte 8 one 24-byte entry per extent that
        # starts with its disk number (a volume can span several disks).
        for i in range(struct.unpack_from("<I", extents)[0] if extents else 0):
            disk = struct.unpack_from("<I", extents, 8 + 24 * i)[0]
            letters.setdefault(f"PhysicalDrive{disk}", set()).add(mount[:2])
    info = {}
    for name in disk_names:
        device = f"\\\\.\\{name}"
        entry = info[name] = {"label": " ".join(sorted(letters.get(name, ()))) or name.replace("PhysicalDrive", "Disk "),
                              "model": "", "temperature": None, "health": None, "wear_percent": None}
        query = 0x2D1400  # IOCTL_STORAGE_QUERY_PROPERTY
        descriptor = _device_query(device, query, struct.pack("<III", 0, 0, 0))  # StorageDeviceProperty
        if descriptor and len(descriptor) >= 20:
            # Bytes 12 and 16 hold where the vendor and product strings start (0: none).
            vendor, product = (_c_string(descriptor, offset) if offset else ""
                               for offset in struct.unpack_from("<II", descriptor, 12))
            entry["model"] = f"{vendor if vendor not in ('', 'ATA') else ''} {product}".strip()
        # NVMe SMART / health log, asked for through the protocol-specific property (50). The
        # request after the property id and query type: protocol NVMe (3), data type log page (2),
        # log page 2 (SMART / health), sub-value 0, the data follows at offset 40, 512 bytes of it.
        request = struct.pack("<II10I", 50, 0, 3, 2, 2, 0, 40, 512, 0, 0, 0, 0) + bytes(512)
        reply = _device_query(device, query, request)
        if reply and len(reply) >= 48 + 512:  # the log follows a 48-byte header
            temperature, wear, healthy = parse_nvme_health(reply[48:])
            entry.update(temperature=temperature, wear_percent=wear, health="healthy" if healthy else "warning")
            continue
        prediction = _device_query(device, 0x2D1100, size=516)  # IOCTL_STORAGE_PREDICT_FAILURE
        if prediction:
            entry["health"] = "failing" if struct.unpack_from("<I", prediction)[0] else "healthy"
        reply = _device_query(device, query, struct.pack("<III", 52, 0, 0))  # StorageDeviceTemperatureProperty
        # Byte 12: how many sensors the drive reports; byte 26: the first one's temperature.
        if reply and len(reply) >= 28 and struct.unpack_from("<H", reply, 12)[0]:
            entry["temperature"] = struct.unpack_from("<h", reply, 26)[0]
    return info


def linux_parent_disks(device):
    """The physical disks under a block device: sda1 -> [sda]; dm-0 (LUKS/LVM) -> the disks below."""
    slaves = glob.glob(f"/sys/class/block/{device}/slaves/*")
    if slaves:
        return [disk for slave in slaves for disk in linux_parent_disks(os.path.basename(slave))]
    parent = os.path.basename(os.path.dirname(os.path.realpath(f"/sys/class/block/{device}")))
    return [device if parent == "block" else parent]


def parse_smartctl(text):
    """Health, temperature and wear from `smartctl --json -H -A` output."""
    data = json.loads(text)
    passed = data.get("smart_status", {}).get("passed")
    return {"health": None if passed is None else "healthy" if passed else "failing",
            "temperature": data.get("temperature", {}).get("current"),
            "wear_percent": data.get("nvme_smart_health_information_log", {}).get("percentage_used")}


def linux_smart(disk_names):
    """smartctl results per disk; needs root, and takes a while, so it runs in the background."""
    results = {}
    for name in disk_names:  # one disk hanging or failing mustn't lose the other disks' results
        results[name] = safe(lambda: parse_smartctl(subprocess.run(
            ["smartctl", "--json", "-H", "-A", f"/dev/{name}"], capture_output=True, text=True, timeout=30).stdout)) or {}
    return results


def linux_disk_info(disk_names, smart):
    """{"sda": {label, model, temperature, health, wear_percent}} from sysfs (and smartctl)."""
    mounts = {}
    for part in safe(psutil.disk_partitions) or []:
        for disk in linux_parent_disks(os.path.basename(os.path.realpath(part.device))):
            mounts.setdefault(disk, []).append(part.mountpoint)
    info = {}
    for name in disk_names:
        temperature = None
        for path in (glob.glob(f"/sys/block/{name}/device/hwmon*/temp1_input")  # NVMe
                     + glob.glob(f"/sys/block/{name}/device/hwmon/hwmon*/temp1_input")):  # SATA (drivetemp)
            millidegrees = to_float(read_file(path))
            if millidegrees is not None:
                temperature = millidegrees / 1000
        label = f"{name} ({', '.join(mounts[name])})" if name in mounts else name
        info[name] = {"label": label, "model": read_file(f"/sys/block/{name}/device/model") or "",
                      "temperature": temperature, "health": None, "wear_percent": None}
        info[name].update({k: v for k, v in (smart or {}).get(name, {}).items() if v is not None})
    return info


# --- Network -----------------------------------------------------------------

def ipv4_addresses():
    """{adapter name: its first IPv4 address, or ""}."""
    return {nic: next((a.address for a in addrs if a.family == socket.AF_INET), "")
            for nic, addrs in (safe(psutil.net_if_addrs) or {}).items()}


def link_speed(stat):
    """An adapter's link speed in bytes/s, or 0 if unknown. Windows reports 4294 Mbit/s
    (2^32 - 1 bit/s) for adapters without a real one, such as VPN and Hyper-V adapters."""
    mbits = stat.speed if stat else 0
    return 0 if mbits in (0, 4294) else mbits * 1e6 / 8


class WindowsTcpTraffic:
    """Bytes per process from Windows' per-connection TCP statistics. Switching the statistics
    on needs administrator rights, and UDP (so also QUIC / HTTP/3) isn't covered."""

    def __init__(self):
        self.available = is_admin()
        self.iphlp = ctypes.WinDLL("iphlpapi")
        self.seen = {}  # connection -> bytes counted so far

    def _connections(self, family):
        """[(pid, MIB_TCPROW / MIB_TCP6ROW bytes, is IPv6)] of established, non-loopback connections.
        The row bytes identify the connection to the statistics calls."""
        size = ctypes.c_uint32(0)
        self.iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, family, 5, 0)  # 5: with owner pid
        buffer = ctypes.create_string_buffer(size.value + 8192)  # room for connections opened meanwhile
        size.value = len(buffer)
        if self.iphlp.GetExtendedTcpTable(buffer, ctypes.byref(size), False, family, 5, 0):
            return []
        raw, rows = buffer.raw, []
        for i in range(struct.unpack_from("<I", raw)[0]):
            if family == socket.AF_INET:  # MIB_TCPROW_OWNER_PID: state, local, port, remote, port, pid
                entry = raw[4 + 24 * i:28 + 24 * i]
                state, _, _, remote, _, pid = struct.unpack("<6I", entry)
                if state == 5 and remote & 0xFF != 127:  # established, not 127.x.x.x
                    rows.append((pid, entry[:20], False))
            else:  # MIB_TCP6ROW_OWNER_PID; the statistics calls want MIB_TCP6ROW: state first
                entry = raw[4 + 56 * i:60 + 56 * i]
                state, pid = struct.unpack_from("<II", entry, 48)
                if state == 5 and entry[24:40] != bytes(15) + b"\x01":  # not ::1
                    rows.append((pid, struct.pack("<I", state) + entry[:48], True))
        return rows

    def bytes_by_pid(self):
        """{pid: bytes sent + received since the previous call}."""
        if not self.available:
            return {}
        traffic, seen = {}, {}
        for pid, row, ipv6 in self._connections(socket.AF_INET) + self._connections(socket.AF_INET6):
            row_buffer = ctypes.create_string_buffer(row, len(row))
            if ipv6:
                enable, read = self.iphlp.SetPerTcp6ConnectionEStats, self.iphlp.GetPerTcp6ConnectionEStats
            else:
                enable, read = self.iphlp.SetPerTcpConnectionEStats, self.iphlp.GetPerTcpConnectionEStats
            if row not in self.seen:  # 1 = TcpConnectionEstatsData; b"\x01" = EnableCollection
                enable(row_buffer, 1, ctypes.create_string_buffer(b"\x01", 1), 0, 1, 0)
            data = ctypes.create_string_buffer(96)  # TCP_ESTATS_DATA_ROD_v0; Windows wants exactly 96
            if read(row_buffer, 1, None, 0, 0, None, 0, 0, data, 0, 96) == 0:
                sent, _, received = struct.unpack_from("<3Q", data)
                seen[row] = sent + received
                # Only what's new since the last call; a connection seen for the first time adds 0.
                traffic[pid] = traffic.get(pid, 0) + seen[row] - self.seen.get(row, seen[row])
        self.seen = seen  # closed connections drop out
        return traffic

    def stop(self):
        self.seen = {}


def packet_ports(data, protocol):
    """("tcp" | "udp", source port, destination port) of an IPv4 / IPv6 packet, else None."""
    if protocol == 0x0800 and len(data) >= 20:
        transport, offset = data[9], (data[0] & 0x0F) * 4
    elif protocol == 0x86DD and len(data) >= 40:
        transport, offset = data[6], 40  # ponytail: ignores IPv6 extension headers
    else:
        return None
    if transport not in (6, 17) or len(data) < offset + 4:
        return None
    source, destination = struct.unpack_from("!HH", data, offset)
    return ("tcp" if transport == 6 else "udp"), source, destination


def linux_socket_owners():
    """{("tcp" | "udp", local port): pid} from /proc/net and every process's open sockets."""
    inodes = {}  # socket inode -> (protocol, local port)
    for table in ("tcp", "tcp6", "udp", "udp6"):
        for line in (read_file(f"/proc/net/{table}") or "").splitlines()[1:]:  # [1:]: skip the header
            fields = line.split()
            if len(fields) > 9:  # fields[1]: local "ADDRESS:PORT" in hex; fields[9]: the socket's inode
                inodes[fields[9]] = (table[:3], int(fields[1].rsplit(":", 1)[1], 16))
    owners = {}
    # A process's open sockets show up as links named "socket:[inode]" among its file descriptors.
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target.startswith("socket:[") and target[8:-1] in inodes:
            owners[inodes[target[8:-1]]] = int(fd.split("/")[2])
    return owners


class LinuxPacketCounter:
    """Bytes per process on Linux: captures packets on every interface (needs root) and credits
    each one to the process that owns its local port. Runs only while the process table is open.
    ponytail: Python keeps up with tens of thousands of packets/s; beyond that it undercounts."""

    def __init__(self):
        self.available = is_admin()
        self.sock = None
        self.lock = threading.Lock()
        self.ports = {}  # (protocol, local port) -> bytes since the last call

    def _capture(self, sock):
        """Background thread: count the bytes of every packet by (protocol, local port)."""
        while self.sock is sock:  # stop() or a new socket ends this thread
            try:
                data, (interface, protocol, packet_type, _, _) = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            ports = packet_ports(data, protocol) if interface != "lo" else None
            if ports:
                local = ports[1] if packet_type == 4 else ports[2]  # 4 = PACKET_OUTGOING
                with self.lock:
                    self.ports[(ports[0], local)] = self.ports.get((ports[0], local), 0) + len(data)
        sock.close()

    def bytes_by_pid(self):
        """{pid: bytes sent + received since the previous call}; starts capturing on first use."""
        if not self.available:
            return {}
        if self.sock is None:
            try:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))  # ETH_P_ALL
            except OSError:  # e.g. root inside a container without the CAP_NET_RAW capability
                self.available = False
                return {}
            self.sock.settimeout(0.5)
            threading.Thread(target=self._capture, args=(self.sock,), daemon=True).start()
        with self.lock:
            ports, self.ports = self.ports, {}
        owners = linux_socket_owners() if ports else {}
        traffic = {}
        for key, count in ports.items():
            if key in owners:
                traffic[owners[key]] = traffic.get(owners[key], 0) + count
        return traffic

    def stop(self):
        self.sock = None  # the capture thread notices within 0.5 s and closes the socket


# --- Processes ---------------------------------------------------------------

class _ProcessInfo(ctypes.Structure):  # SYSTEM_PROCESS_INFORMATION, 64-bit layout
    _fields_ = [("NextEntryOffset", ctypes.c_uint32), ("NumberOfThreads", ctypes.c_uint32),
                ("WorkingSetPrivateSize", ctypes.c_int64), ("_unused1", ctypes.c_byte * 24),
                ("UserTime", ctypes.c_int64), ("KernelTime", ctypes.c_int64),
                ("NameLength", ctypes.c_uint16), ("NameMaxLength", ctypes.c_uint16),
                ("NameBuffer", ctypes.c_void_p), ("BasePriority", ctypes.c_int32),
                ("UniqueProcessId", ctypes.c_void_p), ("InheritedFromUniqueProcessId", ctypes.c_void_p),
                ("_unused2", ctypes.c_byte * 136),
                ("ReadTransferCount", ctypes.c_int64), ("WriteTransferCount", ctypes.c_int64)]


def windows_processes():
    """{pid: (name, CPU seconds, private working set, I/O bytes, parent pid)} for every process,
    from a single system call. psutil opens each process separately and rescans the whole
    system for every protected one, which takes ~2 s per update with ~400 processes."""
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return {}  # ponytail: 64-bit layout only; 32-bit Python would need its own offsets
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtQuerySystemInformation.restype = ctypes.c_uint32
    size = ctypes.c_uint32(1 << 20)
    while True:
        buffer = ctypes.create_string_buffer(size.value)
        status = ntdll.NtQuerySystemInformation(5, buffer, size, ctypes.byref(size))  # 5 = processes
        if status != 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH: processes appeared, grow and retry
            break
        size.value += 1 << 16
    procs, offset = {}, 0
    while status == 0:
        info = _ProcessInfo.from_buffer(buffer, offset)
        if info.UniqueProcessId:  # skip pid 0, the "System Idle Process"
            procs[info.UniqueProcessId] = (ctypes.wstring_at(info.NameBuffer, info.NameLength // 2),
                                           (info.UserTime + info.KernelTime) / 1e7,
                                           info.WorkingSetPrivateSize,
                                           info.ReadTransferCount + info.WriteTransferCount,
                                           info.InheritedFromUniqueProcessId or 0)
        if not info.NextEntryOffset:
            break
        offset += info.NextEntryOffset
    return procs


def process_snapshot():
    """{pid: (name, CPU seconds, memory bytes, I/O bytes, parent pid)} for every process we can see."""
    if IS_WINDOWS:
        return windows_processes()
    procs = {}
    for proc in psutil.process_iter(["name", "cpu_times", "memory_info", "io_counters", "ppid"]):
        info = proc.info  # fields we may not read (other users' I/O) are None
        io = info["io_counters"]
        procs[proc.pid] = (info["name"] or "?",
                           sum(info["cpu_times"][:2]) if info["cpu_times"] else 0.0,
                           info["memory_info"].rss if info["memory_info"] else 0,
                           io.read_bytes + io.write_bytes if io else 0,
                           info["ppid"] or 0)
    return procs


UNITS = {"": 1, "B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}  # memory units in DRM fdinfo


def linux_drm_fdinfo():
    """GPU use per process from the kernel's DRM fdinfo, which amdgpu, i915 and xe provide
    (NVIDIA's driver doesn't): ({(pid, client, engine): busy ns}, {pid: VRAM bytes}).
    Covers the processes we may inspect: our own, or all of them as root."""
    busy, vram = {}, {}
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            if not os.readlink(fd).startswith("/dev/dri/"):
                continue
        except OSError:
            continue
        text = read_file(fd.replace("/fd/", "/fdinfo/")) or ""
        client = re.search(r"^drm-client-id:\s*(\d+)", text, re.M)
        if not client:
            continue
        pid = int(fd.split("/")[2])
        for engine, ns in re.findall(r"^drm-engine-([\w-]+):\s*(\d+) ns", text, re.M):
            busy[(pid, client.group(1), engine)] = int(ns)
        sizes = [int(n) * UNITS.get(unit, 1) for n, unit in re.findall(
            r"^drm-(?:memory-vram|resident-(?:vram|local)\d*):\s*(\d+)\s*(\w*)", text, re.M)]
        if sizes:  # drivers may report the same memory under several names: take the largest
            vram[(pid, client.group(1))] = max(sizes)
    per_pid = {}
    for (pid, _), size in vram.items():
        per_pid[pid] = per_pid.get(pid, 0) + size
    return busy, per_pid


def linux_gpu_by_pid(now, before, dt):
    """GPU % per pid from two fdinfo samples: each process's busiest engine."""
    per_engine = {}
    for (pid, client, engine), ns in now.items():
        busy = ns - before.get((pid, client, engine), ns)
        per_engine[(pid, engine)] = per_engine.get((pid, engine), 0) + busy
    usage = {}
    for (pid, _), ns in per_engine.items():  # busy ns / (dt s * 1e9 ns/s) * 100 % = ns / dt / 1e7
        usage[pid] = max(usage.get(pid, 0.0), min(100.0, ns / dt / 1e7))
    return usage


# A process table row. key: pid, or the name when grouped; prefix: the tree branches before the label.
Row = namedtuple("Row", "key label pids values prefix", defaults=("",))

PROCESS_COLUMNS = {  # column: (title, width, format)
    "cpu": ("CPU", 6, "{:.1f}%".format),
    "memory": ("Memory", 10, fmt_bytes),
    "gpu": ("GPU", 6, "{:.1f}%".format),
    "vram": ("VRAM", 10, fmt_bytes),
    "io": ("I/O", 11, fmt_rate),
    "net": ("Network", 11, fmt_rate),
}
RATE_COLUMNS = ("cpu", "io", "net")  # need two samples, so they're blank right after opening


def process_rows(procs, group):
    """procs {pid: (name, {column: value})} as table rows: one per process, or per program."""
    if not group:
        return [Row(pid, name, [pid], values) for pid, (name, values) in procs.items()]
    programs = {}
    for pid, (name, values) in procs.items():
        pids, totals = programs.setdefault(name, ([], {}))
        pids.append(pid)
        for column, value in values.items():
            totals[column] = totals.get(column, 0) + value
    for _, totals in programs.values():
        if "gpu" in totals:  # several processes' busiest engines can add up past the whole GPU
            totals["gpu"] = min(totals["gpu"], 100.0)
    return [Row(name, f"{name} ({len(pids)})" if len(pids) > 1 else name, pids, totals)
            for name, (pids, totals) in programs.items()]


def top_rows(rows, column, totals, limit=None, keep_idle=False):
    """The rows using the most of `column`, busiest first: all of them with keep_idle, else only
    those using at least 0.1% of its total; `limit` keeps the first ones."""
    floor = totals.get(column, 0) * 0.001
    used = [row for row in rows if keep_idle or (row.values.get(column, 0) > 0 and row.values[column] >= floor)]
    return sorted(used, key=lambda row: row.values.get(column, 0), reverse=True)[:limit]


def tree_rows(rows, parents, column):
    """rows as a process tree: each under its parent, siblings busiest first, with the branch
    lines in their prefix. A process whose parent isn't in rows is at the top level."""
    listed, children, seen, out = {row.key for row in rows}, {}, set(), []
    for row in rows:
        parent = parents.get(row.key)
        children.setdefault(parent if parent in listed and parent != row.key else None, []).append(row)
    busiest = lambda row: row.values.get(column, 0)

    def add(parent, indent):
        kids = [row for row in sorted(children.get(parent, []), key=busiest, reverse=True) if row.key not in seen]
        for i, row in enumerate(kids):
            last = i == len(kids) - 1
            seen.add(row.key)
            out.append(row._replace(prefix="" if parent is None else indent + ("└─ " if last else "├─ ")))
            add(row.key, "" if parent is None else indent + ("   " if last else "│  "))

    add(None, "")
    for row in sorted(rows, key=busiest, reverse=True):  # parents of each other (a reused pid): no top level
        if row.key not in seen:
            seen.add(row.key)
            out.append(row)
            add(row.key, "")
    return out


def end_processes(label, processes):
    """Ask psutil.Process objects to end (SIGTERM on Linux, TerminateProcess on Windows). They're
    created when the user picks the row, so psutil refuses a pid another process got since then."""
    problems = set()
    for process in processes:
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass  # already gone, or its pid now belongs to another process
        except psutil.AccessDenied:
            problems.add("access denied")
        except psutil.Error as error:
            problems.add(str(error))
    return f"Could not end {label}: {', '.join(sorted(problems))}" if problems else f"Ended {label}"


# --- What the screen shows, and the keys that change it -----------------------

GRAPH_PAGES = ("Overview", "CPU cores", "GPU", "Disks", "Network", "Temperatures")
GRAPH_WINDOWS = (60, 300, 900, 3600)  # seconds; + and - switch between them
WIDE = 200  # columns needed to show both panes beside the system view


@dataclass
class View:
    """What the screen shows, changed by the keys the user presses."""
    panes: list = field(default_factory=list)  # open panes, most recent last: "processes", "graphs"
    help: bool = False
    sort: str = "cpu"             # process table column
    group: bool = False           # one row per program instead of per process
    tree: bool = False            # processes under their parents
    filter: str = ""              # only processes whose name contains this (lowercase)
    typing: bool = False          # the keys go to the filter
    selected: object = None       # the selected row's key: a pid, or a program name when grouped
    cursor: int = 0               # the selected row's position
    confirm: tuple | None = None  # (label, psutil processes) waiting for Y to end them
    message: str = ""
    graph_page: int = 0
    window: int = 0               # index into GRAPH_WINDOWS

    def handle(self, key, rows, columns, wide=False):
        """Apply one key press; rows and columns are the process table as last drawn, and
        wide says whether the window has room for both panes."""
        if self.help:
            self.help = False  # any key closes the help
            return
        if self.confirm:
            label, processes = self.confirm
            self.confirm = None
            self.message = end_processes(label, processes) if key == "y" else "Not ended"
            return
        self.message = ""
        if self.typing and key not in ("UP", "DOWN"):  # typing a filter: letters are text, not commands
            if key in ("ENTER", "ESC"):
                self.typing = False
            if key in ("ESC", "BACKSPACE") or len(key) == 1 and key.isprintable():
                self.filter = "" if key == "ESC" else self.filter[:-1] if key == "BACKSPACE" else self.filter + key
                self.selected, self.cursor = None, 0
            return
        pane = {"F1": "processes", "p": "processes", "F2": "graphs", "g": "graphs"}.get(key)
        in_table, in_graphs = "processes" in self.panes, "graphs" in self.panes
        if pane:
            if pane in self.panes and (wide or self.panes[-1] == pane):
                self.panes.remove(pane)  # it's on screen: close it
            else:  # open it; in a narrow window it replaces the other pane instead of hiding behind it
                self.panes = [p for p in self.panes if p != pane] + [pane] if wide else [pane]
        elif key in ("h", "?"):
            self.help = True
        elif in_table and key in ("UP", "DOWN") and rows:
            self.cursor = min(max(self.cursor + (1 if key == "DOWN" else -1), 0), len(rows) - 1)
            self.selected = rows[self.cursor].key
        elif in_table and key in ("LEFT", "RIGHT") and columns:
            i = columns.index(self.sort) if self.sort in columns else 0
            self.sort = columns[(i + (1 if key == "RIGHT" else -1)) % len(columns)]
        elif in_table and key == "/":
            self.typing = True
        elif in_table and key == "ESC" and self.filter:
            self.filter, self.selected, self.cursor = "", None, 0
        elif in_table and key == "t":  # a tree of programs makes no sense: tree and group exclude each other
            self.tree, self.group, self.selected, self.cursor = not self.tree, False, None, 0
        elif in_table and key == "a":
            self.group, self.tree, self.selected, self.cursor = not self.group, False, None, 0
        elif in_table and key in ("k", "DELETE") and rows:
            if IS_LINUX and not is_admin():
                self.message = "Ending processes needs root: start sysmon with sudo"
                return
            row = rows[min(self.cursor, len(rows) - 1)]
            label = f"{row.key} ({len(row.pids)} processes)" if self.group else f"{row.label} (PID {row.key})"
            processes = [p for p in (safe(psutil.Process, pid) for pid in row.pids) if p]
            if processes:
                self.confirm = (label, processes)
            else:
                self.message = f"{label} has already ended"
        elif in_graphs and key == "TAB":
            self.graph_page += 1
        elif in_graphs and key in ("+", "=", "-"):
            step = 1 if key in ("+", "=") else -1  # + shows more time; = is + without Shift
            self.window = min(max(self.window + step, 0), len(GRAPH_WINDOWS) - 1)

    def sync_selection(self, rows):
        """Keep the selection on the same process while the table re-sorts itself."""
        keys = [row.key for row in rows]
        if self.selected in keys:
            self.cursor = keys.index(self.selected)
        elif rows:
            self.cursor = min(self.cursor, len(rows) - 1)
            self.selected = rows[self.cursor].key


HELP = """\
sysmon keys (press any key to close this help)

Panes
  F1 or P         Show or hide the process table
  F2 or G         Show or hide the graphs
                  Both fit beside the system view when the window is 200+ columns wide.
Process table
  Up / Down       Select a process
  Left / Right    Sort by another column
  /               Filter by name (Enter keeps the filter, Esc clears it)
  T               Show the processes as a tree
  A               Group processes by program
  K or Delete     End the selected process (asks first; needs sudo on Linux)
Graphs
  Tab             Next page: overview, CPU cores, GPU, disks, network, temperatures
  + / -           Longer / shorter time span: 1, 5, 15 or 60 minutes
General
  H or ?          This help
  Ctrl+C          Quit

Settings file: {settings}"""


# --- The monitor -------------------------------------------------------------

class Monitor:
    """Collects everything once per update and draws it. Keeps the previous samples of the
    cumulative counters (CPU time, bytes read / sent, ...) to turn them into rates."""

    def __init__(self, interval, settings_path=None, remote=None):
        self.interval = interval
        self.settings_path = settings_path
        self.remote = remote  # a RemoteReport with --connect
        self.host = socket.gethostname()
        self.os_desc = os_description()
        self.cpu_name = cpu_model()
        self.physical_cores = psutil.cpu_count(logical=False) or "?"
        self.logical_cores = psutil.cpu_count() or "?"
        self._cache = {}    # see cached()
        self.snapshot = {}  # the latest data, for --json, --log and --connect
        self.history = {}   # graph page -> {name: [recent values, kind, top]}; kept while F2 is closed
        self.last_rows, self.process_columns = [], ["cpu", "memory", "io"]  # process table as drawn
        self.parents = {}   # pid -> parent pid, for the tree view
        self.vram_total = 0

        # The data sources this platform has; the others stay None.
        self.nvidia = NvidiaSmi(interval)
        self.pdh = self.lhm = self.drm = self.rapl = self.smart = self.battery_wear = self.traffic = None
        self.adapters = []
        if IS_WINDOWS:
            self.pdh = safe(Pdh, PDH_COUNTERS)
            self.adapters = safe(dxgi_adapters) or []
            self.lhm = LibreHardwareMonitor(interval)
            self.traffic = WindowsTcpTraffic()
            if safe(psutil.sensors_battery):
                self.battery_wear = Background(windows_battery_wear, 3600)
        elif IS_LINUX:
            self.drm = LinuxDrmGpus()
            self.rapl = LinuxRapl()
            self.traffic = LinuxPacketCounter()
            if is_admin() and shutil.which("smartctl"):
                disks = [name for name in disk_io() if is_physical_disk(name)]
                self.smart = Background(lambda: linux_smart(disks), 600)

        # Most counters are cumulative; keep the previous sample to turn them into rates.
        psutil.cpu_percent(percpu=True)
        self.prev_time = time.monotonic()
        self.prev_net = psutil.net_io_counters(pernic=True)
        self.prev_disk = disk_io()
        self.prev_procs, self.prev_gpu_ns = None, {}  # only sampled while the process table is open

    def record(self, page, name, value, kind="pct", top=0):
        """Remember a value for the graphs. kind: "pct", "temp", "rate" (scaled to the peak) or
        "net" (log scale up to `top`, the link speed in bytes/s; 0 if unknown)."""
        series = self.history.setdefault(page, {})
        if name not in series:
            # Enough for the longest graph window. ponytail: ~32 bytes per value, so at -i 0.1
            # an hour of ~60 series is ~70 MB; store at 1 s resolution if that ever matters.
            series[name] = [deque(maxlen=int(GRAPH_WINDOWS[-1] / self.interval) + 1), kind, top]
        series[name][0].append(value)
        series[name][2] = top  # links can renegotiate their speed

    def cached(self, key, max_age, fn):
        """Return fn()'s result, recomputing it at most every `max_age` seconds."""
        stamp, value = self._cache.get(key, (None, None))
        if stamp is None or time.monotonic() - stamp > max_age:
            stamp, value = time.monotonic(), fn()
            self._cache[key] = (stamp, value)
        return value

    def render(self, width, height, view):
        """The screen as lines: the system view, plus the panes open in `view`."""
        now = time.monotonic()
        dt = max(now - self.prev_time, 1e-3)
        self.prev_time = now
        counters = self.pdh.read() if self.pdh else {}
        # Split the width: the system view and each open pane get an equal share (the process
        # table at most 72 columns, the rest goes to the system view), 3 columns for each " │ ".
        panes = view.panes if width >= WIDE else view.panes[-1:]
        share = (width - 3 * len(panes)) // (len(panes) + 1)
        widths = [min(share, 72) if pane == "processes" else share for pane in panes]
        left_w = width - sum(widths) - 3 * len(panes)

        self.snapshot = {"time": time.strftime("%Y-%m-%dT%H:%M:%S")}
        lines = self._header()
        # Each section method returns its lines and stores its data in self.snapshot (for --json,
        # --log and --connect) and self.history (for the graphs). Every section is collected even
        # when hidden: graphs, logs and rates need its data.
        sections = {"cpu": self._cpu(left_w, counters, dt), "memory": self._memory(left_w),
                    "gpu": self._gpus(left_w, counters), "disks": self._disks(left_w, dt),
                    "network": self._network(left_w, dt), "battery": self._battery(left_w),
                    "sensors": self._sensors(left_w)}
        lines += [line for name, section in sections.items() if SHOW[name] for line in section]
        if self.remote:  # clipped like the terminal clips them
            self.remote.send(self.snapshot, [truncate(line, left_w) for line in lines])

        table = None
        if "processes" in panes and not view.help:
            table = self._processes_pane(widths[panes.index("processes")], height, dt, counters, view)
        else:
            self.prev_procs, self.prev_gpu_ns = None, {}  # stale once hidden: re-measure on reopen
            if self.traffic:
                self.traffic.stop()
        if view.help:
            return HELP.format(settings=self.settings_path or "none (built-in defaults)").splitlines()
        if not panes:
            return lines
        columns = [lines] + [table if pane == "processes" else self._graphs_pane(w, view)
                             for pane, w in zip(panes, widths)]
        return side_by_side(columns, [left_w] + widths, paint(" │ ", DIM))

    def _header(self):
        """Host, OS and architecture; then uptime, process count, time and the keys; then a blank line."""
        uptime = time.time() - psutil.boot_time()
        processes = len(psutil.pids())
        self.snapshot["system"] = {"host": self.host, "os": self.os_desc, "architecture": platform.machine(),
                                   "uptime_seconds": round(uptime), "processes": processes}
        info = (f"up {fmt_duration(uptime)}   {processes} processes   {time.strftime('%H:%M:%S')}"
                f"   refresh {self.interval:g}s   F1/P processes   F2/G graphs   H help   Ctrl+C quit")
        remote = ""
        if self.remote:
            remote = (paint(f"   sending to {self.remote.address}", DIM) if self.remote.error is None else
                      paint(f"   can't send to {self.remote.address}: {self.remote.error}", COLOR["high"]))
        return [f"{paint(self.host, BOLD)}  {self.os_desc}  {platform.machine()}{remote}", paint(info, DIM), ""]

    def _cpu(self, width, counters, dt):
        loads = psutil.cpu_percent(percpu=True)
        total = sum(loads) / len(loads)
        freq = safe(psutil.cpu_freq)
        current = freq.current if freq else None
        # psutil's Windows "max" is really the base clock, and its "current" never moves.
        limit_label = "base" if IS_WINDOWS else "max"
        limit = freq.max if freq and freq.max else None
        core_mhz = []
        if IS_WINDOWS:
            base, real_mhz, core_mhz = windows_cpu_clocks(counters)
            if real_mhz:
                current, limit = real_mhz, base
        else:
            per_core = safe(psutil.cpu_freq, percpu=True) or []
            if len(per_core) == len(loads):
                core_mhz = [f.current for f in per_core]
        power = self.rapl.read(dt) if self.rapl else self.lhm.cpu_power if self.lhm else None
        load_avg = list(os.getloadavg()) if hasattr(os, "getloadavg") else None

        self.record("Overview", "CPU", total)
        for i, load in enumerate(loads):
            self.record("CPU cores", f"Core {i}", load)
        self.snapshot["cpu"] = {"model": self.cpu_name, "cores": self.physical_cores, "threads": self.logical_cores,
                                "usage_percent": total, "per_core_percent": loads, "clock_mhz": current,
                                "per_core_mhz": core_mhz, "power_w": power, "load_average": load_avg}

        speed = fmt_mhz(current) if current else "n/a"
        if limit:
            speed += paint(f"  ({limit_label} {fmt_mhz(limit)})", DIM)
        if power:
            speed += f"     power {power:.0f} W"
        if load_avg:
            speed += "     load avg " + "  ".join(f"{x:.2f}" for x in load_avg)
        lines = [rule("CPU", width),
                 f"  {paint(self.cpu_name, BOLD)}  "
                 + paint(f"{self.physical_cores} cores / {self.logical_cores} threads", DIM),
                 f"  {'Usage':<{LABEL_W}} {bar(total, bar_width(width))} {total:5.1f}%",
                 f"  {'Speed':<{LABEL_W}} {speed}"]
        # One small cell per logical core, laid out in as many columns as fit.
        num_w = len(str(len(loads) - 1))
        cells = []
        for i, load in enumerate(loads):
            cell = f"{i:>{num_w}} {bar(load, 10)} {load:5.1f}%"
            if i < len(core_mhz):
                cell += f" {core_mhz[i] / 1000:4.2f} GHz"
            cells.append(cell)
        return lines + ["  " + row for row in grid(cells, width - 2)]

    def _memory(self, width):
        # On Windows swap_memory() needs the "Paging File" performance counter, which is
        # missing on some machines, so treat it as optional.
        ram, swap = psutil.virtual_memory(), safe(psutil.swap_memory)
        self.record("Overview", "Memory", ram.percent)
        self.snapshot["memory"] = {"total": ram.total, "used": ram.used, "available": ram.available,
                                   "percent": ram.percent}
        lines = [rule("Memory", width),
                 usage_line("RAM", ram.percent, ram.used, ram.total, width)
                 + paint(f"   {fmt_bytes(ram.available)} available", DIM)]
        if swap and swap.total:
            self.snapshot["memory"]["swap"] = {"total": swap.total, "used": swap.used, "percent": swap.percent}
            lines.append(usage_line("Pagefile" if IS_WINDOWS else "Swap",
                                    swap.percent, swap.used, swap.total, width))
        return lines

    def _gpus(self, width, counters):
        gpus = self.nvidia.read()
        if IS_WINDOWS:
            gpus += windows_gpus(self.adapters, counters, skip_nvidia=bool(gpus))
        elif self.drm:
            gpus += self.drm.read(skip_nvidia=bool(gpus))
        self.vram_total = sum(gpu.mem_total or 0 for gpu in gpus)
        self.snapshot["gpus"] = {gpu.name: {k: v for k, v in asdict(gpu).items() if k != "name"} for gpu in gpus}
        lines = [rule("GPU", width)]
        if not gpus:
            needs = ("Windows 10 1709+ GPU performance counters or nvidia-smi" if IS_WINDOWS
                     else "nvidia-smi, or the amdgpu / i915 kernel driver")
            return lines + [paint(f"  No GPU data (needs {needs})", DIM)]
        for gpu in gpus:
            lines.append(f"  {paint(gpu.name, BOLD)}")
            if gpu.util is not None:
                self.record("Overview", gpu.name, gpu.util)
                self.record("GPU", f"{gpu.name} load", gpu.util)
                lines.append(f"  {'Load':<{LABEL_W}} {bar(gpu.util, bar_width(width))} {gpu.util:5.1f}%")
            if gpu.mem_used is not None and gpu.mem_total:
                self.record("GPU", f"{gpu.name} VRAM", 100 * gpu.mem_used / gpu.mem_total)
                line = usage_line("VRAM", 100 * gpu.mem_used / gpu.mem_total,
                                  gpu.mem_used, gpu.mem_total, width)
                if gpu.shared_used:
                    line += paint(f"   + {fmt_bytes(gpu.shared_used)} shared", DIM)
                lines.append(line)
            details = []
            if gpu.clock:
                details.append(f"Clock {fmt_mhz(gpu.clock)}")
            if gpu.temp is not None:
                self.record("Temperatures", gpu.name, gpu.temp, "temp")
                details.append(f"Temp {fmt_temp(gpu.temp)}")
            if gpu.fan:
                details.append(f"Fan {gpu.fan}")
            if gpu.power is not None:
                details.append(f"Power {gpu.power:.0f} W")
            if details:
                lines.append("  " + " " * (LABEL_W + 1) + "    ".join(details))
        return lines

    def _disk_info(self, names, mounts):
        """Label, model, temperature, health and wear per physical disk; slow, so cached."""
        if IS_WINDOWS:
            return safe(windows_disk_info, names, mounts) or {}
        if IS_LINUX:
            return linux_disk_info(names, self.smart.value if self.smart else None)
        return {}

    def _disks(self, width, dt):
        lines = [rule("Disks", width)]
        mounts = list_mounts()
        volumes = {}
        label_w = min(max([len(m) for m in mounts] + [LABEL_W]), 20)
        for mount in mounts:
            usage = safe(psutil.disk_usage, mount)
            if usage:
                volumes[mount] = {"total": usage.total, "used": usage.used, "percent": usage.percent}
                lines.append(usage_line(mount, usage.percent, usage.used, usage.total, width, label_w))

        io = disk_io()
        names = [name for name in io if is_physical_disk(name)]
        info = self.cached("disk_info", 30, lambda: self._disk_info(names, mounts))
        drives, total = {}, 0.0
        for name in names:
            before = self.prev_disk.get(name)
            if not before:
                continue  # just plugged in: no rate until the next update
            read = max(0, io[name].read_bytes - before.read_bytes) / dt
            write = max(0, io[name].write_bytes - before.write_bytes) / dt
            total += read + write
            drive = drives[name] = dict(info.get(name, {}), read_bps=read, write_bps=write)
            drive["label"] = drive.get("label") or name
            self.record("Disks", f"{drive['label']} read", read, "rate")
            self.record("Disks", f"{drive['label']} write", write, "rate")
            if drive.get("temperature") is not None:
                self.record("Temperatures", f"Disk {drive['label']}", drive["temperature"], "temp")
        self.prev_disk = io
        self.record("Overview", "Disk read + write", total, "rate")
        self.snapshot["disks"] = {"volumes": volumes, "drives": drives}

        name_w = min(max((len(d["label"]) for d in drives.values()), default=0), 18)
        model_w = min(max((len(d.get("model", "")) for d in drives.values()), default=0), 26)
        for drive in drives.values():
            extras = []
            if drive.get("temperature") is not None:
                extras.append(fmt_temp(drive["temperature"]))
            if drive.get("health"):
                extras.append(paint(drive["health"], COLOR["ok"] if drive["health"] == "healthy" else COLOR["high"]))
            if drive.get("wear_percent") is not None:
                extras.append(f"wear {drive['wear_percent']:.0f}%")
            lines.append(f"  {drive['label'][:name_w]:<{name_w}}  {drive.get('model', '')[:model_w]:<{model_w}}"
                         f"  read {fmt_rate(drive['read_bps']):>11}  write {fmt_rate(drive['write_bps']):>11}  "
                         + "  ".join(extras))
        return lines

    def _network(self, width, dt):
        io = psutil.net_io_counters(pernic=True)
        stats = self.cached("nic_stats", 5, lambda: safe(psutil.net_if_stats) or {})
        ips = self.cached("nic_ips", 10, ipv4_addresses)
        rows = []
        for nic, now in io.items():
            before, stat, ip = self.prev_net.get(nic), stats.get(nic), ips.get(nic, "")
            if (not before or (stat and not stat.isup) or ip.startswith("127.")
                    or now.bytes_recv + now.bytes_sent == 0):
                continue  # skip loopback and adapters that are down or have never been used
            rows.append((nic, ip, max(0, now.bytes_recv - before.bytes_recv) / dt,
                         max(0, now.bytes_sent - before.bytes_sent) / dt, now))
        self.prev_net = io
        speeds = {nic: link_speed(stats.get(nic)) for nic, *_ in rows}
        fastest = max(speeds.values(), default=0)  # the totals' scale: usually the real uplink
        self.record("Overview", "Network download", sum(r[2] for r in rows), "net", fastest)
        self.record("Overview", "Network upload", sum(r[3] for r in rows), "net", fastest)
        for nic, _, down, up, _ in rows:
            self.record("Network", f"{nic} download", down, "net", speeds[nic])
            self.record("Network", f"{nic} upload", up, "net", speeds[nic])
        self.snapshot["network"] = {nic: {"ipv4": ip, "download_bps": down, "upload_bps": up,
                                          "received_total": totals.bytes_recv, "sent_total": totals.bytes_sent,
                                          "link_speed_bps": speeds[nic] or None}
                                    for nic, ip, down, up, totals in rows}

        lines = [rule("Network", width)]
        if not rows:
            return lines + [paint("  No active network interfaces", DIM)]
        name_w = min(max(len(r[0]) for r in rows), 24)
        for nic, ip, down, up, totals in rows:
            lines.append(
                f"  {nic[:name_w]:<{name_w}}  {ip:<15}  ↓ {fmt_rate(down):>11}  ↑ {fmt_rate(up):>11}   "
                + paint(f"since boot ↓ {fmt_bytes(totals.bytes_recv)}  ↑ {fmt_bytes(totals.bytes_sent)}", DIM))
        return lines

    def _battery(self, width):
        battery = safe(psutil.sensors_battery)
        if battery is None:
            return []
        wear = linux_battery_wear() if IS_LINUX else self.battery_wear.value if self.battery_wear else None
        self.snapshot["battery"] = {"percent": battery.percent, "plugged_in": battery.power_plugged,
                                    "seconds_left": battery.secsleft if battery.secsleft > 0 else None,
                                    "wear_percent": wear}
        if battery.power_plugged:
            state = "plugged in" + (", charging" if battery.percent < 100 else "")
        else:
            state = "on battery"
            if battery.secsleft > 0:  # negative values mean unknown / unlimited
                state += f", {fmt_duration(battery.secsleft)} left"
        if wear is not None:
            state += f", wear {wear:.0f}%"
        code = (COLOR["high"] if battery.percent < LIMITS["battery_low"] else
                COLOR["warn"] if battery.percent < LIMITS["battery_warn"] else COLOR["ok"])
        return [rule("Battery", width),
                f"  {'Charge':<{LABEL_W}} {bar(battery.percent, bar_width(width), code)} "
                f"{battery.percent:5.1f}%  {state}"]

    def _sensors(self, width):
        if IS_WINDOWS:
            readings = self.lhm.readings
        else:
            readings = linux_sensors() if IS_LINUX else []
        temperatures, fans = {}, {}
        for hardware, kind, label, value in readings or []:
            (temperatures if kind == "temp" else fans).setdefault(hardware, {})[label] = value
            if kind == "temp":
                self.record("Temperatures", f"{hardware} {label}", value, "temp")
        self.snapshot["sensors"] = {"temperatures": temperatures, "fans": fans}

        lines = [rule("Temperatures & fans", width)]
        if IS_WINDOWS and readings is None:
            return lines + [paint(line, DIM) for line in (
                "  Windows has no standard API for these. Run LibreHardwareMonitor (as administrator)",
                "  and enable Options -> Remote Web Server -> Run; it is picked up automatically.")]
        if not readings:
            hint = " (install lm-sensors and run sensors-detect)" if IS_LINUX else ""
            return lines + [paint(f"  No sensors found{hint}", DIM)]
        groups = {}  # one block per chip, its sensors in a grid
        for hardware, kind, label, value in readings:
            reading = fmt_temp(value) if kind == "temp" else f"{value:4.0f} RPM"
            groups.setdefault(hardware, []).append(f"{label[:18]:<18} {pad(reading, 8)}")
        for hardware, cells in groups.items():
            lines.append(f"  {paint(hardware, BOLD)}")
            lines += ["    " + row for row in grid(cells, width - 4)]
        return lines

    def _process_values(self, dt, counters):
        """({pid: (name, {column: value})}, {column: total}) for the process table."""
        snapshot = process_snapshot()
        before, self.prev_procs = self.prev_procs, snapshot
        self.parents = {pid: p[4] for pid, p in snapshot.items()}  # for the tree view
        if IS_WINDOWS:
            gpu = windows_by_pid(counters, "gpu_engine", max)
            vram = windows_by_pid(counters, "gpu_process_vram", lambda a, b: a + b)
            has_gpu = "gpu_engine" in counters
        else:
            busy, vram = linux_drm_fdinfo() if IS_LINUX else ({}, {})
            gpu = linux_gpu_by_pid(busy, self.prev_gpu_ns, dt)
            self.prev_gpu_ns, has_gpu = busy, bool(busy)
        has_net = bool(self.traffic and self.traffic.available)
        net = self.traffic.bytes_by_pid() if has_net else {}
        self.process_columns = (["cpu", "memory"] + (["gpu", "vram"] if has_gpu else [])
                                + ["io"] + (["net"] if has_net else []))

        cores = psutil.cpu_count() or 1
        procs = {}
        for pid, (name, cpu_seconds, memory, io_bytes, _) in snapshot.items():
            values = {"memory": memory}
            if before and before.get(pid, ("",))[0] == name:  # same pid and program as last time
                values["cpu"] = max(0.0, cpu_seconds - before[pid][1]) / dt / cores * 100  # % of the whole CPU
                values["io"] = max(0, io_bytes - before[pid][3]) / dt
                if has_net:
                    values["net"] = net.get(pid, 0) / dt
            if has_gpu:
                values["gpu"], values["vram"] = gpu.get(pid, 0.0), vram.get(pid, 0)
            procs[pid] = (name, values)
        totals = {"cpu": 100.0, "gpu": 100.0, "memory": psutil.virtual_memory().total,
                  "vram": self.vram_total or sum(vram.values())}
        for column in ("io", "net"):  # rates have no fixed maximum: compare to everyone's total
            totals[column] = sum(values.get(column, 0) for _, values in procs.values())
        return procs, totals, before is not None

    def _processes_pane(self, width, height, dt, counters, view):
        """The process table (F1 / P) as lines: sorted, filtered, grouped or as a tree as `view` says."""
        procs, totals, measured = self._process_values(dt, counters)
        columns = self.process_columns
        if view.sort not in columns:
            view.sort = "cpu"
        if view.filter:
            procs = {pid: p for pid, p in procs.items() if view.filter in p[0].lower()}
        # A filter or the tree lists idle processes too; otherwise only the busy ones show.
        rows = top_rows(process_rows(procs, view.group), view.sort, totals, keep_idle=bool(view.filter or view.tree))
        if view.tree:
            rows = tree_rows(rows, self.parents, view.sort)
        self.last_rows = rows
        view.sync_selection(rows)
        fits = max(5, height - 10)
        start = max(0, view.cursor - fits + 1)  # scrolled just enough to keep the selection on screen

        # The sort column always shows; the others as the width allows, in their usual order.
        name_w = 14
        room = width - 10 - name_w - PROCESS_COLUMNS[view.sort][1] - 1  # 10: indent, PID and gaps
        shown = {view.sort}
        for column in columns:
            if column not in shown and PROCESS_COLUMNS[column][1] + 1 <= room:
                shown.add(column)
                room -= PROCESS_COLUMNS[column][1] + 1
        shown = [column for column in columns if column in shown]
        name_w = max(4, name_w + room)  # a very narrow window leaves no room to spare

        title = "Programs" if view.group else "Process tree" if view.tree else "Processes"
        title += f" by {PROCESS_COLUMNS[view.sort][0]}"
        if view.filter and not view.typing:
            title += f", name contains '{view.filter}'"
        hint = (f"Filter: {view.filter}█  Enter keep  Esc clear" if view.typing else
                "↑↓ select  ←→ sort  / filter  T tree  A group  K end  P hide")
        lines = [paint(title, BOLD), paint(hint, DIM), ""]
        header = f"  {'PID':>7} {'Name':<{name_w}}" + "".join(
            f" {('▼' if c == view.sort else '') + PROCESS_COLUMNS[c][0]:>{PROCESS_COLUMNS[c][1]}}" for c in shown)
        lines.append(paint(header, BOLD))
        for i, row in enumerate(rows[start:start + fits], start):
            pid = str(row.key) if not view.group else ""
            text = f"  {pid:>7} {(row.prefix + row.label)[:name_w]:<{name_w}}" + "".join(
                f" {PROCESS_COLUMNS[c][2](row.values[c]) if c in row.values else '-':>{PROCESS_COLUMNS[c][1]}}"
                for c in shown)
            lines.append(paint(text, REVERSE) if i == view.cursor else text)
        if not rows:
            waiting = view.sort in RATE_COLUMNS and not measured
            lines.append(paint(f"  no process name contains '{view.filter}'" if view.filter else
                               "  measuring..." if waiting else "  nothing above 0.1%", DIM))
        elif len(rows) > fits:
            lines.append(paint(f"  {start + 1}-{min(start + fits, len(rows))} of {len(rows)}", DIM))
        lines.append("")
        if view.confirm:
            lines.append(paint(f"End {view.confirm[0]}? Y ends it, any other key cancels", COLOR["high"]))
        elif view.message:
            lines.append(paint(view.message, COLOR["warn"]))
        if self.traffic and not self.traffic.available:
            lines.append(paint("Run as administrator to see network use (TCP)" if IS_WINDOWS else
                               "Run with sudo to see network use and other users' I/O and GPU use", DIM))
        return lines

    def _graphs_pane(self, width, view):
        """The graphs (F2 / G) of the page and time span chosen in `view`, as lines."""
        pages = [page for page in GRAPH_PAGES if page in self.history]  # pages with data on this machine
        page = pages[view.graph_page % len(pages)]
        window = GRAPH_WINDOWS[view.window]
        count = max(1, round(window / self.interval))
        series = list(self.history[page].items())
        columns = 1 if len(series) <= 6 else 2  # many series (cores, sensors): two small charts per row
        height = GRAPH_ROWS if columns == 1 else 2
        chart_w = max(1, (width - 3 * (columns - 1)) // columns - 2)  # at least 1, even in a tiny window
        lines = [paint(f"Graphs: {page}  ({pages.index(page) + 1}/{len(pages)})", BOLD),
                 paint(f"last {window // 60} min   Tab next page   +/- time span   G hide", DIM), ""]
        blocks = []
        for name, (values, kind, link) in series:
            shown, now = resample(values, count, chart_w), values[-1]
            if kind == "net":  # log scale from 1 KiB/s to the link speed, or the peak if it's unknown
                top = link or max(max(shown), 2**20)
                scale = f"{fmt_bits(link)} link" if link else f"top {fmt_rate(top)}"
                shown = [100 * log_position(value, 1024, top) for value in shown]
                top, color = 100.0, lambda value: COLOR["accent"]
                title = f"{name} {fmt_rate(now)}  (log, {scale})"
            elif kind == "rate":  # scaled to the busiest moment on screen
                top, color = max(max(shown), 1024.0), lambda value: COLOR["accent"]
                title = f"{name} {fmt_rate(now)}  peak {fmt_rate(max(shown))}"
            elif kind == "temp":
                top, color, title = max(100.0, max(shown)), temp_color, f"{name} {now:.0f}°C"
            else:
                top, color, title = 100.0, level_color, f"{name} {now:.1f}%"
            blocks.append([rule(title, chart_w + 2)] + ["  " + row for row in chart(shown, chart_w, height, top, color)])
        for i in range(0, len(blocks), columns):
            lines += side_by_side(blocks[i:i + columns], [chart_w + 2] * columns, "   ")
        return lines

    def close(self):
        self.nvidia.close()
        if self.traffic:
            self.traffic.stop()
        if self.remote:
            self.remote.close()


# --- Keyboard ----------------------------------------------------------------

# What terminals send for the keys we use. Special keys arrive as escape sequences, which
# differ between terminals: F1 is "\x1bOP" in most, "\x1b[11~" in rxvt / PuTTY, "\x1b[[A" in the Linux console.
KEY_NAMES = {"\x1bOP": "F1", "\x1b[11~": "F1", "\x1b[[A": "F1",
             "\x1bOQ": "F2", "\x1b[12~": "F2", "\x1b[[B": "F2",
             "\x1b[A": "UP", "\x1bOA": "UP", "\x1b[B": "DOWN", "\x1bOB": "DOWN",
             "\x1b[C": "RIGHT", "\x1bOC": "RIGHT", "\x1b[D": "LEFT", "\x1bOD": "LEFT",
             "\x1b[3~": "DELETE", "\x1b": "ESC", "\t": "TAB", "\r": "ENTER", "\n": "ENTER",
             "\x7f": "BACKSPACE", "\x08": "BACKSPACE"}  # terminals send \x7f, the Windows console \x08
# Splits input into whole escape sequences and single characters.
KEY_TOKEN_RE = re.compile(r"\x1b\[\[[A-E]|\x1b\[[0-9;]*[~A-Za-z]|\x1bO.|\x1b|.", re.S)
# The Windows console (msvcrt) sends special keys as "\x00" or "\xe0" followed by one of these.
WINDOWS_KEYS = {";": "F1", "<": "F2", "H": "UP", "P": "DOWN", "K": "LEFT", "M": "RIGHT", "S": "DELETE"}


def parse_keys(text):
    """Terminal input as key names: "F1", "UP", "TAB", ... or the character in lowercase."""
    keys = []
    for token in KEY_TOKEN_RE.findall(text):
        if token in KEY_NAMES:
            keys.append(KEY_NAMES[token])
        elif not token.startswith("\x1b"):  # other escape sequences (F5, Ctrl+arrows, ...) are ignored
            keys.append(token.lower())
    return keys


class Keyboard:
    """Non-blocking key reading while the monitor runs."""

    def __init__(self):
        self.enabled = sys.stdin.isatty()
        if self.enabled and not IS_WINDOWS:
            self.fd = sys.stdin.fileno()
            self.saved = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)  # deliver keys at once and without echo; Ctrl+C still works

    def pressed(self):
        """The keys pressed since the last call, e.g. ["F1", "DOWN", "k"]."""
        if not self.enabled:
            return []
        if IS_WINDOWS:
            keys = []
            while msvcrt.kbhit():
                char = msvcrt.getwch()
                # Function and arrow keys arrive as two characters: "\x00" or "\xe0", then a code.
                key = (WINDOWS_KEYS.get(msvcrt.getwch()) if char in ("\x00", "\xe0")
                       else KEY_NAMES.get(char, char.lower()))
                if key:
                    keys.append(key)
            return keys
        data = b""
        while select.select([self.fd], [], [], 0)[0]:
            chunk = os.read(self.fd, 1024)
            if not chunk:
                break  # stdin was closed
            data += chunk
        return parse_keys(data.decode(errors="ignore"))

    def close(self):
        if self.enabled and not IS_WINDOWS:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)


# --- Logging -----------------------------------------------------------------

def flatten(data, prefix=""):
    """The numbers in a nested snapshot as CSV columns: {"cpu.usage_percent": 12.5, ...}."""
    flat = {}
    for key, value in (data.items() if isinstance(data, dict) else enumerate(data)):
        name = f"{prefix}{key}"
        if isinstance(value, (dict, list)):
            flat.update(flatten(value, name + "."))
        elif isinstance(value, bool):
            flat[name] = int(value)
        elif isinstance(value, (int, float)):
            flat[name] = round(value, 3)
    return flat


class CsvLog:
    """Appends one row per update. The columns are fixed by the file's first row, so values
    that appear later (a USB disk plugged in) are left out; existing files are appended to."""

    def __init__(self, path):
        self.path = path
        self.fields = None
        if os.path.exists(path) and os.path.getsize(path):
            with open(path, newline="", encoding="utf-8") as f:
                self.fields = next(csv.reader(f), None)
        open(path, "a").close()  # fail now, with a clear message, if the file can't be written

    def write(self, snapshot):
        row = {"time": snapshot["time"], **flatten(snapshot)}
        new = self.fields is None
        if new:
            self.fields = list(row)
        with open(self.path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, self.fields, restval="", extrasaction="ignore")
            if new:
                writer.writeheader()
            writer.writerow(row)


# --- Pictures and reports ----------------------------------------------------

# What sysmon's color codes look like, as sysmon_server.py's page shows them (VS Code's terminal colors).
TERMINAL_COLORS = {30: "#000000", 31: "#cd3131", 32: "#0dbc79", 33: "#e5e510", 34: "#2472c8", 35: "#bc3fbc",
                   36: "#11a8cd", 37: "#e5e5e5", 90: "#767676", 91: "#f14c4c", 92: "#23d18b", 93: "#f5f543",
                   94: "#3b8eea", 95: "#d670d6", 96: "#29b8db", 97: "#ffffff"}


def svg_screenshot(lines):
    """The screen as an SVG picture of a terminal (--svg). Bars and rules are drawn as shapes, not
    characters, so they line up in whatever font the viewer has."""
    cw, lh, pad, fg = 8.4, 18, 16, "#cccccc"  # cell width, line height, margin, default text color
    screen = []
    for line in lines:
        cells, color, bold, dim = [], fg, False, False
        for part in re.split(r"(\x1b\[[\d;]*m)", line):
            codes = re.fullmatch(r"\x1b\[([\d;]*)m", part)
            if not codes:
                cells += [(char, color, bold, dim) for char in part]
                continue
            for code in (int(c) for c in codes.group(1).split(";") if c):
                if code == 0:
                    color, bold, dim = fg, False, False
                bold, dim = bold or code == 1, dim or code == 2
                color = TERMINAL_COLORS.get(code, color)  # 256-color codes keep the previous color
        screen.append(cells)
    w, h = round(max((len(cells) for cells in screen), default=0) * cw + 2 * pad), len(screen) * lh + 2 * pad
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
           "<style>text{font:14px 'Cascadia Mono',Consolas,'DejaVu Sans Mono',Menlo,monospace;white-space:pre}</style>",
           f'<rect width="{w}" height="{h}" rx="8" fill="#0c0c0c"/>']
    for row, cells in enumerate(screen):
        top, col = pad + row * lh, 0
        # Runs of one kind of character in one style: bars, half blocks, rule lines, spaces or text.
        for (kind, color, bold, dim), run in itertools.groupby(cells, lambda c: (c[0] if c[0] in "█▄─ " else "t",) + c[1:]):
            chars = "".join(c[0] for c in run)
            x, width, col = pad + col * cw, len(chars) * cw, col + len(chars)
            style = f' fill="{color}"' + (' opacity=".6"' if dim else "") + (' font-weight="bold"' if bold and kind == "t" else "")
            if kind == "█":
                out.append(f'<rect x="{x:.1f}" y="{top + 2}" width="{width:.1f}" height="{lh - 4}"{style}/>')
            elif kind == "▄":
                out.append(f'<rect x="{x:.1f}" y="{top + lh / 2}" width="{width:.1f}" height="{lh / 2}"{style}/>')
            elif kind == "─":
                out.append(f'<rect x="{x:.1f}" y="{top + lh / 2 - 0.6}" width="{width:.1f}" height="1.2"{style}/>')
            elif kind == "t":  # textLength keeps every run on its columns
                out.append(f'<text x="{x:.1f}" y="{top + lh - 5}" textLength="{width:.1f}"{style}>{html.escape(chars)}</text>')
    return "\n".join(out + ["</svg>"]) + "\n"


# The report's graphs: (title, unit, top of the scale or None for the highest value, [(CSV column, label)]).
# In a column, * stands for a name (a GPU, disk, network adapter or sensor); {} in the label shows it.
REPORT_CHARTS = [
    ("CPU", "%", 100, [("cpu.usage_percent", "all cores")]),
    ("Memory", "%", 100, [("memory.percent", "RAM"), ("memory.swap.percent", "swap / page file")]),
    ("GPU load", "%", 100, [("gpus.*.util", "{}")]),
    ("Disk speed", "B/s", None, [("disks.drives.*.read_bps", "{} read"), ("disks.drives.*.write_bps", "{} write")]),
    ("Network", "B/s", None, [("network.*.download_bps", "{} download"), ("network.*.upload_bps", "{} upload")]),
    ("Temperatures", "°C", None, [("sensors.temperatures.*", "{}"), ("gpus.*.temp", "{}"),
                                  ("disks.drives.*.temperature", "{}")]),
    ("Disk space used", "%", 100, [("disks.volumes.*.percent", "{}")]),
    ("Battery", "%", 100, [("battery.percent", "charge")]),
]
REPORT_COLORS = ("#29b8db", "#23d18b", "#f5f543", "#d670d6", "#f14c4c", "#3b8eea", "#e5e5e5", "#e5e510")


def _report_chart(title, unit, top, series, times):
    """One graph of the report: an SVG with a line per series, and a table of min / average / max."""
    fmt = fmt_rate if unit == "B/s" else lambda v: f"{v:.0f} {unit}"
    top = top or max(v for _, values in series for v in values if v is not None) * 1.1 or 1
    w, h, left, right, above, below = 960, 220, 84, 12, 10, 26
    t0, span = times[0], max(times[-1] - times[0], 1)
    buckets = min(len(times), 600)  # each point averages the updates in its slice of the time span
    slot = [min(buckets - 1, int((t - t0) / span * buckets)) for t in times]
    # Lines break where sysmon wasn't running: 5 times the usual interval without an update.
    steps = sorted(b - a for a, b in zip(times, times[1:]) if b > a)
    gap = 5 * (steps[len(steps) // 2] if steps else 1)
    run = list(itertools.accumulate([0] + [int(b - a > gap) for a, b in zip(times, times[1:])]))
    svg = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{html.escape(title)}">']
    for frac in (0, 0.5, 1):
        y = above + (1 - frac) * (h - above - below)
        svg.append(f'<line x1="{left}" x2="{w - right}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                   f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{html.escape(fmt(top * frac))}</text>')
    for frac, anchor in ((0, "start"), (1, "end")):
        stamp = time.strftime("%Y-%m-%d %H:%M" if span >= 3600 else "%H:%M:%S", time.localtime(t0 + frac * span))
        svg.append(f'<text x="{left + frac * (w - left - right):.1f}" y="{h - 6}" text-anchor="{anchor}">{stamp}</text>')
    rows = []
    for k, (label, values) in enumerate(series):
        color, sums, counts = REPORT_COLORS[k % len(REPORT_COLORS)], {}, {}
        for key, v in zip(zip(run, slot), values):  # key: (stretch of logging, slice of time)
            if v is not None:
                sums[key] = sums.get(key, 0.0) + v
                counts[key] = counts.get(key, 0) + 1
        lines = {}
        for r, s in sorted(sums):
            x = left + (s + 0.5) / buckets * (w - left - right)
            y = above + (1 - min(sums[r, s] / counts[r, s] / top, 1)) * (h - above - below)
            lines.setdefault(r, []).append(f"{x:.1f},{y:.1f}")
        for points in lines.values():  # one line per stretch; a lone update shows as a dot
            svg.append(f'<polyline points="{" ".join(points if len(points) > 1 else points * 2)}" stroke="{color}"/>')
        known = [v for v in values if v is not None]
        rows.append(f'<tr><td><span style="background:{color}"></span>{html.escape(label)}</td>'
                    + "".join(f"<td>{html.escape(fmt(v))}</td>" for v in
                              (min(known), sum(known) / len(known), max(known), known[-1])) + "</tr>")
    return (f"<section><h2>{html.escape(title)}</h2>{''.join(svg)}</svg><table><tr><th></th><th>min</th>"
            f"<th>average</th><th>max</th><th>last</th></tr>{''.join(rows)}</table></section>")


def write_report(csv_path):
    """Turn a --log CSV file into a self-contained HTML page with graphs (--report). Returns the
    page's path: the CSV's, ending in .html instead."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        records = list(csv.DictReader(f))
    times, columns = [], {}
    for record in records:
        try:
            times.append(time.mktime(time.strptime(record.get("time") or "", "%Y-%m-%dT%H:%M:%S")))
        except ValueError:
            continue  # not a row sysmon wrote
        for column, value in record.items():
            if column not in (None, "time"):
                columns.setdefault(column, []).append(to_float(value))
    if not times:
        raise ValueError("no updates in it (is it a sysmon --log file?)")
    sections = []
    for title, unit, top, patterns in REPORT_CHARTS:
        series = []
        for pattern, label in patterns:
            match = re.compile(re.escape(pattern).replace(r"\*", "(.+)"))
            for column, values in columns.items():
                found = match.fullmatch(column)
                if found and any(v is not None for v in values):
                    series.append((label.format(*found.groups()), values))
        if series:
            sections.append(_report_chart(title, unit, top, series, times))
    name, first, last = os.path.basename(csv_path), time.localtime(times[0]), time.localtime(times[-1])
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>sysmon report: {html.escape(name)}</title>
<style>
  body {{ margin: 0 auto; max-width: 1000px; padding: 24px 16px; background: #0c0c0c; color: #cccccc;
         font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }}
  h1 {{ margin: 0 0 4px; font-size: 22px; }} h2 {{ margin: 0 0 8px; font-size: 16px; }}
  .muted {{ color: #8a8a8a; margin: 0 0 20px; }}
  section {{ background: #161616; border: 1px solid #2c2c2c; border-radius: 6px; padding: 14px 16px; margin-bottom: 16px; }}
  svg {{ width: 100%; height: auto; display: block; }}
  svg text {{ fill: #8a8a8a; font-size: 12px; }} .grid {{ stroke: #2c2c2c; }}
  polyline {{ fill: none; stroke-width: 1.6; stroke-linejoin: round; stroke-linecap: round; }}
  table {{ border-collapse: collapse; margin-top: 8px; font-variant-numeric: tabular-nums; }}
  th, td {{ padding: 2px 14px 2px 0; text-align: right; }} th:first-child, td:first-child {{ text-align: left; }}
  th {{ color: #8a8a8a; font-weight: 400; }}
  td span {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 8px; }}
</style></head><body>
<h1>sysmon report</h1>
<p class="muted">{html.escape(name)}: {len(times)} updates from {time.strftime("%Y-%m-%d %H:%M:%S", first)}
to {time.strftime("%Y-%m-%d %H:%M:%S", last)}</p>
{"".join(sections)}
</body></html>
"""
    path = os.path.splitext(csv_path)[0] + ".html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    return path


# --- Remote monitoring -------------------------------------------------------

class RemoteReport:
    """Sends every update to a sysmon_server.py (--connect) from a background thread, so a
    slow or unreachable server never holds up the screen. When sending falls behind, the
    updates in between are skipped: only the newest is worth sending."""

    def __init__(self, address, interval, password=None, server_cert=None):
        self.address = address
        self.url = f"{'https' if server_cert else 'http'}://{address}/report"
        self.headers = {"Content-Type": "application/json"}
        if password:  # HTTP Basic auth; the server ignores the user name
            self.headers["Authorization"] = "Basic " + base64.b64encode(f"sysmon:{password}".encode()).decode()
        self.session = uuid.uuid4().hex  # tells this run apart from others on the same machine
        self.interval = interval
        self.error = None  # why the last report failed; None once one gets through
        self.pending = None  # the newest report, waiting to be sent
        self.ended = False
        self.wake = threading.Event()  # set when there's a new report to send
        self.lock = threading.Lock()   # held while sending, so close() waits for it
        handlers = [urllib.request.ProxyHandler({})]  # never via a proxy
        if server_cert:  # HTTPS that trusts only this certificate: the server's own
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=server_cert)))
        self.opener = urllib.request.build_opener(*handlers)
        threading.Thread(target=self._send_loop, daemon=True).start()

    def send(self, snapshot, lines):
        """Queue this update for the background thread; it replaces one not sent yet."""
        self.pending = {"session": self.session, "interval": self.interval, "snapshot": snapshot, "lines": lines}
        self.wake.set()

    def _send_loop(self):
        while True:
            self.wake.wait()
            self.wake.clear()
            with self.lock:
                if self.ended:
                    return
                try:
                    self._post(self.pending, timeout=5)
                    self.error = None
                except Exception as error:  # whatever went wrong, try again with the next update
                    reason = getattr(error, "reason", error)  # urllib wraps the socket error
                    if getattr(error, "code", None) == 401:
                        self.error = "wrong or missing password (--password)"
                    elif isinstance(reason, ssl.SSLCertVerificationError):  # not the --server-cert server
                        self.error = f"certificate not trusted: {reason.verify_message} (--server-cert)"
                    elif isinstance(reason, ssl.SSLError):  # e.g. WRONG_VERSION_NUMBER: a plain HTTP server
                        self.error = f"HTTPS failed ({reason.reason}): was the server started with --cert?"
                    elif (isinstance(reason, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError))
                          and self.url.startswith("http:")):  # how an HTTPS server drops plain HTTP varies
                        self.error = "the server hung up: if it uses HTTPS, add --server-cert"
                    else:
                        self.error = getattr(reason, "strerror", None) or str(reason)

    def _post(self, report, timeout):
        request = urllib.request.Request(self.url, json.dumps(report).encode(), self.headers)
        self.opener.open(request, timeout=timeout).close()

    def close(self):
        """Tell the server this session has ended, so it drops it instead of reporting it lost."""
        with self.lock:  # waits for a report being sent: it mustn't arrive after the goodbye
            self.ended = True
            if self.error is None:
                safe(self._post, {"session": self.session, "ended": True}, timeout=2)


def server_address(value):
    """argparse type for --connect: IP:PORT (or NAME:PORT, or [IPv6]:PORT)."""
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"expected IP:PORT, e.g. 192.168.1.10:8765, not '{value}'")
    return value


# --- Main loop ---------------------------------------------------------------

def run_live(monitor, interval, log):
    """The full-screen view: redraw every `interval` seconds and react to keys until Ctrl+C."""
    out = sys.stdout
    # Alternate screen + hidden cursor, so the terminal's scrollback is left untouched.
    out.write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2JCollecting data...")
    out.flush()
    keyboard = Keyboard()
    view = View()
    try:
        next_draw = time.monotonic() + interval
        while True:
            keys = keyboard.pressed()
            wide = shutil.get_terminal_size().columns - 1 >= WIDE
            for key in keys:
                view.handle(key, monitor.last_rows, monitor.process_columns, wide)
            now = time.monotonic()
            if keys:
                next_draw = now  # redraw right away
            if now < next_draw:
                time.sleep(min(0.05, next_draw - now))  # short naps keep the keys responsive
                continue
            next_draw += interval
            if next_draw < now:
                next_draw = now + interval  # fell behind (e.g. system was asleep); don't catch up

            cols, rows = shutil.get_terminal_size()
            width = cols - 1  # never write into the last column; it makes some terminals wrap
            lines = monitor.render(width, rows, view)
            if log:
                log.write(monitor.snapshot)
            if len(lines) > rows:
                lines = lines[: rows - 1] + [paint("  ... enlarge the terminal to see more", DIM)]
            # Redraw in place (cursor home, clear leftovers) instead of clearing: no flicker.
            out.write("\x1b[H" + "\x1b[K\n".join(truncate(line, width) for line in lines) + "\x1b[K\x1b[J")
            out.flush()
    finally:
        keyboard.close()
        out.write("\x1b[0m\x1b[?25h\x1b[?1049l")  # reset colors, show the cursor, back to the normal screen
        out.flush()


def run_headless(monitor, interval, log):
    """--connect or --log without a terminal (e.g. started as a service): nothing is drawn,
    only sent and / or logged."""
    while True:
        time.sleep(interval)
        monitor.render(100, 50, View())  # no terminal to fit: 100 columns for the web page
        if log:
            log.write(monitor.snapshot)


def parse_args():
    parser = argparse.ArgumentParser(description="Live system monitor for Windows and Linux terminals.")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="seconds between updates (default: 1)")
    parser.add_argument("--once", action="store_true", help="print a single snapshot and exit")
    parser.add_argument("--json", action="store_true", help="print a single snapshot as JSON and exit")
    parser.add_argument("--svg", metavar="FILE", help="save a single snapshot of the screen as an SVG picture and exit")
    parser.add_argument("--log", metavar="FILE", help="append every update to this CSV file")
    parser.add_argument("--report", metavar="CSV",
                        help="turn a --log CSV file into an HTML page with graphs (saved next to it as .html) and exit")
    parser.add_argument("--config", metavar="FILE",
                        help="settings file (default: sysmon.ini next to this script, if it exists)")
    parser.add_argument("--connect", metavar="IP:PORT", type=server_address,
                        help="also send every update to the sysmon_server.py at this address")
    parser.add_argument("--password", default=os.environ.get("SYSMON_PASSWORD"),
                        help="the server's password, if it has one (default: the SYSMON_PASSWORD "
                             "environment variable, if set)")
    parser.add_argument("--server-cert", metavar="FILE",
                        help="send over HTTPS, trusting only this certificate: a copy of the one "
                             "sysmon_server.py was started with (--cert)")
    parser.add_argument("--version", action="version", version=f"sysmon {__version__}")
    args = parser.parse_args()
    if args.interval < 0.1:
        parser.error("interval must be at least 0.1 seconds")
    if args.connect and (args.once or args.json or args.svg):
        parser.error("--connect sends live updates, so it can't be used with --once, --json or --svg")
    if args.server_cert and not args.connect:
        parser.error("--server-cert goes with --connect")
    return args


def main():
    global USE_COLOR
    args = parse_args()
    if args.report:  # only reads the CSV file: nothing to measure
        try:
            print(f"Report saved as {write_report(args.report)}")
        except (OSError, ValueError, csv.Error) as error:
            sys.exit(f"Can't make a report from {args.report}: {error}")
        return
    # --config, else sysmon.ini next to this script if there is one, else the built-in defaults.
    settings = args.config or (SETTINGS_FILE if os.path.exists(SETTINGS_FILE) else None)
    try:
        apply_settings(load_settings(settings))
    except (OSError, ValueError, configparser.Error) as error:
        sys.exit(f"Settings file {settings}: {error}")
    try:
        log = CsvLog(args.log) if args.log else None
    except OSError as error:
        sys.exit(f"Can't write the log file {args.log}: {error.strerror}")
    # Colors also when the screen only goes to the web page (--connect without a terminal) or a picture.
    USE_COLOR = (sys.stdout.isatty() or bool(args.connect or args.svg)) and not args.json
    sys.stdout.reconfigure(encoding="utf-8")  # e.g. Windows defaults to cp1252 when redirected
    if IS_WINDOWS and USE_COLOR:
        enable_ansi_on_windows()

    # kill and systemctl stop send SIGTERM, which ends Python without running `finally` blocks:
    # exit normally instead, so the terminal is restored and the server hears we've gone.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        remote = RemoteReport(args.connect, args.interval, args.password, args.server_cert) if args.connect else None
    except (OSError, ValueError) as error:  # a missing or broken --server-cert (ssl.SSLError is an OSError)
        sys.exit(f"Can't use the server certificate {args.server_cert}: {error}")
    monitor = Monitor(args.interval, settings, remote)
    try:
        if args.once or args.json or args.svg:
            time.sleep(args.interval)  # rates (CPU %, network, disk I/O) need two samples
            cols, rows = shutil.get_terminal_size()  # without a terminal: $COLUMNS, else 80
            lines = [truncate(line, cols - 1) for line in monitor.render(cols - 1, rows, View())]
            if log:
                log.write(monitor.snapshot)
            if args.svg:
                try:
                    with open(args.svg, "w", encoding="utf-8") as f:
                        f.write(svg_screenshot(lines))
                except OSError as error:
                    sys.exit(f"Can't write {args.svg}: {error.strerror}")
                print(f"Saved {args.svg}")
            else:
                print(json.dumps(monitor.snapshot, indent=2) if args.json else "\n".join(lines))
        elif (remote or log) and not sys.stdout.isatty():  # don't pour screens into a log or journal
            print("sysmon: the output isn't a terminal, so nothing is drawn; --log / --connect keep working",
                  file=sys.stderr, flush=True)
            run_headless(monitor, args.interval, log)
        else:
            run_live(monitor, args.interval, log)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.close()


if __name__ == "__main__":
    main()
