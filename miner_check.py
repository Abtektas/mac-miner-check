#!/usr/bin/env python3
"""Read-only macOS check for hidden crypto miners and their persistence.

Looks for the pattern from the Oct 2026 XMRig report: a process burning many
cores, running from a temp or hidden folder, talking to a mining pool, and kept
alive by a LaunchAgent with KeepAlive and an encoded script.

Nothing is killed, unloaded, moved or deleted. Stdlib only.

Usage:  python3 -I miner_check.py [--json] [--cpu 150] [--days 120]
Exit:   0 clean, 1 medium findings, 2 high findings.

MIT License. Provided "AS IS", without warranty of any kind; see LICENSE.
"""

__version__ = "0.1.0"

DISCLAIMER = (
    "Heuristic, read-only check. Not an antivirus. A clean result does not "
    "prove the machine is clean, and a finding is not proof of malware. "
    "Provided AS IS, without warranty of any kind; you use it at your own "
    "risk and the authors accept no liability (MIT License).")

import argparse
import ctypes
import ctypes.util
import json
import os
import plistlib
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

HOME = Path.home()

MINER_WORDS = re.compile(
    r"xmrig|xmr-stak|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer|t-rex|"
    r"lolminer|phoenixminer|teamredminer|srbminer|nanominer|gminer|"
    r"stratum\+(tcp|ssl)|--donate-level|randomx|cryptonight|monero|"
    r"--coin[= ]|-a rx/|--algo",
    re.I,
)
POOL_DOMAINS = [
    "pool.hashvault.sh", "pool.hashvault.pro", "pool.supportxmr.com",
    "xmr.2miners.com", "xmr-eu1.nanopool.org", "xmr-us-east1.nanopool.org",
    "gulf.moneroocean.stream", "pool.minexmr.com", "xmr.c3pool.com",
    "auto.c3pool.org", "monero.herominers.com", "xmrpool.eu",
    "pool.xmr.pt", "mine.xmrpool.net", "xmr.f2pool.com", "rx.unmineable.com",
]
POOL_WORDS = re.compile(
    r"hashvault|supportxmr|nanopool|moneroocean|minexmr|c3pool|herominers|"
    r"2miners|xmrpool|unmineable|f2pool|nicehash", re.I)
MINER_PORTS = {3333, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444,
               10128, 10343, 20128, 45560, 45700}
ENCODED = re.compile(r"base64\s+(-d|-D|--decode)|b64decode|frombase64|"
                     r"[A-Za-z0-9+/]{120,}={0,2}")
SHELLY = re.compile(r"\b(curl|wget)\b.*\|\s*(ba|z)?sh|osascript\s+-e|"
                    r"\b(ba|z)?sh\s+-c\b|python3?\s+-c\b|perl\s+-e\b", re.I)

# Folders where normal apps do not keep long-running binaries.
TEMP_PREFIXES = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
                 "/Users/Shared/", "/private/var/folders/", "/var/folders/"]
# Hidden folders in $HOME that dev tools use on purpose.
KNOWN_DOT = {".cargo", ".rustup", ".npm", ".nvm", ".pyenv", ".local", ".docker",
             ".colima", ".lima", ".orbstack", ".claude", ".vscode", ".cursor",
             ".bun", ".deno", ".gradle", ".m2", ".sdkman", ".conda", ".ollama",
             ".gem", ".rbenv", ".volta", ".pnpm", ".cache", ".config", ".zsh",
             ".oh-my-zsh", ".swiftpm", ".rye", ".uv", ".codeium", ".git"}

findings = []


def add(level, area, what, why, **extra):
    findings.append({"level": level, "area": area, "what": what,
                     "why": why, **extra})


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def place_flags(path):
    """Return (temp, hidden) for a file path."""
    if not path:
        return False, False
    p = path if path.endswith("/") else path + "/"
    temp = any(p.startswith(t) for t in TEMP_PREFIXES)
    tmpdir = os.environ.get("TMPDIR", "")
    if tmpdir and p.startswith(os.path.realpath(tmpdir)):
        temp = True
    hidden = False
    parts = Path(path).parts
    for i, part in enumerate(parts[:-1]):
        if part.startswith(".") and part not in (".", ".."):
            under_home = str(Path(*parts[:i])) == str(HOME)
            if not (under_home and part in KNOWN_DOT):
                hidden = True
    if Path(path).name.startswith("."):
        hidden = True
    return temp, hidden


# libproc gives the real executable path, even if argv[0] lies.
_libproc = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")


def exe_path(pid):
    buf = ctypes.create_string_buffer(4096)
    n = _libproc.proc_pidpath(pid, buf, 4096)
    return buf.value.decode(errors="replace") if n > 0 else ""


def signed_by(path):
    """'apple', 'devid', 'adhoc', 'unsigned' or 'unknown'."""
    if not path or not os.path.exists(path):
        return "unknown"
    out = subprocess.run(["codesign", "-dvv", path], capture_output=True,
                         text=True).stderr
    if "not signed" in out:
        return "unsigned"
    if "Signature=adhoc" in out:
        return "adhoc"
    if "Authority=Software Signing" in out or "Authority=Apple Mac OS" in out:
        return "apple"
    if "Authority=Developer ID" in out or "Authority=Apple Development" in out:
        return "devid"
    return "unknown"


# ---------------------------------------------------------------- processes
def check_processes(cpu_limit):
    ncpu = os.cpu_count() or 1
    # Two samples: ps %cpu is a decaying average, so take the max.
    samples = []
    for _ in range(2):
        samples.append(run(["ps", "-Ao", "pid=,pcpu=,user=,etime=,args="]))
        time.sleep(1.5)
    best = {}
    for out in samples:
        for line in out.splitlines():
            bits = line.split(None, 4)
            if len(bits) < 5:
                continue
            pid, cpu, user, etime, args = bits
            pid, cpu = int(pid), float(cpu)
            if pid not in best or cpu > best[pid][0]:
                best[pid] = (cpu, user, etime, args)

    top = sorted(best.items(), key=lambda kv: -kv[1][0])[:10]
    total = sum(v[0] for v in best.values())
    for pid, (cpu, user, etime, args) in best.items():
        path = exe_path(pid) or args.split()[0]
        temp, hidden = place_flags(path)
        why = []
        level = None
        busy = cpu >= 50
        if MINER_WORDS.search(Path(path).name):
            why.append("executable has a miner name")
            level = "HIGH"
        elif MINER_WORDS.search(args):
            # A shell or grep that only mentions the word is not a miner.
            why.append("miner word in command line"
                       + ("" if busy else " (idle, maybe a search)"))
            level = "HIGH" if busy else "LOW"
        if POOL_WORDS.search(args):
            why.append("pool name in command line")
            level = "HIGH" if busy or level == "HIGH" else (level or "LOW")
        if path.startswith("/") and not os.path.exists(path) \
                and not path.startswith("/System/") and cpu >= 5:
            why.append("binary deleted from disk while running")
            level = level or "MED"
        if temp:
            why.append("runs from a temp folder")
            level = "HIGH" if cpu >= cpu_limit else (level or "MED")
        if hidden and cpu >= 20:
            why.append("runs from a hidden folder")
            level = level or "MED"
        if cpu >= cpu_limit and not why:
            sig = signed_by(path)
            if sig in ("unsigned", "adhoc", "unknown"):
                why.append(f"high CPU and signature is {sig}")
                level = "MED"
        if level:
            add(level, "process", f"pid {pid} {cpu:.0f}% {path}",
                "; ".join(why), user=user, etime=etime, args=args[:300])
    return {"cores": ncpu, "total_cpu_pct": round(total),
            "top": [{"pid": p, "cpu": v[0], "user": v[1], "etime": v[2],
                     "cmd": (exe_path(p) or v[3])[:120]} for p, v in top]}


# ---------------------------------------------------------------- network
def check_network():
    pool_ips = {}
    for d in POOL_DOMAINS:
        try:
            for info in socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP):
                pool_ips[info[4][0]] = d
        except OSError:
            pass
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn"])
    pid = cmd = None
    seen = 0
    for line in out.splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            pid = int(val)
        elif tag == "c":
            cmd = val
        elif tag == "n" and "->" in val:
            seen += 1
            remote = val.split("->", 1)[1]
            host, _, port = remote.rpartition(":")
            host = host.strip("[]")
            port = int(port) if port.isdigit() else 0
            if host in pool_ips:
                add("HIGH", "network", f"pid {pid} {cmd} -> {remote}",
                    f"connected to known pool {pool_ips[host]}")
            elif port in MINER_PORTS:
                add("MED", "network", f"pid {pid} {cmd} -> {remote}",
                    f"remote port {port} is a common stratum port")
    return {"connections_seen": seen, "pool_ips_resolved": len(pool_ips)}


# ---------------------------------------------------------------- launchd
def plist_exec(d):
    args = d.get("ProgramArguments") or []
    prog = d.get("Program") or (args[0] if args else "")
    return prog, [str(a) for a in args]


def check_launchd(days, extra=()):
    dirs = [HOME / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons")] + [Path(e) for e in extra]
    count = 0
    now = time.time()
    for d in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if f.suffix != ".plist":
                continue
            count += 1
            try:
                data = plistlib.loads(f.read_bytes())
            except PermissionError:
                age = (now - f.stat().st_mtime) / 86400
                add("INFO", "launchd", str(f),
                    f"root-only file, changed {age:.0f} days ago; "
                    "run with sudo to read it")
                continue
            except Exception as e:
                add("MED", "launchd", str(f), f"plist does not parse: {e}")
                continue
            if not isinstance(data, dict):
                continue
            prog, args = plist_exec(data)
            line = " ".join(args) or prog
            keep = bool(data.get("KeepAlive")) or bool(data.get("RunAtLoad"))
            temp, hidden = place_flags(prog)
            age_days = (now - f.stat().st_mtime) / 86400
            why, level = [], None
            if MINER_WORDS.search(line) or POOL_WORDS.search(line):
                why.append("miner or pool words in arguments")
                level = "HIGH"
            if ENCODED.search(line):
                why.append("encoded (base64) payload in arguments")
                level = "HIGH" if keep else (level or "MED")
            if SHELLY.search(line):
                why.append("runs an inline shell or download script")
                level = level or "MED"
            if temp:
                why.append("program lives in a temp folder")
                level = "HIGH" if keep else (level or "MED")
            elif hidden:
                why.append("program lives in a hidden folder")
                level = level or "MED"
            if prog.startswith("/") and not os.path.exists(prog):
                why.append("program file is missing")
                level = level or "LOW"
            if why or not prog.startswith(("/System/", "/usr/", "/bin/",
                                           "/sbin/", "/Applications/",
                                           "/Library/Apple/")):
                sig = signed_by(prog) if prog.startswith("/") else "unknown"
                if sig in ("unsigned", "adhoc") and keep:
                    why.append(f"kept alive and binary is {sig}")
                    level = level or "MED"
            if why:
                add(level or "LOW", "launchd", str(f), "; ".join(why),
                    label=data.get("Label"), keepalive=keep,
                    changed_days_ago=round(age_days), command=line[:300])
            elif age_days <= days:
                add("INFO", "launchd", str(f),
                    f"changed {age_days:.0f} days ago, looks normal",
                    label=data.get("Label"), command=line[:200])
    return {"plists_read": count}


# ---------------------------------------------------------------- loose files
MACHO = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
         b"\xfe\xed\xfa\xcf"}


def check_temp_binaries():
    roots = {"/private/tmp", "/private/var/tmp", "/Users/Shared"}
    if os.environ.get("TMPDIR"):
        roots.add(os.path.realpath(os.environ["TMPDIR"]))
    found = 0
    for root in sorted(roots):
        base = len(Path(root).parts)
        for dirpath, dirnames, files in os.walk(root, onerror=lambda e: None):
            if len(Path(dirpath).parts) - base >= 4:
                dirnames[:] = []
            for name in files:
                p = os.path.join(dirpath, name)
                try:
                    if os.path.islink(p) or not os.access(p, os.X_OK):
                        continue
                    with open(p, "rb") as fh:
                        magic = fh.read(4)
                except OSError:
                    continue
                if magic in MACHO:
                    found += 1
                    if found > 40:
                        continue
                    size = os.path.getsize(p)
                    level = "HIGH" if MINER_WORDS.search(name) else "LOW"
                    add(level, "files", p,
                        f"executable Mach-O in a temp folder ({size // 1024} KB)")
    return {"temp_machos": found}


# ---------------------------------------------------------------- misc
def check_misc():
    cron = run(["crontab", "-l"])
    for line in cron.splitlines():
        if line.strip() and not line.startswith("#"):
            lvl = "HIGH" if (MINER_WORDS.search(line) or ENCODED.search(line)) \
                else "LOW"
            add(lvl, "cron", line[:200], "user crontab entry")
    therm = run(["pmset", "-g", "therm"]).strip()
    load = os.getloadavg()
    return {"load_avg": [round(x, 2) for x in load], "pmset_therm": therm}


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", action="version",
                    version=f"mac-miner-check {__version__}\n{DISCLAIMER}")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--cpu", type=float, default=150,
                    help="per-process CPU %% that counts as high (default 150)")
    ap.add_argument("--days", type=int, default=120,
                    help="show launchd plists changed in this many days")
    ap.add_argument("--plist-dir", action="append", default=[],
                    help="also scan this folder of plists (for tests)")
    a = ap.parse_args()

    if sys.platform != "darwin":
        sys.exit("macOS only")

    info = {"processes": check_processes(a.cpu), "network": check_network(),
            "launchd": check_launchd(a.days, a.plist_dir),"files": check_temp_binaries(),
            "misc": check_misc()}
    order = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: (order[f["level"]], f["area"]))

    if a.json:
        print(json.dumps({"version": __version__, "disclaimer": DISCLAIMER,
                          "info": info, "findings": findings}, indent=2))
    else:
        p = info["processes"]
        print(f"== Cores {p['cores']}, total CPU {p['total_cpu_pct']}%, "
              f"load {info['misc']['load_avg']}")
        print("== Top CPU")
        for t in p["top"][:6]:
            print(f"   {t['cpu']:6.1f}%  pid {t['pid']:<6} {t['user']:<10} {t['cmd']}")
        print(f"== Read {info['launchd']['plists_read']} launchd plists, "
              f"{info['network']['connections_seen']} TCP connections, "
              f"{info['files']['temp_machos']} temp binaries")
        if info["misc"]["pmset_therm"]:
            print("== Thermal: " + " | ".join(
                l.strip() for l in info["misc"]["pmset_therm"].splitlines()
                if l.strip()))
        print()
        if not findings:
            print("No findings.")
        for f in findings:
            print(f"[{f['level']:4}] {f['area']:8} {f['what']}")
            print(f"         why: {f['why']}")
            for k in ("label", "command", "args", "changed_days_ago"):
                if f.get(k) not in (None, ""):
                    print(f"         {k}: {f[k]}")
        print("\nRead-only scan. Nothing was stopped or removed.")
        print(DISCLAIMER)

    levels = {f["level"] for f in findings}
    sys.exit(2 if "HIGH" in levels else 1 if "MED" in levels else 0)


if __name__ == "__main__":
    main()
