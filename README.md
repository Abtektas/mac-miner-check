# mac-miner-check

A read-only macOS check for hidden crypto miners (XMRig and friends) and the
LaunchAgents that keep them alive.

It looks for the pattern from the October 2026 report where a coding agent,
while building a temperature monitor, found XMRig using ~1175% CPU on a Mac:
a process burning many cores from a temp folder, talking to a mining pool,
and restarted by a LaunchAgent with `KeepAlive` and an encoded script.

**It never kills, unloads, moves or deletes anything.** It only reads and
reports. It is a quick heuristic check, not an antivirus.

## Quick start

No programming needed. About two minutes.

1. Open **Terminal** (press `Cmd + Space`, type `Terminal`, press Return).
2. Check that Python is there:

   ```bash
   python3 --version
   ```

   If macOS offers to install the "command line developer tools", click
   **Install**, wait for it to finish, then run the command again.
3. Download the tool and go into its folder:

   ```bash
   git clone https://github.com/Abtektas/mac-miner-check.git
   cd mac-miner-check
   ```

   No `git`? Download the ZIP from the green **Code** button on this page,
   double-click it, then type `cd ` (with a space), drag the unzipped folder
   into the Terminal window and press Return.
4. Optional: prove the tool works on your Mac. This briefly runs a harmless
   fake miner and cleans up after itself; it should end with `SELFTEST PASS`.

   ```bash
   zsh selftest.sh
   ```

5. Scan your Mac:

   ```bash
   python3 -I miner_check.py
   ```

   For a fuller scan that also sees system processes, run it with `sudo` and
   type your Mac password (nothing shows while you type):

   ```bash
   sudo python3 -I miner_check.py
   ```

**Reading the result:** look at the lines that start with `[HIGH]` or
`[MED ]`. If there are none, nothing miner-like was found. `[LOW ]` and
`[INFO]` lines are usually harmless, for example leftovers from apps you
deleted. If you see `[HIGH]`, read [If you get a HIGH finding](#if-you-get-a-high-finding)
before you change anything.

## Requirements

- macOS (tested on macOS 27.2, Apple M4)
- `python3` (the Xcode Command Line Tools one is fine). Standard library only,
  nothing to install.

## Usage

```bash
python3 -I miner_check.py            # your own processes and files
sudo python3 -I miner_check.py       # also root processes and root-only plists
python3 -I miner_check.py --json     # machine-readable output
```

Options: `--cpu 150` sets what counts as high CPU per process (percent,
100 = one full core); `--days 120` lists launchd plists changed in that many
days.

Exit code: `0` nothing above LOW, `1` MED findings, `2` HIGH findings.

## What it checks

| Area | Looks for |
|---|---|
| Processes | high CPU; runs from `/tmp`, `/var/folders`, `/Users/Shared` or a hidden folder; miner names or flags (`xmrig`, `--donate-level`, `stratum+tcp`); pool names; binary deleted while running; high CPU with an unsigned or ad-hoc binary |
| Network | established TCP to known Monero pools (resolved live) or common stratum ports |
| launchd | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`: base64 payloads, inline `bash -c` / `curl \| sh`, program in a temp or hidden folder, unsigned binary kept alive, missing program |
| Files | executable Mach-O files in temp folders |
| Other | user crontab, `pmset -g therm` thermal warnings, load average |

Levels: **HIGH** looks like a miner, check now. **MED** unusual, look at it.
**LOW** usually harmless (for example a plist left behind by an app you
deleted). **INFO** recent launchd changes, for context.

## Self-test

```bash
./selftest.sh
```

It copies `/usr/bin/yes` into a temp folder as `xmrig`, ad-hoc signs it, runs
two copies with miner-like arguments (about two cores, output to `/dev/null`),
writes a fake `KeepAlive` plist with a base64 payload (read by the scanner,
never loaded into launchd), runs the scan and expects all three to be caught.
On exit it stops the fake processes and removes only the folder it created.

## If you get a HIGH finding

1. Read the plist first: `plutil -p <file>`.
2. Stop the job: `launchctl bootout gui/$(id -u) <file>` (or `system` for a
   LaunchDaemon, with `sudo`).
3. Keep the plist and binary as evidence in a folder of your own, then run
   a full malware scanner.
4. Treat the Mac as compromised beyond the miner: change the passwords and
   API keys stored on it.

## Notes

- The output contains your user name, paths and app list. Think before you
  paste it somewhere public. Do not paste it into issues here.
- Known gaps: it does not read Login Items / Background Task Management
  (`sfltool dumpbtm`), browser extensions or GPU use, and a miner that only
  runs while you are away may be idle during the scan.

## Background and credits

The code is original. The idea came from public reporting on one Reddit
user's account (u/UntilHEX, October 2026, not independently verified), for
example
[Developers Digest](https://www.developersdigest.tech/blog/claude-code-found-xmrig-cryptominer-mac-check-yours-2026)
and [Yahoo Tech](https://tech.yahoo.com/ai/claude/articles/claude-code-spotted-cryptominer-mac-143720791.html).
launchd behaviour follows Apple's
[Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
Miner and pool names are public facts used only as search patterns.

For a fuller look at persistent items on a Mac, see Objective-See's free
[KnockKnock](https://objective-see.org/products/knockknock.html).

## Disclaimer and license

This is a heuristic, read-only check, not an antivirus. A clean result does
not prove a machine is clean, and a finding is not proof of malware. Every
action you take on its output is your own decision.

The software is provided "AS IS", without warranty of any kind, express or
implied. You use it entirely at your own risk; the authors and contributors
accept no responsibility or liability for any damage, loss or other
consequence of its use. The same notice is printed at the end of every
report and by `--version`.

Released under the [MIT License](LICENSE).
