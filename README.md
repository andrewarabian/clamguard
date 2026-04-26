# Clamguard

Clamguard is a wrapper around ClamAV's `clamscan` built for beginner to intermediate Linux users. It handles virus database updates, scan profiles, quarantine, and reporting through a guided interface. It is not a replacement for `clamscan` and was never intended to be learning `clamscan` directly is encouraged. ClamGuard exists to make ClamAV accessible while that learning happens.

ClamAV-based malware scanner for Linux. Live TUI with progress tracking, virus database updates, quarantine, and structured report export. Runs as root.

---

## Setup

```bash
sudo bash setup.sh
```

Detects your package manager, installs ClamAV and freshclam, pulls the initial virus database, and installs the `clamguard` binary to `/usr/local/bin/`.

Supported: `apt` · `dnf` · `yum` · `zypper` · `pacman` · `apk` · `emerge` · `pkg` · `brew`

---

## Build & Install

```bash
make                 # compile
sudo make install    # install to /usr/local/bin/
```

Requires `gcc` and `clamav` / `clamav-freshclam`.

---

## Usage

```bash
sudo clamguard                                           # interactive, prompted for all options
sudo clamguard --target /home --action quarantine
sudo clamguard --target / --profile full --accurate --action report
sudo clamguard --target /tmp --action remove --i-accept-risk
sudo clamguard --target /var --no-update --action quarantine
sudo clamguard --theme hackerman --target /home --action quarantine
sudo clamguard --no-color --target /var --action report
```

---

## Options

| Flag | Default | Description |
|---|---|---|
| `--target PATH` | `/` | Directory to scan |
| `--profile NAME` | `recommended` | `recommended` \| `full` \| `custom` |
| `--exclude "PATHS"` | (none) | Space or comma-separated paths to skip (used with `custom`) |
| `--action NAME` | `quarantine` | `report` \| `quarantine` \| `remove` |
| `--theme NAME` | `blueteam` | `blueteam` \| `layer8` \| `hackerman` \| `retro` \| `arctic` |
| `--accurate` | off | Pre-count files for a percentage progress bar instead of a spinner |
| `--no-update` | off | Skip freshclam before scanning |
| `--no-color` | off | Disable ANSI output |
| `--i-accept-risk` | (none) | Required gate to enable `--action remove` |
| `-h`, `--help` | (none) | Show help |

---

## Profiles

| Profile | Behaviour |
|---|---|
| `recommended` | Excludes `/proc /sys /dev /run`; safe for most scans |
| `full` | No exclusions; scans everything |
| `custom` | Use `--exclude` to specify paths manually |

---

## Actions

| Action | Behaviour |
|---|---|
| `report` | Log detections only; no files modified |
| `quarantine` | Move detections to `/var/quarantine/clamguard/TIMESTAMP/`, set `chmod 000`, log SHA-256 |
| `remove` | Permanently delete detections; requires `--i-accept-risk` and interactive confirmation |

> System-critical paths (`/bin`, `/sbin`, `/usr/bin`, `/boot`, `/lib`) are never auto-acted on regardless of action. They are flagged for manual review.

---

## Output

| Path | Contents |
|---|---|
| `/var/log/clamav/fullscan.log` | Raw ClamAV output |
| `/var/log/clamav/reports/TIMESTAMP.txt` | Structured scan report |
| `/var/log/clamav/quarantine_map_TIMESTAMP.log` | Quarantine map with SHA-256 hashes |
| `/var/quarantine/clamguard/TIMESTAMP/` | Quarantined files (mode 000) |

At the end of each scan you are prompted to export the report as `.md` or `.txt`.

---

## Quarantine & Restore

```bash
# List quarantined files
ls /var/quarantine/clamguard/

# Restore a file
sudo chmod 644 /var/quarantine/clamguard/TIMESTAMP/path/to/file
sudo mv /var/quarantine/clamguard/TIMESTAMP/path/to/file /original/path/
```

---

## Bash Fallback

`clamguard.sh` provides the same feature set without requiring a C compiler.

```bash
sudo bash clamguard.sh --target /home --action quarantine
```

---

## Files

| File | Description |
|---|---|
| `setup.sh` | First-time install; detects distro, installs ClamAV, pulls definitions |
| `clamguard.c` | C source, primary implementation |
| `clamguard` | Compiled binary |
| `clamguard.sh` | Bash fallback |
| `Makefile` | Build system |
