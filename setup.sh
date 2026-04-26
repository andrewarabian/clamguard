#!/usr/bin/env bash
# ClamGuard — First-time ClamAV setup
# Detects package manager, installs clamav + freshclam, initializes definitions.

set -euo pipefail

# ── colour ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    R=$'\033[0m' BOLD=$'\033[1m'
    OK=$'\033[1;32m' INFO=$'\033[34m' WARN=$'\033[33m' ERR=$'\033[1;31m'
else
    R='' BOLD='' OK='' INFO='' WARN='' ERR=''
fi

log_info()  { printf "${INFO}[INFO]${R}  %s\n" "$*"; }
log_ok()    { printf "${OK}[ OK ]${R}  %s\n" "$*"; }
log_warn()  { printf "${WARN}[WARN]${R}  %s\n" "$*"; }
log_err()   { printf "${ERR}[ ERR]${R}  %s\n" "$*" >&2; }
die()       { log_err "$*"; exit 1; }

hline() { printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '-'; }

# ── root check ────────────────────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        # Re-exec under sudo, preserving arguments
        log_warn "Not running as root — re-executing with sudo…"
        exec sudo bash "$0" "$@"
    fi
}

# ── distro / package manager detection ───────────────────────────────────────
detect_pm() {
    # Prefer explicit command presence over /etc/os-release guessing
    if   command -v apt-get  &>/dev/null; then PM=apt
    elif command -v dnf      &>/dev/null; then PM=dnf
    elif command -v yum      &>/dev/null; then PM=yum
    elif command -v zypper   &>/dev/null; then PM=zypper
    elif command -v pacman   &>/dev/null; then PM=pacman
    elif command -v apk      &>/dev/null; then PM=apk
    elif command -v emerge   &>/dev/null; then PM=portage
    elif command -v pkg      &>/dev/null; then PM=pkg       # FreeBSD
    elif command -v brew     &>/dev/null; then PM=brew      # macOS / Linuxbrew
    else
        die "No supported package manager found. Install ClamAV manually."
    fi

    # Detect RHEL/CentOS/Rocky/Alma that need EPEL for clamav
    NEED_EPEL=0
    if [[ $PM == dnf || $PM == yum ]]; then
        if [[ -f /etc/os-release ]]; then
            local _distro_id
            _distro_id="$(grep -E '^ID=' /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"' | tr -d "'")"
            case "${_distro_id:-}" in
                rhel|centos|rocky|almalinux|ol)
                    NEED_EPEL=1 ;;
                fedora)
                    NEED_EPEL=0 ;;
            esac
        fi
    fi
}

# ── installation ─────────────────────────────────────────────────────────────
install_clamav() {
    log_info "Package manager: ${BOLD}${PM}${R}"
    case $PM in
        apt)
            apt-get update -qq
            apt-get install -y clamav clamav-freshclam
            # Ubuntu/Debian run clamav-freshclam as a service that holds the
            # database lock — stop it so we can run freshclam manually below.
            if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
                systemctl stop clamav-freshclam
                log_info "Stopped clamav-freshclam service (will restart after update)"
                RESTART_FC_SERVICE=1
            fi
            ;;
        dnf)
            if [[ $NEED_EPEL -eq 1 ]]; then
                log_info "RHEL-family detected — installing EPEL first"
                dnf install -y epel-release
            fi
            dnf install -y clamav clamav-freshclam
            ;;
        yum)
            if [[ $NEED_EPEL -eq 1 ]]; then
                log_info "RHEL-family detected — installing EPEL first"
                yum install -y epel-release
            fi
            yum install -y clamav clamav-freshclam
            ;;
        zypper)
            # openSUSE ships clamav in the main security repo on Tumbleweed;
            # on Leap it may require the security repository.
            if ! zypper repos | grep -q 'security'; then
                log_info "Adding openSUSE security repository"
                local ver
                ver="$(grep -E '^VERSION_ID=' /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"' | tr -d "'" | tr -cd '[:alnum:].')"
                [[ -z "$ver" ]] && ver="Tumbleweed"
                local repo_base="https://download.opensuse.org/repositories/security"
                if [[ $ver == Tumbleweed ]]; then
                    zypper addrepo "${repo_base}/openSUSE_Tumbleweed/security.repo" || true
                else
                    zypper addrepo "${repo_base}/openSUSE_Leap_${ver}/security.repo" || true
                fi
                zypper --gpg-auto-import-keys refresh
            fi
            zypper install -y clamav
            ;;
        pacman)
            pacman -Sy --noconfirm clamav
            ;;
        apk)
            apk add --no-cache clamav clamav-scanner freshclam
            ;;
        portage)
            emerge --ask=n app-antivirus/clamav
            ;;
        pkg)
            pkg install -y clamav
            ;;
        brew)
            # Homebrew does not require root — drop privileges if we are root
            if [[ $EUID -eq 0 ]]; then
                log_warn "Homebrew should not run as root."
                log_warn "Run this script without sudo on macOS:"
                log_warn "  bash setup.sh"
                exit 1
            fi
            brew install clamav
            ;;
    esac
}

# ── verify installation ───────────────────────────────────────────────────────
verify_install() {
    local missing=()
    command -v clamscan   &>/dev/null || missing+=(clamscan)
    command -v freshclam  &>/dev/null || missing+=(freshclam)

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Installation appears incomplete — missing: ${missing[*]}"
    fi
    log_ok "clamscan  : $(command -v clamscan)"
    log_ok "freshclam : $(command -v freshclam)"
}

# ── virus database initialisation ────────────────────────────────────────────
init_database() {
    log_info "Initialising virus database via freshclam — this may take a moment…"
    echo ""

    if ! freshclam; then
        log_warn "freshclam exited non-zero. This is sometimes normal (already up to date)."
        log_warn "Check output above for actual errors."
    fi

    echo ""

    # Restart the service on Debian/Ubuntu if we stopped it earlier
    if [[ ${RESTART_FC_SERVICE:-0} -eq 1 ]]; then
        systemctl start clamav-freshclam
        log_info "Restarted clamav-freshclam service"
    fi
}

# ── clamguard binary ─────────────────────────────────────────────────────────
install_clamguard() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "${script_dir}/clamguard" ]]; then
        install -m 0755 -o root -g root "${script_dir}/clamguard" /usr/local/bin/clamguard
        log_ok "Installed clamguard → /usr/local/bin/clamguard"
    elif [[ -f "${script_dir}/clamguard.c" ]] && command -v gcc &>/dev/null; then
        log_info "Binary not found — compiling from source"
        gcc -O2 -Wall -Wextra -Wpedantic -std=c11 -D_GNU_SOURCE \
            -o "${script_dir}/clamguard" "${script_dir}/clamguard.c" -pthread
        install -m 0755 -o root -g root "${script_dir}/clamguard" /usr/local/bin/clamguard
        log_ok "Compiled and installed clamguard → /usr/local/bin/clamguard"
    else
        log_warn "clamguard binary not found and gcc unavailable — skipping clamguard install"
        log_warn "Install gcc then run: sudo make install"
    fi
}

# ── main ─────────────────────────────────────────────────────────────────────
main() {
    require_root "$@"

    hline
    printf "${BOLD}  ClamGuard — First-time Setup${R}\n"
    hline
    echo ""

    RESTART_FC_SERVICE=0

    detect_pm
    install_clamav
    echo ""
    verify_install
    echo ""
    init_database
    install_clamguard

    echo ""
    hline
    printf "${OK}  Setup complete.${R}\n"
    hline
    echo ""
    printf "  Run a scan:\n"
    printf "    ${BOLD}sudo clamguard${R}                              # interactive\n"
    printf "    ${BOLD}sudo clamguard --target /home --action quarantine${R}\n"
    echo ""
}

main "$@"
