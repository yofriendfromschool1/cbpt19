#!/usr/bin/env bash
# =============================================================================
#  cbptlinux.sh -- CyberPatriot linux image triage + hardening helper
# =============================================================================
#
#  grew out of the team checklist over several practice rounds. it is NOT a
#  magic point button: it automates the boring baseline every team can do,
#  then tells you where the rest of the points are. the README and the
#  forensic questions are still yours -- and they are worth more than
#  anything in this file.
#
#  works on:
#     Debian / Ubuntu / Mint          (apt)
#     RHEL / CentOS / Rocky / Alma / Fedora   (dnf|yum)
#     openSUSE                       (zypper)
#     Arch                           (pacman)
#  anything else: most of it runs, the package bits just get skipped.
#
#  ------------------------------------------------------------------------------
#  WHAT IT DOES
#  ------------------------------------------------------------------------------
#   1. tars up /etc plus a pile of state into /root/cbptlinux-backup/<stamp>/
#      so you can put the box back the way it was (--restore).
#   2. finds and prints the README, ranked (authorized users, critical
#      services -- write them down, they are scored).
#   3. recon pass -> /root/cbptlinux-evidence/ : users, uid0, shadow, sudoers,
#      cron, systemd units, listening sockets, SUID, world-writable, ssh
#      keys, ld.so.preload, history, auth logs, USB traces, media files,
#      PII grep. this is the raw material for the forensic questions.
#   4. applies the boring-but-scored baseline: login.defs, PAM password
#      quality + faillock, sshd, sysctl, umask, cron/at perms, file perms,
#      firewall, service shutdowns -- with config validation and rollback
#      wherever a mistake can lock you out.
#   5. hardens whatever server software is installed (apache, nginx, mysql,
#      postgres, bind, vsftpd, samba, postfix, wordpress, php) -- config
#      only, never touches their data directories.
#   6. prints a PASS/FAIL/WARN scorecard with a hint on every non-PASS,
#      and writes findings.tsv + needs-review.txt.
#
#  ------------------------------------------------------------------------------
#  WHAT IT REFUSES TO DO
#  ------------------------------------------------------------------------------
#   * never deletes a user, a home directory, or a file that looks like
#     business data without asking. it reports, you decide.
#   * never clears logs. cleared logs == attacker behavior, and some images
#     score on log content.
#   * never edits /etc/passwd or /etc/shadow directly -- usermod/chage/passwd
#     only, so the files stay consistent.
#   * will not turn off sshd, and will not flip PasswordAuthentication to
#     "no" unless you pass --aggressive AND confirm. locking yourself out
#     of a scored image is a round-ender.
#
#  ------------------------------------------------------------------------------
#  USAGE
#  ------------------------------------------------------------------------------
#   sudo bash cbptlinux.sh                      # interactive menu
#   sudo bash cbptlinux.sh --all                # backup + recon + harden + verify
#   sudo bash cbptlinux.sh --recon              # look, don't touch
#   sudo bash cbptlinux.sh --module users       # one module
#   sudo bash cbptlinux.sh --dry-run --all      # rehearsal, zero changes
#   sudo bash cbptlinux.sh --paranoid           # recon + verify only
#   sudo bash cbptlinux.sh --hints              # the point-scrounging guide
#   sudo bash cbptlinux.sh --restore /root/cbptlinux-backup/<stamp>
#   sudo bash cbptlinux.sh --baseline           # snapshot for diffing vs clean VM
#   sudo bash cbptlinux.sh --checklist          # closing manual checks
#
#   modules: recon users passwords ssh firewall services packages sysctl
#            perms audit apps verify report checklist
#
#   the users module reconciles accounts against users.txt and admins.txt
#   next to this script (one name per line, copied from the README).
#   templates are created on first run if they are missing.
#
#  ------------------------------------------------------------------------------
#  CHANGELOG
#  ------------------------------------------------------------------------------
#   0.8.x  team checklist -> script. PAM tally2 -> faillock after the sed
#          started silently doing nothing on new distros.
#   0.9.x  sshd drop-in instead of sed-ing the main file. sysctl split into
#          sysctl.d so we stop fighting the distro's own file. evidence dump
#          gained ld.so.preload, lsattr, authorized_keys, USB traces.
#   1.0.0  scorecard, hints, --restore, app modules.
#   1.1.0  merged the best of our other helpers: users.txt/admins.txt
#          reconciliation, --dry-run, prohibited-media hunt, needs-review.txt,
#          the master hints guide.
#   1.2.0  folded in the PenguinOS checklist: dist-upgrade + autoclean,
#          unattended-upgrades reconfiguration, prohibited-software purge
#          (gated behind --aggressive), AppArmor/SELinux enforcement, and a
#          --checklist module that prints the manual follow-up list. the
#          original PenguinOS checklist is by yofriendfromschool1.
#   1.2.1  auditd flush/freq/mail account, /lib/systemd/system watch, and
#          net.core.bpf_jit_harden from the upstream checklist.
#   1.3.0  hierarchical per-file backup/restore with verified hashes and
#          created-file rollback, dry-run leak fixes, firewall snapshots,
#          app-config transactions that validate + roll back, safer package
#          upgrades, SSH host-key backup, and a deeper read-only verify pass
#          (sudoers, capabilities, repo trust, PAM, custom units, host keys).
#
#  TODO / known gaps:
#   - SELinux relabel after perm changes is best-effort only
#   - the SUID baseline list gets stale; refresh it before a round
#   - pam_pwquality vs pam_cracklib: we prefer pwquality, older RHEL may
#     need cracklib and the module will warn
# =============================================================================

# deliberately NOT using set -e: a hardening script that bails on the first
# missing package is worse than useless mid-competition.
set -o pipefail
umask 022

VERSION="1.3.0"
STAMP="$(date +%Y%m%d-%H%M%S)"
EVID="${CP_EVID_DIR:-/root/cbptlinux-evidence}"
BKROOT="${CP_BACKUP_ROOT:-/root/cbptlinux-backup}"
BKDIR="$BKROOT/$STAMP"
LOGFILE="${CP_LOG:-/var/log/cbptlinux-$STAMP.log}"
REVIEW="$EVID/needs-review.txt"
AGGRESSIVE=0
PARANOID=0
DRY=0
FORCE=0
RESTORE_FROM=""
PHASE="menu"
MODULE=""

# things we never stop/disable. EDIT PER IMAGE once you have read the README.
KEEP_SERVICES="sshd ssh cron crond rsyslog systemd-journald systemd-logind \
dbus network NetworkManager systemd-networkd systemd-resolved auditd \
firewalld ufw apparmor apparmord selinuxd polkit postfix"

# password aging defaults. override from the environment if the README says
# something different -- do not edit the numbers in three places.
PASS_MAX_DAYS="${CP_PASS_MAX_DAYS:-90}"
PASS_MIN_DAYS="${CP_PASS_MIN_DAYS:-1}"
PASS_MIN_LEN="${CP_PASS_MIN_LEN:-14}"
PASS_WARN_AGE="${CP_PASS_WARN_AGE:-14}"

# CyberPatriot policy tools and games. exact package names first, then the
# regex patterns for the metapackages / variants. removal is gated behind
# --aggressive; the recon module only reports.
PROHIBITED_SOFTWARE=(nmap zenmap wireshark john john-data hashcat hydra netcat
  netcat-openbsd ncat socat telnetd aircrack-ng kismet nikto sqlmap
  metasploit-framework ophcrack ettercap-common medusa dsniff tcpflow
  netdiscover logkeys freeciv minetest gnome-games qbittorrent bittorrent)
PROHIBITED_PATTERNS=("transmission-.*" "deluge.*" "freeciv.*" "minetest.*"
  "gnome-games.*" "bittorrent.*" "supertux.*" "wesnoth.*" "aisleriot"
  "gnome-mines" "gnome-sudoku" "quadrapassel" "frozen-bubble")

# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[36m'
  C_MAG=$'\033[35m'; C_GRY=$'\033[90m'; C_WHT=$'\033[37m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_GRY=""; C_WHT=""; C_RST=""
fi

log()  { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" >>"$LOGFILE" 2>/dev/null; }
say()  { local m="$*"; printf '%s[*]%s %s\n' "$C_GRY" "$C_RST" "$m"; log "INFO $m"; }
ok()   { local m="$*"; printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$m"; log "OK   $m"; }
warn() { local m="$*"; printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$m"; log "WARN $m"; }
err()  { local m="$*"; printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$m" >&2; log "ERR  $m"; }
step() { local m="$*"; printf '%s==>%s %s\n' "$C_MAG" "$C_RST" "$m"; log "STEP $m"; }
banner(){ printf '\n%s%s%s\n' "$C_BLU" "$(printf '=%.0s' {1..78})" "$C_RST"
          printf '%s %s%s\n' "$C_BLU" "$1" "$C_RST"
          printf '%s%s%s\n' "$C_BLU" "$(printf '=%.0s' {1..78})" "$C_RST"; }

# ---------------------------------------------------------------------------
# findings + scorecard
# ---------------------------------------------------------------------------
FIND_TMP="$(mktemp /tmp/cbptlinux-findings.XXXXXX)"
CHG_TMP="$(mktemp /tmp/cbptlinux-changes.XXXXXX)"
trap 'rm -f "$FIND_TMP" "$CHG_TMP"' EXIT

# finding <ID> <AREA> <STATUS> <DETAIL> [HINT]
finding() {
  local id="$1" area="$2" st="$3" detail="$4" hint="${5:-}"
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$area" "$st" "$detail" "$hint" >>"$FIND_TMP"
  local pre col
  case "$st" in
    PASS) pre="[+]"; col="$C_GRN" ;;
    FAIL) pre="[x]"; col="$C_RED" ;;
    WARN) pre="[!]"; col="$C_YEL" ;;
    INFO) pre="[i]"; col="$C_GRY" ;;
    *)    pre="[-]"; col="$C_YEL" ;;
  esac
  printf ' %s %-26s %s%s%s\n' "$col$pre$C_RST" "$id" "$col" "$detail" "$C_RST"
  if [[ -n "$hint" ]]; then printf '       %shint: %s%s\n' "$C_GRY" "$hint" "$C_RST"; fi
  # IMPORTANT: always return 0. This function is used all over in the
  #   <test> && finding PASS ... || finding FAIL ...
  # idiom, and the trailing printf used to leave the function returning 1
  # whenever no hint was given -- which made the || arm fire as well and
  # printed every passing check twice, once as a FAIL. we did that once. don't.
  return 0
}

change() { printf '%s\t%s\t%s\n' "$1" "${2:-}" "${3:-}" >>"$CHG_TMP"; }

# things a human has to decide with the README in hand
review() {
  mkdir -p "$EVID" 2>/dev/null
  chmod 700 "$EVID" 2>/dev/null
  printf -- '- %s\n' "$*" >>"$REVIEW" 2>/dev/null
  warn "$*  [saved to needs-review.txt]"
}

# destructive / access-affecting operations require the word YES.
confirm() {
  if [[ $DRY -eq 1 ]]; then say "[dry-run] refused to ask: $1"; return 1; fi
  if [[ $PARANOID -eq 1 ]]; then warn "paranoid: refused: $1"; return 1; fi
  [[ $FORCE -eq 1 ]] && return 0
  [[ ! -t 0 ]] && return 1
  printf '\n  %s!! %s%s\n' "$C_YEL" "$1" "$C_RST"
  read -r -p "  type YES to continue: " ans
  [[ "$ans" == "YES" ]]
}

ask() {
  local a=""
  [[ $DRY -eq 1 || $PARANOID -eq 1 ]] && return 1
  [[ ! -t 0 ]] && return 1
  read -r -p "  ? $1 [y/N] " a
  [[ "$a" =~ ^[Yy] ]]
}

# act CMD ARGS... : run a state-changing command unless --dry-run / --paranoid
act() {
  log "run: $*"
  if (( PARANOID )); then warn "[paranoid] $*"; return 0; fi
  if (( DRY )); then say "[dry-run] $*"; return 0; fi
  "$@"
}

# have <cmd> -- some images are missing tools and a page of "command not
# found" noise hides the findings that matter.
have() { command -v "$1" >/dev/null 2>&1; }

is_kept_service() {
  local s="$1" k
  for k in $KEEP_SERVICES; do [[ "$s" == "$k" ]] && return 0; done
  return 1
}

# ---------------------------------------------------------------------------
# distro detection + package wrapper
# ---------------------------------------------------------------------------
PKG=""
detect_distro() {
  local _cbpt_version="${VERSION:-}"
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"; DISTRO_LIKE="${ID_LIKE:-}"; DISTRO_VER="${VERSION_ID:-}"
  else
    DISTRO_ID="unknown"; DISTRO_LIKE=""; DISTRO_VER=""
  fi
  VERSION="$_cbpt_version"
  if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
  elif command -v dnf    >/dev/null 2>&1; then PKG="dnf"
  elif command -v yum   >/dev/null 2>&1; then PKG="yum"
  elif command -v zypper >/dev/null 2>&1; then PKG="zypper"
  elif command -v pacman >/dev/null 2>&1; then PKG="pacman"
  else PKG="none"; fi
}

pkg_has() { command -v "$1" >/dev/null 2>&1 || rpm -q "$1" >/dev/null 2>&1 || \
            dpkg -s "$1" >/dev/null 2>&1; }

# pkg_find_installed <extended-regex> -- print installed package names that
# match. pkg_has takes exact names, so patterns like minetest.* used to match
# nothing at all. this is also the only reliable way to catch metapackages
# whose binary names differ from the package name.
pkg_find_installed() {
  local rx="$1"
  case "$PKG" in
    apt)             dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -Eix "$rx" ;;
    dnf|yum|zypper)  rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -Eix "$rx" ;;
    pacman)          pacman -Qq 2>/dev/null | grep -Eix "$rx" ;;
    *)               return 1 ;;
  esac
}

# pkg_install a b c -- best effort. offline images fail, and that's fine.
pkg_install() {
  [[ $DRY -eq 1 || $PARANOID -eq 1 ]] && { say "[dry-run/paranoid] install: $*"; return 0; }
  local want=()
  for p in "$@"; do pkg_has "$p" || want+=("$p"); done
  [[ ${#want[@]} -eq 0 ]] && return 0
  say "installing: ${want[*]}"
  case "$PKG" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${want[@]}" >/dev/null 2>&1 ;;
    dnf)    dnf install -y "${want[@]}" >/dev/null 2>&1 ;;
    yum)    yum install -y "${want[@]}" >/dev/null 2>&1 ;;
    zypper) zypper --non-interactive install "${want[@]}" >/dev/null 2>&1 ;;
    pacman) pacman -S --noconfirm --needed "${want[@]}" >/dev/null 2>&1 ;;
    *)      warn "no package manager found, cannot install ${want[*]}" ;;
  esac
  for p in "${want[@]}"; do pkg_has "$p" || warn "could not install $p (offline image?)" ; done
}

pkg_remove() {
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: would remove $*"; return 0; }
  [[ $DRY -eq 1 ]] && { say "[dry-run] would remove: $*"; return 0; }
  if [[ $AGGRESSIVE -ne 1 ]]; then
    warn "not removing $* (needs --aggressive)"
    return 0
  fi
  if ! confirm "AGGRESSIVE: purge ${*}? Make sure the README does not need them."; then return 0; fi
  case "$PKG" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" >/dev/null 2>&1 ;;
    dnf)    dnf remove -y "$@" >/dev/null 2>&1 ;;
    yum)    yum remove -y "$@" >/dev/null 2>&1 ;;
    zypper) zypper --non-interactive remove "$@" >/dev/null 2>&1 ;;
    pacman) pacman -Rns --noconfirm "$@" >/dev/null 2>&1 ;;
  esac
  ok "removed: $*"
}

# ---------------------------------------------------------------------------
# idempotent file editors
# ---------------------------------------------------------------------------

backup_file() {
  local f="$1" rel dest tmp hash manifest
  [[ -e "$f" || -L "$f" ]] || return 0
  [[ $DRY -eq 1 ]] && { say "[dry-run] would back up $f"; return 0; }
  case "$f" in
    /*) ;;
    *) warn "backup refused: not an absolute path: $f"; return 1 ;;
  esac
  case "$f" in
    *$'\t'*|*$'\n'*) warn "backup refused: unsupported path characters: $f"; return 1 ;;
  esac
  [[ -f "$f" || -L "$f" ]] || { warn "backup refused: not a regular file or symlink: $f"; return 1; }
  rel="${f#/}"
  case "/$rel/" in *"/../"*) warn "backup refused: path traversal: $f"; return 1 ;; esac
  manifest="$BKDIR/files.manifest"
  mkdir -p "$BKDIR" || return 1
  if [[ -f "$manifest" ]] && awk -F '\t' -v p="$f" '$1==p{found=1} END{exit !found}' "$manifest"; then
    return 0
  fi
  dest="$BKDIR/files/$rel"
  if [[ ! -e "$dest" && ! -L "$dest" ]]; then
    mkdir -p "$(dirname "$dest")" || return 1
    tmp="$dest.tmp.$$.$RANDOM"
    if ! cp -a -- "$f" "$tmp"; then
      rm -f -- "$tmp" 2>/dev/null
      warn "could not back up $f"
      return 1
    fi
    if ! mv -f -- "$tmp" "$dest"; then
      rm -f -- "$tmp" 2>/dev/null
      warn "could not finish backup of $f"
      return 1
    fi
  fi
  if [[ -L "$dest" ]]; then
    hash="link:$(readlink -- "$dest" 2>/dev/null)"
  else
    hash="$(sha256sum -- "$dest" 2>/dev/null | awk '{print $1}')"
  fi
  [[ -n "$hash" ]] || { warn "could not hash backup of $f"; return 1; }
  printf '%s\t%s\t%s\n' "$f" "$rel" "$hash" >>"$manifest" || return 1
  return 0
}

created_file() {
  local f="$1"
  [[ -n "$f" ]] || return 1
  [[ $DRY -eq 1 || $PARANOID -eq 1 ]] && return 0
  case "$f" in /*) ;; *) return 1 ;; esac
  case "$f" in *$'\t'*|*$'\n'*) return 1 ;; esac
  case "/$f/" in *"/../"*) return 1 ;; esac
  mkdir -p "$BKDIR" || return 1
  grep -Fqx -- "$f" "$BKDIR/created-files.manifest" 2>/dev/null ||
    printf '%s\n' "$f" >>"$BKDIR/created-files.manifest"
}

# restore_file <absolute-path> [backup-root]
restore_file() {
  local f="$1" base="${2:-$BKDIR}" manifest row orig rel hash dest actual
  case "$f" in /*) ;; *) return 1 ;; esac
  case "$f" in *$'\t'*|*$'\n'*) return 1 ;; esac
  manifest="$base/files.manifest"
  if [[ -f "$manifest" ]]; then
    row="$(awk -F '\t' -v p="$f" '$1==p{print; exit}' "$manifest")"
  fi
  if [[ -z "${row:-}" ]]; then
    if [[ -f "$base/created-files.manifest" ]] && grep -Fqx -- "$f" "$base/created-files.manifest"; then
      if [[ -e "$f" || -L "$f" ]]; then act rm -f -- "$f"; fi
      return 0
    fi
    return 1
  fi
  IFS=$'\t' read -r orig rel hash <<<"$row"
  case "$rel" in ""|/*|..|../*|*/..|*"/../"*) return 1 ;; esac
  dest="$base/files/$rel"
  if [[ -L "$dest" ]]; then
    actual="link:$(readlink -- "$dest" 2>/dev/null)"
  elif [[ -f "$dest" ]]; then
    actual="$(sha256sum -- "$dest" 2>/dev/null | awk '{print $1}')"
  else
    return 1
  fi
  if [[ "$actual" != "$hash" ]]; then
    warn "backup hash mismatch for $f; refusing to restore it"
    return 1
  fi
  act cp -a --remove-destination -- "$dest" "$f"
}

# ensure_line <file> <eregex> <replacement-line>
#
# Replaces the first matching line in place. Three rules that took a few
# broken practice images to learn:
#   1. Prefer an ACTIVE (uncommented) match. Only fall back to a commented
#      one. config files like /etc/login.defs carry prose comments that
#      begin with the key name ("# UMASK is the default umask value for...")
#      and matching those replaces documentation while leaving the real
#      setting alone -- the worst outcome, because it looks like it worked.
#   2. A commented match is only accepted if it looks like "#key value",
#      not a sentence. eight tokens or fewer.
#   3. Any further ACTIVE duplicates are deleted, so exactly one setting wins.
#
# The regex and replacement travel via ENVIRON, never via `awk -v`: awk -v
# processes backslash escapes in the assigned value, which silently rewrites
# patterns like '^\s*\$FileCreateMode' into something that matches nothing.
ensure_line() {
  local f="$1" rx="$2" line="$3"
  [[ $PARANOID -eq 1 ]] && { say "paranoid: would set in $f: $line"; return 0; }
  if [[ $DRY -eq 1 ]]; then say "[dry-run] $f: $line"; return 0; fi
  if [[ ! -f "$f" ]]; then
    created_file "$f"
    mkdir -p "$(dirname "$f")" 2>/dev/null; : >"$f"
  fi
  backup_file "$f"
  local tmp; tmp="$(mktemp)"
  CP_RX="$rx" CP_LINE="$line" awk '
    BEGIN { rx = ENVIRON["CP_RX"]; repl = ENVIRON["CP_LINE"]; act = 0; cmt = 0 }
    {
      lines[NR] = $0
      if ($0 ~ rx) {
        t = $0; sub(/^[[:space:]]*/, "", t)
        n = split(t, w, /[[:space:]]+/)
        if (substr(t, 1, 1) != "#") { if (act == 0) act = NR; else dup[NR] = 1 }
        else if (n <= 8)            { if (cmt == 0) cmt = NR }
      }
    }
    END {
      pick = (act > 0) ? act : ((cmt > 0) ? cmt : 0)
      for (i = 1; i <= NR; i++) {
        if (i in dup) continue
        if (i == pick) print repl; else print lines[i]
      }
      if (pick == 0) print repl
      exit(pick > 0 ? 10 : 11)
    }' "$f" >"$tmp"
  local rc=$?
  if [[ -s "$tmp" ]] || [[ ! -s "$f" ]]; then cat "$tmp" >"$f"; fi
  rm -f "$tmp"
  if (( rc == 11 )); then
    say "  appended to $f: $line"
  else
    change "$f" "" "$line"
  fi
  return 0
}

# sysctl_get <key> -- read a kernel parameter, falling back to /proc/sys when
# the sysctl(8) binary is not installed (procps missing on a lot of images).
sysctl_get() {
  local k="$1" v="" pf
  if command -v sysctl >/dev/null 2>&1; then v="$(sysctl -n "$k" 2>/dev/null)"; fi
  if [[ -z "$v" ]]; then
    pf="/proc/sys/$(echo "$k" | tr '.' '/')"
    [[ -r "$pf" ]] && v="$(tr -d '\t' <"$pf" 2>/dev/null)"
  fi
  printf '%s' "$v"
}

comment_out() {
  local f="$1" rx="$2"
  [[ -f "$f" ]] || return 0
  [[ $DRY -eq 1 || $PARANOID -eq 1 ]] && { say "would comment out /$rx/ in $f"; return 0; }
  backup_file "$f"
  local tmp; tmp="$(mktemp)"
  sed -E "s|^([[:space:]]*($rx).*)\$|#cbptlinux# \1|" "$f" >"$tmp" && cat "$tmp" >"$f" && rm -f "$tmp"
  change "$f" "/$rx/" "commented"
}
# ---------------------------------------------------------------------------
# BACKUP
# ---------------------------------------------------------------------------
do_backup() {
  banner "BACKUP"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: backup snapshot skipped"; return; }
  if [[ $DRY -eq 1 ]]; then
    say "[dry-run] would snapshot /etc and runtime state to $BKDIR"
    return 0
  fi
  mkdir -p "$BKDIR/files" "$EVID" || { err "could not create backup directory $BKDIR"; return 1; }
  chmod 700 "$BKDIR" "$BKDIR/files" "$EVID" 2>/dev/null
  say "backup -> $BKDIR"
  act tar czf "$BKDIR/etc.tar.gz" /etc 2>/dev/null && ok "etc.tar.gz" || warn "could not tar /etc"
  for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/login.defs \
           /etc/ssh/sshd_config /etc/pam.d/common-password /etc/pam.d/common-auth \
           /etc/pam.d/password-auth /etc/pam.d/system-auth /etc/hosts /etc/fstab \
           /etc/crontab /etc/rc.local /etc/ld.so.preload /etc/profile /etc/bash.bashrc \
           /etc/sysctl.conf /etc/apt/sources.list; do
    backup_file "$f"
  done
  [[ -d /etc/sudoers.d ]] && act tar czf "$BKDIR/sudoers.d.tar.gz" /etc/sudoers.d 2>/dev/null
  [[ -d /etc/pam.d ]]     && act tar czf "$BKDIR/pam.d.tar.gz" /etc/pam.d 2>/dev/null
  [[ -d /etc/ssh ]]       && act tar czf "$BKDIR/ssh.tar.gz" /etc/ssh 2>/dev/null
  [[ -d /etc/systemd/system ]] && act tar czf "$BKDIR/systemd-system.tar.gz" /etc/systemd/system 2>/dev/null
  [[ -d /etc/cron.d ]]    && act tar czf "$BKDIR/cron.d.tar.gz" /etc/cron.d 2>/dev/null

  # state snapshots (all optional tools -- skip silently if absent)
  have ss        && ss -tulpnH        >"$BKDIR/listening.txt" 2>&1
  have ps        && ps auxf           >"$BKDIR/processes.txt" 2>&1
  have ip        && { ip a >"$BKDIR/ip-a.txt" 2>&1; ip r >"$BKDIR/ip-r.txt" 2>&1; }
  have systemctl && { systemctl list-unit-files --type=service --state=enabled >"$BKDIR/enabled-services.txt" 2>&1
                      systemctl list-units     --type=service --state=running >"$BKDIR/running-services.txt"  2>&1; }
  have dpkg      && dpkg -l           >"$BKDIR/dpkg-l.txt"  2>&1
  have rpm       && rpm  -qa          >"$BKDIR/rpm-qa.txt"  2>&1
  have crontab   && crontab -l        >"$BKDIR/root-crontab.txt" 2>&1
  have iptables  && iptables-save     >"$BKDIR/iptables.txt" 2>&1
  have nft       && nft list ruleset  >"$BKDIR/nft.txt" 2>&1
  have ufw       && ufw status verbose >"$BKDIR/ufw-status.txt" 2>&1
  ok "backup done ($(du -sh "$BKDIR" 2>/dev/null | cut -f1))"
}

do_restore() {
  local d="$1" manifest orig rel hash f b
  [[ -d "$d" ]] || { err "no such backup: $d"; return 1; }
  banner "RESTORE FROM $d"
  if [[ $DRY -eq 1 ]]; then
    say "[dry-run] would restore /etc and per-file snapshots from $d"
    return 0
  fi
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: restore refused"; return 0; }
  confirm "Restore /etc and the config files from this backup? Current state will be lost." || return 0
  if [[ -f "$d/etc.tar.gz" ]]; then
    act tar xzf "$d/etc.tar.gz" -C / 2>/dev/null && ok "/etc restored" || warn "could not restore /etc from the archive"
  fi
  manifest="$d/files.manifest"
  if [[ -f "$manifest" ]]; then
    while IFS=$'\t' read -r orig rel hash; do
      [[ -n "$orig" && "$orig" == /* ]] || { warn "skipping invalid backup path: ${orig:-<empty>}"; continue; }
      if restore_file "$orig" "$d"; then say "restored $orig"; else warn "could not restore $orig"; fi
    done <"$manifest"
  elif [[ -d "$d/files" ]]; then
    # old backups used flattened names (etc_passwd) with no manifest
    while IFS= read -r -d '' f; do
      b="$(basename "$f")"
      orig="/${b//_//}"
      act cp -a --remove-destination -- "$f" "$orig" 2>/dev/null && say "restored $orig"
    done < <(find "$d/files" -maxdepth 1 -type f -print0 2>/dev/null)
  fi
  if [[ -f "$d/created-files.manifest" ]]; then
    while IFS= read -r f; do
      [[ -n "$f" && "$f" == /* ]] || continue
      case "/$f/" in *"/../"*) continue ;; esac
      if [[ -e "$f" || -L "$f" ]]; then
        act rm -f -- "$f" && say "removed newly-created $f"
      fi
    done <"$d/created-files.manifest"
  fi
  if [[ -f "$d/iptables.txt" ]]; then
    warn "iptables snapshot is in $d/iptables.txt; it is not applied automatically because live firewall restore differs by frontend"
  fi
  warn "reboot the box so sshd/pam/sysctl all pick up the restored config."
}

# ---------------------------------------------------------------------------
# README / scenario -- the highest-value two minutes of the round
# ---------------------------------------------------------------------------
do_readme() {
  banner "README / SCENARIO"
  local found=()
  local f
  # Prune the noise, or you get 50 hits from node_modules and /usr/share/doc
  # and you stop reading any of them. a CP README is never in a vendor dir.
  local prune='( -path /proc -o -path /sys -o -path /run -o -path /snap -o -path /dev
                -o -name node_modules -o -name .git -o -name vendor -o -name site-packages
                -o -name dist-info -o -name __pycache__ -o -path /usr/share/doc
                -o -path /usr/share/man -o -path /usr/lib -o -path /usr/share/common-licenses
                -o -path /var/lib/docker -o -path '"$EVID"' -o -path '"$BKROOT"' )'
  while IFS= read -r f; do found+=("$f"); done < <(
    eval find / -xdev "$prune" -prune -o \
      -maxdepth 6 -type f \
      '\(' -iname 'readme*' -o -iname 'read*me*' -o -iname 'instructions*' \
        -o -iname 'scenario*' -o -iname 'todo*' -o -iname 'notes*' -o -iname 'welcome*' \
        -o -iname 'company*policy*' -o -iname 'important*' -o -iname 'memo*' -o -iname 'task*' -o -iname 'audit*' '\)' \
      '\(' -iname '*.txt' -o -iname '*.md' -o -iname '*.rst' -o -iname '*.doc' -o -iname '*.docx' -o -iname '*.pdf' -o -iname '*.rtf' '\)' \
      -print 2>/dev/null | head -25
  )
  # loose docs in the places a scenario author would actually put them
  while IFS= read -r f; do found+=("$f"); done < <(
    find /root /home /var/www /opt /srv /tmp /mnt /media /var/ftp /etc -maxdepth 4 -type f \
      \( -iname '*.txt' -o -iname '*.docx' -o -iname '*.pdf' -o -iname '*.md' \) 2>/dev/null | head -25
  )

  if [[ ${#found[@]} -eq 0 ]]; then
    warn "no readme-looking file found automatically."
    finding "README-LOCATE" "Scenario" "WARN" "nothing that looks like a README" \
      "Check every user's home, /root, /var/www, /opt. The README lists authorized users and critical services -- it is worth more than any sysctl key."
    return
  fi

  # dedupe
  local -A seen=(); local uniq=()
  for f in "${found[@]}"; do [[ -z "${seen[$f]:-}" ]] && { seen[$f]=1; uniq+=("$f"); }; done

  # Rank them: a file literally named README on a desktop outranks some random
  # notes.txt in /tmp. cap size and lines too -- echoing 20 KB of every .txt
  # on the box buries the one file you actually came here for.
  local -a ranked=()
  local rf score bn sz
  for rf in "${uniq[@]}"; do
    score=0
    bn="$(basename "$rf" | tr 'A-Z' 'a-z')"
    [[ "$bn" =~ ^readme|^read.me ]]     && score=$((score+100))
    [[ "$bn" =~ instruction|scenario ]] && score=$((score+80))
    [[ "$bn" =~ todo|task|notes|important|memo|welcome|audit|policy ]] && score=$((score+50))
    [[ "$rf" =~ /root/|/home/|/Desktop/|/var/www/ ]] && score=$((score+30))
    [[ "$rf" =~ ^/tmp/|/node_modules/|/var/log/ ]]   && score=$((score-60))
    sz="$(stat -c%s "$rf" 2>/dev/null || echo 0)"
    (( sz > 262144 )) && score=$((score-70))     # >256 KB is not a readme
    (( sz < 20 ))     && score=$((score-40))
    ranked+=("$(printf '%06d' $((100000+score)))|$rf")
  done
  mapfile -t ranked < <(printf '%s\n' "${ranked[@]}" | sort -r)

  ok "candidate files: ${#ranked[@]}  (full dump in $EVID/readme-candidates.txt)"
  : >"$EVID/readme-candidates.txt"
  local shown=0 entry
  for entry in "${ranked[@]}"; do
    local f="${entry#*|}"
    (( shown++ >= 12 )) && break          # only echo the top dozen to the screen
    local sz; sz="$(stat -c%s "$f" 2>/dev/null || echo 0)"
    printf -- '--------------------------------------------------------------------------------\n'
    printf ' FILE: %s  (%s bytes, mtime %s)\n' "$f" "$sz" "$(stat -c%y "$f" 2>/dev/null | cut -d. -f1)"
    printf -- '--------------------------------------------------------------------------------\n'
    case "$f" in
      *.pdf)  have pdftotext && pdftotext "$f" - 2>/dev/null | head -80 || warn "  (pdf -- install poppler-utils or open it by hand)" ;;
      *.docx) have unzip && unzip -p "$f" word/document.xml 2>/dev/null | sed -e 's/<[^>]*>/ /g' | head -80 || warn "  (docx)" ;;
      *)      (( sz > 262144 )) && echo "  (too large to echo -- ${sz} bytes, open it directly)" || head -c 12000 "$f" 2>/dev/null | head -80 ;;
    esac
    { printf '\n===== %s =====\n' "$f"; head -c 200000 "$f" 2>/dev/null; } >>"$EVID/readme-candidates.txt"
  done
  (( ${#ranked[@]} > shown )) && say "  ... and $(( ${#ranked[@]} - shown )) more, lowest-ranked first suppressed (see the dump file)"
  printf '\n'
  warn "ACTION: write down (1) authorized users, (2) critical services, (3) business/PII data, (4) any explicit task. Those are scored."
  finding "README-READ" "Scenario" "INFO" "${#uniq[@]} candidate file(s) dumped" \
    "Everything the README asks for is a guaranteed point if you actually do it. Most teams skim it."
}
# ---------------------------------------------------------------------------
# RECON / EVIDENCE
# ---------------------------------------------------------------------------
do_recon() {
  banner "RECON + EVIDENCE"
  mkdir -p "$EVID"
  chmod 700 "$EVID" 2>/dev/null
  say "evidence -> $EVID"

  { echo "hostname   : $(hostname)"
    echo "kernel     : $(uname -a)"
    echo "distro     : ${PRETTY_NAME:-$DISTRO_ID} (like=${DISTRO_LIKE:-none}, version=${DISTRO_VER:-unknown}, pkg=$PKG)"
    echo "started    : $(date -Is)"
    have uptime && echo "uptime     : $(uptime 2>/dev/null)"
    echo "run as     : $(id)"
  } >"$EVID/00-summary.txt"
  cat "$EVID/00-summary.txt"

  do_readme

  # ---- users / groups ------------------------------------------------------
  step "accounts"
  cp -a /etc/passwd  "$EVID/10-passwd"  2>/dev/null
  cp -a /etc/group   "$EVID/10-group"   2>/dev/null
  cp -a /etc/shadow  "$EVID/10-shadow"  2>/dev/null
  cp -a /etc/gshadow "$EVID/10-gshadow" 2>/dev/null
  cp -a /etc/sudoers "$EVID/10-sudoers" 2>/dev/null
  [[ -d /etc/sudoers.d ]] && tar czf "$EVID/10-sudoers.d.tar.gz" /etc/sudoers.d 2>/dev/null
  getent passwd >"$EVID/10-getent-passwd.txt" 2>&1
  lastlog 2>/dev/null >"$EVID/10-lastlog.txt"
  last -a -n 200 2>/dev/null >"$EVID/10-last.txt"

  # UID 0 other than root -- the classic backdoor
  local uid0
  uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx root | tr '\n' ' ')"
  if [[ -n "$uid0" ]]; then
    finding "USER-UID0" "Accounts" "FAIL" "extra UID-0 account(s): $uid0" \
      "A second UID-0 account is a backdoor. Verify against the README, then remove it (only if unauthorized) and note it in the report."
  else
    finding "USER-UID0" "Accounts" "PASS" "only root has UID 0"
  fi

  # empty password fields
  local empties
  empties="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')"
  if [[ -n "$empties" ]]; then
    finding "USER-NOPASS" "Accounts" "FAIL" "accounts with an EMPTY password: $empties" \
      "Blank passwords are almost always scored. passwd <user> to set one, or lock with passwd -l if the README says the account should exist but not be usable."
  else
    finding "USER-NOPASS" "Accounts" "PASS" "no empty password fields"
  fi

  # UID < 1000 with a login shell
  local sysusers
  sysusers="$(awk -F: '$3<1000 && $3!=0 && $7!~/(nologin|false|sync|shutdown|halt)/ {print $1"("$3","$7")"}' /etc/passwd | tr '\n' ' ')"
  [[ -n "$sysusers" ]] && finding "USER-SYSSHELL" "Accounts" "WARN" "system accounts with a usable shell: $sysusers" \
    "Set these to /usr/sbin/nologin unless the README needs them (e.g. a service account)."

  # password aging / expiry. /etc/shadow field 5 is max days; the shell lives
  # in /etc/passwd, so join the two -- otherwise every nologin system account
  # gets flagged as noise.
  local nopasschg
  nopasschg="$(awk -F: 'NR==FNR{shell[$1]=$7; next}
                        ($5=="" || $5>=99999) && ($1 in shell) && (shell[$1] !~ /(nologin|false)/) {print $1}' \
                    /etc/passwd /etc/shadow 2>/dev/null | tr '\n' ' ')"
  if [[ -n "$nopasschg" ]]; then
    finding "USER-NOEXPIRE" "Accounts" "WARN" "login accounts whose password never expires: $nopasschg" \
      "chage -M 90 -W 14 <user>. Frequently scored. System accounts with a nologin shell are correctly excluded."
  else
    finding "USER-NOEXPIRE" "Accounts" "PASS" "all login accounts have a password max age"
  fi

  # who can sudo
  { echo "### /etc/sudoers"; cat /etc/sudoers 2>/dev/null
    echo; echo "### /etc/sudoers.d/*"; for f in /etc/sudoers.d/*; do [[ -f "$f" ]] && { echo "-- $f"; cat "$f"; }; done
    echo; echo "### groups"; getent group sudo wheel admin root 2>/dev/null
  } >"$EVID/11-sudo.txt"
  if grep -REn '^[^#]*(NOPASSWD|ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL|%\w+\s+ALL)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null >/dev/null; then
    finding "SUDO-RULES" "Accounts" "WARN" "broad sudo rule(s) present, see $EVID/11-sudo.txt" \
      "NOPASSWD and 'ALL=(ALL) ALL' for a whole group are usually scored. Trim to the specific commands the user needs."
  fi
  if grep -REq '^[^#]*\sALL\s*=\s*\(ALL(:ALL)?\)\s*NOPASSWD:\s*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    finding "SUDO-NOPASSWD" "Accounts" "FAIL" "someone has NOPASSWD:ALL" \
      "Passwordless full root is a serious finding. Remove unless the README justifies it."
  fi
  # world-writable sudoers is game over
  local ww
  ww="$(find /etc/sudoers /etc/sudoers.d -type f -perm /o+w 2>/dev/null | tr '\n' ' ')"
  [[ -n "$ww" ]] && finding "SUDO-PERM" "Accounts" "FAIL" "world-writable sudoers file(s): $ww" "chmod 0440 /etc/sudoers and everything in /etc/sudoers.d/"

  # ---- ssh keys (classic persistence) --------------------------------------
  step "authorized_keys / ssh persistence"
  : >"$EVID/12-authorized-keys.txt"
  local home d
  while IFS=: read -r _ _ _ _ _ home _; do
    [[ -d "$home" ]] || continue
    for k in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2" \
             "$home/.ssh/id_rsa" "$home/.ssh/id_ed25519" "$home/.ssh/config" \
             "$home/.ssh/known_hosts"; do
      [[ -f "$k" ]] && { echo "===== $k"; cat "$k"; echo; } >>"$EVID/12-authorized-keys.txt"
    done
  done < <(getent passwd | awk -F: '$3>=0 {print $1":x:"$3":"$4":"$5":"$6":"$7}')
  for k in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
    [[ -f "$k" ]] && { echo "===== $k"; cat "$k"; echo; } >>"$EVID/12-authorized-keys.txt"
  done
  if [[ -s /root/.ssh/authorized_keys ]]; then
    finding "SSH-ROOTKEY" "Persistence" "WARN" "/root/.ssh/authorized_keys exists ($(wc -l </root/.ssh/authorized_keys) line(s))" \
      "An authorized_keys for root is a backdoor unless the README says remote root access is a business requirement. Remove the key, keep the file."
  fi
  if [[ -s "$EVID/12-authorized-keys.txt" ]]; then
    finding "SSH-KEYS" "Persistence" "INFO" "authorized_keys dump at $EVID/12-authorized-keys.txt" \
      "Check every key against the README. Unknown key = intrusion evidence, write it down before you delete it."
  fi

  # ---- networking ------------------------------------------------------------
  step "network"
  # ss and netstat disagree on columns, so normalize into a TSV:
  #   proto <TAB> localaddr <TAB> port <TAB> pid <TAB> process
  : >"$EVID/20-listening.tsv"
  if command -v ss >/dev/null 2>&1; then
    ss -tulpnH 2>/dev/null >"$EVID/20-listening.txt"
    awk '{ proto=$1; la=$5; proc=$6; pid="";
           n=split(proc, a, "="); if (n>=2) { split(a[2], b, ","); pid=b[1] }
           pname=proc; sub(/.*"/, "", pname); sub(/".*/, "", pname);
           p=la; sub(/.*:/, "", p);
           if (p ~ /^[0-9]+$/) printf "%s\t%s\t%s\t%s\t%s\n", proto, la, p, pid, pname }' \
      "$EVID/20-listening.txt" >>"$EVID/20-listening.tsv"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn 2>/dev/null >"$EVID/20-listening.txt"
    awk 'NR>2 && $1 ~ /^(tcp|udp)/ { la=$4; pp=$7; pid=""; pname="";
           if (split(pp, a, "/") == 2) { pid=a[1]; pname=a[2] }
           p=la; sub(/.*:/, "", p);
           if (p ~ /^[0-9]+$/) printf "%s\t%s\t%s\t%s\t%s\n", $1, la, p, pid, pname }' \
      "$EVID/20-listening.txt" >>"$EVID/20-listening.tsv"
  else
    warn "neither ss nor netstat is installed -- port recon is empty"
    finding "RECON-PORTS" "Network" "WARN" "no ss/netstat available" \
      "Install iproute2 or net-tools. Without them you cannot see what is listening, and you cannot confirm a critical service is up."
  fi
  sort -t$'\t' -k3,3n -u "$EVID/20-listening.tsv" >"$EVID/20-listening-sorted.tsv" 2>/dev/null
  column -t -s$'\t' "$EVID/20-listening-sorted.tsv" 2>/dev/null || cat "$EVID/20-listening-sorted.tsv"
  ip a >"$EVID/20-ip-a.txt" 2>&1; ip r >"$EVID/20-ip-r.txt" 2>&1
  iptables-save >"$EVID/20-iptables.txt" 2>&1
  nft list ruleset >"$EVID/20-nftables.txt" 2>&1
  cp -a /etc/hosts "$EVID/20-hosts" 2>/dev/null
  cp -a /etc/resolv.conf "$EVID/20-resolv.conf" 2>/dev/null

  local laddr port pid proc
  while IFS=$'\t' read -r _ laddr port pid proc; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    case "$port" in
      21)     finding "PORT-21" "Network" "WARN" "FTP listening ($proc)" "Plaintext creds. Enable TLS (ssl_enable=YES) or stop it unless it is a critical service." ;;
      23)     finding "PORT-23" "Network" "FAIL" "TELNET listening ($proc)" "Telnet is essentially never legitimate. Stop+disable it and purge telnetd." ;;
      25|587) finding "PORT-25" "Network" "INFO" "SMTP listening ($proc)" "If it is a critical service, disable open relay + VRFY and require auth." ;;
      69)     finding "PORT-69" "Network" "WARN" "TFTP listening ($proc)" "Unauthenticated file transfer; usually a scored vuln." ;;
      111)    finding "PORT-111" "Network" "WARN" "rpcbind listening ($proc)" "Disable rpcbind unless NFS is required." ;;
      161)    finding "PORT-161" "Network" "WARN" "SNMP listening ($proc)" "Change community off public/private, restrict sources, prefer SNMPv3." ;;
      445|139) finding "PORT-445" "Network" "INFO" "SMB listening ($proc)" "Samba is often a critical service. Harden smb.conf rather than killing it." ;;
      3306)   finding "PORT-3306" "Network" "WARN" "MySQL listening ($proc)" "bind-address=127.0.0.1 unless remote DB access is required." ;;
      5432)   finding "PORT-5432" "Network" "WARN" "Postgres listening ($proc)" "listen_addresses='localhost' unless required; check pg_hba.conf for trust." ;;
      5900|5901) finding "PORT-5900" "Network" "FAIL" "VNC listening ($proc)" "VNC on a CP image is usually a backdoor. Investigate." ;;
      6667|6668|6669) finding "PORT-6667" "Network" "FAIL" "IRC listening ($proc)" "IRC daemon = botnet C2 until proven otherwise." ;;
      31337|4444|5555|12345) finding "PORT-$port" "Network" "FAIL" "suspicious high port $port listening ($proc)" "Textbook backdoor port. Find the binary, hash it, note it, kill it." ;;
    esac
  done < <(sort -t$'\t' -k3,3n -u "$EVID/20-listening.tsv" 2>/dev/null)

  # promisc mode / sniffing
  if ip link 2>/dev/null | grep -qi 'PROMISC'; then
    finding "NET-PROMISC" "Network" "FAIL" "an interface is in promiscuous mode" \
      "Strong sniffing indicator. ip link set <iface> promisc off, then hunt for the tool."
  fi

  # hosts file oddities
  if grep -Ev '^\s*(#|$|127\.0\.0\.1\s+localhost|::1\s+localhost|127\.0\.1\.1)' /etc/hosts 2>/dev/null | grep -q .; then
    finding "HOSTS" "Network" "WARN" "/etc/hosts has non-default entries" \
      "Redirect entries are used for phishing and to break updates. See $EVID/20-hosts."
  fi
# ---- persistence ------------------------------------------------------------
  step "persistence"
  { echo "### /etc/rc.local"; cat /etc/rc.local 2>/dev/null
    echo; echo "### /etc/profile.d/"; ls -la /etc/profile.d/ 2>/dev/null
    for f in /etc/profile.d/*; do [[ -f "$f" ]] && { echo "-- $f"; cat "$f"; }; done
    echo; echo "### /etc/profile"; cat /etc/profile 2>/dev/null
    echo; echo "### /etc/bash.bashrc"; cat /etc/bash.bashrc 2>/dev/null
    echo; echo "### per-user rc files"
    for d in /root /home/*; do
      for f in "$d/.bashrc" "$d/.bash_profile" "$d/.profile" "$d/.bash_login"; do
        [[ -f "$f" ]] && { echo "-- $f"; cat "$f"; }
      done
    done
  } >"$EVID/30-shell-startup.txt"

  # ld.so.preload == rootkit city
  if [[ -s /etc/ld.so.preload ]]; then
    finding "ROOTKIT-PRELOAD" "Persistence" "FAIL" "/etc/ld.so.preload is NOT empty: $(tr '\n' ' ' </etc/ld.so.preload)" \
      "This is a userland rootkit technique. Do not just delete it -- hash the library, note the path, report it, then remove."
  else
    finding "ROOTKIT-PRELOAD" "Persistence" "PASS" "/etc/ld.so.preload empty or absent"
  fi

  # cron
  { echo "### /etc/crontab"; cat /etc/crontab 2>/dev/null
    echo; echo "### /etc/cron.d/"; for f in /etc/cron.d/*; do [[ -f "$f" ]] && { echo "-- $f"; cat "$f"; }; done
    echo; echo "### cron.{hourly,daily,weekly,monthly}"
    ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    echo; echo "### user crontabs"
    for d in /var/spool/cron/crontabs/* /var/spool/cron/*; do [[ -f "$d" ]] && { echo "-- $d"; cat "$d"; }; done 2>/dev/null
    echo; echo "### crontab -l (root)"; crontab -l 2>&1
    echo; echo "### at jobs"; atq 2>&1
  } >"$EVID/31-cron.txt"
  if grep -REq '(wget|curl|nc |ncat|/dev/tcp/|base64|python -c|perl -e|bash -i)' /etc/cron* /var/spool/cron 2>/dev/null; then
    finding "CRON-SUSPECT" "Persistence" "FAIL" "cron entry downloads/executes something" \
      "cat the offending file, screenshot it, then remove the entry. Cron-based downloaders are extremely common on CP images."
  fi

  # systemd units outside the distro default
  : >"$EVID/32-systemd-units.txt"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files --type=service --state=enabled >>"$EVID/32-systemd-units.txt" 2>&1
    { echo; echo "### non-packaged units in /etc/systemd/system";
      for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/multi-user.target.wants/*; do
        [[ -e "$f" ]] && { echo "-- $f"; cat "$f" 2>/dev/null || readlink -f "$f"; echo; }
      done
    } >>"$EVID/32-systemd-units.txt"
    systemctl list-timers --all >>"$EVID/32-systemd-units.txt" 2>&1
  fi
  local u
  for u in /etc/systemd/system/*.service; do
    [[ -f "$u" ]] || continue
    if grep -Eq 'ExecStart=.*(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/home\/.*\/\.|wget|curl|nc |python -c|bash -c)' "$u" 2>/dev/null; then
      finding "UNIT-$(basename "$u")" "Persistence" "FAIL" "$u ExecStart looks malicious" \
        "systemctl cat $(basename "$u") -- then disable + mask it and record the binary path."
    fi
  done

  # processes with odd paths
  ps -eo pid,ppid,user,etimes,cmd --sort=-etimes >"$EVID/33-processes.txt" 2>&1
  while read -r pid user cmd; do
    [[ "$pid" == "PID" ]] && continue
    if [[ "$cmd" =~ ^(/tmp/|/var/tmp/|/dev/shm/|/home/[^/]+/\.) ]]; then
      finding "PROC-$pid" "Persistence" "FAIL" "pid $pid ($user) running from a writable dir: $cmd" \
        "Process running out of /tmp, /dev/shm or a dotdir = malware. ls -l /proc/$pid/exe, sha256sum it, note it, then kill."
    fi
    if [[ "$cmd" =~ (nc[[:space:]]+-[le]|ncat|socat.*exec|/dev/tcp/|cryptominer|xmrig|minerd|kdevtmpfsi) ]]; then
      finding "PROC-$pid" "Persistence" "FAIL" "pid $pid suspicious: $cmd" "Reverse shell / miner. Capture cmdline, hash the binary, kill it, then find how it starts."
    fi
  done < <(ps -eo pid,user,args 2>/dev/null)

  # deleted-but-running binaries
  find /proc/[0-9]*/exe -lname '*deleted*' -printf '%p -> %l\n' 2>/dev/null >"$EVID/34-deleted-exe.txt"
  if [[ -s "$EVID/34-deleted-exe.txt" ]]; then
    finding "PROC-DELETED" "Persistence" "FAIL" "running process(es) whose binary was deleted" \
      "Classic fileless malware. cat /proc/<pid>/cmdline, dump the binary with cat /proc/<pid>/exe > /root/evidence.bin, then kill."
  fi

  # ---- file integrity-ish checks ----------------------------------------------
  step "file permissions / SUID / world-writable"
  find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path "$EVID" -o -path "$BKROOT" \) -prune -o \
    -type f \( -perm -4000 -o -perm -2000 \) -printf '%M %u:%g %p\n' 2>/dev/null | sort >"$EVID/40-suid-sgid.txt"
  ok "SUID/SGID list: $(wc -l <"$EVID/40-suid-sgid.txt") entries -> $EVID/40-suid-sgid.txt"

  # Two very different buckets. distro-default SUID binaries (mount, su,
  # passwd, newgrp...) are NORMAL and flagging them just buries the real
  # findings under noise. editors/interpreters/network tools with SUID are
  # the actual GTFOBins problem and they are never a distro default.
  local dangerous_suid="nmap vim vim.basic vim.tiny vi nano emacs less more man gdb \
python python2 python2.7 python3 python3.9 python3.10 python3.11 perl ruby php php-cgi lua \
ftp telnet socat nc nc.openbsd ncat netcat tcpdump strace ltrace gdbserver \
env find awk gawk mawk sed cp mv dd tar zip unzip gzip rsync scp ssh \
bash sh ksh csh tcsh zsh dash ash xterm screen tmux whois \
cpulimit taskset make gcc cc time docker lxc"
  local default_suid="mount umount su sudo passwd chsh chfn newgrp gpasswd pkexec chage \
crontab at unix_chkpwd unix_chkshadow pam_timestamp_check \
fusermount fusermount3 staprun X Xorg chrome-sandbox dbus-daemon-launch-helper \
locate pppd write expire login kismet_capture"
  local mode owner path b
  local ndanger=0
  while read -r mode owner path; do
    [[ -z "$path" ]] && continue
    b="$(basename "$path")"
    local isdefault=0 d
    for d in $default_suid; do [[ "$b" == "$d" ]] && { isdefault=1; break; }; done
    if (( isdefault )); then
      # only worth a note if the ownership looks wrong
      [[ "$owner" != "root:"* ]] && finding "SUID-$b" "Permissions" "WARN" "$path is $mode owned by $owner" \
        "A SUID binary not owned by root is a privesc. chown root:root $path"
      continue
    fi
    for d in $dangerous_suid; do
      if [[ "$b" == "$d" ]]; then
        ndanger=$((ndanger+1))
        finding "SUID-$b" "Permissions" "FAIL" "$path is $mode (a shell/editor/interpreter with SUID)" \
          "GTFOBins privesc. chmod u-s $path unless the README explicitly needs it."
        break
      fi
    done
  done <"$EVID/40-suid-sgid.txt"
  (( ndanger == 0 )) && finding "SUID-DANGER" "Permissions" "PASS" "no dangerous SUID binaries (only distro defaults)"

  find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path "$EVID" -o -path "$BKROOT" \) -prune -o \
    -type f -perm -0002 ! -perm -1000 -printf '%M %u:%g %p\n' 2>/dev/null | head -500 >"$EVID/41-world-writable.txt"
  local wwc; wwc="$(wc -l <"$EVID/41-world-writable.txt")"
  if (( wwc > 0 )); then
    finding "PERM-WW" "Permissions" "WARN" "$wwc world-writable file(s) without the sticky bit" \
      "chmod o-w on each one. world-writable /etc files and scripts in PATH are the scored ones."
  fi
  find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -200 >"$EVID/42-ww-dirs.txt"
  (( $(wc -l <"$EVID/42-ww-dirs.txt") > 0 )) && finding "PERM-WWDIR" "Permissions" "WARN" "$(wc -l <"$EVID/42-ww-dirs.txt") world-writable dir(s) missing +t" "chmod +t or chmod o-w."

  # critical config perms. compare "no more permissive than" rather than exact
  # equality: /etc/shadow is 640 on Debian/Ubuntu and 000 on RHEL, and both
  # are correct. flagging the RHEL one is exactly the kind of noise that
  # makes you stop reading the report.
  local f want
  while read -r f want; do
    [[ -e "$f" ]] || continue
    local got; got="$(stat -c '%a' "$f" 2>/dev/null)"
    [[ "$got" =~ ^[0-7]{3,4}$ ]] || continue
    local g=$((8#${got: -3})) w=$((8#$want))
    if (( (g & ~w) != 0 )); then
      finding "PERM-$(basename "$f")" "Permissions" "FAIL" "$f is $got, must be no looser than $want" \
        "chmod $want $f  -- and check the owner: root:root, or root:shadow for /etc/shadow and /etc/gshadow."
    fi
  done < <(printf '%s\n' "/etc/passwd 644" "/etc/group 644" "/etc/shadow 640" "/etc/gshadow 640" \
                        "/etc/ssh/sshd_config 600" "/etc/sudoers 440" "/etc/crontab 644" \
                        "/boot/grub/grub.cfg 600")

  find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -200 >"$EVID/43-unowned.txt"
  (( $(wc -l <"$EVID/43-unowned.txt") > 0 )) && finding "PERM-UNOWNED" "Permissions" "WARN" "$(wc -l <"$EVID/43-unowned.txt") file(s) with no owner/group" "chown root:root them (or the right service user)."

  # home directory perms -- what matters is a group/other WRITE bit
  local name _ uid _ _ home shell hp
  while IFS=: read -r name _ uid _ _ home shell; do
    (( uid < 1000 )) && continue
    [[ "$shell" =~ (nologin|false) ]] && continue
    [[ -d "$home" ]] || continue
    hp="$(stat -c '%a' "$home" 2>/dev/null)"
    if [[ "${hp: -2:1}" =~ [2367] || "${hp: -1:1}" =~ [2367] ]]; then
      finding "PERM-HOME-$name" "Permissions" "WARN" "$home is mode $hp (group or other writable)" "chmod 750 $home (or 700). Group/other-writable homes are scored."
    fi
    [[ -f "$home/.rhosts" ]] && finding "PERM-RHOSTS-$name" "Persistence" "FAIL" "$home/.rhosts exists" "rhosts = passwordless remote trust. Delete it."
    [[ -f "$home/.netrc" ]] && finding "PERM-NETRC-$name" "Persistence" "WARN" "$home/.netrc exists" "Often contains plaintext FTP/HTTP creds."
  done < <(getent passwd)

  # immutable attributes (attackers love chattr +i)
  if command -v lsattr >/dev/null 2>&1; then
    # lsattr -R emits bare directory headers like "/etc/init.d:" which contain
    # an 'i' -- matching the whole line gives a page of false positives.
    # the attribute string is field 1 and only exists on real file lines.
    lsattr -R /etc /root /home /var/spool/cron 2>/dev/null \
      | awk 'NF>=2 && $1 ~ /i/ {print}' >"$EVID/44-immutable.txt"
    if [[ -s "$EVID/44-immutable.txt" ]]; then
      finding "FS-IMMUTABLE" "Persistence" "WARN" "immutable (+i) files found, see $EVID/44-immutable.txt" \
        "chattr +i on a config or a dropped binary stops you from fixing it. chattr -i, then re-check the file."
    fi
  fi

  # ---- recently touched files ------------------------------------------------
  step "recently modified files"
  find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path "$EVID" -o -path "$BKROOT" -o -path /var/lib -o -path /var/cache \) -prune -o \
    -type f -mtime -180 -printf '%T+ %M %u:%g %s %p\n' 2>/dev/null | sort -r | head -3000 >"$EVID/50-recent-files.txt"
  ok "recent files -> $EVID/50-recent-files.txt ($(wc -l <"$EVID/50-recent-files.txt") rows)"

  # ---- prohibited media hunt ---------------------------------------------------
  step "prohibited media hunt"
  find / -xdev -type f \( \
        -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' \
        -o -iname '*.mov' -o -iname '*.wmv' -o -iname '*.flv' -o -iname '*.wav' \
        -o -iname '*.ogg' -o -iname '*.flac' -o -iname '*.m4a' -o -iname '*.m4v' \
        -o -iname '*.torrent' -o -iname '*.pcap' \
        \) 2>/dev/null | grep -v '/usr/share/' | tee "$EVID/52-media-found.txt" | head -40 | sed 's/^/    /'
  # NB: no `|| echo 0` here -- grep already prints 0 and exits 1 on an empty
  # file, so the fallback would append a second 0 and break the arithmetic.
  local mc; mc="$(grep -vc '^[[:space:]]*$' "$EVID/52-media-found.txt" 2>/dev/null)"
  [[ -z "$mc" ]] && mc=0
  if (( mc > 0 )); then
    finding "MEDIA" "Files" "WARN" "$mc prohibited-media candidate(s) -> $EVID/52-media-found.txt" \
      "Delete ONLY what the README calls prohibited. /usr/share backgrounds are already filtered out -- those are fine."
  else
    finding "MEDIA" "Files" "PASS" "no media files outside /usr/share"
  fi

  # ---- PII / secrets grep (report only, NEVER delete) ---------------------------
  # Scan only where business data actually lives, and only file types that can
  # plausibly hold it. grepping all of /opt and /usr turns up thousands of
  # hits in vendored libraries and the one real finding disappears.
  step "PII / cleartext credential hunt"
  : >"$EVID/51-pii-candidates.txt"
  local pii_roots="/home /root /var/www /srv /mnt /media /opt /var/ftp /tmp /etc"
  # prune vendored library trees AND every artifact this script has ever
  # written, or the scan finds our own output and reports it back as a leak.
  local pii_prune=( -path "$EVID" -o -path "$BKROOT" -o -path /var/log
                    -o -name node_modules -o -name site-packages -o -name dist-packages
                    -o -name vendor -o -name .git -o -name __pycache__
                    -o -name '*.egg-info' -o -name .venv -o -name venv
                    -o -path '*/lib/python*' -o -path '*/lib64/python*'
                    -o -path '*/share/doc/*' -o -path '*/share/man/*'
                    -o -path /etc/ssl -o -path /etc/pam.d -o -path /etc/ssh
                    -o -name 'cbptlinux-evidence' -o -name 'cbptlinux-backup'
                    -o -name 'cbptlinux-*.log' -o -name 'findings.tsv' -o -name 'changes.tsv'
                    -o -name 'readme-candidates.txt' -o -name '*-pii-candidates.txt' )
  local pii_exts="txt csv tsv md rst xml json yaml yml ini conf cfg cnf env sql
                  doc docx xls xlsx ppt pptx rtf odt bak old save orig htm html"
  local -a pii_names=( )
  local e first=1
  for e in $pii_exts; do
    if (( first )); then pii_names+=( -iname "*.$e" ); first=0
    else pii_names+=( -o -iname "*.$e" ); fi
  done

  local pii_files="$EVID/.pii-filelist"
  : >"$pii_files"
  local pr
  for pr in $pii_roots; do
    [[ -d "$pr" ]] || continue
    find "$pr" -xdev \( "${pii_prune[@]}" \) -prune -o \
      -type f -size -2M \( "${pii_names[@]}" \) -print 2>/dev/null >>"$pii_files"
  done
  for pr in /home /root /var/www /srv; do
    [[ -d "$pr" ]] || continue
    find "$pr" -xdev -maxdepth 3 -type f -size -2M \
      \( -iname 'README*' -o -iname 'PASSWORDS*' -o -iname 'passwords*' -o -iname 'creds*' \
         -o -iname '*.env' -o -iname 'htpasswd' -o -iname '.htpasswd' \) \
      -print 2>/dev/null >>"$pii_files"
  done
  sort -u "$pii_files" -o "$pii_files"
  local pii_total; pii_total="$(wc -l <"$pii_files")"
  say "scanning $pii_total document-type file(s) for SSN / card / cleartext-credential patterns"

  local ssn_re='\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
  local cred_keys='password|passwd|pwd|passphrase|passcode|secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|token|credential|private[_-]?key|connection[_-]?string'
  local cred_re="(^|[^A-Za-z0-9])(${cred_keys})([[:space:]]*[:=][[:space:]]*[\"']?|[\"']?[[:space:]]+)[^[:space:]\"']{4,}"
  local pem_re='BEGIN (RSA |OPENSSH |DSA |EC )?PRIVATE KEY'
  local card_re='\b(4[0-9]{12}([0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(011|5[0-9]{2})[0-9]{12})\b'

  if (( pii_total > 0 )); then
    # values that are legitimately not secrets: mostly config-file idioms.
    # "passwd: files systemd" in nsswitch.conf otherwise fires on every image.
    local notsecret='files|systemd|sss|sssd|db|ldap|nis|compat|dns|mdns|resolve|mymachines|myhostname|nisplus|hesiod|usrfiles|winbind|md5|sha256|sha512|crypt|yes|no|on|off|true|false|none|null|nil|auto|manual|disabled|enabled|0|1|2|'
    # placeholder shapes: "your_api_key_here", "*SECRET*", "${VAR}". NOT listed
    # on purpose: changeme, admin, Password1 -- on a CP image a weak default
    # password IS the finding.
    local placeholder='^(your|their|my|the|some|new|old|enter|insert|type)[_.-]?(password|passwd|pwd|passphrase|secret|key|token|credential)|[_-]here$|^-here$|^placeholder$|^example$|^sample$|^dummy$|^lorem|^x{3,}$|^\*+$|^\.+$'

    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      local hit="" m v k vn body is_template
      # ignore comment lines; a documented example is not a leaked credential
      body="$(grep -Ev '^[[:space:]]*[#;]' "$f" 2>/dev/null)"
      [[ -z "$body" ]] && continue
      if printf '%s\n' "$body" | grep -qIm1 -E "$pem_re" 2>/dev/null; then
        hit="private-key-material"
      elif printf '%s\n' "$body" | grep -qIm1 -E "$ssn_re" 2>/dev/null; then
        hit="SSN-pattern"
      else
        m="$(printf '%s\n' "$body" | grep -ohIm1 -iE "$cred_re" 2>/dev/null | head -1)"
        if [[ -n "$m" ]]; then
          v="${m##*[=:]}"
          v="${v//[[:space:]\"]/}"
          v="${v//\'/}"
          k="$(printf '%s' "$m" | grep -oiE "$cred_keys" | head -1 | tr 'A-Z' 'a-z' | tr -d '_-')"
          vn="$(printf '%s' "$v" | tr 'A-Z' 'a-z' | tr -d '_-')"
          is_template=0
          [[ -z "$v" ]] && is_template=1
          printf '%s' "$v" | grep -qiE "^(${notsecret})$" && is_template=1
          [[ -n "$k" ]] && printf '%s' "$vn" | grep -qiF "$k" && is_template=1
          printf '%s' "$v" | grep -qiE "$placeholder" && is_template=1
          case "$v" in
            \*\*\*|\**\*|\<*\>|\$\{*\}|\{*\}|%s|%d|\.|\.\*) is_template=1 ;;
          esac
          (( is_template == 0 )) && hit="cleartext-credential"
        fi
      fi
      if [[ -z "$hit" ]] && printf '%s\n' "$body" | grep -qIm1 -E "$card_re" 2>/dev/null; then
        hit="card-pattern"
      fi
      [[ -n "$hit" ]] && printf '%s\t%s\n' "$hit" "$f" >>"$EVID/51-pii-candidates.txt"
    done < <(head -4000 "$pii_files")
  fi
  rm -f "$pii_files"

  local pc; pc="$(wc -l <"$EVID/51-pii-candidates.txt" 2>/dev/null || echo 0)"
  if (( pc > 0 )); then
    finding "PII" "Data" "WARN" "$pc file(s) with SSN / card / cleartext-credential patterns" \
      "PII exposure is normally a scored item AND a README task. Record the exact path in your report. Do NOT delete the file -- deleting business data loses points."
    head -25 "$EVID/51-pii-candidates.txt" | while IFS=$'\t' read -r t f; do
      printf '     %-20s %s\n' "$t" "$f"
    done
    (( pc > 25 )) && say "     ... and $((pc-25)) more in $EVID/51-pii-candidates.txt"
  else
    finding "PII" "Data" "PASS" "no SSN / card / cleartext-credential patterns in document files"
  fi

  # ---- logs / history ----------------------------------------------------------
  step "logs and shell history"
  for l in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/kern.log \
           /var/log/faillog /var/log/lastlog /var/log/wtmp /var/log/btmp /var/log/dpkg.log /var/log/apt/history.log \
           /var/log/apache2/access.log /var/log/nginx/access.log /var/log/vsftpd.log \
           /var/log/mysql/error.log /var/log/mail.log; do
    [[ -e "$l" ]] && cp -a "$l" "$EVID/logs-$(basename "$l")" 2>/dev/null
  done
  : >"$EVID/60-bash-history.txt"
  for d in /root /home/*; do
    [[ -f "$d/.bash_history" ]]    && { echo "===== $d/.bash_history";    cat "$d/.bash_history";    echo; } >>"$EVID/60-bash-history.txt"
    [[ -f "$d/.python_history" ]]  && { echo "===== $d/.python_history";  cat "$d/.python_history";  echo; } >>"$EVID/60-bash-history.txt"
    [[ -f "$d/.mysql_history" ]]   && { echo "===== $d/.mysql_history";   cat "$d/.mysql_history";   echo; } >>"$EVID/60-bash-history.txt"
    [[ -f "$d/.wget-hsts" ]]       && { echo "===== $d/.wget-hsts";       cat "$d/.wget-hsts";       echo; } >>"$EVID/60-bash-history.txt"
  done
  [[ -s "$EVID/60-bash-history.txt" ]] && finding "HIST" "Forensics" "INFO" "shell history dumped to $EVID/60-bash-history.txt" \
    "History is the single best source of forensic answers: what the attacker ran, what passwords were typed on a command line, what got downloaded."

  if command -v lastb >/dev/null 2>&1; then
    lastb -a -n 200 >"$EVID/61-failed-logins.txt" 2>&1
    (( $(wc -l <"$EVID/61-failed-logins.txt") > 3 )) && finding "AUTH-FAIL" "Forensics" "INFO" "$(wc -l <"$EVID/61-failed-logins.txt") failed login record(s)" \
      "Brute-force evidence. Note the source IP and username -- that is often a forensic answer."
  fi
  local pat c
  for pat in 'Failed password' 'Accepted password' 'session opened for user root' 'sudo:'; do
    c=$(grep -rc "$pat" /var/log/auth.log /var/log/secure 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
    (( c > 0 )) && say "  '$pat' -> $c hit(s)"
  done

  # USB / mount traces
  { echo "### dmesg usb"; dmesg 2>/dev/null | grep -iE 'usb|sd[a-z]: ' | tail -200
    echo; echo "### /var/log/kern.log usb"; grep -iE 'usb|sd[a-z]:' /var/log/kern.log* 2>/dev/null | tail -200
    echo; echo "### mounts"; cat /proc/mounts
    echo; echo "### fstab"; cat /etc/fstab
    echo; echo "### udisks"; ls -la /media /mnt /run/media/* 2>/dev/null
  } >"$EVID/62-usb-mounts.txt" 2>&1
  finding "USB" "Forensics" "INFO" "USB/mount traces -> $EVID/62-usb-mounts.txt" \
    "For 'what device was connected' questions: dmesg, kern.log, /var/log/syslog, and /media/* leftover mount dirs."

  # ---- packages -----------------------------------------------------------------
  step "packages"
  case "$PKG" in
    apt)
      apt-mark showmanual >"$EVID/70-manual-packages.txt" 2>&1
      dpkg -l >"$EVID/70-dpkg.txt" 2>&1
      zgrep -h . /var/log/dpkg.log* 2>/dev/null | tail -2000 >"$EVID/70-dpkg-log.txt"
      zgrep -h . /var/log/apt/history.log* 2>/dev/null >"$EVID/70-apt-history.txt"
      ;;
    dnf|yum)
      dnf history list >"$EVID/70-dnf-history.txt" 2>&1 || yum history list >"$EVID/70-dnf-history.txt" 2>&1
      rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME:date}\n' | sort >"$EVID/70-rpm.txt" 2>&1
      ;;
    zypper) rpm -qa >"$EVID/70-rpm.txt" 2>&1 ;;
    pacman) pacman -Qe >"$EVID/70-explicit.txt" 2>&1; pacman -Q >"$EVID/70-all.txt" 2>&1 ;;
  esac
  local badpkgs="telnet telnetd rsh-server rsh-client rlogin rexec ypserv tftp tftpd talk talkd \
                 xinetd finger fingerd nmap zenmap netcat netcat-openbsd ncat socat \
                 john john-data hashcat hydra aircrack-ng metasploit-framework nikto sqlmap wireshark \
                 ophcrack ettercap-common medusa dsniff tcpflow kismet netdiscover logkeys \
                 transmission-.* deluge.* qbittorrent bittorrent freeciv.* minetest.* supertux.* wesnoth.* \
                 gnome-games gnome-games-.* gnome-mines gnome-sudoku aisleriot quadrapassel frozen-bubble"
  local p m
  for p in $badpkgs; do
    m="$(pkg_find_installed "$p" 2>/dev/null)"
    [[ -n "$m" ]] || continue
    case "$p" in
      telnet|telnetd|rsh-server|rsh-client|ypserv|tftp|tftpd|talk|talkd|finger|fingerd|xinetd)
        finding "PKG-$p" "Software" "FAIL" "$(echo "$m" | tr '\n' ' ') installed" \
          "Insecure legacy daemon. Remove it (needs --aggressive) and confirm the port is closed." ;;
      *)
        finding "PKG-${p%%.*}" "Software" "WARN" "$(echo "$m" | tr '\n' ' ') installed" \
          "Attack tooling / game / p2p on a business host = policy violation. Confirm against the README, then purge and document it." ;;
    esac
  done
  # manually installed stuff not from the distro
  find /usr/local/bin /usr/local/sbin /opt -maxdepth 2 -type f -perm /111 2>/dev/null >"$EVID/71-local-binaries.txt"
  (( $(wc -l <"$EVID/71-local-binaries.txt") > 0 )) && finding "PKG-LOCAL" "Software" "INFO" "$(wc -l <"$EVID/71-local-binaries.txt") binary(ies) outside the package manager" \
    "Anything in /usr/local/bin or /opt the package manager does not own deserves a look. sha256sum it and check the README."

  # ---- bootloader ------------------------------------------------------------------
  step "boot"
  if [[ -f /boot/grub/grub.cfg ]] && grep -Eq '^\s*password|^\s*set superusers' /boot/grub/grub.cfg; then
    finding "BOOT-GRUBPW" "Boot" "PASS" "grub has a superuser/password entry"
  else
    finding "BOOT-GRUBPW" "Boot" "WARN" "grub has no password / superusers" \
      "grub-mkpasswd-pbkdf2, then set superusers + password_pbkdf2 in /etc/grub.d/40_custom and update-grub. Single-user boot bypass is a real scored item."
  fi

  # rootkit scanners if available
  for t in rkhunter chkrootkit; do
    if command -v $t >/dev/null 2>&1; then
      step "$t"
      $t --check >"$EVID/80-$t.txt" 2>&1 || $t >"$EVID/80-$t.txt" 2>&1
      grep -Ei 'warning|infected|found' "$EVID/80-$t.txt" | head -20
      finding "RKT-$t" "Malware" "INFO" "$t output -> $EVID/80-$t.txt"
    fi
  done

  ok "evidence collection done: $(find "$EVID" -type f | wc -l) files in $EVID"
}
# ---------------------------------------------------------------------------
# USERS + GROUPS. reconciles accounts against users.txt / admins.txt (copied
# from the README), fixes sudo membership, shells, aging, and the display
# manager. never deletes anything without asking.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

read_list() {
  # one name per line, '#' starts a comment. template created if missing.
  # NB: everything except the list itself goes to stderr -- this is consumed
  # by mapfile, and a stray warn on stdout becomes a fake username.
  local f="$1" tpl="$2"
  if [[ ! -f "$f" ]]; then
    if (( DRY )); then say "[dry-run] would create template $f" >&2; return 1; fi
    printf '%s\n' "$tpl" >"$f" && warn "created template $f -- fill it from the README and re-run" >&2
    return 1
  fi
  tr -d '\r' <"$f" | sed 's/#.*//;s/[[:space:]]//g;/^$/d'
}

do_users() {
  banner "USERS + GROUPS"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: accounts untouched"; return; }
  local made=0
  [[ -f "$SCRIPT_DIR/users.txt"  ]] || { (( DRY )) || { printf '# standard (non-admin) users from the README, one per line\n' >"$SCRIPT_DIR/users.txt"; made=1; } ; }
  [[ -f "$SCRIPT_DIR/admins.txt" ]] || { (( DRY )) || { printf '# administrators from the README, one per line\n'            >"$SCRIPT_DIR/admins.txt"; made=1; }; }
  (( made )) && warn "users.txt / admins.txt templates created next to the script."

  local -a A=() S=()
  mapfile -t A < <(read_list "$SCRIPT_DIR/admins.txt" '# administrators from the README, one per line' || true)
  mapfile -t S < <(read_list "$SCRIPT_DIR/users.txt"  '# standard (non-admin) users from the README, one per line' || true)
  if (( ${#A[@]} + ${#S[@]} == 0 )); then
    warn "users.txt / admins.txt are empty. fill them in from the README, then run users again."
    review "users.txt/admins.txt empty: account reconciliation skipped"
  else
    local -A isadmin=() isok=()
    local n
    for n in "${A[@]}"; do isadmin["$n"]=1; isok["$n"]=1; done
    for n in "${S[@]}"; do isok["$n"]=1; done
    local me="${SUDO_USER:-}"
    local admingrp="sudo"
    if ! getent group sudo >/dev/null 2>&1; then
      getent group wheel >/dev/null 2>&1 && admingrp="wheel"
    fi

    local -a real=()
    mapfile -t real < <(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd)

    # 1. accounts that should not exist
    local u
    for u in "${real[@]}"; do
      [[ -n "${isok[$u]:-}" ]] && continue
      warn "'$u' is not in users.txt / admins.txt"
      if [[ "$u" == "$me" ]]; then
        review "you are logged in as '$u' but it is not on the lists -- re-read the README"
        continue
      fi
      if ask "Delete '$u' and their home directory?"; then
        if [[ "$PKG" == apt ]]; then
          act deluser --remove-home "$u" && change "user:$u" "present" "deleted"
        else
          act userdel -r "$u" && change "user:$u" "present" "deleted"
        fi
      else
        review "unlisted account '$u' left in place"
      fi
    done

    # 2. accounts the README wants that are missing
    for n in "${!isok[@]}"; do
      id "$n" &>/dev/null && continue
      if ask "'$n' is on the lists but does not exist. Create it?"; then
        if [[ "$PKG" == apt ]]; then
          act adduser --disabled-password --gecos "" "$n"
        else
          act useradd -m -s /bin/bash "$n"
        fi
      fi
    done
    mapfile -t real < <(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd)

    # 3. sudo membership
    local insudo
    for u in "${real[@]}"; do
      [[ -n "${isok[$u]:-}" ]] || continue
      insudo=0
      id -nG "$u" | tr ' ' '\n' | grep -qx "$admingrp" && insudo=1
      if [[ -n "${isadmin[$u]:-}" ]]; then
        (( insudo )) || { ask "'$u' is an admin per the README but not in $admingrp. Add?" && act usermod -aG "$admingrp" "$u"; }
      else
        (( insudo )) && { ask "'$u' is in $admingrp but is a standard user. Remove?" && act gpasswd -d "$u" "$admingrp"; }
      fi
    done
    say "current $admingrp/admin members:"; getent group "$admingrp" 2>/dev/null | sed 's/^/    /'
  fi

  # 4. one strong password on every authorized account (optional)
  if (( ${#S[@]} + ${#A[@]} > 0 )); then
    if ask "Set one new strong password on every authorized account?"; then
      local p1 p2
      read -rsp "  new password (10+ chars): " p1; echo
      read -rsp "  again: " p2; echo
      if [[ "$p1" == "$p2" && ${#p1} -ge 10 ]]; then
        local u
        for u in "${real[@]}"; do
          [[ -n "${isok[$u]:-}" ]] || continue
          if (( DRY )); then say "[dry-run] chpasswd $u"; else printf '%s:%s\n' "$u" "$p1" | chpasswd && log "password set for $u"; fi
        done
        ok "passwords updated - write the new one down"
      else
        warn "passwords differ or are shorter than 10 characters - skipped"
      fi
    fi
    ask "Lock the root account's password (sudo keeps working)?" && act passwd -l root
  fi

  # 5. shells for system daemons that somehow got a real shell
  local a sh nologin="/usr/sbin/nologin"
  command -v nologin >/dev/null || nologin="/sbin/nologin"
  [[ -x "$nologin" ]] || nologin="/bin/false"
  for a in bin daemon games lp mail news uucp proxy www-data backup list irc gnats _apt \
           systemd-timesync systemd-network systemd-resolve messagebus syslog nobody ftp tftp; do
    if getent passwd "$a" >/dev/null 2>&1; then
      sh="$(getent passwd "$a" | cut -d: -f7)"
      if [[ ! "$sh" =~ (nologin|false|sync|shutdown|halt) ]]; then
        act usermod -s "$nologin" "$a" && { ok "$a shell -> $nologin"; change "shell:$a" "$sh" "$nologin"; }
      fi
    fi
  done

  # root shell sanity
  local rc; rc="$(getent passwd root | cut -d: -f7)"
  [[ "$rc" =~ (nologin|false) ]] && finding "USER-ROOTSHELL" "Accounts" "FAIL" "root shell is $rc" \
    "You will not be able to log in as root. usermod -s /bin/bash root" || \
    finding "USER-ROOTSHELL" "Accounts" "PASS" "root shell = $rc"

  # 6. empty password fields -> lock (locking is reversible, deleting is not)
  while IFS=: read -r name pass rest; do
    if [[ -z "$pass" ]]; then
      if [[ $DRY -eq 1 || $PARANOID -eq 1 ]]; then warn "paranoid/dry: would lock '$name' (empty password)"; continue; fi
      if confirm "Lock account '$name' (empty password)? Say no if the README authorizes it."; then
        passwd -l "$name" >/dev/null 2>&1 && { ok "locked $name"; change "lock:$name" "empty password" "locked"; }
      else
        finding "USER-LOCK-$name" "Accounts" "SKIP" "left unlocked by operator"
      fi
    fi
  done < <(awk -F: '($2==""){print $1":"$2":"$3}' /etc/shadow 2>/dev/null)

  # 7. /etc/passwd- / shadow- leftovers (only matter if looser than original)
  local f m orig om
  for f in /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-; do
    [[ -f "$f" ]] || continue
    m="$(stat -c '%a' "$f" 2>/dev/null)"
    orig="${f%-}"; om="$(stat -c '%a' "$orig" 2>/dev/null || echo 000)"
    if (( (8#${m: -3}) > (8#${om: -3}) )); then
      finding "USER-BACKUP-$(basename "$f")" "Permissions" "WARN" "$f is $m but $orig is $om (backup is looser)" \
        "chmod $om $f -- a backup copy more readable than the original leaks password hashes."
    elif [[ "${m: -1}" != "0" && "$f" == *shadow* ]]; then
      finding "USER-BACKUP-$(basename "$f")" "Permissions" "WARN" "$f is $m (world has access)" \
        "chmod o-rwx $f. A world-readable shadow backup leaks every password hash on the box."
    fi
  done

  # 8. group + dup sanity
  local rootgrp; rootgrp="$(getent group root | cut -d: -f4)"
  [[ -n "$rootgrp" ]] && finding "GRP-ROOT" "Accounts" "WARN" "group 'root' has members: $rootgrp" \
    "gpasswd -d <user> root unless the README wants it."
  for g in wheel sudo admin; do
    local m2; m2="$(getent group "$g" 2>/dev/null | cut -d: -f4)"
    [[ -n "$m2" ]] && finding "GRP-$g" "Accounts" "INFO" "$g members: $m2" \
      "Every member of $g can become root. Verify each against the README authorized-user list."
  done
  local du duid
  du="$(cut -d: -f1 /etc/passwd | sort | uniq -d | tr '\n' ' ')"
  [[ -n "$du" ]] && finding "USER-DUPNAME" "Accounts" "FAIL" "duplicate usernames: $du"
  duid="$(cut -d: -f3 /etc/passwd | sort -n | uniq -d | tr '\n' ' ')"
  [[ -n "$duid" ]] && finding "USER-DUPUID" "Accounts" "FAIL" "duplicate UIDs: $duid"
  [[ -z "$du$duid" ]] && finding "USER-DUP" "Accounts" "PASS" "no duplicate usernames or UIDs"

  # legacy trust files
  for f in /etc/hosts.equiv /etc/hosts.lpd /etc/shosts.equiv; do
    [[ -e "$f" ]] && { finding "USER-$f" "Persistence" "FAIL" "$f exists" "r-commands trust file. Remove it."; }
  done
  find /home /root -maxdepth 2 -name '.rhosts' -o -maxdepth 2 -name '.shosts' 2>/dev/null | while read -r f; do
    finding "USER-RHOSTS" "Persistence" "FAIL" "$f exists" "Remove .rhosts -- it grants passwordless remote access."
  done

  # 9. /etc/login.defs
  step "/etc/login.defs"
  backup_file /etc/login.defs
  local -A LD=(
    [PASS_MAX_DAYS]="$PASS_MAX_DAYS" [PASS_MIN_DAYS]="$PASS_MIN_DAYS"
    [PASS_MIN_LEN]="$PASS_MIN_LEN" [PASS_WARN_AGE]="$PASS_WARN_AGE"
    [UID_MIN]=1000 [GID_MIN]=1000 [SYS_UID_MIN]=101 [SYS_UID_MAX]=999
    [SYS_GID_MIN]=101 [SYS_GID_MAX]=999 [UMASK]=027 [USERGROUPS_ENAB]=yes
    [ENCRYPT_METHOD]=SHA512 [SHA_CRYPT_MIN_ROUNDS]=10000 [SHA_CRYPT_MAX_ROUNDS]=100000
    [LOGIN_RETRIES]=3 [LOGIN_TIMEOUT]=60 [CHFN_RESTRICT]=rwh [DEFAULT_HOME]=no
    [MAIL_DIR]=/var/mail [FAILLOG_ENAB]=yes [LASTLOG_ENAB]=yes [SYSLOG_SU_ENAB]=yes
    [SYSLOG_SG_ENAB]=yes [LOG_UNKFAIL_ENAB]=yes [CREATE_HOME]=yes [MD5_CRYPT_ENAB]=no
  )
  local k
  for k in "${!LD[@]}"; do
    # NB: no \b here. grep -E understands it but awk reads \b as a
    # backspace, so the replacer inside ensure_line silently matches nothing.
    ensure_line /etc/login.defs "^[[:space:]]*#?[[:space:]]*${k}([[:space:]]|\$)" "${k}   ${LD[$k]}"
  done
  [[ $DRY -eq 0 ]] && ok "login.defs written"
  if [[ $DRY -eq 1 ]]; then
    finding "LD-UMASK" "Accounts" "INFO" "login.defs UMASK=027 would be set (dry-run)"
    finding "LD-PASSLEN" "Accounts" "INFO" "login.defs PASS_MIN_LEN=$PASS_MIN_LEN, MAX_DAYS=$PASS_MAX_DAYS, MIN_DAYS=$PASS_MIN_DAYS would be set (dry-run)"
  else
    if grep -qE '^[[:space:]]*UMASK[[:space:]]+027([[:space:]]|$)' /etc/login.defs; then
      finding "LD-UMASK" "Accounts" "PASS" "login.defs UMASK=027"
    else
      finding "LD-UMASK" "Accounts" "WARN" "login.defs UMASK is not 027" \
        "Set UMASK 027 in /etc/login.defs and re-run the password module."
    fi
    if grep -qE "^[[:space:]]*PASS_MAX_DAYS[[:space:]]+$PASS_MAX_DAYS([[:space:]]|$)" /etc/login.defs \
       && grep -qE "^[[:space:]]*PASS_MIN_DAYS[[:space:]]+$PASS_MIN_DAYS([[:space:]]|$)" /etc/login.defs \
       && grep -qE "^[[:space:]]*PASS_MIN_LEN[[:space:]]+$PASS_MIN_LEN([[:space:]]|$)" /etc/login.defs; then
      finding "LD-PASSLEN" "Accounts" "PASS" "login.defs PASS_MIN_LEN=$PASS_MIN_LEN, MAX_DAYS=$PASS_MAX_DAYS, MIN_DAYS=$PASS_MIN_DAYS"
    else
      finding "LD-PASSLEN" "Accounts" "WARN" "login.defs password aging/length values are not all applied" \
        "Check PASS_MAX_DAYS/PASS_MIN_DAYS/PASS_MIN_LEN in /etc/login.defs."
    fi
  fi

  # 10. apply aging to existing interactive accounts
  if [[ $DRY -eq 0 && $PARANOID -eq 0 ]]; then
    chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" root >/dev/null 2>&1 && \
      say "  chage applied to root"
    while IFS=: read -r name _ uid _ _ home shell; do
      (( uid < 1000 )) && continue
      [[ "$shell" =~ (nologin|false) ]] && continue
      chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$name" >/dev/null 2>&1 && say "  chage applied to $name"
    done < <(getent passwd)
  fi

  # 11. graphical login: guest + autologin
  if [[ -d /etc/lightdm ]]; then
    act mkdir -p /etc/lightdm/lightdm.conf.d
    if [[ $DRY -eq 0 ]]; then
      [[ -f /etc/lightdm/lightdm.conf.d/99-cbptlinux.conf ]] && backup_file /etc/lightdm/lightdm.conf.d/99-cbptlinux.conf
      [[ -e /etc/lightdm/lightdm.conf.d/99-cbptlinux.conf ]] || created_file /etc/lightdm/lightdm.conf.d/99-cbptlinux.conf
      printf '[Seat:*]\nallow-guest=false\nautologin-user=\ngreeter-hide-users=true\ngreeter-show-manual-login=true\n' \
        > /etc/lightdm/lightdm.conf.d/99-cbptlinux.conf
      ok "LightDM: guest + autologin off"
    else
      say "[dry-run] lightdm guest/autologin off"
    fi
  fi
  if [[ -f /etc/gdm3/custom.conf ]]; then
    ensure_line /etc/gdm3/custom.conf "^[[:space:]]*#?[[:space:]]*AutomaticLoginEnable" "AutomaticLoginEnable=false"
    ensure_line /etc/gdm3/custom.conf "^[[:space:]]*#?[[:space:]]*TimedLoginEnable"     "TimedLoginEnable=false"
  fi
  grep -rniE 'autologin|allow-guest' /etc/lightdm /etc/gdm3 /etc/sddm.conf* 2>/dev/null | grep -v '^.*:\s*#' | sed 's/^/    /'
}

# ---------------------------------------------------------------------------
# PASSWORD POLICY (PAM)
# ---------------------------------------------------------------------------
do_passwords() {
  banner "PASSWORD POLICY (PAM)"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: PAM untouched"; return; }

  # NB: pam_pwquality / pam_faillock are MODULE names, not package names.
  case "$PKG" in
    apt)   pkg_install libpam-pwquality libpam-cracklib cracklib-runtime libpam-modules ;;
    dnf|yum|zypper) pkg_install libpwquality cracklib-dicts pam ;;
    pacman) pkg_install libpwquality pam ;;
  esac

  local have_pwq=0 have_faillock=0
  local so
  for so in /lib/x86_64-linux-gnu/security/pam_pwquality.so \
            /lib64/security/pam_pwquality.so /lib/security/pam_pwquality.so \
            /usr/lib/security/pam_pwquality.so /usr/lib64/security/pam_pwquality.so; do
    [[ -f "$so" ]] && have_pwq=1
  done
  for so in /lib/x86_64-linux-gnu/security/pam_faillock.so \
            /lib64/security/pam_faillock.so /lib/security/pam_faillock.so \
            /usr/lib/security/pam_faillock.so /usr/lib64/security/pam_faillock.so; do
    [[ -f "$so" ]] && have_faillock=1
  done

  # --- pwquality config (distro neutral, read by pam_pwquality) ---
  backup_file /etc/security/pwquality.conf
  if [[ $DRY -eq 0 && ! -e /etc/security/pwquality.conf ]]; then
    created_file /etc/security/pwquality.conf
  fi
  if [[ $DRY -eq 0 ]]; then
    cat >/etc/security/pwquality.conf <<'PWQ'
# written by cbptlinux.sh -- CyberPatriot baseline
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
difok = 4
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
PWQ
  else
    say "[dry-run] write /etc/security/pwquality.conf"
  fi
  [[ $DRY -eq 0 ]] && ok "/etc/security/pwquality.conf written"
  if [[ $DRY -eq 1 ]]; then
    finding "PAM-PWQ-CONF" "Passwords" "INFO" "pwquality settings would be written (dry-run)"
  elif grep -qE '^[[:space:]]*minlen[[:space:]]*=[[:space:]]*14([[:space:]]|$)' /etc/security/pwquality.conf \
       && grep -qE '^[[:space:]]*minclass[[:space:]]*=[[:space:]]*4([[:space:]]|$)' /etc/security/pwquality.conf; then
    finding "PAM-PWQ-CONF" "Passwords" "PASS" "pwquality: minlen 14, 4 classes, difok 4"
  else
    finding "PAM-PWQ-CONF" "Passwords" "WARN" "pwquality.conf does not contain the expected minlen/minclass" \
      "Set minlen = 14 and minclass = 4 in /etc/security/pwquality.conf."
  fi

  # --- wire it into PAM ---
  local pwfile authfile
  if [[ -f /etc/pam.d/common-password ]]; then
    pwfile=/etc/pam.d/common-password; authfile=/etc/pam.d/common-auth
  else
    pwfile=/etc/pam.d/password-auth; authfile=/etc/pam.d/system-auth
  fi
  if [[ ! -f "$pwfile" ]]; then
    err "no PAM password stack found ($pwfile). Skipping PAM edits -- do these by hand."
    finding "PAM-STACK" "Passwords" "WARN" "PAM stack not found" \
      "On SUSE use /etc/pam.d/common-password; on RHEL use password-auth/system-auth (or authselect/authconfig)."
    return
  fi

  backup_file "$pwfile"; [[ -f "$authfile" ]] && backup_file "$authfile"

  # SAFETY: keep a copy we can slam back in one command if we lock ourselves out
  if [[ $DRY -eq 0 ]]; then
    cp -a "$pwfile" "${pwfile}.cbptlinuxbak-$STAMP" 2>/dev/null
    [[ -f "$authfile" ]] && cp -a "$authfile" "${authfile}.cbptlinuxbak-$STAMP" 2>/dev/null
    warn "PAM backups: ${pwfile}.cbptlinuxbak-$STAMP  (cp it back + reboot if you get locked out)"
  fi

  if [[ $have_pwq -eq 1 ]]; then
    if [[ $DRY -eq 1 ]]; then
      say "[dry-run] wire pam_pwquality into $pwfile"
      finding "PAM-PWQ" "Passwords" "INFO" "pam_pwquality would be wired (dry-run)"
    else
      if grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$pwfile"; then
        sed -i -E '/^[[:space:]]*password.*pam_pwquality\.so/ s|^.*$|password\trequisite\tpam_pwquality.so retry=3 enforce_for_root|' "$pwfile"
      else
        # insert before the first password line, then append only if the stack is unusual
        sed -i -E '0,/^[[:space:]]*password[[:space:]]/{s|^([[:space:]]*password[[:space:]].*)$|password\trequisite\tpam_pwquality.so retry=3 enforce_for_root\n\1|}' "$pwfile"
        grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$pwfile" || \
          printf 'password\trequisite\tpam_pwquality.so retry=3 enforce_for_root\n' >>"$pwfile"
      fi
      if grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$pwfile"; then
        ok "pam_pwquality wired into $pwfile"
        finding "PAM-PWQ" "Passwords" "PASS" "pam_pwquality active"
      else
        finding "PAM-PWQ" "Passwords" "WARN" "could not wire pam_pwquality into $pwfile" \
          "Add manually: password requisite pam_pwquality.so retry=3 enforce_for_root"
      fi
    fi
  else
    finding "PAM-PWQ" "Passwords" "WARN" "pam_pwquality module not present" \
      "Install libpam-pwquality (Debian/Ubuntu) or libpwquality (RHEL). Without it, minlen in login.defs is not enforced."
  fi

  # pam_unix password options: remember + sha512 + rounds
  if grep -q 'pam_unix.so' "$pwfile"; then
    if [[ $DRY -eq 0 ]]; then
      sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/[[:space:]]+(use_authtok|nullok|obscure|sha512|remember=[0-9]+|rounds=[0-9]+|md5|bigcrypt)//g' "$pwfile"
      sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s|$| sha512 rounds=100000 remember=12 use_authtok obscure|' "$pwfile"
    else
      say "[dry-run] pam_unix password options (sha512, remember=12)"
    fi
    [[ $DRY -eq 0 ]] && ok "pam_unix password options set (sha512, remember=12)"
    if [[ $DRY -eq 1 ]]; then
      finding "PAM-UNIX-HIST" "Passwords" "INFO" "pam_unix password history would be set (dry-run)"
    elif grep -qE '^[[:space:]]*password.*pam_unix\.so.*remember=12' "$pwfile" \
         && grep -qE '^[[:space:]]*password.*pam_unix\.so.*sha512' "$pwfile"; then
      finding "PAM-UNIX-HIST" "Passwords" "PASS" "password history = 12, sha512"
    else
      finding "PAM-UNIX-HIST" "Passwords" "WARN" "pam_unix password history/sha512 options not both present" \
        "Inspect the pam_unix password line in $pwfile: it needs remember=12 and sha512."
    fi
  fi

  # remove nullok from the auth stack -- it is what allows blank passwords
  if [[ ! -f "$authfile" ]]; then
    finding "PAM-NULLOK" "Passwords" "WARN" "auth stack not found ($authfile)" \
      "Locate the auth stack for this distro and confirm nullok is absent by hand."
  elif grep -q 'nullok' "$authfile"; then
    if [[ $DRY -eq 0 ]]; then
      sed -i 's/[[:space:]]*nullok//g' "$authfile"
      if grep -q 'nullok' "$authfile"; then
        finding "PAM-NULLOK" "Passwords" "WARN" "nullok still present in $authfile" \
          "Remove nullok from the pam_unix auth line by hand."
      else
        finding "PAM-NULLOK" "Passwords" "PASS" "nullok removed from auth stack"
      fi
      ok "removed 'nullok' from $authfile"
    else
      say "[dry-run] remove nullok from $authfile"
      finding "PAM-NULLOK" "Passwords" "INFO" "nullok would be removed from $authfile (dry-run)"
    fi
  else
    finding "PAM-NULLOK" "Passwords" "PASS" "no nullok in auth stack"
  fi

  # --- lockout ---
  if [[ $have_faillock -eq 1 ]]; then
    # faillock.conf (modern) -- cleaner than passing options on every PAM line
    if [[ $DRY -eq 0 ]]; then
      mkdir -p /etc/security
      backup_file /etc/security/faillock.conf
      [[ -e /etc/security/faillock.conf ]] || created_file /etc/security/faillock.conf
      cat >/etc/security/faillock.conf <<'FL'
# written by cbptlinux.sh
deny = 5
fail_interval = 900
unlock_time = 900
audit
silent
even_deny_root
root_unlock_time = 900
FL
      ok "/etc/security/faillock.conf written (deny=5, unlock=900s)"
    else
      say "[dry-run] write /etc/security/faillock.conf"
    fi

    # Wire it into the auth stack in the CORRECT positions.
    #
    # This matters more than it looks. With Debian's
    #     auth [success=1 default=ignore] pam_unix.so
    #     auth requisite  pam_deny.so
    #     auth required   pam_permit.so
    # a success skips exactly ONE line. So the layout has to be:
    #     auth required   pam_faillock.so preauth
    #     auth [success=1 default=ignore] pam_unix.so
    #     auth [default=die] pam_faillock.so authfail     <- skipped on success
    #     auth sufficient    pam_faillock.so authsucc     <- lands here on success
    #     auth requisite  pam_deny.so
    #
    # Appending authfail at the END of the file (after pam_permit.so) makes it
    # run on EVERY login, successful ones included, which trips the counter
    # and locks the account after `deny` good logins. we did that once. don't.
    local wire=0 f="$authfile" nu nf
    [[ -f "$f" ]] || f=""
    if [[ -n "$f" ]]; then
      backup_file "$f"
      if [[ $DRY -eq 0 ]]; then
        cp -a "$f" "${f}.cbptlinuxbak-$STAMP" 2>/dev/null
        local tmp; tmp="$(mktemp)"
        # self-healing: strip any faillock lines from earlier/incorrect runs first
        grep -v 'pam_faillock\.so' "$f" >"$tmp"
        awk 'BEGIN{done=0}
             /^[[:space:]]*auth[[:space:]].*pam_unix\.so/ && !done {
               print "auth\trequired\t\tpam_faillock.so preauth"
               print
               print "auth\t[default=die]\tpam_faillock.so authfail"
               print "auth\tsufficient\t\tpam_faillock.so authsucc"
               done=1
               next
             }
             { print }' "$tmp" >"$f"
        rm -f "$tmp"
        # Sanity-check the result before we trust it. a PAM stack we broke is
        # far worse than one we left alone -- it means nobody can log in.
        nu="$(grep -cE '^[[:space:]]*auth[[:space:]].*pam_unix\.so' "$f")"
        nf="$(grep -cE '^[[:space:]]*auth[[:space:]].*pam_faillock\.so' "$f")"
        if (( nu != 1 )) || (( nf != 3 )); then
          err "auth stack looks wrong after wiring ($nu pam_unix, $nf faillock) -- rolling back $f"
          cp -a "${f}.cbptlinuxbak-$STAMP" "$f" 2>/dev/null
          finding "PAM-LOCKOUT" "Passwords" "FAIL" "faillock wiring rejected, $f rolled back" \
            "Wire it by hand. Correct order: preauth, pam_unix, authfail, authsucc, then pam_deny/pam_permit. authfail must never come after pam_permit.so."
        elif grep -q 'pam_faillock\.so preauth' "$f"; then
          wire=1
          ok "faillock wired into $f (preauth -> pam_unix -> authfail -> authsucc)"
          grep -nE '^[[:space:]]*auth' "$f" | sed 's/^/      /'
        else
          warn "no 'auth ... pam_unix.so' line found in $f -- faillock NOT wired"
          finding "PAM-LOCKOUT" "Passwords" "WARN" "could not locate the primary auth line in $f" \
            "Wire it by hand: preauth before pam_unix, authfail+authsucc immediately after."
        fi
      else
        say "[dry-run] wire pam_faillock into $f"
        wire=1
      fi
    fi
    (( wire )) && finding "PAM-LOCKOUT" "Passwords" "$( [[ $DRY -eq 0 ]] && echo PASS || echo INFO )" "pam_faillock: 5 failures -> 15 min lockout, correctly positioned"

    # account stack: safe to append, all account modules run in order
    if [[ $DRY -eq 0 ]]; then
      grep -q 'pam_faillock\.so' "$pwfile" || printf 'account\trequired\tpam_faillock.so\n' >>"$pwfile"
    else
      say "[dry-run] account-stack faillock line"
    fi
  else
    # older: pam_tally2. same positioning rules apply.
    if [[ -f /lib/x86_64-linux-gnu/security/pam_tally2.so || -f /lib64/security/pam_tally2.so \
          || -f /lib/security/pam_tally2.so || -f /usr/lib/security/pam_tally2.so \
          || -f /usr/lib64/security/pam_tally2.so ]]; then
      if [[ $DRY -eq 0 ]]; then
        backup_file "$authfile"
        local tmp; tmp="$(mktemp)"
        grep -v 'pam_tally2\.so' "$authfile" >"$tmp"
        awk 'BEGIN{done=0}
             /^[[:space:]]*auth[[:space:]].*pam_unix\.so/ && !done {
               print "auth\trequired\t\tpam_tally2.so deny=5 unlock_time=900 even_deny_root root_unlock_time=900"
               print
               print "auth\trequired\t\tpam_tally2.so deny=5 unlock_time=900 even_deny_root root_unlock_time=900"
               done=1
               next
             }
             { print }' "$tmp" >"$authfile"
        rm -f "$tmp"
        grep -q 'pam_tally2' "$pwfile" || printf 'account\trequired\tpam_tally2.so\n' >>"$pwfile"
      else
        say "[dry-run] pam_tally2 lockout"
      fi
      finding "PAM-LOCKOUT" "Passwords" "$( [[ $DRY -eq 0 ]] && echo PASS || echo INFO )" "pam_tally2: 5 failures -> 15 min lockout"
    else
      finding "PAM-LOCKOUT" "Passwords" "WARN" "neither pam_faillock nor pam_tally2 available" \
        "Install libpam-modules (Debian/Ubuntu) or pam (RHEL). Account lockout is a scored item on almost every image."
    fi
  fi

  # --- su restriction (pam_wheel). make sure somebody can still su BEFORE
  # we restrict it. restricting su to an empty wheel group locks every human
  # out of root and there is no recovery except the console.
  local sufile=/etc/pam.d/su
  if [[ -f "$sufile" ]]; then
    backup_file "$sufile"
    if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' "$sufile"; then
      local sugrp sumembers
      sugrp="$(sed -nE 's/.*pam_wheel\.so.*group=([^[:space:]]+).*/\1/p' "$sufile" | head -1)"
      sugrp="${sugrp:-wheel}"
      sumembers="$(getent group "$sugrp" 2>/dev/null | cut -d: -f4)"
      if [[ -n "$sumembers" ]]; then
        finding "PAM-SU" "Passwords" "PASS" "su restricted to group $sugrp ($sumembers)"
      else
        finding "PAM-SU" "Passwords" "WARN" "pam_wheel is active but group $sugrp has no members -- su would be unusable" \
          "Add at least one admin user to $sugrp (gpasswd -a <adminuser> $sugrp) before relying on this. Keep a root console open."
      fi
    else
      getent group wheel >/dev/null 2>&1 || act groupadd wheel
      local wm sm u
      wm="$(getent group wheel | cut -d: -f4)"
      if [[ -z "$wm" ]]; then
        sm="$(getent group sudo 2>/dev/null | cut -d: -f4)"
        [[ -z "$sm" ]] && sm="$(getent group admin 2>/dev/null | cut -d: -f4)"
        if [[ -n "$sm" ]]; then
          IFS=',' read -ra _arr <<< "$sm"
          for u in "${_arr[@]}"; do [[ -n "$u" ]] && act gpasswd -a "$u" wheel; done
          wm="$(getent group wheel | cut -d: -f4)"
          [[ $DRY -eq 1 && -z "$wm" ]] && wm="$sm"
          [[ -n "$wm" ]] && ok "seeded wheel from the sudo/admin group: $wm"
        fi
      fi
      if [[ -z "$wm" ]]; then
        warn "wheel group is EMPTY and no sudo/admin group to seed it from -- NOT restricting su"
        finding "PAM-SU" "Passwords" "WARN" "su left unrestricted (wheel group has no members)" \
          "Create a wheel group and add your admin user first: gpasswd -a <adminuser> wheel -- then re-run this module."
      else
        if [[ $DRY -eq 0 ]]; then
          printf 'auth\t\trequired\tpam_wheel.so use_uid group=wheel\n' >>"$sufile"
          if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=wheel' "$sufile"; then
            finding "PAM-SU" "Passwords" "PASS" "su restricted to wheel ($wm)"
            ok "restricted su to the wheel group ($wm)"
          else
            finding "PAM-SU" "Passwords" "WARN" "could not verify the pam_wheel line in $sufile" \
              "Add manually: auth required pam_wheel.so use_uid group=wheel"
          fi
        else
          say "[dry-run] restrict su to wheel ($wm)"
          finding "PAM-SU" "Passwords" "INFO" "su would be restricted to wheel ($wm) (dry-run)"
        fi
      fi
    fi
  fi

  # --- umask everywhere ---
  step "umask"
  if [[ $DRY -eq 0 ]]; then
    for f in /etc/profile /etc/bash.bashrc /etc/login.defs; do
      [[ -f "$f" ]] && backup_file "$f"
      [[ -f "$f" ]] && sed -i -E 's|^[[:space:]]*umask[[:space:]]+[0-9]+|umask 027|' "$f"
    done
    [[ -e /etc/profile ]] || created_file /etc/profile
    [[ -e /etc/bash.bashrc ]] || created_file /etc/bash.bashrc
    grep -q '^umask 027' /etc/profile || printf '\numask 027\n' >>/etc/profile
    [[ -f /etc/bash.bashrc ]] && { grep -q '^umask 027' /etc/bash.bashrc || printf '\numask 027\n' >>/etc/bash.bashrc; }
    mkdir -p /etc/profile.d
    [[ -f /etc/profile.d/99-cbptlinux-umask.sh ]] && backup_file /etc/profile.d/99-cbptlinux-umask.sh
    [[ -e /etc/profile.d/99-cbptlinux-umask.sh ]] || created_file /etc/profile.d/99-cbptlinux-umask.sh
    printf '# cbptlinux.sh\numask 027\n' >/etc/profile.d/99-cbptlinux-umask.sh
    chmod 644 /etc/profile.d/99-cbptlinux-umask.sh
  else
    say "[dry-run] umask 027 in profile files"
  fi
  [[ $DRY -eq 0 ]] && ok "umask 027 applied"
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-UMASK" "Passwords" "INFO" "umask 027 would be applied (dry-run)"
  elif grep -qx 'umask 027' /etc/profile.d/99-cbptlinux-umask.sh 2>/dev/null \
       || grep -qx 'umask 027' /etc/profile 2>/dev/null; then
    finding "PERM-UMASK" "Passwords" "PASS" "umask 027"
  else
    finding "PERM-UMASK" "Passwords" "WARN" "umask 027 is not set in the profile files" \
      "Add 'umask 027' to /etc/profile.d/99-cbptlinux-umask.sh and /etc/login.defs."
  fi

  # core dumps
  backup_file /etc/security/limits.conf
  if ! grep -q '#cbptlinux' /etc/security/limits.conf 2>/dev/null; then
    if [[ $DRY -eq 0 ]]; then
      [[ -e /etc/security/limits.conf ]] || created_file /etc/security/limits.conf
      cat >>/etc/security/limits.conf <<'LIM'

#cbptlinux.sh
*               hard    core            0
*               hard    maxlogins       10
root            hard    core            0
LIM
      ok "limits.conf: core dumps off, maxlogins 10"
    else
      say "[dry-run] limits.conf: core dumps off"
    fi
  fi

  # verify the stack still parses
  if command -v pam-auth-update >/dev/null 2>&1 && [[ $DRY -eq 0 ]]; then
    DEBIAN_FRONTEND=noninteractive pam-auth-update --package >/dev/null 2>&1 || true
  fi
  warn "TEST YOUR LOGIN IN A SECOND SESSION BEFORE YOU CLOSE THIS ONE."
}
# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
do_ssh() {
  banner "SSH DAEMON"
  local cfg=/etc/ssh/sshd_config
  [[ -f "$cfg" ]] || { warn "no sshd_config, skipping"; return; }
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: sshd untouched"; return; }

  backup_file "$cfg"

  # prefer a drop-in: cleaner, survives package updates, easy to revert
  local dropin=/etc/ssh/sshd_config.d target="$cfg"
  if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d' "$cfg" 2>/dev/null; then
    [[ $DRY -eq 0 ]] && mkdir -p "$dropin"
    target="$dropin/99-cbptlinux.conf"
  else
    if ! grep -q '^Include' "$cfg"; then
      [[ $DRY -eq 0 ]] && mkdir -p "$dropin"
      if [[ $DRY -eq 0 ]]; then printf 'Include /etc/ssh/sshd_config.d/*.conf\n' >>"$cfg"; fi
      target="$dropin/99-cbptlinux.conf"
    fi
  fi

  local -A SSHD=(
    [Protocol]=2
    [PermitRootLogin]=no
    [X11Forwarding]=no
    [MaxAuthTries]=3
    [MaxSessions]=4
    [LoginGraceTime]=30
    [ClientAliveInterval]=300
    [ClientAliveCountMax]=2
    [PermitEmptyPasswords]=no
    [PermitUserEnvironment]=no
    [IgnoreRhosts]=yes
    [HostbasedAuthentication]=no
    [ChallengeResponseAuthentication]=no
    [KbdInteractiveAuthentication]=no
    [UsePAM]=yes
    [PrintLastLog]=yes
    [TCPKeepAlive]=no
    [Compression]=delayed
    [AllowAgentForwarding]=no
    [AllowTcpForwarding]=no
    [GatewayPorts]=no
    [StrictModes]=yes
    [Banner]=/etc/issue.net
    [LogLevel]=VERBOSE
    [UseDNS]=no
    [PermitTunnel]=no
    [DebianBanner]=no
  )
  # ciphers / MACs / KEX -- modern only
  local CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
  local MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
  local KEX="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
  local HOSTKEY="-ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"

  local k
  for k in "${!SSHD[@]}"; do
    # skip keys this openssh does not know, or sshd refuses to start
    case "$k" in
      DebianBanner) [[ "$DISTRO_ID" =~ (ubuntu|debian) ]] || continue ;;
      KbdInteractiveAuthentication) sshd -T 2>/dev/null | grep -qi kbdinteractiveauthentication || continue ;;
    esac
    ensure_line "$target" "^[[:space:]]*#?[[:space:]]*${k}[[:space:]]" "${k} ${SSHD[$k]}"
  done
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*Ciphers[[:space:]]"          "Ciphers ${CIPHERS}"
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*MACs[[:space:]]"             "MACs ${MACS}"
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*KexAlgorithms[[:space:]]"    "KexAlgorithms ${KEX}"
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*HostKeyAlgorithms[[:space:]]" "HostKeyAlgorithms ${HOSTKEY}"

  # PasswordAuthentication: leave ON by default. flipping it off without keys
  # loaded is the #1 self-inflicted lockout in this competition.
  if [[ $AGGRESSIVE -eq 1 ]]; then
    if confirm "AGGRESSIVE: set PasswordAuthentication no? Only if key auth already works for your admin user."; then
      ensure_line "$target" "^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]" "PasswordAuthentication no"
      local pwauth
      pwauth="$(sshd -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{print $2}')"
      if [[ "$pwauth" == "no" ]]; then
        finding "SSH-PWAUTH" "SSH" "PASS" "PasswordAuthentication no"
      else
        finding "SSH-PWAUTH" "SSH" "WARN" "PasswordAuthentication is still ${pwauth:-unreadable}" \
          "A later Include or Match block may override sshd_config. Run sshd -T and inspect the effective PasswordAuthentication value."
      fi
    fi
  else
    ensure_line "$target" "^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]" "PasswordAuthentication yes"
    finding "SSH-PWAUTH" "SSH" "INFO" "PasswordAuthentication left ON" \
      "Re-run with --aggressive to disable password auth. Do NOT do it until key login is verified working."
  fi

  # login banner
  if [[ $DRY -eq 0 ]]; then
    [[ -f /etc/issue.net ]] && backup_file /etc/issue.net
    [[ -f /etc/issue ]] && backup_file /etc/issue
    [[ -e /etc/issue.net ]] || created_file /etc/issue.net
    [[ -e /etc/issue ]] || created_file /etc/issue
    cat >/etc/issue.net <<'BANNER'
***************************************************************************
                         AUTHORIZED ACCESS ONLY

This system is the property of the organization and is provided for
authorized use only. Unauthorized access, use, or modification of this
system or of the data it contains is prohibited and may result in
disciplinary, civil, and criminal penalties.

All activity on this system is logged, monitored, and subject to audit.
Use of this system constitutes consent to such monitoring.
***************************************************************************
BANNER
    chmod 644 /etc/issue.net
    cp -f /etc/issue.net /etc/issue 2>/dev/null
    ok "login banner installed"
  else
    say "[dry-run] write /etc/issue.net banner"
  fi
  if [[ $DRY -eq 1 ]]; then
    finding "SSH-BANNER" "SSH" "INFO" "/etc/issue.net banner would be set (dry-run)"
  elif [[ -s /etc/issue.net ]] && grep -q 'AUTHORIZED ACCESS ONLY' /etc/issue.net \
       && sshd -T 2>/dev/null | grep -qiE '^[[:space:]]*banner[[:space:]]+/etc/issue\.net$'; then
    finding "SSH-BANNER" "SSH" "PASS" "/etc/issue.net banner set and active"
  else
    finding "SSH-BANNER" "SSH" "WARN" "/etc/issue.net banner missing or incomplete" \
      "Write the authorized-use banner to /etc/issue.net and confirm sshd_config has: Banner /etc/issue.net"
  fi

  # weak host keys
  local removed=0 dsa_left=0
  for f in /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub; do
    if [[ -f "$f" ]]; then
      if ! backup_file "$f"; then
        warn "could not snapshot $f; leaving it in place"
        dsa_left=1
        continue
      fi
      if [[ $DRY -eq 1 ]]; then
        say "[dry-run] remove $f"
        removed=1
      elif rm -f "$f" 2>/dev/null && [[ ! -e "$f" ]]; then
        removed=1
      else
        warn "could not remove $f"
        dsa_left=1
      fi
    fi
  done
  if (( removed )); then
    if [[ $DRY -eq 1 ]]; then
      finding "SSH-DSA" "SSH" "INFO" "DSA host keys would be removed"
    else
      ok "removed DSA host keys"
      finding "SSH-DSA" "SSH" "PASS" "DSA host keys removed"
    fi
  elif (( dsa_left )); then
    finding "SSH-DSA" "SSH" "WARN" "DSA host keys are still present" \
      "Remove /etc/ssh/ssh_host_dsa_key and .pub after confirming the backup exists. DSA host keys are obsolete and commonly scored."
  else
    finding "SSH-DSA" "SSH" "PASS" "no DSA host keys present"
  fi

  # any weak RSA key left?
  if [[ -f /etc/ssh/ssh_host_rsa_key ]] && command -v ssh-keygen >/dev/null 2>&1; then
    local bits; bits="$(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key 2>/dev/null | awk '{print $1}')"
    if [[ -n "$bits" && "$bits" -lt 2048 ]]; then
      if [[ $DRY -eq 1 ]]; then
        say "[dry-run] RSA host key is only $bits bits -- would regenerate at 4096"
      else
        warn "RSA host key is only $bits bits -- regenerating"
      fi
      if [[ $DRY -eq 0 && $PARANOID -eq 0 ]]; then
        if ! backup_file /etc/ssh/ssh_host_rsa_key; then
          warn "could not snapshot the old RSA host key; leaving it in place"
        else
          [[ -f /etc/ssh/ssh_host_rsa_key.pub ]] && backup_file /etc/ssh/ssh_host_rsa_key.pub
          rm -f /etc/ssh/ssh_host_rsa_key*
          if ! ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N '' -q; then
            warn "RSA key regeneration failed; restoring previous host key"
            restore_file /etc/ssh/ssh_host_rsa_key || true
            restore_file /etc/ssh/ssh_host_rsa_key.pub || true
          fi
        fi
      fi
    fi
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
      [[ $DRY -eq 0 ]] && ssh-keygen -A >/dev/null 2>&1
    fi
  fi

  if [[ $DRY -eq 0 ]]; then
    chmod 600 "$cfg"
    [[ -f "$target" ]] && chmod 600 "$target" 2>/dev/null
    chown root:root "$cfg" 2>/dev/null
  fi

  # client side hardening too (scored sometimes)
  local cli=/etc/ssh/ssh_config
  if [[ -f "$cli" ]]; then
    backup_file "$cli"
    ensure_line "$cli" "^[[:space:]]*#?[[:space:]]*Protocol[[:space:]]"          "Protocol 2"
    ensure_line "$cli" "^[[:space:]]*#?[[:space:]]*StrictHostKeyChecking[[:space:]]" "    StrictHostKeyChecking ask"
    ensure_line "$cli" "^[[:space:]]*#?[[:space:]]*HashKnownHosts[[:space:]]"    "    HashKnownHosts yes"
  fi

  # config test before restart -- a broken sshd is a lost round
  if [[ $DRY -eq 1 ]]; then
    say "[dry-run] sshd -t + reload"
  elif sshd -t 2>/dev/null; then
    ok "sshd -t passed"
    local reloaded=0 active=0
    if systemctl reload sshd >/dev/null 2>&1; then reloaded=1
    elif systemctl reload ssh >/dev/null 2>&1; then reloaded=1
    elif systemctl restart sshd >/dev/null 2>&1; then reloaded=1
    elif systemctl restart ssh >/dev/null 2>&1; then reloaded=1
    elif service sshd reload >/dev/null 2>&1; then reloaded=1
    elif service ssh reload >/dev/null 2>&1; then reloaded=1
    fi
    if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null \
       || systemctl is-active --quiet sshd.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null; then
      active=1
    elif service sshd status >/dev/null 2>&1 || service ssh status >/dev/null 2>&1; then
      active=1
    fi
    if (( reloaded && active )); then
      finding "SSH-RELOAD" "SSH" "PASS" "sshd config valid and service active"
    elif (( reloaded )); then
      finding "SSH-RELOAD" "SSH" "WARN" "sshd config valid and reloaded, but the service is not active" \
        "systemctl status sshd (or ssh); sshd -t was successful, so start the service and verify it is listening on the expected port."
    else
      finding "SSH-RELOAD" "SSH" "WARN" "sshd config valid but reload/restart failed" \
        "systemctl restart sshd (or ssh). Confirm with systemctl status and sshd -T."
    fi
  else
    err "sshd -t FAILED. Restoring $cfg from backup."
    sshd -t
    restore_file "$cfg" || warn "could not restore $cfg from the protected backup"
    if [[ "$target" != "$cfg" ]]; then
      restore_file "$target" || rm -f "$target" 2>/dev/null
    fi
    restore_file /etc/ssh/ssh_host_dsa_key >/dev/null 2>&1 || true
    restore_file /etc/ssh/ssh_host_dsa_key.pub >/dev/null 2>&1 || true
    finding "SSH-RELOAD" "SSH" "FAIL" "sshd config rejected, rolled back" \
      "Read the sshd -t error above. Usually an unknown keyword for that openssh version."
  fi

  finding "SSH-ALLOWUSERS" "SSH" "INFO" "AllowUsers not set" \
    "If the README names the authorized users, add: AllowUsers user1 user2 -- this single line is often worth points."
}

# ---------------------------------------------------------------------------
# FIREWALL
# ---------------------------------------------------------------------------
do_firewall() {
  banner "FIREWALL"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: firewall untouched"; return; }

  local fw=""
  command -v ufw >/dev/null 2>&1 && [[ -d /etc/ufw ]] && fw="ufw"
  if [[ -z "$fw" ]] && systemctl is-active firewalld >/dev/null 2>&1; then fw="firewalld"; fi
  if [[ -z "$fw" ]] && command -v iptables >/dev/null 2>&1; then fw="iptables"; fi
  if [[ -z "$fw" ]] && command -v nft >/dev/null 2>&1; then fw="nft"; fi
  if [[ -z "$fw" ]]; then
    pkg_install iptables 2>/dev/null
    command -v iptables >/dev/null 2>&1 && fw="iptables"
  fi

  case "$fw" in
    ufw)
      say "using ufw"
      for f in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/default/ufw /etc/ufw/ufw.conf; do
        backup_file "$f"
      done
      if ufw status 2>/dev/null | grep -q '^Status: active'; then
        say "ufw is active; preserving existing rules and only enforcing defaults"
      else
        act ufw --force reset
      fi
      act ufw default deny incoming
      act ufw default allow outgoing
      if [[ $DRY -eq 0 ]]; then
        local p proto
        while read -r laddr proto; do
          p="${laddr##*:}"
          [[ "$p" =~ ^[0-9]+$ ]] || continue
          case "$p" in
            21|23|69|111|135|137|138|139|445|512|513|514|1433|3306|5900|6667) warn "  NOT opening insecure port $p"; continue ;;
          esac
          if [[ "$proto" == "udp" ]]; then
            ufw allow "$p/udp" >/dev/null 2>&1 && say "  allowed $p/udp (verify against README)"
          else
            ufw allow "$p" >/dev/null 2>&1 && say "  allowed $p (verify against README)"
          fi
        done < <(ss -tulpnH 2>/dev/null | awk '{print $5,$1}' | sort -u)
      else
        say "[dry-run] auto-allow the currently listening TCP/UDP ports"
      fi
      act ufw logging medium
      if [[ $DRY -eq 1 ]]; then
        say "[dry-run] would enable ufw with default-deny inbound"
        finding "FW-UFW" "Firewall" "INFO" "ufw rules would be enabled (dry-run)"
      elif act ufw --force enable \
           && ufw status 2>/dev/null | grep -q '^Status: active' \
           && ufw status verbose 2>/dev/null | grep -qiE '^Default: deny \(incoming\)' \
           && { ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ':22$' \
                || ufw status 2>/dev/null | grep -qE '(^|[[:space:]])22(/tcp)?([[:space:]]|$)'; }; then
        ufw status verbose
        finding "FW-UFW" "Firewall" "PASS" "ufw: default deny inbound, logging medium, enabled, SSH reachable"
      else
        ufw status verbose 2>/dev/null || true
        finding "FW-UFW" "Firewall" "FAIL" "ufw is not active with default deny incoming and SSH allowed" \
          "Run: ufw default deny incoming ; ufw allow 22/tcp ; ufw --force enable ; ufw status verbose. If SSH uses a different port, allow that port instead."
      fi
      ;;
    firewalld)
      say "using firewalld"
      act firewall-cmd --set-default-zone=drop
      act firewall-cmd --permanent --zone=drop --remove-services="$(firewall-cmd --zone=drop --list-services 2>/dev/null | tr ' ' ',')"
      local s
      for s in ssh dhcpv6-client; do act firewall-cmd --permanent --zone=drop --add-service=$s; done
      act firewall-cmd --reload
      if [[ $DRY -eq 1 ]]; then
        finding "FW-FIREWALLD" "Firewall" "INFO" "firewalld drop-zone rules would be applied (dry-run)"
      elif [[ "$(firewall-cmd --get-default-zone 2>/dev/null)" == "drop" ]] \
           && firewall-cmd --state >/dev/null 2>&1 \
           && { ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ':22$' \
                || firewall-cmd --zone=drop --query-service=ssh >/dev/null 2>&1 \
                || firewall-cmd --zone=drop --query-port=22/tcp >/dev/null 2>&1; }; then
        firewall-cmd --list-all
        finding "FW-FIREWALLD" "Firewall" "PASS" "firewalld default zone = drop; SSH reachable"
      else
        finding "FW-FIREWALLD" "Firewall" "FAIL" "firewalld is not active with default zone drop and SSH allowed" \
          "firewall-cmd --set-default-zone=drop ; firewall-cmd --permanent --zone=drop --add-service=ssh ; firewall-cmd --reload ; firewall-cmd --state"
      fi
      ;;
    iptables)
      say "using raw iptables"
      pkg_install iptables 2>/dev/null
      command -v iptables >/dev/null 2>&1 || { warn "no firewall tooling available"; return; }
      if [[ $DRY -eq 0 ]]; then
        command -v iptables-save >/dev/null 2>&1 && iptables-save >"$BKDIR/iptables-before-flush.rules" 2>/dev/null
        iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
        iptables -F; iptables -X
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 6/min -j ACCEPT
        local p
        while read -r laddr _; do
          p="${laddr##*:}"
          [[ "$p" =~ ^[0-9]+$ ]] || continue
          [[ "$p" == 22 ]] && continue
          case "$p" in 21|23|69|111|135|137|138|139|445|512|513|514|1433|3306|5900|6667) warn "  NOT opening insecure port $p"; continue;; esac
          iptables -I INPUT 4 -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
          iptables -I INPUT 4 -p udp --dport "$p" -j ACCEPT
          say "  opened $p (verify against README)"
        done < <(ss -tulpnH 2>/dev/null | awk '{print $5,$1}' | sort -u)
        iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "cbptlinux-DROP: " --log-level 4
        mkdir -p /etc/iptables 2>/dev/null
        [[ -f /etc/iptables/rules.v4 ]] && backup_file /etc/iptables/rules.v4
        [[ -e /etc/iptables/rules.v4 ]] || created_file /etc/iptables/rules.v4
        iptables-save >/etc/iptables/rules.v4 2>/dev/null || warn "could not persist iptables rules to /etc/iptables/rules.v4"
        pkg_install iptables-persistent netfilter-persistent 2>/dev/null
        iptables -L -n -v | head -40
      else
        say "[dry-run] default-DROP iptables ruleset + allow currently listening ports"
      fi
      if [[ $DRY -eq 1 ]]; then
        finding "FW-IPTABLES" "Firewall" "INFO" "default-DROP ruleset would be applied (dry-run)"
      elif iptables -S 2>/dev/null | grep -qx -- '-P INPUT DROP' \
           && ! iptables -S INPUT 2>/dev/null | grep -qx -- '-A INPUT -j ACCEPT' \
           && iptables -S INPUT 2>/dev/null | grep -q -- '-A INPUT -i lo -j ACCEPT' \
           && { ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ':22$' \
                || iptables -S INPUT 2>/dev/null | grep -qE -- '-A INPUT .*--dport 22 .*ACCEPT'; }; then
        finding "FW-IPTABLES" "Firewall" "PASS" "iptables default DROP + loopback/SSH rules present; rules saved to /etc/iptables/rules.v4"
      else
        finding "FW-IPTABLES" "Firewall" "FAIL" "iptables INPUT is not a safe default-DROP ruleset" \
          "Run the firewall module again; confirm: iptables -P INPUT DROP ; iptables -A INPUT -i lo -j ACCEPT ; allow established/related and SSH (or the README port) ; iptables-save >/etc/iptables/rules.v4"
      fi
      ;;
    nft)
      say "using nftables"
      command -v nft >/dev/null 2>&1 || { warn "nft not available"; return; }
      local nftfile nftconf nftunit p proto nft_persist_ok=0
      local -a tports=() uports=()
      nftfile="$BKDIR/nft-cbpt-filter.nft"
      nftunit=/etc/nftables.d/99-cbpt-filter.nft
      mkdir -p "$BKDIR" || { warn "could not create $BKDIR"; return; }
      while read -r laddr proto; do
        p="${laddr##*:}"
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        [[ "$p" == 22 ]] && continue
        case "$p" in
          21|23|69|111|135|137|138|139|445|512|513|514|1433|3306|5900|6667)
            warn "  NOT opening insecure port $p"; continue ;;
        esac
        case "$proto" in
          tcp) tports+=("$p") ;;
          udp) uports+=("$p") ;;
        esac
      done < <(ss -tulpnH 2>/dev/null | awk '{print $5,$1}' | sort -u)
      {
        printf '%s\n' 'destroy table inet cbpt_filter'
        printf '%s\n' 'table inet cbpt_filter {'
        printf '%s\n' '  chain input {'
        printf '%s\n' '    type filter hook input priority 0; policy drop;'
        printf '%s\n' '    iif "lo" accept'
        printf '%s\n' '    ct state established,related accept'
        printf '%s\n' '    icmp type echo-request limit rate 1/second accept'
        printf '%s\n' '    icmpv6 type echo-request limit rate 1/second accept'
        printf '%s\n' '    tcp dport 22 ct state new limit rate 6/minute accept'
        for p in "${tports[@]}"; do
          printf '    tcp dport %s ct state new accept\n' "$p"
        done
        for p in "${uports[@]}"; do
          printf '    udp dport %s accept\n' "$p"
        done
        printf '%s\n' '    limit rate 5/minute log prefix "cbptlinux-DROP: " level warn'
        printf '%s\n' '  }'
        printf '%s\n' '  chain forward {'
        printf '%s\n' '    type filter hook forward priority 0; policy drop;'
        printf '%s\n' '  }'
        printf '%s\n' '  chain output {'
        printf '%s\n' '    type filter hook output priority 0; policy accept;'
        printf '%s\n' '  }'
        printf '%s\n' '}'
      } >"$nftfile" || { warn "could not write $nftfile"; return; }
      if [[ $DRY -eq 1 ]]; then
        say "[dry-run] default-DROP nftables table + allow currently listening ports"
        finding "FW-NFT" "Firewall" "INFO" "default-DROP nftables table would be applied (dry-run)"
      else
        mkdir -p "$BKDIR" 2>/dev/null
        nft list ruleset >"$BKDIR/nft-before-cbpt.nft" 2>/dev/null || true
        if ! nft -c -f "$nftfile" >/dev/null 2>&1; then
          finding "FW-NFT" "Firewall" "FAIL" "generated nftables ruleset failed nft -c validation" \
            "Inspect $nftfile, then run: nft -c -f $nftfile"
          return
        fi
        if ! act nft -f "$nftfile"; then
          finding "FW-NFT" "Firewall" "FAIL" "nft could not apply the default-DROP table" \
            "Inspect $nftfile and the previous ruleset at $BKDIR/nft-before-cbpt.nft."
          return
        fi
        mkdir -p /etc/nftables.d
        backup_file "$nftunit"
        [[ -e "$nftunit" ]] || created_file "$nftunit"
        if ! cp -- "$nftfile" "$nftunit"; then
          finding "FW-NFT" "Firewall" "WARN" "nftables rules are active but not persisted" \
            "Copy $nftfile to $nftunit and add: include \"/etc/nftables.d/*.nft\" to the nftables service config."
          return
        fi
        if [[ -f /etc/sysconfig/nftables.conf ]]; then
          nftconf=/etc/sysconfig/nftables.conf
        else
          nftconf=/etc/nftables.conf
        fi
        [[ -e "$nftconf" ]] || created_file "$nftconf"
        ensure_line "$nftconf" '^[[:space:]]*include[[:space:]]+"/etc/nftables.d/\*\.nft"' 'include "/etc/nftables.d/*.nft"'
        if [[ -f "$nftunit" ]] && grep -qE '^[[:space:]]*include[[:space:]]+"/etc/nftables.d/\*\.nft"' "$nftconf"; then
          nft_persist_ok=1
        else
          warn "nftables rules are active but the include/persisted file could not be verified"
        fi
        if command -v systemctl >/dev/null 2>&1; then
          act systemctl enable nftables >/dev/null 2>&1 || warn "could not enable nftables.service; rules are active but may not survive reboot"
        fi
      fi
      if [[ $DRY -eq 1 ]]; then
        :
      elif nft list table inet cbpt_filter 2>/dev/null | grep -q 'policy drop'; then
        nft list table inet cbpt_filter
        if [[ $nft_persist_ok -eq 1 ]]; then
          finding "FW-NFT" "Firewall" "PASS" "nftables default DROP (inet cbpt_filter) + persisted include"
        else
          finding "FW-NFT" "Firewall" "WARN" "nftables default DROP is active but persistence was not verified" \
            "Confirm $nftunit exists and $nftconf contains: include \"/etc/nftables.d/*.nft\""
        fi
      else
        finding "FW-NFT" "Firewall" "FAIL" "nftables cbpt_filter table is not active with policy drop" \
          "Run: nft list table inet cbpt_filter ; nft -f $nftfile ; check nftables.service."
      fi
      ;;
    *)
      if [[ $DRY -eq 1 ]]; then
        finding "FW-IPTABLES" "Firewall" "INFO" "no firewall frontend present; iptables would be installed (dry-run)"
      else
        finding "FW-NONE" "Firewall" "WARN" "no supported firewall frontend is available" \
          "Install ufw, firewalld, iptables, or nftables, then re-run --module firewall. A host with no firewall cannot score the firewall items."
      fi
      ;;
  esac

  warn "if a critical service is now unreachable, open its port explicitly. A dead critical service costs more than an open port."
}
# ---------------------------------------------------------------------------
# SERVICES
# ---------------------------------------------------------------------------
do_services() {
  banner "SERVICES"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: services untouched"; return; }
  command -v systemctl >/dev/null 2>&1 || warn "no systemd, sysvinit paths will be partial"

  # safe to disable basically everywhere
  local safe_off="telnet telnetd.socket openbsd-inetd inetd xinetd rsh.socket rlogin.socket \
                  rexec.socket rpcbind rpcbind.socket avahi-daemon bluetooth cups-browsed \
                  whoopsie apport modemmanager \
                  snmpd tftpd tftpd-hpa talk talkd finger \
                  spice-vdagent spice-webdavd"
  # only with --aggressive (could be a critical service)
  local agg_off="apache2 httpd nginx lighttpd mysql mariadb mysqld postgresql \
                 named bind9 samba smbd nmbd slapd dovecot exim4 sendmail \
                 docker containerd libvirtd cups vsftpd proftpd nfs-server nfs-kernel-server"

  local s st en nowst nowen
  for s in $safe_off; do
    is_kept_service "$s" && continue
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.(service|socket)"; then
      st="$(systemctl is-active "$s" 2>/dev/null)"
      act systemctl stop "$s"
      act systemctl disable "$s"
      act systemctl mask "$s"
      if [[ $DRY -eq 1 ]]; then
        finding "SVC-$s" "Services" "INFO" "$s would be stopped+disabled+masked (dry-run)"
      else
        nowst="$(systemctl is-active "$s" 2>/dev/null)"
        nowen="$(systemctl is-enabled "$s" 2>/dev/null || true)"
        if [[ "$nowst" != "active" && "$nowen" != "enabled" && "$nowen" != "enabled-runtime" ]]; then
          finding "SVC-$s" "Services" "PASS" "$s stopped+disabled+masked (was $st)"
          change "service:$s" "$st" "masked"
        else
          finding "SVC-$s" "Services" "WARN" "$s still active=$nowst enabled=$nowen" \
            "systemctl status $s ; systemctl mask $s -- a unit that refused to stop/disable is still a scored risk."
        fi
      fi
    elif [[ -x /etc/init.d/$s ]]; then
      act service "$s" stop
      command -v update-rc.d >/dev/null && act update-rc.d "$s" disable
      command -v chkconfig >/dev/null && act chkconfig "$s" off
      if [[ $DRY -eq 1 ]]; then
        finding "SVC-$s" "Services" "INFO" "$s would be stopped+disabled (dry-run)"
      else
        nowst="$(service "$s" status >/dev/null 2>&1 && printf active || printf inactive)"
        nowen="$(find /etc/rc[0-9S].d -maxdepth 1 -name "S??$s" -print -quit 2>/dev/null)"
        if [[ "$nowst" != "active" && -z "$nowen" ]]; then
          finding "SVC-$s" "Services" "PASS" "$s (sysvinit) stopped+disabled"
          change "service:$s" "$st" "stopped"
        else
          finding "SVC-$s" "Services" "WARN" "$s still active=$nowst start-link=${nowen:-none}" \
            "service $s stop ; update-rc.d $s disable ; verify with service $s status and ls /etc/rc*.d/S*$s"
        fi
      fi
    fi
  done

  if [[ $AGGRESSIVE -eq 1 ]]; then
    warn "aggressive tier: these are commonly CRITICAL services. check the README first."
    for s in $agg_off; do
      is_kept_service "$s" && continue
      systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.(service|socket)" || continue
      st="$(systemctl is-active "$s" 2>/dev/null)"
      [[ "$st" != "active" ]] && continue
      if confirm "AGGRESSIVE: stop+disable '$s'? If the README calls it critical, say no."; then
        if [[ $DRY -eq 1 ]]; then
          finding "SVC-$s" "Services" "INFO" "$s would be stopped+disabled (dry-run)"
          continue
        fi
        act systemctl stop "$s"
        act systemctl disable "$s"
        nowst="$(systemctl is-active "$s" 2>/dev/null)"
        nowen="$(systemctl is-enabled "$s" 2>/dev/null || true)"
        if [[ "$nowst" != "active" && "$nowen" != "enabled" && "$nowen" != "enabled-runtime" ]]; then
          finding "SVC-$s" "Services" "PASS" "$s stopped+disabled by operator"
          change "service:$s" "$st" "disabled"
        else
          finding "SVC-$s" "Services" "WARN" "$s still active=$nowst enabled=$nowen after stop/disable" \
            "systemctl status $s ; stop it manually or revisit the README if it is critical."
        fi
      else
        finding "SVC-$s" "Services" "SKIP" "$s left running by operator"
      fi
    done
  else
    finding "SVC-AGG" "Services" "INFO" "web/db/mail/samba services left alone" \
      "Re-run with --aggressive if the README confirms none of them are critical. Otherwise HARDEN their configs instead of stopping them (apps module)."
  fi

  # things that should be running
  for s in rsyslog systemd-journald cron crond auditd sshd; do
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
      if [[ $DRY -eq 1 ]]; then
        finding "SVC-ON-$s" "Services" "INFO" "$s would be enabled+started (dry-run)"
        continue
      fi
      act systemctl enable "$s"
      act systemctl start "$s"
      st="$(systemctl is-active "$s" 2>/dev/null)"
      en="$(systemctl is-enabled "$s" 2>/dev/null || true)"
      if [[ "$st" == "active" && ( "$en" == "enabled" || "$en" == "enabled-runtime" || "$en" == "static" || "$en" == "indirect" || "$en" == "generated" ) ]]; then
        finding "SVC-ON-$s" "Services" "PASS" "$s active+$en"
      else
        finding "SVC-ON-$s" "Services" "WARN" "$s active=$st enabled=$en" \
          "systemctl status $s ; a dead or unenabled logging/audit daemon is a scored item."
      fi
    fi
  done

  # leftover rc.local
  if [[ -f /etc/rc.local ]]; then
    local content; content="$(grep -Ev '^\s*(#|#!|$)' /etc/rc.local)"
    if [[ -n "$content" ]]; then
      finding "SVC-RCLOCAL" "Persistence" "WARN" "/etc/rc.local runs: $(echo "$content" | tr '\n' '; ' | head -c 200)" \
        "rc.local is a classic persistence spot. Verify each command, comment out anything you do not recognize."
    fi
  fi
}

# ---------------------------------------------------------------------------
# PACKAGES / UPDATES
# ---------------------------------------------------------------------------
do_packages() {
  banner "PACKAGES + UPDATES"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: no package changes"; return; }

  step "refreshing package lists"
  case "$PKG" in
    apt)
      # a broken sources.list is itself a scored vuln and blocks everything else
      if [[ -f /etc/apt/sources.list ]]; then
        backup_file /etc/apt/sources.list
        if grep -RIl 'deb cdrom' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -q .; then
          finding "PKG-SOURCES" "Updates" "WARN" "a sources file contains a cdrom: line" \
            "Comment out the cdrom line: sed -i 's/^deb cdrom/#deb cdrom/' <file>  -- then apt-get update."
        fi
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
          finding "PKG-LOCK" "Updates" "WARN" "dpkg lock held" "ps aux | grep apt -- a stuck apt breaks the whole update chain and graders notice."
        fi
      fi
      if [[ $DRY -eq 1 ]]; then
        say "[dry-run] apt-get update"
        finding "PKG-UPDATE" "Updates" "INFO" "package list refresh would run (dry-run)"
      elif act apt-get update; then
        ok "apt-get update succeeded"
      else
        warn "apt-get update failed"
        finding "PKG-UPDATE" "Updates" "FAIL" "apt-get update failed" \
          "Read the error. common causes: broken sources.list, cdrom entry, expired release, DNS. fixing updates is itself worth points."
      fi
      if [[ $DRY -eq 0 ]]; then
        if [[ $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: full apt-get upgrade? can take 10+ min and may need a reboot."; then
          local up_rc=0
          DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade 2>&1 | tail -20 || up_rc=1
          # dist-upgrade also follows changed dependencies; it is what an
          # image with held-back kernel/lib packages needs. autoremove and
          # autoclean keep /var/cache from filling mid-round.
          DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade 2>&1 | tail -20 || up_rc=1
          DEBIAN_FRONTEND=noninteractive apt-get -y autoremove 2>&1 | tail -5 || up_rc=1
          DEBIAN_FRONTEND=noninteractive apt-get -y autoclean 2>&1 | tail -5 || up_rc=1
          if (( up_rc == 0 )); then
            finding "PKG-UPGRADE" "Updates" "PASS" "full upgrade + dist-upgrade applied"
          else
            finding "PKG-UPGRADE" "Updates" "WARN" "apt upgrade/dist-upgrade reported an error" \
              "Read the apt output and rerun: apt-get -f install ; apt-get upgrade ; apt-get dist-upgrade"
          fi
        else
          # at minimum: security updates; skip the call entirely when apt
          # sees no pending security packages, so we never run an empty install.
          local -a secpkgs=()
          mapfile -t secpkgs < <(apt-get -s upgrade 2>/dev/null | awk '/^Inst/ && tolower($0) ~ /secur/ {print $2}' | head -80)
          if (( ${#secpkgs[@]} )); then
            DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef install --only-upgrade \
              "${secpkgs[@]}" >/dev/null 2>&1 || warn "security-only package upgrade reported an error"
          fi
          finding "PKG-UPGRADE" "Updates" "INFO" "security-only upgrade attempted" \
            "Run --aggressive for a full upgrade. unpatched packages are scored; so is a broken apt."
        fi
      else
        say "[dry-run] package upgrade"
      fi
      ;;
    dnf|yum)
      local mgr=dnf; command -v dnf >/dev/null || mgr=yum
      if [[ $DRY -eq 1 ]]; then say "[dry-run] $mgr makecache"
      elif act $mgr makecache; then ok "$mgr makecache ok"
      else warn "$mgr makecache failed"; fi
      if [[ $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: full $mgr upgrade?"; then
        if [[ $DRY -eq 1 ]]; then
          say "[dry-run] $mgr -y upgrade + autoremove"
          finding "PKG-UPGRADE" "Updates" "INFO" "full $mgr upgrade would run (dry-run)"
        elif act $mgr -y upgrade; then
          finding "PKG-UPGRADE" "Updates" "PASS" "full upgrade applied"
          act $mgr -y autoremove
        else
          finding "PKG-UPGRADE" "Updates" "WARN" "full $mgr upgrade reported an error" \
            "Read the $mgr output and rerun the upgrade; a partially applied update can leave the image broken."
        fi
      else
        if [[ $DRY -eq 1 ]]; then
          say "[dry-run] $mgr -y --security upgrade"
          finding "PKG-UPGRADE" "Updates" "INFO" "security-only $mgr upgrade would run (dry-run)"
        else
          act $mgr -y --security upgrade
          finding "PKG-UPGRADE" "Updates" "INFO" "security-only upgrade attempted"
        fi
      fi
      ;;
    zypper) act zypper --non-interactive refresh; act zypper --non-interactive patch ;;
    pacman) act pacman -Sy; [[ $AGGRESSIVE -eq 1 ]] && act pacman -Su --noconfirm ;;
  esac

  # automatic security updates (apt)
  if [[ "$PKG" == "apt" ]]; then
    pkg_install unattended-upgrades 2>/dev/null
    if [[ -d /etc/apt/apt.conf.d ]]; then
      backup_file /etc/apt/apt.conf.d/20auto-upgrades
      if [[ $DRY -eq 0 ]]; then
        [[ -e /etc/apt/apt.conf.d/20auto-upgrades ]] || created_file /etc/apt/apt.conf.d/20auto-upgrades
        cat >/etc/apt/apt.conf.d/20auto-upgrades <<'AU'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
AU
        chmod 644 /etc/apt/apt.conf.d/20auto-upgrades
        # the debconf question also writes 20auto-upgrades on some releases;
        # run it noninteractively so a scored image never blocks on a dialog.
        DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades >/dev/null 2>&1 || \
          warn "dpkg-reconfigure unattended-upgrades failed (config file above still applies)"
        ok "unattended-upgrades configured"
      else
        say "[dry-run] write /etc/apt/apt.conf.d/20auto-upgrades"
      fi
      local svc
      for svc in unattended-upgrades apt-daily.timer apt-daily-upgrade.timer; do
        systemctl list-unit-files 2>/dev/null | grep -qE "^${svc//./\\.}" && act systemctl enable --now "$svc"
      done
      if [[ $DRY -eq 1 ]]; then
        finding "PKG-AUTO" "Updates" "INFO" "unattended-upgrades would be enabled (dry-run)"
      elif [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] \
           && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades \
           && grep -q 'Update-Package-Lists "1"' /etc/apt/apt.conf.d/20auto-upgrades \
           && pkg_has unattended-upgrades; then
        finding "PKG-AUTO" "Updates" "PASS" "unattended-upgrades enabled"
      else
        finding "PKG-AUTO" "Updates" "WARN" "unattended-upgrades is not fully configured" \
          "Install unattended-upgrades and confirm /etc/apt/apt.conf.d/20auto-upgrades contains both periodic settings."
      fi
    fi
  fi

  # remove the insecure legacy daemons
  local purge="telnet telnetd rsh-server rsh-client rexec ypserv tftpd tftpd-hpa talk talkd \
               finger fingerd xinetd openbsd-inetd"
  local present="" p
  for p in $purge; do pkg_has "$p" 2>/dev/null && present="$present $p"; done
  if [[ -n "$present" ]]; then
    finding "PKG-INSECURE" "Software" "FAIL" "insecure daemons installed:$present" \
      "Remove them. they are almost always scored, and they almost never are a legitimate critical service."
    pkg_remove $present
  else
    finding "PKG-INSECURE" "Software" "PASS" "no legacy insecure daemons installed"
  fi

  # policy-banned attack tools, p2p clients, and games. report always;
  # removal only when the operator asked for --aggressive.
  local banned="" name
  local -A seen_pkg=()
  for p in "${PROHIBITED_SOFTWARE[@]}" "${PROHIBITED_PATTERNS[@]}"; do
    while IFS= read -r name; do
      [[ -n "$name" ]] || continue
      [[ -n "${seen_pkg[$name]:-}" ]] && continue
      seen_pkg[$name]=1
      banned="$banned $name"
    done < <(pkg_find_installed "$p")
  done
  if [[ -n "$banned" ]]; then
    finding "PKG-PROHIBITED" "Software" "FAIL" "prohibited software installed:$banned" \
      "Attack tools, sniffers, crackers, p2p clients and games are policy violations. Re-run with --aggressive to purge them, or remove them by hand and document it in the report."
    if (( AGGRESSIVE )); then
      pkg_remove $banned
    else
      warn "prohibited software left installed (needs --aggressive):$banned"
    fi
  else
    finding "PKG-PROHIBITED" "Software" "PASS" "no prohibited tools or games installed"
  fi
}

# ---------------------------------------------------------------------------
# SYSCTL
# ---------------------------------------------------------------------------
do_sysctl() {
  banner "KERNEL PARAMETERS (sysctl)"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: sysctl untouched"; return; }

  local f=/etc/sysctl.d/99-cyberpatriot.conf
  if [[ $DRY -eq 0 ]]; then mkdir -p /etc/sysctl.d; fi
  [[ -f /etc/sysctl.conf ]] && backup_file /etc/sysctl.conf
  [[ -f "$f" ]] && backup_file "$f"
  if [[ $DRY -eq 0 && ! -e "$f" ]]; then created_file "$f"; fi

  if [[ $DRY -eq 0 ]]; then
    cat >"$f" <<'SYSCTL'
# written by cbptlinux.sh -- CyberPatriot baseline
# test with: sysctl --system   (a bad key here is only a warning, not fatal)

# ---- network ----
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.max_addresses = 1

# ---- kernel ----
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1
kernel.core_uses_pid = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1

# ---- fs ----
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
SYSCTL
    chmod 644 "$f"
    ok "wrote $f"
  else
    say "[dry-run] write $f"
  fi

  # IP forwarding: if this box is meant to be a router (README), do not kill it
  if grep -qiE 'router|routing|gateway' /etc/sysctl.conf 2>/dev/null; then
    warn "/etc/sysctl.conf already mentions routing -- verify ip_forward=0 is correct for this image"
  fi

  local sysctl_live=1
  if command -v sysctl >/dev/null 2>&1; then
    act sysctl --system
  else
    sysctl_live=0
    warn "the sysctl binary is not installed -- $f still applies at boot,"
    warn "but nothing is live right now. install procps (apt) or procps-ng (dnf)."
    finding "SYSCTL-BINARY" "Kernel" "WARN" "sysctl(8) not installed" \
      "Install procps. without it you cannot read or apply kernel parameters, and several scored checks become unverifiable."
  fi
  # report anything that did not stick
  local k v cur stuck=0 checked=0
  while read -r k v; do
    [[ -z "$k" ]] && continue
    k="${k%%=*}"; k="$(echo "$k" | tr -d ' ')"
    v="$(echo "$v" | tr -d ' ')"
    cur="$(sysctl_get "$k")"
    [[ -z "$cur" ]] && continue          # key not present on this kernel: skip
    checked=$((checked+1))
    if [[ "$cur" != "$v" ]]; then
      warn "  $k did not take (want $v, got $cur)"
      stuck=$((stuck+1))
    fi
  done < <(grep -E '^[a-z]' "$f" 2>/dev/null)
  (( checked > 0 && stuck == 0 )) && ok "$checked/$checked parameters applied cleanly"

  # core dumps via systemd
  if [[ $DRY -eq 0 ]]; then
    mkdir -p /etc/systemd/coredump.conf.d
    [[ -f /etc/systemd/coredump.conf.d/99-cp.conf ]] && backup_file /etc/systemd/coredump.conf.d/99-cp.conf
    [[ -e /etc/systemd/coredump.conf.d/99-cp.conf ]] || created_file /etc/systemd/coredump.conf.d/99-cp.conf
    printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' >/etc/systemd/coredump.conf.d/99-cp.conf 2>/dev/null
    chmod 644 /etc/systemd/coredump.conf.d/99-cp.conf 2>/dev/null
  fi

  if [[ $DRY -eq 1 ]]; then
    finding "SYSCTL" "Kernel" "INFO" "sysctl drop-in would be written (dry-run)"
  elif [[ $sysctl_live -eq 0 ]]; then
    finding "SYSCTL" "Kernel" "WARN" "99-cyberpatriot.conf written but sysctl(8) is unavailable, so it was not applied live" \
      "Install procps/procps-ng, then run: sysctl --system"
  elif (( checked == 0 )); then
    finding "SYSCTL" "Kernel" "WARN" "99-cyberpatriot.conf written but no keys could be verified" \
      "Check that /proc/sys is mounted and sysctl --system reports no errors."
  elif (( stuck > 0 )); then
    finding "SYSCTL" "Kernel" "WARN" "99-cyberpatriot.conf written; $stuck of $checked live values did not take effect" \
      "Inspect the warnings above, confirm /etc/sysctl.d/99-cyberpatriot.conf is loaded last, then run: sysctl --system"
  else
    finding "SYSCTL" "Kernel" "PASS" "99-cyberpatriot.conf applied ($checked/$checked values verified)"
  fi
  local _a _f
  _a="$(sysctl_get kernel.randomize_va_space)"; _f="$(sysctl_get net.ipv4.ip_forward)"
  finding "SYSCTL-ASLR" "Kernel" "$( [[ "$_a" == "2" ]] && echo PASS || echo FAIL )" \
          "kernel.randomize_va_space=${_a:-<unreadable>} (want 2)" \
          "ASLR must be 2 (full randomization). if it reads empty, install procps and re-run."
  finding "SYSCTL-FWD" "Kernel" "$( [[ "$_f" == "0" ]] && echo PASS || echo FAIL )" \
          "net.ipv4.ip_forward=${_f:-<unreadable>} (want 0)" \
          "IP forwarding should be 0 UNLESS the README says this box is a router/gateway. if it is, set it back to 1 -- a router that cannot route loses a critical-service check."
}
# ---------------------------------------------------------------------------
# FILE PERMISSIONS
# ---------------------------------------------------------------------------
do_perms() {
  banner "FILE + DIRECTORY PERMISSIONS"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: permissions untouched"; return; }

  setperm() { local f="$1" mode="$2" own="${3:-root}" grp="${4:-root}"
    [[ -e "$f" ]] || return 0
    local before; before="$(stat -c '%a %U:%G' "$f" 2>/dev/null)"
    if [[ $DRY -eq 1 ]]; then say "[dry-run] chmod $mode chown $own:$grp $f"; return 0; fi
    chmod "$mode" "$f" 2>/dev/null && chown "$own:$grp" "$f" 2>/dev/null
    local after; after="$(stat -c '%a %U:%G' "$f" 2>/dev/null)"
    [[ "$before" != "$after" ]] && { change "$f" "$before" "$after"; ok "  $f: $before -> $after"; }
  }

  # identity files
  setperm /etc/passwd   644 root root
  setperm /etc/group    644 root root
  setperm /etc/shadow   640 root shadow
  setperm /etc/gshadow  640 root shadow
  setperm /etc/shadow-  640 root shadow
  setperm /etc/gshadow- 640 root shadow
  setperm /etc/passwd-  644 root root
  setperm /etc/group-   644 root root
  # some distros have no shadow group
  getent group shadow >/dev/null 2>&1 || { [[ $DRY -eq 0 ]] && chmod 600 /etc/shadow /etc/gshadow 2>/dev/null; }
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-IDENTITY" "Permissions" "INFO" "identity file modes would be normalized (dry-run)"
  else
    local idbad=0 idwant
    for f in /etc/passwd /etc/group /etc/passwd- /etc/group-; do
      [[ -e "$f" ]] || continue
      [[ "$(stat -c '%a' "$f" 2>/dev/null)" == "644" ]] || { idbad=$((idbad+1)); warn "  $f mode=$(stat -c '%a' "$f" 2>/dev/null), want 644"; }
    done
    idwant=640; getent group shadow >/dev/null 2>&1 || idwant=600
    for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do
      [[ -e "$f" ]] || continue
      [[ "$(stat -c '%a' "$f" 2>/dev/null)" == "$idwant" ]] || { idbad=$((idbad+1)); warn "  $f mode=$(stat -c '%a' "$f" 2>/dev/null), want $idwant"; }
    done
    if (( idbad == 0 )); then
      finding "PERM-IDENTITY" "Permissions" "PASS" "passwd/group 644, shadow/gshadow $idwant"
    else
      finding "PERM-IDENTITY" "Permissions" "WARN" "$idbad identity file(s) still have the wrong mode" \
        "Fix with: chmod 644 /etc/passwd /etc/group ; chmod $idwant /etc/shadow /etc/gshadow"
    fi
  fi

  setperm /etc/sudoers  440 root root
  if [[ -d /etc/sudoers.d ]]; then
    if [[ $DRY -eq 0 ]]; then
      chmod 750 /etc/sudoers.d
      find /etc/sudoers.d -type f -exec chmod 440 {} \; 2>/dev/null
      chown -R root:root /etc/sudoers.d 2>/dev/null
    else
      say "[dry-run] tighten /etc/sudoers.d"
    fi
  fi
  local sbad=0 sf
  for sf in /etc/sudoers.d/*; do
    [[ -f "$sf" ]] || continue
    [[ "$(stat -c '%a' "$sf" 2>/dev/null)" == "440" ]] || { sbad=$((sbad+1)); warn "  $sf mode=$(stat -c '%a' "$sf" 2>/dev/null), want 440"; }
  done
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-SUDOERS" "Permissions" "INFO" "sudoers mode would be 440 (dry-run)"
  elif [[ -e /etc/sudoers && "$(stat -c '%a' /etc/sudoers 2>/dev/null)" == "440" ]] \
       && { [[ ! -d /etc/sudoers.d ]] || [[ "$(stat -c '%a' /etc/sudoers.d 2>/dev/null)" == "750" ]]; } \
       && (( sbad == 0 )); then
    finding "PERM-SUDOERS" "Permissions" "PASS" "sudoers 440, sudoers.d files 440"
  else
    finding "PERM-SUDOERS" "Permissions" "WARN" "sudoers/sudoers.d mode is not fully tightened" \
      "chmod 440 /etc/sudoers ; chmod 750 /etc/sudoers.d ; chmod 440 /etc/sudoers.d/*"
  fi

  setperm /etc/ssh/sshd_config 600 root root
  if [[ -d /etc/ssh ]]; then
    if [[ $DRY -eq 0 ]]; then
      chmod 755 /etc/ssh
      find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' -exec chmod 600 {} \; 2>/dev/null
      find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key.pub' -exec chmod 644 {} \; 2>/dev/null
    else
      say "[dry-run] tighten /etc/ssh"
    fi
  fi
  local hbad=0 hk
  for hk in /etc/ssh/ssh_host_*_key; do
    [[ -e "$hk" ]] || continue
    [[ "$(stat -c '%a' "$hk" 2>/dev/null)" == "600" ]] || { hbad=$((hbad+1)); warn "  $hk mode=$(stat -c '%a' "$hk" 2>/dev/null), want 600"; }
  done
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-SSH" "Permissions" "INFO" "sshd_config/host key modes would be tightened (dry-run)"
  elif [[ -e /etc/ssh/sshd_config && "$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null)" == "600" ]] \
       && [[ "$(stat -c '%a' /etc/ssh 2>/dev/null)" == "755" ]] && (( hbad == 0 )); then
    finding "PERM-SSH" "Permissions" "PASS" "sshd_config 600, host keys 600"
  else
    finding "PERM-SSH" "Permissions" "WARN" "sshd_config or host key mode is not fully tightened" \
      "chmod 600 /etc/ssh/sshd_config ; chmod 755 /etc/ssh ; chmod 600 /etc/ssh/ssh_host_*_key"
  fi

  # cron
  setperm /etc/crontab 644 root root
  local d
  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    if [[ -d "$d" ]]; then
      if [[ $DRY -eq 0 ]]; then
        chmod 750 "$d"; chown root:root "$d"; find "$d" -type f -exec chmod 640 {} \; 2>/dev/null
      else
        say "[dry-run] tighten $d"
      fi
    fi
  done
  for d in /var/spool/cron /var/spool/cron/crontabs; do
    if [[ -d "$d" ]]; then
      if [[ $DRY -eq 0 ]]; then
        chmod 700 "$d"; chown root:crontab "$d" 2>/dev/null || chown root:root "$d"
        find "$d" -type f -exec chmod 600 {} \; 2>/dev/null
      else
        say "[dry-run] tighten $d"
      fi
    fi
  done
  if [[ $DRY -eq 0 ]]; then
    [[ -f /etc/cron.deny ]] && backup_file /etc/cron.deny
    [[ -f /etc/at.deny ]] && backup_file /etc/at.deny
    rm -f /etc/cron.deny /etc/at.deny 2>/dev/null && ok "  removed cron.deny/at.deny (allow-lists are safer)"
    if [[ ! -f /etc/cron.allow ]]; then
      created_file /etc/cron.allow
      printf 'root\n' >/etc/cron.allow; chmod 640 /etc/cron.allow; chown root:root /etc/cron.allow
      ok "  created /etc/cron.allow (root only)"
    fi
    if [[ ! -f /etc/at.allow ]]; then
      created_file /etc/at.allow
      printf 'root\n' >/etc/at.allow; chmod 640 /etc/at.allow; chown root:root /etc/at.allow
    fi
  else
    say "[dry-run] cron.allow / at.allow"
  fi
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-CRON" "Permissions" "INFO" "cron permissions/allow-lists would be normalized (dry-run)"
  else
    local cbad=0
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
      [[ ! -d "$d" ]] && continue
      [[ "$(stat -c '%a' "$d" 2>/dev/null)" == "750" ]] || { cbad=$((cbad+1)); warn "  $d mode=$(stat -c '%a' "$d" 2>/dev/null), want 750"; }
    done
    [[ -f /etc/crontab ]] && [[ "$(stat -c '%a' /etc/crontab 2>/dev/null)" != "644" ]] && { cbad=$((cbad+1)); warn "  /etc/crontab mode=$(stat -c '%a' /etc/crontab 2>/dev/null), want 644"; }
    [[ -f /etc/cron.allow && ! -f /etc/cron.deny ]] || { cbad=$((cbad+1)); warn "  cron.allow/cron.deny policy is not the expected allow-list"; }
    if (( cbad == 0 )); then
      finding "PERM-CRON" "Permissions" "PASS" "cron dirs 750, crontab 644, allow-lists in place"
    else
      finding "PERM-CRON" "Permissions" "WARN" "$cbad cron permission/allow-list issue(s)" \
        "chmod 750 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly ; ensure /etc/cron.allow exists and /etc/cron.deny does not."
    fi
  fi

  # boot
  if [[ $DRY -eq 0 ]]; then
    [[ -d /boot ]] && { chmod 700 /boot 2>/dev/null; find /boot -type f -exec chmod 600 {} \; 2>/dev/null; chown -R root:root /boot 2>/dev/null; }
  fi
  setperm /boot/grub/grub.cfg 600 root root
  setperm /boot/grub2/grub.cfg 600 root root
  setperm /etc/grub.conf 600 root root
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-BOOT" "Permissions" "INFO" "/boot would be locked to 700/600 (dry-run)"
  else
    local bbad=0
    if [[ -d /boot && "$(stat -c '%a' /boot 2>/dev/null)" != "700" ]]; then
      bbad=$((bbad+1)); warn "  /boot mode=$(stat -c '%a' /boot 2>/dev/null), want 700"
    fi
    for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg /etc/grub.conf; do
      [[ -e "$f" ]] || continue
      [[ "$(stat -c '%a' "$f" 2>/dev/null)" == "600" ]] || { bbad=$((bbad+1)); warn "  $f mode=$(stat -c '%a' "$f" 2>/dev/null), want 600"; }
    done
    if (( bbad == 0 )); then
      finding "PERM-BOOT" "Permissions" "PASS" "/boot locked to 700/600"
    else
      finding "PERM-BOOT" "Permissions" "WARN" "$bbad boot file/directory mode(s) not tightened" \
        "chmod 700 /boot ; chmod 600 /boot/grub/grub.cfg (or /boot/grub2/grub.cfg) ; chown -R root:root /boot"
    fi
  fi

  # misc sensitive
  for f in /etc/hosts /etc/resolv.conf /etc/hostname /etc/networks /etc/issue /etc/issue.net /etc/fstab /etc/login.defs; do
    setperm "$f" 644 root root
  done
  setperm /etc/ld.so.conf 644 root root
  [[ -d /etc/ld.so.conf.d ]] && [[ $DRY -eq 0 ]] && chmod 644 /etc/ld.so.conf.d/* 2>/dev/null
  setperm /etc/sysctl.conf 644 root root
  [[ -d /etc/sysctl.d ]] && [[ $DRY -eq 0 ]] && chmod 644 /etc/sysctl.d/* 2>/dev/null
  setperm /etc/profile 644 root root
  setperm /etc/bash.bashrc 644 root root
  [[ -d /etc/profile.d ]] && [[ $DRY -eq 0 ]] && chmod 644 /etc/profile.d/* 2>/dev/null
  setperm /etc/security/limits.conf 644 root root
  setperm /etc/security/pwquality.conf 644 root root
  setperm /etc/security/access.conf 644 root root
  setperm /etc/rc.local 750 root root
  setperm /etc/exports 644 root root
  setperm /etc/ftpusers 644 root root
  setperm /var/log/wtmp 664 root utmp
  setperm /var/log/btmp 660 root utmp
  setperm /var/log/lastlog 664 root utmp
  [[ $DRY -eq 0 ]] && chmod 755 /etc 2>/dev/null
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-MISC" "Permissions" "INFO" "core config files would be normalized (dry-run)"
  else
    local mbad=0
    for f in /etc/hosts /etc/resolv.conf /etc/hostname /etc/networks /etc/issue /etc/issue.net \
             /etc/fstab /etc/login.defs /etc/ld.so.conf /etc/sysctl.conf /etc/profile /etc/bash.bashrc \
             /etc/security/limits.conf /etc/security/pwquality.conf /etc/security/access.conf \
             /etc/exports /etc/ftpusers; do
      [[ -e "$f" ]] || continue
      [[ "$(stat -c '%a' "$f" 2>/dev/null)" == "644" ]] || { mbad=$((mbad+1)); warn "  $f mode=$(stat -c '%a' "$f" 2>/dev/null), want 644"; }
    done
    if (( mbad == 0 )); then
      finding "PERM-MISC" "Permissions" "PASS" "core config files normalized"
    else
      finding "PERM-MISC" "Permissions" "WARN" "$mbad core config file(s) are not mode 644" \
        "chmod 644 /etc/hosts /etc/resolv.conf /etc/fstab /etc/login.defs /etc/security/limits.conf -- adjust only files that exist."
    fi
  fi

  # log directory
  if [[ -d /var/log && $DRY -eq 0 ]]; then
    chmod 755 /var/log; find /var/log -maxdepth 1 -type f -exec chmod 640 {} \; 2>/dev/null
  fi
  [[ -d /var/log/journal ]] && [[ $DRY -eq 0 ]] && chmod 2755 /var/log/journal 2>/dev/null

  # home dirs
  local name _ uid _ _ home shell hbad=0
  while IFS=: read -r name _ uid _ _ home shell; do
    (( uid < 1000 )) && continue
    [[ "$shell" =~ (nologin|false) ]] && continue
    [[ -d "$home" ]] || continue
    local cur; cur="$(stat -c '%a' "$home" 2>/dev/null)"
    if [[ "$cur" != "750" && "$cur" != "700" ]]; then
      if [[ $DRY -eq 1 ]]; then say "[dry-run] chmod 750 $home"; else
        chmod 750 "$home" 2>/dev/null && change "$home" "$cur" "750"
      fi
    fi
    if [[ -d "$home/.ssh" && $DRY -eq 0 ]]; then
      chmod 700 "$home/.ssh"
      find "$home/.ssh" -type f -exec chmod 600 {} \; 2>/dev/null
      find "$home/.ssh" -name '*.pub' -exec chmod 644 {} \; 2>/dev/null
    fi
    if [[ $DRY -eq 0 ]]; then
      cur="$(stat -c '%a' "$home" 2>/dev/null)"
      [[ "$cur" == "750" || "$cur" == "700" ]] || { hbad=$((hbad+1)); warn "  $home mode=$cur, want 750"; }
      if [[ -d "$home/.ssh" && "$(stat -c '%a' "$home/.ssh" 2>/dev/null)" != "700" ]]; then
        hbad=$((hbad+1)); warn "  $home/.ssh mode=$(stat -c '%a' "$home/.ssh" 2>/dev/null), want 700"
      fi
    fi
  done < <(getent passwd)
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-HOME" "Permissions" "INFO" "home dirs would be tightened (dry-run)"
  elif (( hbad == 0 )); then
    finding "PERM-HOME" "Permissions" "PASS" "home dirs 750, .ssh 700, private keys 600"
  else
    finding "PERM-HOME" "Permissions" "WARN" "$hbad home/.ssh permission issue(s)" \
      "chmod 750 <home> ; chmod 700 <home>/.ssh ; chmod 600 <home>/.ssh/* (public .pub files 644)."
  fi

  # world-writable sweep (files without sticky bit)
  if [[ $DRY -eq 0 ]]; then
    local n=0
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      chmod o-w "$f" 2>/dev/null && n=$((n+1))
    done < <(find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path "$EVID" -o -path "$BKROOT" \) -prune -o -type f -perm -0002 ! -perm -1000 -print 2>/dev/null | head -2000)
    (( n > 0 )) && { ok "removed world-writable bit from $n file(s)"; finding "PERM-WW-FIX" "Permissions" "PASS" "$n world-writable file(s) fixed"; }

    # world-writable dirs get sticky instead of losing o+w (breaking /tmp is fatal)
    while IFS= read -r d; do
      [[ -z "$d" ]] && continue
      case "$d" in /tmp|/var/tmp|/dev/shm) chmod 1777 "$d" 2>/dev/null ;; *) chmod +t "$d" 2>/dev/null ;; esac
    done < <(find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -500)
    chmod 1777 /tmp /var/tmp /dev/shm 2>/dev/null
  else
    say "[dry-run] world-writable sweep"
  fi
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-TMP" "Permissions" "INFO" "/tmp,/var/tmp,/dev/shm would be 1777 (dry-run)"
  else
    local tbad=0 tmode
    for d in /tmp /var/tmp /dev/shm; do
      [[ -d "$d" ]] || continue
      tmode="$(stat -c '%a' "$d" 2>/dev/null)"
      [[ "$tmode" == "1777" ]] || { warn "  $d mode=$tmode (want 1777)"; tbad=$((tbad+1)); }
    done
    if (( tbad == 0 )); then
      finding "PERM-TMP" "Permissions" "PASS" "/tmp,/var/tmp,/dev/shm = 1777"
    else
      finding "PERM-TMP" "Permissions" "WARN" "$tbad temp director(ies) not 1777" \
        "chmod 1777 /tmp /var/tmp /dev/shm -- do not remove the sticky bit; it protects files in shared directories."
    fi
  fi

  # dangerous SUID: strip from shells/editors/interpreters that are not distro-default
  local strip="nmap vim vim.basic vim.tiny nano less more man gdb python python2 python3 perl ruby php \
               socat nc ncat tcpdump strace ltrace find awk sed cp mv tar rsync"
  local s removed=0 suid_left=0
  for s in $strip; do
    if [[ $DRY -eq 0 ]]; then
      while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        local pm; pm="$(stat -c '%a' "$p" 2>/dev/null)"
        if chmod u-s "$p" 2>/dev/null && [[ ! -u "$p" ]]; then
          removed=$((removed+1)); change "suid:$p" "$pm" "$(stat -c '%a' "$p" 2>/dev/null)"; warn "  stripped SUID: $p"
        else
          suid_left=$((suid_left+1)); warn "  could not strip SUID: $p"
        fi
      done < <(find / -xdev -type f -name "$s" -perm -4000 -print 2>/dev/null)
    else
      say "[dry-run] SUID strip on $s"
    fi
  done
  if [[ $DRY -eq 1 ]]; then
    finding "PERM-SUID-STRIP" "Permissions" "INFO" "dangerous SUID strip not run (dry-run)"
  elif (( suid_left > 0 )); then
    finding "PERM-SUID-STRIP" "Permissions" "WARN" "$suid_left dangerous SUID binary(ies) still present" \
      "Inspect with: find / -xdev -type f -perm -4000 -print ; chmod u-s <path> for nmap/interpreters/editors."
  elif (( removed > 0 )); then
    finding "PERM-SUID-STRIP" "Permissions" "PASS" "stripped SUID from $removed dangerous binary(ies)"
  else
    finding "PERM-SUID-STRIP" "Permissions" "PASS" "no dangerous SUID binaries found"
  fi

  # unowned
  local uo; uo="$(find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -500 | wc -l)"
  if (( uo > 0 )) && [[ $DRY -eq 0 ]]; then
    find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print0 2>/dev/null | \
      head -z -n 500 | xargs -0 -r chown root:root 2>/dev/null
    local uleft
    uleft="$(find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -500 | wc -l)"
    if (( uleft == 0 )); then
      finding "PERM-UNOWNED-FIX" "Permissions" "PASS" "chowned ~$uo unowned file(s) to root:root"
    else
      finding "PERM-UNOWNED-FIX" "Permissions" "WARN" "$uleft unowned file(s) remain after chown" \
        "Review: find / -xdev \\( -nouser -o -nogroup \\) -print ; check for immutable flags (lsattr) or read-only mounts."
    fi
  fi

  # SELinux relabel if enforcing
  if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    command -v restorecon >/dev/null 2>&1 && { act restorecon -R /etc /boot /var/log; ok "restorecon run on /etc /boot /var/log"; }
  fi
  command -v ldconfig >/dev/null 2>&1 && [[ $DRY -eq 0 ]] && ldconfig 2>/dev/null
}

# ---------------------------------------------------------------------------
# AUDIT + LOGGING
# ---------------------------------------------------------------------------
do_audit() {
  banner "AUDIT + LOGGING"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: audit untouched"; return; }

  pkg_install auditd audispd-plugins rsyslog 2>/dev/null

  if command -v auditctl >/dev/null 2>&1; then
    if [[ $DRY -eq 0 ]]; then mkdir -p /etc/audit/rules.d; fi
    [[ -f /etc/audit/auditd.conf ]] && backup_file /etc/audit/auditd.conf
    [[ -f /etc/audit/rules.d/cyberpatriot.rules ]] && backup_file /etc/audit/rules.d/cyberpatriot.rules
    if [[ $DRY -eq 0 && ! -e /etc/audit/rules.d/cyberpatriot.rules ]]; then
      created_file /etc/audit/rules.d/cyberpatriot.rules
    fi
    if [[ -f /etc/audit/auditd.conf ]]; then
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*max_log_file[[:space:]]*=' 'max_log_file = 25'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*max_log_file_action[[:space:]]*=' 'max_log_file_action = keep_logs'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*space_left[[:space:]]*=' 'space_left = 75'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*space_left_action[[:space:]]*=' 'space_left_action = SYSLOG'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*admin_space_left[[:space:]]*=' 'admin_space_left = 50'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*admin_space_left_action[[:space:]]*=' 'admin_space_left_action = SYSLOG'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*disk_full_action[[:space:]]*=' 'disk_full_action = SYSLOG'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*log_format[[:space:]]*=' 'log_format = ENRICHED'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*num_logs[[:space:]]*=' 'num_logs = 10'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*flush[[:space:]]*=' 'flush = INCREMENTAL_ASYNC'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*freq[[:space:]]*=' 'freq = 50'
      ensure_line /etc/audit/auditd.conf '^[[:space:]]*action_mail_acct[[:space:]]*=' 'action_mail_acct = root'
      ok "auditd.conf tuned"
    fi

    if [[ $DRY -eq 0 ]]; then
      cat >/etc/audit/rules.d/cyberpatriot.rules <<'AUD'
## cbptlinux.sh audit rules
-D
-b 8192
-f 1

## identity / auth
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/security/ -p wa -k pam
-w /etc/pam.d/ -p wa -k pam
-w /etc/login.defs -p wa -k identity

## ssh
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k rootkey

## logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /etc/securetty -p wa -k logins

## time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## network / host config
-w /etc/hosts -p wa -k network
-w /etc/hostname -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysconfig/network -p wa -k network

## MAC / policy changes
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

## module load/unload
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

## privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privcmd

## file deletion / perms by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k permchange
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k permchange
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k permchange
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k permchange

## mounts / media
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-w /media/ -p wa -k media
-w /mnt/ -p wa -k media

## execution tracking (noisy but very useful for forensics)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k exec
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k exec

## cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

## startup / persistence
-w /etc/rc.local -p wa -k startup
-w /etc/profile -p wa -k startup
-w /etc/profile.d/ -p wa -k startup
-w /etc/bash.bashrc -p wa -k startup
-w /etc/systemd/system/ -p wa -k startup
-w /lib/systemd/system/ -p wa -k startup
-w /etc/ld.so.preload -p wa -k rootkit
-w /etc/ld.so.conf -p wa -k rootkit
-w /etc/ld.so.conf.d/ -p wa -k rootkit

## unsuccessful auth attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access

## immutable last
-e 2
AUD
      chmod 644 /etc/audit/rules.d/cyberpatriot.rules
    else
      say "[dry-run] write /etc/audit/rules.d/cyberpatriot.rules"
    fi
    act augenrules --load || act auditctl -R /etc/audit/rules.d/cyberpatriot.rules
    act systemctl enable auditd
    act systemctl restart auditd || act service auditd restart
    local n; n="$(auditctl -l 2>/dev/null | wc -l)"
    ok "audit rules loaded: $n"
    if (( n > 10 )); then
      finding "AUDIT-RULES" "Audit" "PASS" "$n audit rules active"
    else
      finding "AUDIT-RULES" "Audit" "WARN" "only $n audit rules loaded" \
        "augenrules --load ; auditctl -l ; check /var/log/audit/audit.log for 'Error' lines. some rules need a different arch on 32-bit."
    fi
    # note: -e 2 makes the rules immutable until reboot -- that is intended,
    # but if you need to change them: auditctl -e 1
  elif [[ $DRY -eq 1 ]]; then
    finding "AUDIT-INSTALLED" "Audit" "INFO" "auditd would be installed and configured (dry-run)"
  else
    finding "AUDIT-INSTALLED" "Audit" "FAIL" "auditd not installed" \
      "Install auditd. audit policy + rules are worth several points and auditd is the only way to get them."
  fi

  # ---- AppArmor / SELinux ----
  step "mandatory access control"
  local mac="" mode prof enf
  if command -v getenforce >/dev/null 2>&1; then
    mode="$(getenforce 2>/dev/null)"
    [[ "$mode" != "Disabled" ]] && mac="selinux"
  fi
  if [[ -z "$mac" ]] && { command -v aa-status >/dev/null 2>&1 || [[ -d /etc/apparmor.d ]]; }; then
    mac="apparmor"
  fi
  case "$mac" in
    selinux)
      backup_file /etc/selinux/config
      if [[ "$mode" == "Enforcing" ]]; then
        finding "MAC-SELINUX" "Hardening" "PASS" "SELinux enforcing"
      else
        finding "MAC-SELINUX" "Hardening" "FAIL" "SELinux is $mode" \
          "setenforce 1, then set SELINUX=enforcing in /etc/selinux/config and reboot. If labels were changed by hand, touch /.autorelabel first."
        act setenforce 1
        [[ -f /etc/selinux/config ]] && ensure_line /etc/selinux/config '^[[:space:]]*SELINUX=' 'SELINUX=enforcing'
      fi
      ;;
    apparmor)
      pkg_install apparmor apparmor-utils 2>/dev/null
      act systemctl enable apparmor
      act systemctl start apparmor
      if [[ $DRY -eq 0 && -d /etc/apparmor.d ]]; then
        # some images carry profiles left in complain mode; enforce them all.
        aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
      else
        say "[dry-run] aa-enforce /etc/apparmor.d/*"
      fi
      if command -v aa-status >/dev/null 2>&1; then
        prof="$(aa-status --profiled 2>/dev/null)"
        enf="$(aa-status --enforced 2>/dev/null)"
        prof="${prof:-0}"; enf="${enf:-0}"
        if (( prof > 0 && enf >= prof )); then
          finding "MAC-APPARMOR" "Hardening" "PASS" "AppArmor enforcing $enf/$prof profiles"
        else
          finding "MAC-APPARMOR" "Hardening" "WARN" "AppArmor enforcing $enf/$prof profiles" \
            "aa-status; aa-enforce /etc/apparmor.d/*; check for profiles still in complain mode. A few unconfined profiles on a desktop image is normal."
        fi
      else
        finding "MAC-APPARMOR" "Hardening" "WARN" "apparmor-utils not available" \
          "Install apparmor-utils and run aa-status. AppArmor enforcement is commonly scored on Ubuntu images."
      fi
      ;;
    *)
      finding "MAC-NONE" "Hardening" "WARN" "no AppArmor or SELinux userspace found" \
        "On Ubuntu install apparmor apparmor-utils and enable it. On RHEL/Fedora SELinux should already exist; if getenforce is missing the image may be intentionally minimal."
      ;;
  esac

  # ---- rsyslog ----
  step "rsyslog"
  if [[ -f /etc/rsyslog.conf ]]; then
    backup_file /etc/rsyslog.conf
    ensure_line /etc/rsyslog.conf '^[[:space:]]*\$FileCreateMode' '$FileCreateMode 0640'
    ensure_line /etc/rsyslog.conf '^[[:space:]]*\$UMASK'          '$UMASK 0027'
    grep -q 'authpriv' /etc/rsyslog.conf || { [[ $DRY -eq 0 ]] && printf 'auth,authpriv.*\t\t\t/var/log/auth.log\n' >>/etc/rsyslog.conf; }
    [[ $DRY -eq 0 ]] && ok "rsyslog.conf tuned"
    act systemctl restart rsyslog || act service rsyslog restart
    if [[ $DRY -eq 1 ]]; then
      finding "LOG-RSYSLOG" "Logging" "INFO" "rsyslog FileCreateMode/UMASK would be set (dry-run)"
    elif grep -qE '^[[:space:]]*\$FileCreateMode[[:space:]]+0640' /etc/rsyslog.conf \
         && grep -qE '^[[:space:]]*\$UMASK[[:space:]]+0027' /etc/rsyslog.conf \
         && (systemctl is-active rsyslog >/dev/null 2>&1 || service rsyslog status >/dev/null 2>&1); then
      finding "LOG-RSYSLOG" "Logging" "PASS" "FileCreateMode 0640, UMASK 0027, rsyslog active"
    else
      finding "LOG-RSYSLOG" "Logging" "WARN" "rsyslog permissions are not fully active" \
        "Check the FileCreateMode/UMASK lines in /etc/rsyslog.conf, then: systemctl restart rsyslog ; systemctl status rsyslog"
    fi
    finding "LOG-REMOTE" "Logging" "INFO" "no remote syslog target configured" \
      "If the README names a log server, add: *.* @@loghost:514  to /etc/rsyslog.conf and restart. centralized logging is a common scored item."
  fi

  # journald: persist to disk
  if [[ -d /etc/systemd/journald.conf.d || -f /etc/systemd/journald.conf ]]; then
    if [[ $DRY -eq 0 ]]; then
      mkdir -p /etc/systemd/journald.conf.d
      backup_file /etc/systemd/journald.conf
      backup_file /etc/systemd/journald.conf.d/99-cp.conf
      [[ -e /etc/systemd/journald.conf.d/99-cp.conf ]] || created_file /etc/systemd/journald.conf.d/99-cp.conf
      cat >/etc/systemd/journald.conf.d/99-cp.conf <<'JRN'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=2G
SystemKeepFree=1G
MaxRetentionSec=1month
ForwardToSyslog=yes
JRN
      chmod 644 /etc/systemd/journald.conf.d/99-cp.conf
      mkdir -p /var/log/journal && chmod 2755 /var/log/journal
      systemctl restart systemd-journald >/dev/null 2>&1
    else
      say "[dry-run] journald persistent"
    fi
    if [[ $DRY -eq 1 ]]; then
      finding "LOG-JOURNALD" "Logging" "INFO" "journald would be persistent, 2G cap, forwarded to syslog (dry-run)"
    elif [[ -f /etc/systemd/journald.conf.d/99-cp.conf ]] \
         && grep -qx 'Storage=persistent' /etc/systemd/journald.conf.d/99-cp.conf \
         && grep -qx 'SystemMaxUse=2G' /etc/systemd/journald.conf.d/99-cp.conf \
         && grep -qx 'ForwardToSyslog=yes' /etc/systemd/journald.conf.d/99-cp.conf \
         && systemctl is-active systemd-journald >/dev/null 2>&1; then
      finding "LOG-JOURNALD" "Logging" "PASS" "journald persistent, 2G cap, forwarded to syslog"
    else
      finding "LOG-JOURNALD" "Logging" "WARN" "journald persistence is not fully active" \
        "Check /etc/systemd/journald.conf.d/99-cp.conf, then: systemctl restart systemd-journald ; journalctl --disk-usage"
    fi
  fi

  # do NOT clear any log. ever.
  finding "LOG-INTACT" "Logging" "PASS" "no logs were cleared or truncated" \
    "Never run > /var/log/* or logrotate -f on a scored image. cleared logs look like the attacker covering tracks and can destroy forensic answers."

  # bash history: keep it, make it richer, do not disable it
  if [[ -f /etc/profile ]]; then
    if ! grep -q 'cbptlinux history' /etc/profile; then
      if [[ $DRY -eq 0 ]]; then
        backup_file /etc/profile
        cat >>/etc/profile <<'HIST'

# cbptlinux history -- timestamps + no dedup hiding
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=100000
export HISTFILESIZE=200000
shopt -s histappend
PROMPT_COMMAND="history -a; ${PROMPT_COMMAND}"
HIST
      else
        say "[dry-run] history enrichment in /etc/profile"
      fi
      [[ $DRY -eq 0 ]] && ok "shell history now timestamped"
      finding "LOG-HIST" "Logging" "$( [[ $DRY -eq 0 ]] && echo PASS || echo INFO )" "HISTTIMEFORMAT set, histappend on"
    fi
  fi
}
# ---------------------------------------------------------------------------
# INSTALLED SERVER APPS -- config only, never their data directories
# ---------------------------------------------------------------------------
do_apps() {
  banner "INSTALLED SERVICES"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: app configs untouched"; return; }
  [[ $DRY -eq 1 ]] && { say "[dry-run] preview only: app configs, permissions, packages and services untouched"; return; }

  local -a app_files=() app_validate=() app_reload=() app_status=() app_verify=()
  local app_failed=0 app_activation_failed=0 app_output="" app_unit=""
  # These helpers share only this invocation's transaction state.
  _apps_service() {
    local config="$1" s id selected="" start
    shift
    have systemctl || return 1
    for s in "$@"; do
      systemctl is-active --quiet "$s" 2>/dev/null || continue
      id="$(systemctl show -p Id --value "$s" 2>/dev/null)" || return 1
      [[ -n "$id" && ( -z "$selected" || "$selected" == "$id" ) ]] || return 1
      selected="$id"
    done
    [[ -n "$selected" ]] || return 1
    start="$(systemctl show -p ExecStart --value "$selected" 2>/dev/null)" || return 1
    [[ -n "$start" ]] || return 1
    if [[ "$start" =~ (--defaults(-extra)?-file|--config(file|-file)?|--fpm-config|[[:space:]]-[cfy]([[:space:]=]|$)) && "$start" != *"$config"* ]]; then
      return 1
    fi
    printf '%s\n' "$selected"
  }
  _apps_valid() {
    app_output="$("${app_validate[@]}" 2>&1)" || return 1
    ! grep -qiE 'syntax error|PHP (Warning|Fatal|Parse)|\[ERROR\]' <<<"$app_output"
  }
  _apps_begin() {
    local id="$1" path f target
    local -A saved=()
    shift
    app_files=(); app_verify=(); app_failed=0; app_activation_failed=0
    if ! declare -F backup_file >/dev/null || ! declare -F restore_file >/dev/null ||
       [[ ${#app_validate[@]} -eq 0 || ${#app_reload[@]} -eq 0 || ${#app_status[@]} -eq 0 ]]; then
      finding "$id" "Apps" "WARN" "transaction support unavailable; original unchanged"
      return 1
    fi
    if ! _apps_valid; then
      finding "$id" "Apps" "WARN" "existing configuration did not validate; original unchanged" "Run: ${app_validate[*]}"
      return 1
    fi
    for path in "$@"; do
      [[ "$path" == /* ]] || return 1
      target="$path"
      if [[ -L "$path" ]]; then
        target="$(readlink -f "$path")" || return 1
        [[ -f "$target" ]] || return 1
      fi
      for f in "$path" "$target"; do
        [[ -n "${saved[$f]:-}" ]] && continue
        if ! backup_file "$f"; then
          finding "$id" "Apps" "WARN" "snapshot failed for $f; original unchanged"
          return 1
        fi
        [[ -e "$f" || -L "$f" ]] || created_file "$f"
        saved[$f]=1; app_files+=("$f")
      done
    done
  }
  _apps_write() {
    local tmp rc=0
    tmp="$(mktemp)" || return 1
    # Stage before opening the destination, including when stdin reads it.
    { cat >"$tmp" && cat "$tmp" >"$1"; } || rc=1
    rm -f "$tmp"
    return "$rc"
  }
  _apps_ini() {
    local input="$1"
    [[ -f "$input" ]] || input=/dev/null
    CP_APP_SECTION="$2" CP_APP_SETTINGS="$3" awk '
      function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
      function key(s) { s=tolower(trim(s)); if (section=="mysqld") gsub(/_/, "-", s); return s }
      BEGIN {
        section=tolower(ENVIRON["CP_APP_SECTION"]); inside=(section=="")
        n=split(ENVIRON["CP_APP_SETTINGS"], settings, "\n")
        for (j=1; j<=n; j++) { s=settings[j]; sub(/=.*/, "", s); keys[key(s)]=1 }
      }
      {
        lines[NR]=$0; s=trim($0)
        if (section!="" && s ~ /^\[/) {
          if (inside) insert=NR
          sub(/\].*/, "", s); sub(/^\[/, "", s)
          inside=(tolower(trim(s))==section); if (inside) seen=1
        }
        if (inside && $0 !~ /^[[:space:]]*[#;]/ && index($0,"=")) {
          s=$0; sub(/=.*/, "", s); if (key(s) in keys) omit[NR]=1
        }
      }
      END {
        if (inside || !seen || section=="") insert=NR+1
        for (i=1; i<=NR+1; i++) {
          if (i==insert) {
            if (section!="" && !seen) print "\n[" section "]"
            for (j=1; j<=n; j++) print (section=="global" ? "   " : "") settings[j]
          }
          if (i<=NR && !(i in omit)) print lines[i]
        }
      }' "$input" | _apps_write "$1"
  }
  _apps_finish() {
    local id="$1" detail="$2" i restored=1
    if (( app_failed == 0 )) && _apps_valid; then
      app_activation_failed=1
      if "${app_reload[@]}" >/dev/null 2>&1 && "${app_status[@]}" >/dev/null 2>&1 &&
         { [[ ${#app_verify[@]} -eq 0 ]] || "${app_verify[@]}" >/dev/null 2>&1; }; then
        app_activation_failed=0
        finding "$id" "Apps" "PASS" "$detail"
        return 0
      fi
    fi
    for ((i=${#app_files[@]}-1; i>=0; i--)); do
      restore_file "${app_files[i]}" || restored=0
    done
    finding "$id" "Apps" "FAIL" "configuration write, validation or activation failed; rollback attempted" "Check ${app_validate[*]} and the service journal."
    if (( restored == 0 )) || ! _apps_valid; then
      finding "$id-ROLLBACK" "Apps" "FAIL" "original configuration could not be restored and validated; manual recovery required"
    elif (( app_activation_failed )) && ! { "${app_reload[@]}" >/dev/null 2>&1 && "${app_status[@]}" >/dev/null 2>&1; }; then
      finding "$id-ROLLBACK" "Apps" "FAIL" "original files restored, but service recovery failed; manual recovery required"
    fi
    return 1
  }

  # ---- Apache ----
  local conf sec root ctl enabled f snippet
  local -a apache_files=()
  for conf in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
    [[ -f "$conf" ]] || continue
    step "apache: $conf"
    finding "APP-APACHE-SSL" "Apps" "INFO" "manual: verify TLS config" \
      "Check every vhost for TLS1.2+, SSLHonorCipherOrder and appropriate HSTS; retain stronger existing TLS policies."
    sec=""; enabled=""
    if [[ "$conf" == /etc/apache2/apache2.conf ]]; then
      root=/etc/apache2; ctl=apache2ctl
      have "$ctl" || ctl=apachectl
      app_unit="$(_apps_service "$conf" apache2)"
      if [[ -d /etc/apache2/conf-available && -d /etc/apache2/conf-enabled ]] &&
         grep -qE '^[[:space:]]*Include(Optional)?[[:space:]]+"?(/etc/apache2/)?conf-enabled/\*\.conf"?([[:space:]]|$)' "$conf"; then
        sec=/etc/apache2/conf-available/security-hardening.conf
        enabled=/etc/apache2/conf-enabled/security-hardening.conf
      fi
    else
      root=/etc/httpd; ctl=apachectl
      have "$ctl" || ctl=httpd
      app_unit="$(_apps_service "$conf" httpd)"
      if [[ -d /etc/httpd/conf.d ]] && grep -qE '^[[:space:]]*Include(Optional)?[[:space:]]+"?(/etc/httpd/)?conf.d/\*\.conf"?([[:space:]]|$)' "$conf"; then
        sec=/etc/httpd/conf.d/security-hardening.conf
      fi
    fi
    if ! have "$ctl" || [[ -z "$app_unit" ]]; then
      finding "APP-APACHE" "Apps" "WARN" "validator or unambiguous active default-config service unavailable; unchanged"
      continue
    fi
    if [[ -n "$sec" && -e "$sec" ]] && ! grep -qxF '# cbptlinux.sh' "$sec"; then
      finding "APP-APACHE" "Apps" "WARN" "unmanaged $sec retained; review hardening manually"
      continue
    fi
    if [[ -n "$enabled" && ( -e "$enabled" || -L "$enabled" ) ]] &&
       { [[ ! -L "$enabled" ]] || [[ "$(readlink -f "$enabled")" != "$(readlink -f "$sec")" ]]; }; then
      finding "APP-APACHE" "Apps" "WARN" "existing enabled configuration has a different target; unchanged"
      continue
    fi
    apache_files=("$conf")
    while IFS= read -r -d '' f; do apache_files+=("$f"); done < <(
      grep -rlZiE '^[[:space:]]*Options[[:space:]].*(Indexes|All)' "$root" 2>/dev/null)
    [[ -n "$sec" ]] && apache_files+=("$sec")
    [[ -n "$enabled" ]] && apache_files+=("$enabled")
    app_validate=("$ctl" -t -f "$conf")
    app_reload=(systemctl reload "$app_unit"); app_status=(systemctl is-active --quiet "$app_unit")
    _apps_begin "APP-APACHE" "${apache_files[@]}" || continue
    snippet="$(cat <<'APSEC'
# cbptlinux.sh
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
<IfModule mod_headers.c>
Header unset X-Powered-By
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
<Directory />
    Options -Indexes
</Directory>
<DirectoryMatch "/\.(git|svn|hg|env)">
    Require all denied
</DirectoryMatch>
APSEC
    )"
    if [[ $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: restrict Apache symlinks/CGI/overrides, uploads and timeouts? Confirm the README and every vhost permit this."; then
      snippet+=$'\n<Directory />\n    Options -FollowSymLinks -Includes -ExecCGI\n    AllowOverride None\n    Require all denied\n</Directory>\nLimitRequestBody 10485760\nTimeout 60\nKeepAlive On\nMaxKeepAliveRequests 100\nKeepAliveTimeout 5'
    fi
    if [[ -n "$sec" ]]; then
      printf '%s\n' "$snippet" | _apps_write "$sec" || app_failed=1
      chmod 644 "$sec" || app_failed=1
      if [[ -n "$enabled" && ! -L "$enabled" ]]; then ln -s "$sec" "$enabled" || app_failed=1; fi
    else
      { cat "$conf"; printf '\n%s\n' "$snippet"; } | _apps_write "$conf" || app_failed=1
    fi
    for f in "${apache_files[@]}"; do
      [[ -f "$f" && "$f" != "$enabled" ]] || continue
      awk '
        tolower($1)=="options" {
          line=$0; comment=""; if (match(line, /#.*/)) { comment=" " substr(line,RSTART); line=substr(line,1,RSTART-1) }
          if (line ~ /\\[[:space:]]*$/) exit 1
          match(line,/[^[:space:]]/); indent=substr(line,1,RSTART-1)
          sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+/, "", line)
          sub(/[[:space:]]+$/, "", line); n=split(line,w,/[[:space:]]+/)
          positive=0; signed=0; all=0
          for (i=1;i<=n;i++) {
            t=tolower(w[i]); if (t=="indexes" || t=="+indexes" || t=="all" || t=="+all") positive=1
            if (t=="all" || t=="+all") all=1
            if (w[i] ~ /^[+-]/) signed=1
          }
          if (positive) {
            out=""
            for (i=1;i<=n;i++) {
              t=tolower(w[i]); if (t ~ /^[+-]?indexes$/) continue
              if ((all || signed) && w[i] !~ /^[+-]/) w[i]="+" w[i]
              out=out (out=="" ? "" : " ") w[i]
            }
            if (all || signed) out=out (out=="" ? "" : " ") "-Indexes"
            if (out=="") out="None"
            print indent "Options " out comment; next
          }
        }
        { print }' "$f" | _apps_write "$f" || app_failed=1
    done
    _apps_finish "APP-APACHE" "apache config validated and reloaded; headers guarded, Indexes removed without dropping other options"
  done

  # ---- nginx ----
  if [[ -f /etc/nginx/nginx.conf ]]; then
    step "nginx"
    local ngxdrop=/etc/nginx/conf.d/99-cbptlinux.conf ngx_aggressive=0 header value
    local -a nginx_files=(/etc/nginx/nginx.conf)
    app_unit="$(_apps_service /etc/nginx/nginx.conf nginx)"
    # Accept only a conf.d include directly in http {}, not at main/server scope.
    if ! have nginx || [[ -z "$app_unit" || ! -d /etc/nginx/conf.d ]]; then
      finding "APP-NGINX" "Apps" "WARN" "validator or unambiguous active nginx service unavailable; unchanged"
    elif ! awk '
      {
        raw=$0; clean=""; initial_quote=quote
        for (i=1;i<=length(raw);i++) {
          c=substr(raw,i,1)
          if (quote!="") { if (escape) escape=0; else if(c=="\\") escape=1; else if(c==quote) quote=""; continue }
          if(c=="#") break
          if(c=="\"" || c==sprintf("%c",39)) { quote=c; continue }
          if(c=="$" && substr(raw,i+1,1)=="{") { while(i<=length(raw) && substr(raw,i,1)!="}") i++; continue }
          clean=clean c
        }
        if(clean ~ /^[[:space:]]*http[[:space:]]*\{[[:space:]]*$/) http=depth+1
        if(!initial_quote && http && depth==http && raw ~ /^[[:space:]]*include[[:space:]]+"?\/etc\/nginx\/conf\.d\/\*\.conf"?;[[:space:]]*(#.*)?$/) found++
        s=clean; opens=gsub(/\{/,"",s); closes=gsub(/\}/,"",s); depth+=opens-closes
        if(http && depth<http) http=0
      }
      END { exit(found==1 && depth==0 && quote=="" ? 0 : 1) }' /etc/nginx/nginx.conf; then
      finding "APP-NGINX" "Apps" "WARN" "no unique /etc/nginx/conf.d/*.conf include directly inside http {}; unchanged" \
        "Place server_tokens off in the actual http context; do not append it at main scope."
    else
      while IFS= read -r -d '' f; do nginx_files+=("$f"); done < <(
        grep -rlZiE 'server_tokens|autoindex[[:space:]]+on|ssl_protocols' /etc/nginx 2>/dev/null)
      nginx_files+=("$ngxdrop")
      app_validate=(nginx -t -c /etc/nginx/nginx.conf)
      app_reload=(systemctl reload "$app_unit"); app_status=(systemctl is-active --quiet "$app_unit")
      if _apps_begin "APP-NGINX" "${nginx_files[@]}"; then
        if [[ $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: remove pre-TLS1.2 nginx protocols and add missing upload/time limits? Confirm client and workload compatibility."; then ngx_aggressive=1; fi
        for f in "${nginx_files[@]}"; do
          [[ -f "$f" ]] || continue
          awk -v aggressive="$ngx_aggressive" '
            /^[[:space:]]*server_tokens[[:space:]]+[^;]+;[[:space:]]*(#.*)?$/ { next }
            /^[[:space:]]*autoindex[[:space:]]+on;[[:space:]]*(#.*)?$/ { sub(/on;/,"off;") }
            aggressive && /^[[:space:]]*ssl_protocols[[:space:]]+[^;]+;[[:space:]]*(#.*)?$/ {
              s=$0; sub(/^[[:space:]]*ssl_protocols[[:space:]]+/,"",s); sub(/;.*/,"",s)
              n=split(s,w,/[[:space:]]+/); out=""
              for(i=1;i<=n;i++) if(w[i]!="" && w[i] !~ /^(SSLv2|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1)$/) out=out " " w[i]
              if(out=="") out=" TLSv1.2 TLSv1.3"
              print "ssl_protocols" out ";"; next
            }
            /^[[:space:]]*#/ { print; next }
            /(^|[;{}])[[:space:]]*(server_tokens[[:space:]]|autoindex[[:space:]]+on[[:space:]]*;)/ { exit 1 }
            { print }' "$f" | _apps_write "$f" || app_failed=1
        done
        snippet="# cbptlinux.sh"
        [[ -f "$ngxdrop" ]] && snippet="$(cat "$ngxdrop")"
        snippet+=$'\nserver_tokens off;'
        for header in X-Content-Type-Options X-Frame-Options Referrer-Policy; do
          case "$header" in
            X-Content-Type-Options) value=nosniff ;;
            X-Frame-Options) value=SAMEORIGIN ;;
            Referrer-Policy) value=strict-origin-when-cross-origin ;;
          esac
          if ! grep -rqiE "^[[:space:]]*add_header[[:space:]]+\"?${header}\"?[[:space:]]" /etc/nginx; then
            snippet+=$'\n'"add_header $header \"$value\" always;"
          fi
        done
        if (( ngx_aggressive )); then
          for value in 'client_max_body_size 10m;' 'client_body_timeout 10s;' 'client_header_timeout 10s;' 'send_timeout 10s;' 'ssl_protocols TLSv1.2 TLSv1.3;' 'ssl_prefer_server_ciphers on;' 'ssl_session_cache shared:SSL:10m;' 'ssl_session_timeout 10m;'; do
            grep -rqE "^[[:space:]]*${value%% *}[[:space:]]" /etc/nginx || snippet+=$'\n'"$value"
          done
        fi
        printf '%s\n' "$snippet" | _apps_write "$ngxdrop" || app_failed=1
        chmod 644 "$ngxdrop" || app_failed=1
        _apps_finish "APP-NGINX" "nginx config validated and reloaded; http-context tokens off, simple autoindex directives off; existing headers/TLS policies retained"
      fi
    fi
    finding "APP-NGINX-TLS" "Apps" "INFO" "review per-vhost headers, TLS and externally included files" "Inherited add_header rules can be overridden by a server/location block."
  fi

  # ---- MySQL / MariaDB ----
  local c drop="" dbroot="" dbdaemon dbhelp bindaddr settings db_ready=1 server_count=0
  local -a mycnf=()
  for c in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf /etc/my.cnf.d/mariadb-server.cnf; do
    [[ -f "$c" ]] && mycnf+=("$c")
  done
  if [[ ${#mycnf[@]} -gt 0 ]]; then
    step "mysql"
    finding "APP-MYSQL-DB" "Apps" "INFO" "manual SQL work required" \
      "Inventory user,host,plugin in mysql.user; review anonymous users, remote root and the test database against the README before changing accounts."
    [[ -f /etc/mysql/my.cnf ]] && dbroot=/etc/mysql/my.cnf
    [[ -z "$dbroot" && -f /etc/my.cnf ]] && dbroot=/etc/my.cnf
    if [[ -f /etc/mysql/my.cnf && -f /etc/my.cnf && "$(readlink -f /etc/mysql/my.cnf)" != "$(readlink -f /etc/my.cnf)" ]]; then db_ready=0; fi
    app_unit="$(_apps_service "${dbroot:-/etc/my.cnf}" mysql mysqld mariadb)"
    dbdaemon=mysqld
    [[ "$app_unit" == mariadb* ]] && have mariadbd && dbdaemon=mariadbd
    if [[ -z "$dbroot" || -z "$app_unit" || $db_ready -eq 0 ]] || ! have "$dbdaemon"; then
      finding "APP-MYSQL" "Apps" "WARN" "validator or unambiguous active default-config database unavailable; unchanged"
      db_ready=0
    fi
    if (( db_ready )); then
      # Only write a drop-in which an existing option file actually includes.
      for c in /etc/mysql/conf.d /etc/mysql/mysql.conf.d /etc/mysql/mariadb.conf.d /etc/my.cnf.d; do
        [[ -d "$c" ]] || continue
        if awk -v dir="$c" 'tolower($1)=="!includedir" { d=$2; sub(/\/$/,"",d); if(d==dir) found=1 } END { exit !found }' "${mycnf[@]}"; then
          drop="$c/99-cbptlinux.cnf"
        fi
      done
      if [[ -z "$drop" ]]; then
        for c in "${mycnf[@]}"; do
          if grep -qiE '^[[:space:]]*\[mysqld\][[:space:]]*([#;].*)?$' "$c"; then drop="$c"; ((server_count+=1)); fi
        done
        [[ $server_count -eq 1 ]] || db_ready=0
      fi
      if [[ -z "$drop" || $db_ready -eq 0 ]] || ! dbhelp="$("$dbdaemon" --verbose --help 2>/dev/null)"; then
        finding "APP-MYSQL" "Apps" "WARN" "server option layout or read-only validator is ambiguous; unchanged"
        db_ready=0
      fi
    fi
    if (( db_ready )); then
      app_validate=("$dbdaemon" --verbose --help)
      grep -q -- '--validate-config' <<<"$dbhelp" && app_validate=("$dbdaemon" --validate-config)
      app_reload=(systemctl restart "$app_unit"); app_status=(systemctl is-active --quiet "$app_unit")
      settings='local-infile = 0'
      grep -q -- 'symbolic-links' <<<"$dbhelp" && settings+=$'\nsymbolic-links = 0'
      bindaddr="$(awk '$1=="bind-address" { print $2; exit }' <<<"$dbhelp")"
      if [[ "$bindaddr" != 127.0.0.1 && "$bindaddr" != ::1 && "$bindaddr" != localhost ]] &&
         ! grep -qiE '^skip-networking[[:space:]]+(TRUE|ON|1)$' <<<"$dbhelp"; then
        finding "APP-MYSQL-NET" "Apps" "WARN" "database bind is ${bindaddr:-unknown}; remote access retained pending README review"
        if [[ -n "$bindaddr" && $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: bind MySQL to 127.0.0.1? Confirm the README and all clients require no remote database access."; then
          settings+=$'\nbind-address = 127.0.0.1'
        fi
      fi
      finding "APP-MYSQL-PATHS" "Apps" "INFO" "existing secure-file-priv, error log and SQL modes retained" \
        "Check secure-file-priv is NULL or an existing restricted directory and that the configured error log is writable by the DB service; no directories or fixed paths are invented."
      if _apps_begin "APP-MYSQL" "${mycnf[@]}" "$drop"; then
        _apps_ini "$drop" mysqld "$settings" || app_failed=1
        if ! _apps_finish "APP-MYSQL" "mysql options validated and service restarted; local-infile off, supported symlink option off; existing paths/modes retained" && (( app_activation_failed )); then
          finding "APP-MYSQL-RESTART" "Apps" "FAIL" "database restart failed; original files restored where possible" "Check journalctl -u $app_unit; a TCP listener is not required for a socket-only database."
        fi
      fi
    fi
  fi

  # ---- PostgreSQL ----
  if [[ -d /etc/postgresql ]] || [[ -f /var/lib/pgsql/data/postgresql.conf ]]; then
    step "postgresql"
    local pgconf pghba pgmeta="" pg_activeconf="" pg_activehba="" pg_version="" pg_log="" pgtrust pgcount pgroles pg_auth_change pgsql
    local -a pgconfs=() pghbas=() pgclient=(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 -d postgres)
    _apps_hba() {
      awk -v mode="$2" '
        {
          delete token; delete first; delete last; n=0; word=""; quote=0; start=0
          for(i=1;i<=length($0)+1;i++) {
            c=substr($0,i,1)
            if(c=="\"") { if(!start) start=i; quote=!quote; continue }
            if(!quote && (c=="#" || c ~ /[[:space:]]/ || i>length($0))) {
              if(start) { token[++n]=word; first[n]=start; last[n]=i-1; word=""; start=0 }
              if(c=="#") break
            } else { if(!start) start=i; word=word c }
          }
          method=0
          if(token[1]=="local" && token[4]=="trust") method=4
          if(token[1] ~ /^host(ssl|nossl|gssenc|nogssenc)?$/) {
            if(token[5]=="trust") method=5; else if(token[6]=="trust") method=6
          }
          if(mode=="inventory") { if(method) print FNR ":" $0 }
          else if(method) print substr($0,1,first[method]-1) "scram-sha-256" substr($0,last[method]+1)
          else print
        }' "$1"
    }
    while IFS= read -r -d '' f; do
      case "$f" in */postgresql.conf) pgconfs+=("$f") ;; */pg_hba.conf) pghbas+=("$f") ;; esac
    done < <(find -L /etc/postgresql -type f \( -name postgresql.conf -o -name pg_hba.conf \) -print0 2>/dev/null)
    [[ -f /var/lib/pgsql/data/postgresql.conf ]] && pgconfs+=(/var/lib/pgsql/data/postgresql.conf)
    [[ -f /var/lib/pgsql/data/pg_hba.conf ]] && pghbas+=(/var/lib/pgsql/data/pg_hba.conf)
    if have runuser && have psql; then
      pgmeta="$("${pgclient[@]}" -F $'\t' -c "SELECT current_setting('config_file'), current_setting('hba_file'), current_setting('server_version_num'), current_setting('log_statement');" 2>/dev/null)"
      IFS=$'\t' read -r pg_activeconf pg_activehba pg_version pg_log <<<"$pgmeta"
    fi
    if [[ -n "$pg_activehba" && -f "$pg_activehba" && " ${pghbas[*]} " != *" $pg_activehba "* ]]; then pghbas+=("$pg_activehba"); fi
    for pghba in "${pghbas[@]}"; do
      pgtrust="$(_apps_hba "$pghba" inventory)"
      if [[ -n "$pgtrust" ]]; then
        finding "APP-PG-HBA" "Apps" "FAIL" "active trust authentication in $pghba" \
          "Inventory below includes local, loopback, subnet, named database/user and host SSL/GSS variants. Choose peer/password auth per role; do not blindly convert passwords."
        say "$pghba:$pgtrust"
      elif grep -qE '^[[:space:]]*include(_dir|_if_exists)?[[:space:]]' "$pghba"; then
        finding "APP-PG-HBA" "Apps" "WARN" "$pghba includes other HBA files; inspect pg_hba_file_rules for their auth_method/error"
      else
        finding "APP-PG-HBA" "Apps" "PASS" "no active local/host trust entries in $pghba"
      fi
    done
    [[ ${#pgconfs[@]} -eq 0 ]] && finding "APP-PG" "Apps" "WARN" "PostgreSQL detected, but no known configuration path found; unchanged"
    for pgconf in "${pgconfs[@]}"; do
      if [[ -z "$pg_activeconf" || "$(readlink -f "$pgconf")" != "$(readlink -f "$pg_activeconf")" || ! -f "$pg_activehba" || ! "$pg_version" =~ ^[0-9]+$ || "$pg_version" -lt 100000 ]]; then
        finding "APP-PG" "Apps" "WARN" "$pgconf not matched to a live cluster with validation views; unchanged" \
          "Connect explicitly to this cluster and inspect pg_file_settings and pg_hba_file_rules; no generic postgresql reload is attempted."
        continue
      fi
      pghba="$pg_activehba"; pg_auth_change=0
      pgcount="$("${pgclient[@]}" -c "SELECT count(*) FROM pg_hba_file_rules WHERE auth_method = 'trust';" 2>/dev/null)"
      if [[ "$pgcount" =~ ^[0-9]+$ ]] && (( pgcount > 0 )); then
        finding "APP-PG-HBA" "Apps" "FAIL" "live cluster HBA inventory has $pgcount trust rules, including any includes"
        pgroles="$("${pgclient[@]}" -c "SELECT count(*) FROM pg_authid WHERE rolcanlogin AND (rolpassword IS NULL OR rolpassword NOT LIKE 'SCRAM-SHA-256$%');" 2>/dev/null)"
        if [[ "$pgroles" == 0 ]] && ! grep -qE '^[[:space:]]*include(_dir|_if_exists)?[[:space:]]' "$pghba" &&
           [[ $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: replace trust rules in $pghba with SCRAM? All LOGIN roles have SCRAM verifiers; confirm every client supports SCRAM and has the required password."; then
          pg_auth_change=1
        else
          finding "APP-PG-HBA" "Apps" "WARN" "trust rules retained: password/client compatibility or explicit approval is missing" "No role passwords are changed. Included HBA files require a separately reviewed transaction."
        fi
      fi
      finding "APP-PG-NET" "Apps" "INFO" "listen_addresses retained" "Local-only binding can break required DB clients and needs a controlled restart, not merely a reload. Review the README first."
      pgsql='DO $cbpt$ BEGIN IF EXISTS (SELECT 1 FROM pg_file_settings WHERE error IS NOT NULL) OR EXISTS (SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL) THEN RAISE EXCEPTION '\''invalid PostgreSQL configuration'\''; END IF; END $cbpt$;'
      app_validate=("${pgclient[@]}" -c "$pgsql")
      app_reload=("${pgclient[@]}" -c 'DO $cbpt$ BEGIN IF NOT pg_reload_conf() THEN RAISE EXCEPTION '\''reload failed'\''; END IF; END $cbpt$;')
      app_status=("${pgclient[@]}" -c 'SELECT 1;')
      if _apps_begin "APP-PG" "$pgconf" "$pghba"; then
        case "$pg_log" in all|mod|ddl) ;; *) pg_log=ddl ;; esac
        settings=$'log_connections = on\nlog_disconnections = on\n'"log_statement = '$pg_log'"
        _apps_ini "$pgconf" "" "$settings" || app_failed=1
        if (( pg_auth_change )); then
          _apps_hba "$pghba" change | _apps_write "$pghba" || app_failed=1
          [[ "$("${pgclient[@]}" -c "SELECT count(*) FROM pg_hba_file_rules WHERE auth_method = 'trust';" 2>/dev/null)" == 0 ]] || app_failed=1
        fi
        app_verify=("${pgclient[@]}" -c "SELECT pg_sleep(0.2); DO \$cbpt\$ BEGIN IF current_setting('log_connections') <> 'on' OR current_setting('log_disconnections') <> 'on' OR current_setting('log_statement') = 'none' THEN RAISE EXCEPTION 'logging was not applied'; END IF; END \$cbpt\$;")
        _apps_finish "APP-PG" "postgres configuration validated, reload acknowledged and logging verified; existing stronger statement logging retained"
      fi
    done
  fi

  # ---- BIND ----
  local nc
  for nc in /etc/bind/named.conf.options /etc/named.conf; do
    [[ -f "$nc" ]] || continue
    step "bind"
    backup_file "$nc"
    ensure_line "$nc" '^[[:space:]]*version' '    version "none";'
    ensure_line "$nc" '^[[:space:]]*allow-transfer' '    allow-transfer { none; };'
    if grep -qE '^[[:space:]]*acl[[:space:]]+trusted' /etc/bind/named.conf /etc/bind/named.conf.local /etc/named.conf 2>/dev/null; then
      ensure_line "$nc" '^[[:space:]]*allow-recursion' '    allow-recursion { trusted; };'
    else
      ensure_line "$nc" '^[[:space:]]*allow-recursion' '    allow-recursion { localnets; localhost; };'
    fi
    grep -q 'recursion' "$nc" || { [[ $DRY -eq 0 ]] && printf '    recursion no;\n' >>"$nc"; }
    if [[ $DRY -eq 1 ]]; then
      finding "APP-BIND" "Apps" "INFO" "bind hardening would be applied to $nc (dry-run)"
    elif command -v named-checkconf >/dev/null 2>&1 && named-checkconf >/dev/null 2>&1; then
      local bind_active=0 bind_reloaded=0
      if act systemctl reload bind9 >/dev/null 2>&1; then bind_reloaded=1
      elif act systemctl reload named >/dev/null 2>&1; then bind_reloaded=1
      fi
      if systemctl is-active --quiet bind9 2>/dev/null || systemctl is-active --quiet named 2>/dev/null; then bind_active=1; fi
      if (( bind_reloaded && bind_active )); then
        finding "APP-BIND" "Apps" "PASS" "bind: config validated, version hidden, transfers denied, recursion restricted"
      elif (( bind_active )); then
        finding "APP-BIND" "Apps" "WARN" "bind config validated but reload failed; old rules may still be active" \
          "systemctl reload bind9 (or named); check the journal for a config include or permission problem."
      else
        finding "APP-BIND" "Apps" "WARN" "bind config validated but the service is not active" \
          "systemctl status bind9 (or named); check the journal and the listening sockets."
      fi
    else
      finding "APP-BIND" "Apps" "WARN" "bind config changed but named-checkconf failed or is unavailable" \
        "Run named-checkconf; an undefined 'trusted' ACL or a syntax error prevents reload. Fix the config before restarting bind."
    fi
    finding "APP-BIND-ACL" "Apps" "INFO" "manual: verify the recursion ACL" \
      "If clients need recursion, define acl trusted { 10.0.0.0/8; 192.168.0.0/16; 127.0.0.1; }; in named.conf and reference it from allow-recursion; otherwise keep localnets/localhost or recursion no."
  done

  # ---- vsftpd ----
  local fc
  for fc in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [[ -f "$fc" ]] || continue
    step "vsftpd"
    backup_file "$fc"
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*anonymous_enable'   'anonymous_enable=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*local_enable'       'local_enable=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*chroot_local_user'   'chroot_local_user=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*ssl_enable'         'ssl_enable=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*force_local_data_ssl' 'force_local_data_ssl=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*force_local_logins_ssl' 'force_local_logins_ssl=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*xferlog_enable'      'xferlog_enable=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*ls_recurse_enable'   'ls_recurse_enable=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*idle_session_timeout' 'idle_session_timeout=600'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*banner_file'         'banner_file=/etc/issue.net'
    if [[ $DRY -eq 1 ]]; then
      finding "APP-FTP" "Apps" "INFO" "vsftpd hardening would be applied (dry-run)"
    elif act systemctl restart vsftpd >/dev/null 2>&1 \
         && systemctl is-active --quiet vsftpd >/dev/null 2>&1; then
      finding "APP-FTP" "Apps" "PASS" "vsftpd: anon off, chroot, TLS forced, logging on, service active"
    else
      finding "APP-FTP" "Apps" "WARN" "vsftpd config changed but restart failed or the service is not active" \
        "systemctl status vsftpd ; journalctl -u vsftpd --no-pager ; TLS requires a valid rsa_cert_file/rsa_private_key_file."
    fi
  done

  # ---- Samba ----
  local sc=/etc/samba/smb.conf
  if [[ -f "$sc" ]]; then
    step "samba"
    backup_file "$sc"
    ensure_line "$sc" '^[[:space:]]*#?[[:space:]]*server min protocol' '   server min protocol = SMB2_10'
    ensure_line "$sc" '^[[:space:]]*#?[[:space:]]*client min protocol'  '   client min protocol = SMB2_10'
    ensure_line "$sc" '^[[:space:]]*#?[[:space:]]*server signing'      '   server signing = mandatory'
    ensure_line "$sc" '^[[:space:]]*#?[[:space:]]*restrict anonymous' '   restrict anonymous = 2'
    ensure_line "$sc" '^[[:space:]]*#?[[:space:]]*map to guest'        '   map to guest = Never'
    if grep -qE '^\s*guest ok\s*=\s*yes' "$sc"; then
      finding "APP-SAMBA-GUEST" "Apps" "FAIL" "a share has guest ok = yes" \
        "Anonymous/guest SMB shares are almost always scored. set guest ok = no and give each user a smbpasswd."
    else
      finding "APP-SAMBA-GUEST" "Apps" "PASS" "no guest shares"
    fi
    if [[ $DRY -eq 1 ]]; then
      finding "APP-SAMBA" "Apps" "INFO" "samba hardening would be applied (dry-run)"
    elif command -v testparm >/dev/null 2>&1 && testparm -s >/dev/null 2>&1; then
      local smb_reloaded=0
      if act systemctl reload smbd >/dev/null 2>&1; then smb_reloaded=1
      elif act systemctl restart smbd >/dev/null 2>&1; then smb_reloaded=1
      fi
      if (( smb_reloaded )) && systemctl is-active --quiet smbd >/dev/null 2>&1; then
        finding "APP-SAMBA" "Apps" "PASS" "samba: SMB2+, mandatory signing, anon restricted, service active"
      elif (( smb_reloaded )); then
        finding "APP-SAMBA" "Apps" "WARN" "samba config validated and reloaded, but smbd is not active" \
          "systemctl status smbd ; check the journal and the listening sockets."
      else
        finding "APP-SAMBA" "Apps" "WARN" "samba config validated but reload/restart failed" \
          "systemctl restart smbd ; check the journal for a config or permission problem."
      fi
    else
      finding "APP-SAMBA" "Apps" "WARN" "samba config changed but testparm failed or is unavailable" \
        "Run testparm -s and fix smb.conf before restarting Samba."
    fi
  fi

  # ---- Postfix ----
  local mc=/etc/postfix/main.cf
  if [[ -f "$mc" ]]; then
    step "postfix"
    backup_file "$mc"
    ensure_line "$mc" '^[[:space:]]*#?[[:space:]]*smtpd_banner' 'smtpd_banner = $myhostname ESMTP'
    ensure_line "$mc" '^[[:space:]]*#?[[:space:]]*disable_vrfy_command' 'disable_vrfy_command = yes'
    ensure_line "$mc" '^[[:space:]]*#?[[:space:]]*smtpd_tls_security_level' 'smtpd_tls_security_level = may'
    ensure_line "$mc" '^[[:space:]]*#?[[:space:]]*smtpd_helo_required' 'smtpd_helo_required = yes'
    ensure_line "$mc" '^[[:space:]]*#?[[:space:]]*smtpd_recipient_restrictions' 'smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination, reject_unknown_recipient_domain'
    if grep -qE '^\s*mynetworks\s*=\s*(0\.0\.0\.0/0|127\.0\.0\.0/8,\s*0\.0\.0\.0/0)' "$mc"; then
      finding "APP-MAIL-RELAY" "Apps" "FAIL" "postfix is an open relay" \
        "mynetworks = 0.0.0.0/0 means anyone can relay mail through this box. restrict it to your actual subnets."
    else
      finding "APP-MAIL-RELAY" "Apps" "PASS" "postfix relay restricted"
    fi
    if [[ $DRY -eq 1 ]]; then
      finding "APP-MAIL" "Apps" "INFO" "postfix hardening would be applied (dry-run)"
    elif postfix check >/dev/null 2>&1; then
      local mail_reloaded=0
      if act systemctl reload postfix >/dev/null 2>&1; then mail_reloaded=1
      elif act systemctl restart postfix >/dev/null 2>&1; then mail_reloaded=1
      fi
      if (( mail_reloaded )) && systemctl is-active --quiet postfix >/dev/null 2>&1; then
        finding "APP-MAIL" "Apps" "PASS" "postfix: VRFY off, HELO required, TLS on, banner trimmed, service active"
        ok "postfix reloaded"
      elif (( mail_reloaded )); then
        finding "APP-MAIL" "Apps" "WARN" "postfix config validated and reloaded, but the service is not active" \
          "systemctl status postfix ; check the journal."
      else
        finding "APP-MAIL" "Apps" "WARN" "postfix config validated but reload/restart failed" \
          "systemctl restart postfix ; check the journal for a config or permission problem."
      fi
    else
      finding "APP-MAIL" "Apps" "WARN" "postfix config changed but postfix check failed" \
        "Run postfix check and inspect /etc/postfix/main.cf before restarting."
    fi
  fi

  # ---- WordPress / CMS (common on CP images) ----
  local wp
  for wp in /var/www/html/wp-config.php /var/www/wp-config.php /srv/www/htdocs/wp-config.php; do
    [[ -f "$wp" ]] || continue
    step "wordpress"
    backup_file "$wp"
    act chmod 640 "$wp"
    act chown root:www-data "$wp" 2>/dev/null || act chown root:apache "$wp" 2>/dev/null
    if grep -qE "DB_PASSWORD',\s*''" "$wp"; then
      finding "APP-WP-DBPW" "Apps" "FAIL" "wp-config.php has an EMPTY DB_PASSWORD" \
        "Set a real password and apply it in MySQL. empty DB creds is a very common scored vuln."
    else
      finding "APP-WP-DBPW" "Apps" "PASS" "wp-config.php DB password set"
    fi
    grep -q "AUTH_KEY" "$wp" || finding "APP-WP-KEYS" "Apps" "WARN" "wp-config.php has no AUTH_KEY/SALT block" \
      "Generate salts and paste them into wp-config.php."
    local wp_mode; wp_mode="$(stat -c '%a' "$wp" 2>/dev/null)"
    if [[ "$wp_mode" == "640" ]]; then
      finding "APP-WP" "Apps" "PASS" "wp-config.php perms 640"
    else
      finding "APP-WP" "Apps" "WARN" "wp-config.php mode is ${wp_mode:-unknown} (want 640)" \
        "chmod 640 $wp ; chown root:www-data $wp (or root:apache). The web server group needs read access."
    fi
    finding "APP-WP-MANUAL" "Apps" "INFO" "manual WordPress checks" \
      "Check for: table_prefix = 'wp_' (change it), WP_DEBUG on, file editing enabled (add DISALLOW_FILE_EDIT), outdated core/plugins, an 'admin' user, xmlrpc.php exposed."
  done

  # ---- PHP ----
  local pi
  for pi in /etc/php/*/fpm/php.ini /etc/php.ini /etc/php/*/apache2/php.ini; do
    [[ -f "$pi" ]] || continue
    backup_file "$pi"
    ensure_line "$pi" '^[[:space:]]*#?[[:space:]]*expose_php'        'expose_php = Off'
    ensure_line "$pi" '^[[:space:]]*#?[[:space:]]*display_errors'    'display_errors = Off'
    ensure_line "$pi" '^[[:space:]]*#?[[:space:]]*log_errors'       'log_errors = On'
    ensure_line "$pi" '^[[:space:]]*#?[[:space:]]*allow_url_fopen'  'allow_url_fopen = Off'
    ensure_line "$pi" '^[[:space:]]*#?[[:space:]]*allow_url_include' 'allow_url_include = Off'
    ensure_line "$pi" '^[[:space:]]*#?[[:space:]]*session\.cookie_httponly' 'session.cookie_httponly = 1'
    ensure_line "$pi" '^[[:space:]]*#?[[:space:]]*disable_functions' 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,phpinfo'
    if [[ $DRY -eq 1 ]]; then
      finding "APP-PHP" "Apps" "INFO" "php.ini hardening would be applied to $pi (dry-run)"
    elif grep -qE '^[[:space:]]*expose_php[[:space:]]*=[[:space:]]*Off' "$pi" \
         && grep -qE '^[[:space:]]*display_errors[[:space:]]*=[[:space:]]*Off' "$pi" \
         && grep -qE '^[[:space:]]*allow_url_include[[:space:]]*=[[:space:]]*Off' "$pi"; then
      finding "APP-PHP" "Apps" "PASS" "php.ini hardened: $pi"
    else
      finding "APP-PHP" "Apps" "WARN" "php.ini values are not fully applied: $pi" \
        "Set expose_php=Off, display_errors=Off, allow_url_include=Off and reload PHP-FPM/Apache."
    fi
    warn "php: disable_functions can break a legit web app. if the README needs it, trim the list."
  done
  [[ $DRY -eq 0 ]] && act systemctl reload 'php*-fpm'

  # ---- Docker (if present, it is a huge attack surface) ----
  if [[ -S /var/run/docker.sock ]]; then
    local dp; dp="$(stat -c '%a' /var/run/docker.sock)"
    [[ "$dp" != "660" && "$dp" != "600" ]] && finding "APP-DOCKER" "Apps" "FAIL" "/var/run/docker.sock is mode $dp" \
      "chmod 660 /var/run/docker.sock -- a world-writable docker socket is instant root."
  fi
}
# ---------------------------------------------------------------------------
# baseline snapshot (for diffing against a clean box)
# ---------------------------------------------------------------------------
do_baseline() {
  banner "BASELINE SNAPSHOT"
  local b="$EVID/baseline"
  mkdir -p "$b"
  say "writing baseline artifacts to $b (copy these to a clean VM later and diff)"
  find /etc -type f -exec sha256sum {} \; 2>/dev/null | sort -k2 >"$b/etc-sha256.txt"
  find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type f -printf '%M %u %g %p\n' 2>/dev/null | sort -k4 >"$b/all-file-perms.txt"
  find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort >"$b/suid.txt"
  find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type f -perm -0002 -print 2>/dev/null | sort >"$b/world-writable.txt"
  { systemctl list-unit-files 2>/dev/null; } | sort >"$b/systemd-units.txt"
  { ss -tulpnH 2>/dev/null; } | sort >"$b/listening.txt"
  { ps -eo args --no-headers 2>/dev/null; } | sort >"$b/processes.txt"
  getent passwd | sort >"$b/passwd.txt"; getent group | sort >"$b/group.txt"
  { ls -laR /etc/cron* /var/spool/cron 2>/dev/null; } >"$b/cron.txt"
  case "$PKG" in
    apt) dpkg -l 2>/dev/null | awk 'NR>5{print $2,$3}' | sort >"$b/packages.txt" ;;
    dnf|yum|zypper) rpm -qa --qf '%{NAME} %{VERSION}\n' 2>/dev/null | sort >"$b/packages.txt" ;;
    pacman) pacman -Q 2>/dev/null | sort >"$b/packages.txt" ;;
  esac
  ok "baseline written. on a CLEAN box: run --baseline, copy both dirs, diff -ru"
  finding "BASELINE" "Baseline" "INFO" "snapshot in $b" \
    "Baselining is the highest-yield habit there is: diff this against the same distro/version clean install and every delta is a candidate vuln."
}

# ---------------------------------------------------------------------------
# VERIFY
# ---------------------------------------------------------------------------
do_verify() {
  banner "VERIFY"

  # identity perms
  local f want got shadowwant
  shadowwant=640; getent group shadow >/dev/null 2>&1 || shadowwant=600
  while read -r f want; do
    [[ -e "$f" ]] || continue
    got="$(stat -c '%a' "$f" 2>/dev/null)"
    if [[ "$got" == "$want" ]]; then finding "VER-PERM-$(basename "$f")" "Verify" "PASS" "$f = $got"
    else finding "VER-PERM-$(basename "$f")" "Verify" "FAIL" "$f = $got, want $want"; fi
  done < <(printf '%s\n' "/etc/passwd 644" "/etc/group 644" "/etc/shadow $shadowwant" "/etc/gshadow $shadowwant" \
                         "/etc/sudoers 440" "/etc/ssh/sshd_config 600" "/etc/crontab 644")

  # uid0 / empty pw
  local u0 ep
  u0="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | tr '\n' ' ')"
  [[ -z "$u0" ]] && finding "VER-UID0" "Verify" "PASS" "no extra UID 0" || finding "VER-UID0" "Verify" "FAIL" "extra UID0: $u0"
  ep="$(awk -F: '($2==""){print $1}' /etc/shadow | tr '\n' ' ')"
  [[ -z "$ep" ]] && finding "VER-NOPASS" "Verify" "PASS" "no empty passwords" || finding "VER-NOPASS" "Verify" "FAIL" "empty passwords: $ep"

  # login.defs
  local kv k v
  for kv in "PASS_MAX_DAYS $PASS_MAX_DAYS" "PASS_MIN_DAYS $PASS_MIN_DAYS" "PASS_MIN_LEN $PASS_MIN_LEN" \
            "PASS_WARN_AGE $PASS_WARN_AGE" "UMASK 027" "ENCRYPT_METHOD SHA512"; do
    k="${kv%% *}"; v="${kv##* }"
    got="$(grep -E "^\s*${k}\b" /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)"
    [[ "$got" == "$v" ]] && finding "VER-$k" "Verify" "PASS" "$k=$got" \
                        || finding "VER-$k" "Verify" "FAIL" "$k=$got (want $v)"
  done

  # pwquality
  if [[ -f /etc/security/pwquality.conf ]]; then
    local ml; ml="$(grep -E '^\s*minlen' /etc/security/pwquality.conf | awk '{print $3}')"
    [[ "$ml" -ge 14 ]] 2>/dev/null && finding "VER-PWQ" "Verify" "PASS" "pwquality minlen=$ml" \
                                   || finding "VER-PWQ" "Verify" "FAIL" "pwquality minlen=$ml"
  fi

  # ssh -- read the EFFECTIVE config, not the file
  if command -v sshd >/dev/null 2>&1; then
    local t; t="$(sshd -T 2>/dev/null)"
    if [[ -z "$t" ]]; then
      finding "VER-SSH" "Verify" "WARN" "sshd -T produced no effective configuration" \
        "Run sshd -T as root and check for a bad Include, missing host key, or broken key permissions."
    else
      check_sshd() { local k="$1" want="$2"; local got; got="$(echo "$t" | awk -v k="$k" 'tolower($1)==k{print $2}')"
        if [[ "$got" == "$want" ]]; then finding "VER-SSH-$k" "Verify" "PASS" "$k=$got"
        else finding "VER-SSH-$k" "Verify" "FAIL" "$k=$got (want $want)"; fi; }
      check_sshd permitrootlogin no
      check_sshd permitemptypasswords no
      check_sshd x11forwarding no
      check_sshd maxauthtries 3
      check_sshd permituserenvironment no
      check_sshd ignorerhosts yes
      check_sshd hostbasedauthentication no
      if echo "$t" | grep -qi '^protocol '; then
        check_sshd protocol 2
      else
        finding "VER-SSH-protocol" "Verify" "INFO" "protocol directive not reported (SSH2-only build)"
      fi
      local c; c="$(echo "$t" | awk 'tolower($1)=="ciphers"{print $2}')"
      if [[ -z "$c" ]]; then
        finding "VER-SSH-CIPHERS" "Verify" "WARN" "sshd -T did not report a Ciphers list" \
          "Run sshd -T and inspect the Ciphers line. A missing value can mean the effective config is unreadable."
      elif echo "$c" | grep -qE '3des|arcfour|cbc'; then
        finding "VER-SSH-CIPHERS" "Verify" "FAIL" "weak cipher still offered: $c"
      else
        finding "VER-SSH-CIPHERS" "Verify" "PASS" "ciphers OK"
      fi
      sshd -t >/dev/null 2>&1 && finding "VER-SSH-VALID" "Verify" "PASS" "sshd_config parses" \
                               || finding "VER-SSH-VALID" "Verify" "FAIL" "sshd_config is INVALID"
    fi
  fi

  # sysctl spot checks
  for kv in "net.ipv4.ip_forward 0" "net.ipv4.conf.all.accept_redirects 0" "net.ipv4.conf.all.send_redirects 0" \
            "net.ipv4.conf.all.accept_source_route 0" "net.ipv4.conf.all.log_martians 1" "net.ipv4.conf.all.rp_filter 1" \
            "net.ipv4.tcp_syncookies 1" "kernel.randomize_va_space 2" "kernel.dmesg_restrict 1" \
            "kernel.kptr_restrict 2" "fs.protected_symlinks 1" "fs.protected_hardlinks 1" "fs.suid_dumpable 0"; do
    local k="${kv%% *}"; local v="${kv##* }"
    local got; got="$(sysctl_get "$k")"
    if [[ -z "$got" ]]; then
      finding "VER-$k" "Verify" "WARN" "$k unreadable" "Key absent on this kernel, or sysctl/procps is not installed. check /proc/sys/$(echo "$k" | tr '.' '/')."
    elif [[ "$got" == "$v" ]]; then finding "VER-$k" "Verify" "PASS" "$k=$got"
    else finding "VER-$k" "Verify" "FAIL" "$k=$got (want $v)" "sysctl -w $k=$v  -- and confirm it is in /etc/sysctl.d/99-cyberpatriot.conf so it survives a reboot."; fi
  done

  # firewall
  local fwup=0
  if command -v ufw >/dev/null 2>&1; then
    ufw status verbose 2>/dev/null | grep -qiE '^Status: active' && \
      ufw status verbose 2>/dev/null | grep -qiE '^Default: deny \(incoming\)' && fwup=1
  fi
  if systemctl is-active firewalld >/dev/null 2>&1; then
    local fwzone fwtarget
    fwzone="$(firewall-cmd --get-default-zone 2>/dev/null)"
    fwtarget="$(firewall-cmd --zone="$fwzone" --get-target 2>/dev/null)"
    if [[ "$fwzone" == "drop" || "$fwtarget" == "DROP" || "$fwtarget" == "%%REJECT%%" ]]; then
      fwup=1
    fi
  fi
  command -v iptables >/dev/null 2>&1 && [[ "$(iptables -S INPUT 2>/dev/null | head -1)" =~ DROP ]] && fwup=1
  if command -v nft >/dev/null 2>&1 && nft list table inet cbpt_filter 2>/dev/null | grep -q 'policy drop'; then
    fwup=1
  fi
  if (( fwup )); then
    finding "VER-FW" "Verify" "PASS" "a firewall is active with a default-deny inbound policy"
  else
    finding "VER-FW" "Verify" "FAIL" "no active default-deny firewall detected" \
      "Run --module firewall. if you already did: confirm the critical-service ports from the README are explicitly allowed, then verify with 'ufw status' / 'firewall-cmd --list-all' / 'iptables -L -n' / 'nft list table inet cbpt_filter'. an unapplied firewall scores zero."
  fi

  # umask -- check a login shell, not this script's own umask 022
  local um; um="$(bash -lc 'umask' 2>/dev/null)"
  [[ -n "$um" ]] || um="$(umask)"
  [[ "$um" == "0027" || "$um" == "027" ]] && finding "VER-UMASK" "Verify" "PASS" "umask=$um" \
                                          || finding "VER-UMASK" "Verify" "WARN" "umask=$um (want 0027)" "new shells need to source /etc/profile. log out and back in."

  # auditd
  if command -v auditctl >/dev/null 2>&1; then
    local n; n="$(auditctl -l 2>/dev/null | wc -l)"
    if (( n > 10 )); then
      finding "VER-AUDIT" "Verify" "PASS" "$n audit rules loaded"
    else
      finding "VER-AUDIT" "Verify" "FAIL" "only $n audit rule(s) loaded" \
        "augenrules --load ; auditctl -l   -- if it errors, a rule references an arch or syscall this kernel lacks; delete that line and reload."
    fi
    if systemctl is-active auditd >/dev/null 2>&1 || service auditd status >/dev/null 2>&1; then
      finding "VER-AUDITD" "Verify" "PASS" "auditd running"
    else
      finding "VER-AUDITD" "Verify" "FAIL" "auditd is not running" \
        "systemctl enable --now auditd  -- note some images need 'audit=1' on the kernel command line (edit /etc/default/grub, then update-grub) before auditd will collect anything."
    fi
  fi

  # mandatory access control
  if command -v getenforce >/dev/null 2>&1; then
    local sm; sm="$(getenforce 2>/dev/null)"
    [[ "$sm" == "Enforcing" ]] && finding "VER-MAC" "Verify" "PASS" "SELinux enforcing" \
                               || finding "VER-MAC" "Verify" "FAIL" "SELinux is $sm (want Enforcing)" \
                                    "setenforce 1; SELINUX=enforcing in /etc/selinux/config; reboot. Check ausearch/audit2allow for denials before blaming the policy."
  elif command -v aa-status >/dev/null 2>&1; then
    local ap ae
    ap="$(aa-status --profiled 2>/dev/null)"; ae="$(aa-status --enforced 2>/dev/null)"
    ap="${ap:-0}"; ae="${ae:-0}"
    if (( ap > 0 && ae >= ap )); then
      finding "VER-MAC" "Verify" "PASS" "AppArmor enforcing $ae/$ap profiles"
    else
      finding "VER-MAC" "Verify" "WARN" "AppArmor enforcing $ae/$ap profiles" \
        "aa-status; aa-enforce /etc/apparmor.d/*; profiles still in complain mode do not protect anything."
    fi
  else
    finding "VER-MAC" "Verify" "WARN" "no AppArmor/SELinux tooling detected" \
      "Install and enable AppArmor on Ubuntu, or confirm SELinux is built into the kernel with getenforce."
  fi

  # logging
  systemctl is-active rsyslog >/dev/null 2>&1 && finding "VER-RSYSLOG" "Verify" "PASS" "rsyslog active" \
                                              || finding "VER-RSYSLOG" "Verify" "WARN" "rsyslog not active"
  grep -q 'Storage=persistent' /etc/systemd/journald.conf.d/99-cp.conf 2>/dev/null && \
    finding "VER-JOURNALD" "Verify" "PASS" "journald persistent" || finding "VER-JOURNALD" "Verify" "WARN" "journald not persistent"

  # leftover risks
  [[ -s /etc/ld.so.preload ]] && finding "VER-PRELOAD" "Verify" "FAIL" "/etc/ld.so.preload still populated"
  [[ -f /etc/cron.deny ]] && finding "VER-CRONDENY" "Verify" "WARN" "/etc/cron.deny still exists" "remove it and use /etc/cron.allow."

  # ---- deep read-only audit ------------------------------------------------
  # sudoers syntax: a typo here locks everyone out of sudo, and some images
  # intentionally seed a broken drop-in so the "fix" is reverting it.
  if command -v visudo >/dev/null 2>&1; then
    if visudo -c >/dev/null 2>&1; then
      finding "VER-SUDOERS" "Verify" "PASS" "sudoers parses"
    else
      finding "VER-SUDOERS" "Verify" "FAIL" "visudo -c rejected the sudoers files" \
        "Run visudo -c and fix the reported file. Keep a root shell open; a bad sudoers file can lock out sudo entirely."
    fi
  fi
  if grep -RhsE '^[[:space:]]*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -q .; then
    finding "VER-SUDOERS-NOPASSWD" "Verify" "WARN" "a sudoers rule uses NOPASSWD" \
      "Review with: grep -R NOPASSWD /etc/sudoers /etc/sudoers.d. Remove it unless the README explicitly requires passwordless sudo."
  else
    finding "VER-SUDOERS-NOPASSWD" "Verify" "PASS" "no NOPASSWD sudoers rule found"
  fi

  # file capabilities: setuid is not the only way to gain root.
  if command -v getcap >/dev/null 2>&1; then
    local capout; capout="$(getcap -r /usr /bin /sbin /opt 2>/dev/null || true)"
    if [[ -n "$capout" ]]; then
      if grep -qE 'cap_(setuid|setgid|sys_admin|sys_ptrace|sys_module|dac_read_search|dac_override)' <<<"$capout"; then
        finding "VER-CAPS" "Verify" "WARN" "file capabilities can grant elevated access" \
          "Review: getcap -r /usr /bin /sbin /opt. Remove unexpected caps with: setcap -r <file>. Some daemons legitimately need cap_net_bind_service."
      else
        finding "VER-CAPS" "Verify" "PASS" "no dangerous file capabilities found"
      fi
      printf '%s\n' "$capout" >"$EVID/46-capabilities.txt" 2>/dev/null
    else
      finding "VER-CAPS" "Verify" "PASS" "no file capabilities set"
    fi
  fi

  # custom systemd timers and sockets are persistence, not just services.
  local unit frag
  while read -r unit; do
    [[ -n "$unit" ]] || continue
    frag="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)"
    case "$frag" in
      /etc/systemd/system/*) finding "VER-UNIT-$(basename "$unit")" "Verify" "WARN" "custom enabled unit: $unit ($frag)" \
        "systemctl cat $unit; systemctl disable --now $unit if the README does not require it. custom timers/sockets are a common persistence trick." ;;
    esac
  done < <(systemctl list-unit-files --type=timer --type=socket --state=enabled --no-legend 2>/dev/null | awk '{print $1}')

  # SSH host keys: DSA and short RSA keys are forgeable/too weak.
  local hk hb
  for hk in /etc/ssh/ssh_host_*_key; do
    [[ -f "$hk" ]] || continue
    case "$hk" in
      *_dsa_key) finding "VER-SSH-HOSTKEY" "Verify" "FAIL" "DSA host key present: $hk" "rm it and regenerate with ssh-keygen -A after saving the old key if rollback matters." ;;
      *_rsa_key)
        hb="$(ssh-keygen -lf "$hk" 2>/dev/null | awk '{print $1}')"
        if [[ -n "$hb" && "$hb" -lt 2048 ]] 2>/dev/null; then
          finding "VER-SSH-HOSTKEY" "Verify" "FAIL" "RSA host key is only $hb bits" "ssh-keygen -t rsa -b 4096 -f $hk -N '' after backing up the old key."
        fi
        ;;
    esac
  done

  # package repository trust: plain http and trusted=yes bypass signature checks.
  if [[ -d /etc/apt ]]; then
    if grep -RhsE '^[[:space:]]*(deb(-src)?[[:space:]].*(http://|trusted=yes)|URIs:.*http://|Trusted:[[:space:]]*yes)' \
         /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null | grep -q .; then
      finding "VER-REPO" "Verify" "WARN" "an apt source uses plain http or trusted=yes" \
        "Use https mirrors and remove trusted=yes; then apt-get update. A tampered repo can install a backdoor during an update."
    else
      finding "VER-REPO" "Verify" "PASS" "apt sources use no plain-http or trusted=yes entries"
    fi
  elif [[ -d /etc/yum.repos.d ]]; then
    if grep -RhsE '^[[:space:]]*(gpgcheck|repo_gpgcheck|sslverify)[[:space:]]*=[[:space:]]*0' /etc/yum.repos.d /etc/yum.conf 2>/dev/null | grep -q .; then
      finding "VER-REPO" "Verify" "WARN" "a yum/dnf repo disables GPG or TLS verification" \
        "Set gpgcheck=1, repo_gpgcheck=1 and sslverify=1, then import the vendor key; unsigned packages are a supply-chain risk."
    else
      finding "VER-REPO" "Verify" "PASS" "yum/dnf repos require GPG/TLS verification"
    fi
  fi

  # PAM must actually load pwquality, not just have the config file.
  local pwqstack="" pwqfound=0 pwqany=0
  for pwqstack in /etc/pam.d/common-password /etc/pam.d/password-auth /etc/pam.d/system-auth; do
    [[ -f "$pwqstack" ]] || continue
    pwqany=1
    if grep -Eq '^[^#]*pam_pwquality\.so' "$pwqstack"; then pwqfound=1; break; fi
  done
  if (( pwqfound )); then
    finding "VER-PAM-PWQ" "Verify" "PASS" "pam_pwquality is enabled in $pwqstack"
  elif (( pwqany )); then
    finding "VER-PAM-PWQ" "Verify" "FAIL" "pam_pwquality is not enabled in the PAM password stack" \
      "Run --module passwords, then check: grep pwquality /etc/pam.d/common-password /etc/pam.d/password-auth. Without the PAM line, pwquality.conf is ignored."
  else
    finding "VER-PAM-PWQ" "Verify" "WARN" "no standard PAM password stack found" \
      "Check the distro's PAM layout; install libpam-pwquality/libpwquality and wire pam_pwquality manually."
  fi

  # anything still listening that shouldn't be
  local p
  while read -r laddr; do
    p="${laddr##*:}"
    case "$p" in
      23|21|69|111|512|513|514) finding "VER-PORT-$p" "Verify" "FAIL" "port $p still listening" "stop + mask the service, then confirm with ss -tulpn." ;;
    esac
  done < <(ss -tulpnH 2>/dev/null | awk '{print $5}' | sort -u)

  # reboot needed?
  if [[ -f /var/run/reboot-required ]]; then
    finding "VER-REBOOT" "Verify" "WARN" "reboot required ($(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' '))" \
      "Reboot BEFORE the final scoring pass, but never with less than ~25 minutes on the clock. kernel updates and some PAM/audit changes only apply on reboot."
  fi
}

# ---------------------------------------------------------------------------
# REPORT / SCORECARD
# ---------------------------------------------------------------------------
do_report() {
  banner "SCORECARD"
  local p f w i s t pct
  # NOTE: do not use `grep -c ... || echo 0` here. grep already prints 0 and
  # then exits non-zero on no match, so you end up with "0\n0" and arithmetic
  # blows up. awk it is.
  count_st() { awk -F'\t' -v st="$1" '$3==st{n++} END{print n+0}' "$FIND_TMP" 2>/dev/null; }
  p="$(count_st PASS)"; f="$(count_st FAIL)"; w="$(count_st WARN)"
  i="$(count_st INFO)"; s="$(count_st SKIP)"
  t=$((p+f+w))
  (( t > 0 )) && pct=$(( p * 100 / t )) || pct=0

  printf '\n  PASS %-4s  FAIL %-4s  WARN %-4s  INFO %-4s  SKIP %-4s\n' "$p" "$f" "$w" "$i" "$s"
  printf '  %sautomated coverage: %s%%%s   (this is NOT your score -- see --hints)\n\n' "$C_BLU" "$pct" "$C_RST"

  if (( f > 0 )); then
    printf '  %s---- FAIL (fix these first) ----%s\n' "$C_RED" "$C_RST"
    awk -F'\t' '$3=="FAIL"{printf "   %-26s %s\n       hint: %s\n",$1,$4,$5}' "$FIND_TMP"
    printf '\n'
  fi
  if (( w > 0 )); then
    printf '  %s---- WARN (decide with the README in hand) ----%s\n' "$C_YEL" "$C_RST"
    awk -F'\t' '$3=="WARN"{printf "   %-26s %s\n       hint: %s\n",$1,$4,$5}' "$FIND_TMP"
    printf '\n'
  fi
  if (( i > 0 )); then
    printf '  %s---- INFO (things this script refuses to do for you) ----%s\n' "$C_GRY" "$C_RST"
    awk -F'\t' '$3=="INFO"{printf "   %-26s %s\n       hint: %s\n",$1,$4,$5}' "$FIND_TMP"
    printf '\n'
  fi

  local nc; nc="$(wc -l <"$CHG_TMP" 2>/dev/null || echo 0)"
  if (( nc > 0 )); then
    printf '  %s---- changes made this run: %s ----%s\n' "$C_MAG" "$nc" "$C_RST"
    head -60 "$CHG_TMP" | awk -F'\t' '{printf "   %-46s %s -> %s\n",$1,$2,$3}'
    (( nc > 60 )) && printf '   ... and %s more (see changes.tsv)\n' "$((nc-60))"
    mkdir -p "$EVID"
    cp "$CHG_TMP" "$EVID/changes.tsv"
  fi

  mkdir -p "$EVID"
  cp "$FIND_TMP" "$EVID/findings.tsv"
  if [[ -s "$REVIEW" ]]; then
    printf '\n  %s---- needs a human decision (needs-review.txt) ----%s\n' "$C_YEL" "$C_RST"
    head -25 "$REVIEW" | sed 's/^/   /'
    local rl; rl="$(wc -l <"$REVIEW")"
    (( rl > 25 )) && printf '   ... and %s more\n' "$((rl-25))"
  fi
  ok "findings -> $EVID/findings.tsv"
  ok "evidence -> $EVID"
  ok "backup   -> $BKDIR"
  ok "log      -> $LOGFILE"
}
# ---------------------------------------------------------------------------
# HINTS -- how to actually max the score
# ---------------------------------------------------------------------------
do_hints() {
  banner "HOW TO ACTUALLY MAX THE SCORE (LINUX)"
  cat <<'HINTS'

 THE PART NOBODY TELLS YOU
 -------------------------
 The script gets you the boring 40-60%. Linux images are more automatable
 than Windows, so MORE teams get that part. The spread is in reading
 comprehension and knowing where to look. Nobody out-researches you on
 "chmod 644 /etc/passwd".

 ORDER OF OPERATIONS
 -------------------
 0:00  README. authorized users. critical services. business data. explicit
       tasks. write them down on paper, not in your head.
 0:10  Forensic questions. do these BEFORE you harden -- hardening rotates
       logs and overwrites the evidence they ask about.
 0:30  sudo bash cbptlinux.sh --recon     (read only)
       read every WARN and FAIL. that is your vuln list.
 0:45  fill in users.txt / admins.txt from the README.
 1:00  sudo bash cbptlinux.sh --module users
 1:15  --module passwords   (keep a second root terminal open for PAM)
 1:30  --module ssh  and  --module firewall
 2:00  baseline + manual backdoor hunt (commands below).
 2:30  --module services / packages / sysctl / perms / audit
 3:00  re-read the README. do the tasks it asked for, by hand.
 3:30  critical services: verify each one still answers. a dead critical
       service costs more than ten config files.
 4:00  app hardening (--module apps): apache/nginx/mysql/bind/postfix/samba/
       vsftpd/wordpress. restart each and CONFIRM it is listening.
 4:30  --module verify. fix every FAIL.
  5:00  reboot if you have >25 min left. then write the report.
  5:30  point scrounging + re-check the scoring report.
  5:45  sudo bash cbptlinux.sh --checklist and work the list by hand.

 WHERE THE POINTS LIVE
 ---------------------
  1. Forensic questions   -- the biggest easy chunk on the image
  2. README tasks         -- explicitly listed, fully in your control
  3. Users/groups/sudo    -- extra UID0, blank password, NOPASSWD:ALL
  4. Backdoor/persistence -- authorized_keys, cron, systemd units, rc.local,
                             ld.so.preload, SUID shell, deleted-but-running
  5. Password + lockout + PAM
  6. sshd_config          -- root login, protocol, empty pw, X11, weak ciphers
  7. sysctl               -- forwarding, redirects, source route, ASLR, martians
  8. File/dir permissions -- /etc/shadow, sudoers, home dirs, world-writable
  9. Critical services UP and correctly configured
 10. App configs          -- ServerTokens, bind-address, guest ok, open relay
 11. Logging/audit policy (auditd rules, rsyslog, journald persistent)
 12. Updates / package hygiene
 13. Bootloader password

 HOW TO LOSE POINTS
 ------------------
  * deleting a user the README authorizes.
  * deleting business documents or PII. document it, do not rm it.
  * killing a critical service or blocking its port in the firewall.
  * clearing /var/log/*. looks like the attacker, destroys evidence.
  * locking yourself out: bad PAM, PasswordAuthentication no with no key,
    firewall with no SSH allowance, su restricted to an empty wheel group.
  * editing a config and not restarting the service. a config change that
    is not loaded scores zero.
  * breaking apt/dnf. if updates cannot run, several checks fail at once.
  * needing a re-extraction. costs the clock, which costs you everything.

 BACKDOOR HUNT (Linux) -- run these, in this order
 -------------------------------------------------
  awk -F: '$3==0' /etc/passwd                 # extra UID 0
  awk -F: '($2=="")' /etc/shadow              # empty passwords
  grep -vE '(nologin|false)$' /etc/passwd     # who can log in
  getent group sudo wheel                     # who can escalate
  cat /etc/sudoers /etc/sudoers.d/*           # NOPASSWD?
  cat /etc/ld.so.preload                      # rootkit
  lsattr -R /etc /root /home | grep i         # immutable files
  find / -xdev -perm -4000 -printf '%p\n'     # SUID
  find / -xdev -perm -0002 ! -perm -1000      # world-writable
  cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys
  ls -la /etc/cron* /var/spool/cron/*         # cron
  systemctl list-timers --all
  ls -la /etc/systemd/system/*.service        # hand-rolled units
  cat /etc/rc.local /etc/profile /etc/profile.d/* /etc/bash.bashrc
  for d in /root /home/*; do cat $d/.bashrc $d/.bash_profile $d/.profile; done
  cat /root/.bash_history /home/*/.bash_history
  ss -tulpn                                   # listeners
  ps auxf                                     # weird processes/parents
  ls -l /proc/[0-9]*/exe | grep deleted       # fileless
  ip a; netstat -rn                           # promisc, routes
  find / -xdev -newer /etc/hostname -type f 2>/dev/null | grep -vE '^/(proc|sys|run)' | head -100
  grep -RIl 'base64\|nc -e\|/dev/tcp/' /etc /home /root /tmp /opt /var/www 2>/dev/null
  dmesg | grep -i 'usb\|sd[a-z]'              # removable media
  last -a; lastb -a; grep 'Accepted\|Failed' /var/log/auth.log*

 FORENSIC QUESTION STAPLES (Linux)
 --------------------------------
  "hash of file X"        sha256sum X    md5sum X
  "what ran / who ran it" /var/log/auth.log, ~/.bash_history,
                          ausearch -k exec, journalctl
  "what logged in"        last -a ; lastb -a ; /var/log/wtmp,btmp ;
                          grep 'Accepted' /var/log/auth.log
  "what was downloaded"   ~/.bash_history, /var/log/apt/history.log,
                          /var/log/dpkg.log, ~/.wget-hsts
  "what device was
   plugged in"            dmesg, /var/log/kern.log, /var/log/syslog,
                          leftover /media/* dirs, journalctl -k
  "what connected to us"  /var/log/auth.log, apache/nginx access.log,
                          iptables LOG output, journalctl -u ssh
  "what did they delete"  find / -xdev -cmin -N, /var/log/dpkg.log
  "hidden data in a file" file X ; strings X ; binwalk X ; xxd X | tail
                          (look for data appended after PNG IEND / JPEG EOI)
                          exiftool X for metadata
  "decode this blob"      echo 'BLOB' | base64 -d ; xxd -r -p hex.txt
  "what is in this pcap"  tshark -r f.pcap ; tcpdump -nnr f.pcap ;
                          strings f.pcap | grep -i 'GET\|POST\|USER\|PASS'
  "steg"                  steghide extract -sf img ; zsteg img

 POINT SCROUNGING WITH TIME LEFT
 -------------------------------
   umask 027, chmod 644 /etc/passwd 640 /etc/shadow, /etc/cron.allow
   instead of cron.deny, auditd rules, rsyslog FileCreateMode, journald
   persistent, grub password, login banner, MaxAuthTries, hidden dotfiles
   in /home (ls -laR), chattr anomalies, /etc/hosts entries. AppArmor in
   enforce or SELinux Enforcing, unattended-upgrades, and a clean package
   list (no tools/games/p2p) are quick scored items too.

 HABITS THAT WIN ROUNDS
 ----------------------
  * screenshot/tee everything before you change it. evidence disappears.
  * keep a running vuln log in the format the report wants. free points.
  * after every config edit: restart the service, then verify it is
    listening and answering. ss -tulpn && curl -I localhost.
  * never edit PAM without a second SSH session open.
  * think like the attacker for 5 minutes: how would I stay in this box?
    then go look for exactly that. you will find it.
  * test the whole script on a practice image first. always.
HINTS
}

# ---------------------------------------------------------------------------
# FINAL MANUAL CHECKLIST -- read-only. the script cannot read the README for
# you, and the README is where the remaining points are.
# ---------------------------------------------------------------------------
do_checklist() {
  banner "FINAL MANUAL CHECKLIST"
  cat <<'CHECK'
  Work through this with the README and the scoring report open. Nothing here
  changes the system; it is a prompt list plus a live snapshot.

  1. AUTHORIZED USERS
     - Compare users.txt / admins.txt against the README, not against memory.
     - Remove or disable every account the README does not authorize.
     - Check for extra UID 0, empty passwords, duplicate UIDs, and accounts
       with real login shells that should be service accounts.
     - Change every remaining user's password to a strong one. Do not reuse
       the old password just because it still works.

  2. SUDO / PRIVILEGE
     - getent group sudo wheel admin; remove anyone not authorized.
     - grep -R NOPASSWD /etc/sudoers /etc/sudoers.d/
     - Check for wildcard sudo rules and group-writable sudoers files.
     - Verify no authorized user lost sudo by accident.

  3. SERVICES + PORTS
     - ss -tulpn; compare every listener to the README's critical services.
     - Stop and mask anything unnecessary. NEVER stop a scored service.
     - After each config change: restart the service and confirm it answers.
     - Check systemctl --failed and journalctl -u <service> for errors.

  4. PERSISTENCE
     - /etc/cron.*, /var/spool/cron, systemd timers, rc.local, profile.d,
       bashrc, authorized_keys, ld.so.preload, unusual SUID binaries.
     - Look for deleted-but-running processes and files newer than the image.
     - Read the user's shell history; attackers leave commands there.

  5. LOGS + FORENSIC QUESTIONS
     - Answer the forensic questions BEFORE hardening rotates more evidence.
     - auth.log / secure, journalctl, last/lastb, dpkg/apt history, dmesg.
     - Do not clear or truncate a log. Ever.
     - Put the evidence and findings.tsv in the report folder.

  6. FIREWALL + REMOTE ACCESS
     - Default deny inbound, default allow outbound, explicit allow only for
       the ports the README calls critical.
     - Confirm SSH still works from a second session before closing yours.
     - Disable root SSH login, empty passwords, X11 forwarding, and weak crypto.

  7. UPDATES + MAC
     - Confirm apt/dnf update completed and any reboot requirement is handled.
     - AppArmor: aa-status, aa-enforce /etc/apparmor.d/*.
     - SELinux: getenforce should say Enforcing; check /etc/selinux/config.
     - Do the reboot with enough clock left to re-verify every service.

  8. FILES + PERMISSIONS
     - /etc/shadow 640, /etc/passwd 644, /etc/group 644, /etc/gshadow 640,
       /etc/sudoers 440, sshd_config 600, home directories not world-readable.
     - Find world-writable files and unexpected SUID/SGID binaries.
     - Check for immutable files with lsattr and suspicious hidden files.

  9. REPORT + HANDOFF
     - Write down what you changed, why, and which README requirement it maps
       to. Screenshot the scoring report before and after.
     - Keep /root/cbptlinux-backup/<stamp> and /root/cbptlinux-evidence.
     - Re-run --module verify and fix every FAIL before the clock ends.
CHECK

  step "accounts (UID >= 1000, excluding nobody)"
  awk -F: '$3 >= 1000 && $1 != "nobody" {printf "   %-20s uid=%-5s home=%-24s shell=%s\n", $1, $3, $6, $7}' /etc/passwd 2>/dev/null

  step "extra UID 0 / empty passwords"
  awk -F: '$3 == 0 {print "   UID0: " $1}' /etc/passwd 2>/dev/null
  awk -F: '($2 == "") {print "   EMPTY PASSWORD: " $1}' /etc/shadow 2>/dev/null

  step "sudo / wheel / admin membership"
  for g in sudo wheel admin; do
    getent group "$g" 2>/dev/null | awk -F: -v g="$g" '{printf "   %-6s %s\n", g, ($4 == "" ? "(empty)" : $4)}'
  done

  step "listening sockets"
  if have ss; then ss -tulpnH 2>/dev/null | awk '{printf "   %-6s %-24s %s\n", $1, $5, $7}'
  elif have netstat; then netstat -tulpn 2>/dev/null | sed 's/^/   /'
  else say "   neither ss nor netstat is installed"; fi

  step "scheduled tasks"
  ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron 2>/dev/null | sed 's/^/   /'
  systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/   /'

  step "recent failed logins"
  if have lastb; then lastb -a 2>/dev/null | head -15 | sed 's/^/   /'; fi
  grep -hiE 'failed password|invalid user' /var/log/auth.log /var/log/secure 2>/dev/null | tail -15 | sed 's/^/   /'

  step "reboot / update state"
  [[ -f /var/run/reboot-required ]] && warn "reboot required: $(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
  [[ -f /var/run/reboot-required ]] || say "no reboot-required marker"
  say "evidence: $EVID   backup: $BKDIR   log: $LOGFILE"
  finding "CHECKLIST" "Checklist" "INFO" "manual checklist printed" \
    "The remaining points are in the README, the forensic questions, and the services you verify by hand."
}

# ---------------------------------------------------------------------------
# MENU
# ---------------------------------------------------------------------------
do_menu() {
  while true; do
    banner "cbptlinux.sh $VERSION  --  $(hostname)  (${PRETTY_NAME:-$DISTRO_ID})"
    printf '\n'
    printf '   %sr%s) recon + evidence dump      (read only)\n' "$C_WHT" "$C_RST"
    printf '   %sb%s) baseline snapshot\n' "$C_WHT" "$C_RST"
    printf '   %sc%s) final manual checklist  (read only)\n' "$C_WHT" "$C_RST"
    printf '   %s1%s) users + groups (users.txt/admins.txt)\n' "$C_WHT" "$C_RST"
    printf '   %s2%s) password policy (PAM)\n' "$C_WHT" "$C_RST"
    printf '   %s3%s) sshd\n' "$C_WHT" "$C_RST"
    printf '   %s4%s) firewall\n' "$C_WHT" "$C_RST"
    printf '   %s5%s) services\n' "$C_WHT" "$C_RST"
    printf '   %s6%s) packages + updates\n' "$C_WHT" "$C_RST"
    printf '   %s7%s) sysctl\n' "$C_WHT" "$C_RST"
    printf '   %s8%s) file permissions\n' "$C_WHT" "$C_RST"
    printf '   %s9%s) audit + logging\n' "$C_WHT" "$C_RST"
    printf '   %s0%s) installed apps\n' "$C_WHT" "$C_RST"
    printf '   %sv%s) verify + scorecard\n' "$C_WHT" "$C_RST"
    printf '   %sA%s) RUN ALL  (backup -> recon -> harden -> verify)\n' "$C_GRN" "$C_RST"
    printf '   %sH%s) hints: how to max the score\n' "$C_BLU" "$C_RST"
    printf '   %sx%s) toggle --aggressive  (now: %s)\n' "$C_WHT" "$C_RST" "$AGGRESSIVE"
    printf '   %sp%s) toggle --paranoid    (now: %s)\n' "$C_WHT" "$C_RST" "$PARANOID"
    printf '   %sd%s) toggle --dry-run     (now: %s)\n' "$C_WHT" "$C_RST" "$DRY"
    printf '   %sq%s) quit\n' "$C_GRY" "$C_RST"
    printf '\n'
    read -r -p "  pick one: " c
    case "$c" in
      r) do_recon;     do_report ;;
      b) do_baseline ;;
      c) do_checklist ;;
      1) do_users ;;
      2) do_passwords ;;
      3) do_ssh ;;
      4) do_firewall ;;
      5) do_services ;;
      6) do_packages ;;
      7) do_sysctl ;;
      8) do_perms ;;
      9) do_audit ;;
      0) do_apps ;;
      v) do_verify; do_report ;;
      A) if confirm "Run the full safe pass now? (backup, recon, users, passwords, ssh, firewall, services, packages, sysctl, perms, audit, apps, verify, checklist)"; then
           do_backup
           do_recon
           do_users
           do_passwords
           do_ssh
           do_firewall
           do_services
           do_packages
           do_sysctl
           do_perms
           do_audit
           do_apps
           do_verify
           do_report
           do_checklist
         fi ;;
      H) do_hints ;;
      x) AGGRESSIVE=$(( 1 - AGGRESSIVE )) ;;
      p) PARANOID=$(( 1 - PARANOID )) ;;
      d) DRY=$(( 1 - DRY )) ;;
      q) say "bye. good luck on the round."; exit 0 ;;
      *) warn "huh?" ;;
    esac
    printf '\n'
    read -r -p "  press enter to go back to the menu: " _
  done
}

run_all() {
  if (( PARANOID )); then
    warn "paranoid: running recon + verify only"
    do_recon
    do_verify
    do_report
    return
  fi
  do_backup
  do_recon
  do_users
  do_passwords
  do_ssh
  do_firewall
  do_services
  do_packages
  do_sysctl
  do_perms
  do_audit
  do_apps
  do_verify
  do_report
  do_checklist
  banner "DONE"
  warn "now go read the README again and answer the forensic questions."
  warn "then restart every critical service and confirm it is listening."
}

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
usage() {
  sed -n '2,72p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all|-a)        PHASE="all"; shift ;;
    --recon)         PHASE="recon"; shift ;;
    --baseline)      PHASE="baseline"; shift ;;
    --paranoid)      PARANOID=1; shift ;;
    --aggressive)    AGGRESSIVE=1; shift ;;
    --dry-run|-n)    DRY=1; shift ;;
    --force|-y)      FORCE=1; shift ;;
    --hints|-H)      PHASE="hints"; shift ;;
    --checklist)     PHASE="checklist"; shift ;;
    --help|-h)       usage ;;
    --version|-V)    echo "cbptlinux.sh $VERSION"; exit 0 ;;
    --restore)
      [[ $# -ge 2 && -n "$2" ]] || { err "--restore needs a backup directory"; exit 2; }
      RESTORE_FROM="$2"; shift 2 ;;
    --module|-m)
      [[ $# -ge 2 && -n "$2" ]] || { err "--module needs a module name"; exit 2; }
      MODULE="$2"; PHASE="module"; shift 2 ;;
    --evid-dir)
      [[ $# -ge 2 && -n "$2" ]] || { err "--evid-dir needs a directory"; exit 2; }
      EVID="$2"; REVIEW="$EVID/needs-review.txt"; shift 2 ;;
    --backup-dir)
      [[ $# -ge 2 && -n "$2" ]] || { err "--backup-dir needs a directory"; exit 2; }
      BKROOT="$2"; BKDIR="$BKROOT/$STAMP"; shift 2 ;;
    *) err "unknown option: $1"; usage ;;
  esac
done

main() {
  mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null
  : >>"$LOGFILE" 2>/dev/null || LOGFILE="/tmp/cbptlinux-$STAMP.log"
  mkdir -p "$EVID" "$BKROOT"
  chmod 700 "$EVID" "$BKROOT" 2>/dev/null
  chmod 600 "$LOGFILE" 2>/dev/null

  detect_distro

  banner "cbptlinux.sh $VERSION | $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"
  say "distro: ${PRETTY_NAME:-$DISTRO_ID}   pkg: $PKG   evidence: $EVID"
  local tier="DEFAULT (safe)"
  (( PARANOID )) && tier="PARANOID (read only)"
  (( AGGRESSIVE )) && tier="AGGRESSIVE"
  (( PARANOID && AGGRESSIVE )) && tier="PARANOID (aggressive flag ignored)"
  (( DRY )) && tier="$tier + DRY RUN (no changes)"
  say "tier: $tier"

  if [[ $EUID -ne 0 ]]; then
    err "you are not root. run: sudo bash $0 $*"
    err "most of this silently fails otherwise."
    exit 1
  fi

  if [[ -n "$RESTORE_FROM" ]]; then do_restore "$RESTORE_FROM"; return; fi

  if (( PARANOID )) && [[ "$PHASE" == "menu" ]]; then
    warn "paranoid: skipping the mutating menu; doing recon + verify only"
    do_recon
    do_verify
    do_report
    return
  fi

  # warn about the things that will actually hurt you
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "no systemd. service modules use sysvinit paths and may be partial."
  fi
  if (( PARANOID == 0 )) && [[ -z "$(command -v ss)" && -z "$(command -v netstat)" ]]; then
    warn "neither ss nor netstat present -- the port scan in recon will be empty."
  fi

  case "$PHASE" in
    menu)     do_menu ;;
    hints)    do_hints ;;
    all)      run_all ;;
    recon)    (( PARANOID || DRY )) || do_backup; do_recon; do_report ;;
    baseline) do_backup; do_recon; do_baseline; do_report ;;
    checklist) do_checklist; do_report ;;
    module)
      case "$MODULE" in
        recon)     do_recon ;;
        baseline)  do_baseline ;;
        users)     do_users ;;
        passwords) do_passwords ;;
        ssh)       do_ssh ;;
        firewall)  do_firewall ;;
        services)  do_services ;;
        packages)  do_packages ;;
        sysctl)    do_sysctl ;;
        perms)     do_perms ;;
        audit)     do_audit ;;
        logging)   do_audit ;;
        apps)      do_apps ;;
        verify)    do_verify ;;
        report)    do_report ;;
        checklist) do_checklist ;;
        backup)    do_backup ;;
        *) err "unknown module: $MODULE"; exit 1 ;;
      esac
      do_report
      ;;
    *) do_menu ;;
  esac
}

main "$@"
