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
#
#   modules: recon users passwords ssh firewall services packages sysctl
#            perms audit apps verify report
#
#   the users module reconciles accounts against users.txt, admins.txt, and
#   groups.txt next to this script (one name per line, copied from the README).
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
#   1.2.0  added groups.txt reconciliation, GID/nopasswdlogin/shell/sudoers-README
#          escalation checks, single-pass filesystem find + fast pre-filtered
#          PII scan + cached package inventory, archive/tool/debsums/browser/
#          nonpackaged-proc hunts, pam_pwhistory + nullok_secure + inline PAM
#          options, 10periodic + 50unattended-upgrades + apt security check,
#          OpenSSH 00-cbptlinux.conf + direct sshd_config sync + rollback fix,
#          99-zzz-cyberpatriot.conf sysctl override protection + host.conf,
#          vsftpd guest_enable prompt, ctrl-alt-del mask, AppArmor enforcement,
#          and expanded verify coverage.
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

VERSION="1.2.0"
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
  printf -- '- %s\n' "$*" >>"$REVIEW" 2>/dev/null
  warn "$*  [saved to needs-review.txt]"
}

# destructive / access-affecting operations require the word YES.
confirm() {
  [[ $FORCE -eq 1 ]] && return 0
  [[ $DRY -eq 1 ]] && { say "[dry-run] would ask: $1"; return 0; }
  [[ ! -t 0 ]] && return 1
  printf '\n  %s!! %s%s\n' "$C_YEL" "$1" "$C_RST"
  read -r -p "  type YES to continue: " ans
  [[ "$ans" == "YES" ]]
}

ask() {
  local a=""
  [[ ! -t 0 ]] && return 1
  read -r -p "  ? $1 [y/N] " a
  [[ "$a" =~ ^[Yy] ]]
}

# act CMD ARGS... : run a state-changing command unless --dry-run / --paranoid
act() {
  log "run: $*"
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
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"; DISTRO_LIKE="${ID_LIKE:-}"; DISTRO_VER="${VERSION_ID:-}"
  else
    DISTRO_ID="unknown"; DISTRO_LIKE=""; DISTRO_VER=""
  fi
  if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
  elif command -v dnf    >/dev/null 2>&1; then PKG="dnf"
  elif command -v yum   >/dev/null 2>&1; then PKG="yum"
  elif command -v zypper >/dev/null 2>&1; then PKG="zypper"
  elif command -v pacman >/dev/null 2>&1; then PKG="pacman"
  else PKG="none"; fi
}

pkg_has() { command -v "$1" >/dev/null 2>&1 || rpm -q "$1" >/dev/null 2>&1 || \
            dpkg -s "$1" >/dev/null 2>&1; }

# pkg_install a b c -- best effort. offline images fail, and that's fine.
pkg_install() {
  [[ $DRY -eq 1 || $PARANOID -eq 1 ]] && { say "[dry-run/paranoid] install: $*"; return 0; }
  # one package at a time: apt/dnf refuse the whole transaction when a single
  # name is unavailable (libpam-cracklib is gone on Ubuntu 24.04), which used
  # to block libpam-pwquality as well.
  local p
  for p in "$@"; do
    pkg_has "$p" && continue
    say "installing: $p"
    case "$PKG" in
      apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1 ;;
      dnf)    dnf install -y "$p" >/dev/null 2>&1 ;;
      yum)    yum install -y "$p" >/dev/null 2>&1 ;;
      zypper) zypper --non-interactive install "$p" >/dev/null 2>&1 ;;
      pacman) pacman -S --noconfirm --needed "$p" >/dev/null 2>&1 ;;
      *)      warn "no package manager found, cannot install $p" ;;
    esac
    pkg_has "$p" || warn "could not install $p (offline image?)"
  done
}

pkg_remove() {
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: would remove $*"; return 0; }
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
  local f="$1"
  [[ -e "$f" ]] || return 0
  [[ $DRY -eq 1 ]] && return 0
  mkdir -p "$BKDIR/files"
  local d; d="$(echo "${f#/}" | tr '/' '_')"
  cp -a "$f" "$BKDIR/files/$d" 2>/dev/null
  # the flattened name cannot be reversed reliably (/etc/ssh/sshd_config vs
  # /etc/ssh/sshd/config), so keep the original path next to the copy.
  printf '%s\n' "$f" >"$BKDIR/files/$d.path"
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
  if [[ ! -f "$f" ]]; then mkdir -p "$(dirname "$f")" 2>/dev/null; : >"$f"; fi
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
  mkdir -p "$BKDIR" "$EVID"
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
  ok "backup done ($(du -sh "$BKDIR" 2>/dev/null | cut -f1))"
}

do_restore() {
  local d="$1"
  [[ -d "$d" ]] || { err "no such backup: $d"; return 1; }
  banner "RESTORE FROM $d"
  confirm "Restore /etc and the config files from this backup? Current state will be lost." || return 0
  [[ -f "$d/etc.tar.gz" ]] && { act tar xzf "$d/etc.tar.gz" -C / 2>/dev/null && ok "/etc restored"; }
  if [[ -d "$d/files" ]]; then
    for f in "$d/files"/*; do
      [[ -f "$f" ]] || continue
      [[ "$f" == *.path ]] && continue
      local orig=""
      [[ -f "$f.path" ]] && orig="$(cat "$f.path" 2>/dev/null)"
      [[ -n "$orig" ]] || orig="/$(basename "$f" | tr '_' '/')"
      act cp -a "$f" "$orig" 2>/dev/null && say "restored $orig"
    done
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
  # loose docs in the places a scenario author would actually put them.
  # do not let the script find its own evidence/backup output.
  while IFS= read -r f; do found+=("$f"); done < <(
    find /root /home /var/www /opt /srv /tmp /mnt /media /var/ftp /etc -maxdepth 4 -type f \
      \( -iname '*.txt' -o -iname '*.docx' -o -iname '*.pdf' -o -iname '*.md' \) 2>/dev/null | \
      grep -vF -e "$EVID/" -e "$BKROOT/" | head -25
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
  IFS=$'\n' ranked=($(printf '%s\n' "${ranked[@]}" | sort -r)); unset IFS

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
  say "evidence -> $EVID"

  { echo "hostname   : $(hostname)"
    echo "kernel     : $(uname -a)"
    echo "distro     : ${PRETTY_NAME:-$DISTRO_ID} (pkg=$PKG)"
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

  # root blank password specifically
  if awk -F: '$1=="root" && $2=="" {found=1} END{exit !found}' /etc/shadow 2>/dev/null; then
    finding "USER-ROOT-BLANK" "Accounts" "FAIL" "root has a BLANK password" \
      "Set a strong root password (passwd root) or lock root (passwd -l root)."
  fi

  # extra GID 0 or primary GID matching sudo/wheel/admin (bypasses /etc/group membership!)
  local priv_gids="" gn gidv gid_hits=""
  for gn in root sudo wheel admin; do
    gidv="$(getent group "$gn" 2>/dev/null | cut -d: -f3)"
    [[ "$gidv" =~ ^[0-9]+$ ]] && priv_gids="${priv_gids:+$priv_gids|}$gidv"
  done
  if [[ -n "$priv_gids" ]]; then
    gid_hits="$(awk -F: -v rx="^($priv_gids)$" '$1!="root" && ($4==0 || $4 ~ rx) {print $1"(gid="$4")"}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
    if [[ -n "$gid_hits" ]]; then
      finding "USER-GID-PRIV" "Accounts" "FAIL" "non-root account(s) with privileged primary GID: $gid_hits" \
        "Setting primary GID to 0 or sudo/wheel GID grants hidden privilege without appearing in /etc/group. usermod -g <user_gid> <user>."
    fi
  fi

  # nopasswdlogin group (passwordless GUI login)
  local npw
  npw="$(getent group nopasswdlogin 2>/dev/null | cut -d: -f4)"
  if [[ -n "$npw" ]]; then
    finding "GRP-NOPASSWDLOGIN" "Accounts" "FAIL" "nopasswdlogin group has members: $npw" \
      "gpasswd -d <user> nopasswdlogin -- members can log into the desktop without a password."
  fi

  # non-standard / trojaned shells not in /etc/shells
  local badsh=""
  if [[ -r /etc/shells ]]; then
    badsh="$(awk -F: 'NR==FNR{if($0 ~ /^\//) valid[$0]=1; next}
      $7 != "" && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && !($7 in valid) {print $1"("$7")"}' \
      /etc/shells /etc/passwd 2>/dev/null | tr '\n' ' ')"
    [[ -n "$badsh" ]] && finding "USER-BADSHELL" "Accounts" "FAIL" "account(s) with non-standard shell not in /etc/shells: $badsh" \
      "Check if the shell is a trojaned script or backdoor binary. Fix with usermod -s /bin/bash or /usr/sbin/nologin."
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
    echo; echo "### groups"; getent group sudo wheel admin root nopasswdlogin 2>/dev/null
  } >"$EVID/11-sudo.txt"
  if grep -REn '^[^#]*(NOPASSWD|!authenticate|ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL|%\w+\s+ALL)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null >/dev/null; then
    finding "SUDO-RULES" "Accounts" "WARN" "broad sudo rule(s) present, see $EVID/11-sudo.txt" \
      "NOPASSWD, !authenticate, and 'ALL=(ALL) ALL' for a whole group are usually scored. Trim to the specific commands the user needs."
  fi
  if grep -REq '^[^#]*(\sALL\s*=\s*\(ALL(:ALL)?\)\s*NOPASSWD:\s*ALL|!authenticate)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    finding "SUDO-NOPASSWD" "Accounts" "FAIL" "someone has NOPASSWD:ALL or !authenticate in sudoers" \
      "Passwordless full root or !authenticate is a serious finding. Remove unless the README justifies it."
  fi
  if [[ -f /etc/sudoers.d/README ]] && grep -Evq '^[[:space:]]*(#|$)' /etc/sudoers.d/README 2>/dev/null; then
    finding "SUDO-TRAPS" "Accounts" "FAIL" "/etc/sudoers.d/README contains active non-comment rule(s)" \
      "Classic CyberPatriot hiding spot for 'ALL ALL=NOPASSWD:ALL'. Inspect and clean /etc/sudoers.d/README."
  elif grep -REq '^[^#]*timestamp_timeout[[:space:]]*=[[:space:]]*(-1|[2-9][0-9]|[0-9]{3,})' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    finding "SUDO-TRAPS" "Accounts" "FAIL" "sudo timestamp_timeout is disabled (-1) or excessively long" \
      "Remove timestamp_timeout=-1 or set Defaults timestamp_timeout=5."
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

  local proto laddr port pid proc
  while IFS=$'\t' read -r proto laddr port pid proc; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    case "$port" in
      21)     finding "PORT-21" "Network" "WARN" "FTP listening ($proc)" "Plaintext creds. Enable TLS (ssl_enable=YES) or stop it unless it is a critical service." ;;
      23)     finding "PORT-23" "Network" "FAIL" "TELNET listening ($proc)" "Telnet is essentially never legitimate. Stop+disable it and purge telnetd." ;;
      25|587) finding "PORT-25" "Network" "INFO" "SMTP listening ($proc)" "If it is a critical service, disable open relay + VRFY and require auth." ;;
      69)     finding "PORT-69" "Network" "WARN" "TFTP listening ($proc)" "Unauthenticated file transfer; usually a scored vuln." ;;
      110|995) finding "PORT-$port" "Network" "FAIL" "POP3 listening ($proc)" "POP3 service (dovecot/qpopper) is frequently scored. Stop+disable+purge unless README requires mail." ;;
      143|993) finding "PORT-$port" "Network" "WARN" "IMAP listening ($proc)" "Stop+disable unless README requires mail." ;;
      111)    finding "PORT-111" "Network" "WARN" "rpcbind listening ($proc)" "Disable rpcbind unless NFS is required." ;;
      161)    finding "PORT-161" "Network" "WARN" "SNMP listening ($proc)" "Change community off public/private, restrict sources, prefer SNMPv3." ;;
      445|139) finding "PORT-445" "Network" "INFO" "SMB listening ($proc)" "Samba is often a critical service. Harden smb.conf rather than killing it." ;;
      2049)   finding "PORT-2049" "Network" "WARN" "NFS listening ($proc)" "Disable nfs-kernel-server unless required by README." ;;
      3128)   finding "PORT-3128" "Network" "FAIL" "Squid proxy listening ($proc)" "Proxy server is frequently a scored unauthorized service. Stop+disable+purge unless README requires it." ;;
      3306)   finding "PORT-3306" "Network" "WARN" "MySQL listening ($proc)" "bind-address=127.0.0.1 unless remote DB access is required." ;;
      5432)   finding "PORT-5432" "Network" "WARN" "Postgres listening ($proc)" "listen_addresses='localhost' unless required; check pg_hba.conf for trust." ;;
      5900|5901) finding "PORT-5900" "Network" "FAIL" "VNC listening ($proc)" "VNC on a CP image is usually a backdoor. Investigate." ;;
      6379)   finding "PORT-6379" "Network" "WARN" "Redis listening ($proc)" "Bind to 127.0.0.1 and requirepass, or stop+disable if unused." ;;
      6667|6668|6669) finding "PORT-6667" "Network" "FAIL" "IRC listening ($proc)" "IRC daemon = botnet C2 until proven otherwise." ;;
      27017)  finding "PORT-27017" "Network" "WARN" "MongoDB listening ($proc)" "Bind to 127.0.0.1 and enable auth, or stop+disable if unused." ;;
      1337|4444|5555|9001|9050|12345|31337) finding "PORT-$port" "Network" "FAIL" "suspicious high port $port listening ($proc)" "Textbook backdoor/Tor port. Find the binary, hash it, note it, kill it." ;;
    esac
  done < <(sort -t$'\t' -k3,3n -u "$EVID/20-listening.tsv" 2>/dev/null)

  # /etc/host.conf nospoof check
  if [[ -f /etc/host.conf ]] && ! grep -Eq '^[[:space:]]*nospoof[[:space:]]+on' /etc/host.conf 2>/dev/null; then
    finding "NET-HOSTCONF" "Network" "WARN" "/etc/host.conf missing 'nospoof on'" \
      "Add 'nospoof on' to /etc/host.conf (sysctl module handles this too)."
  fi

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
  { echo "### /etc/environment"; cat /etc/environment 2>/dev/null
    echo; echo "### /etc/rc.local"; cat /etc/rc.local 2>/dev/null
    echo; echo "### /etc/profile.d/"; ls -la /etc/profile.d/ 2>/dev/null
    for f in /etc/profile.d/*; do [[ -f "$f" ]] && { echo "-- $f"; cat "$f"; }; done
    echo; echo "### /etc/profile"; cat /etc/profile 2>/dev/null
    echo; echo "### /etc/bash.bashrc"; cat /etc/bash.bashrc 2>/dev/null
    echo; echo "### per-user rc files"
    for d in /root /home/*; do
      for f in "$d/.bashrc" "$d/.bash_profile" "$d/.profile" "$d/.bash_login" "$d/.bash_aliases"; do
        [[ -f "$f" ]] && { echo "-- $f"; cat "$f"; }
      done
    done
  } >"$EVID/30-shell-startup.txt"

  # /etc/environment PATH hijack
  if [[ -f /etc/environment ]] && grep -Eq 'PATH=.*(/tmp/|/var/tmp/|/dev/shm/|/home/|:\.:|^\.|:\s*$)' /etc/environment 2>/dev/null; then
    finding "ENV-PATH" "Persistence" "FAIL" "/etc/environment PATH looks hijacked" \
      "Inspect /etc/environment and restore standard PATH."
  fi

  # shell startup tampering (history disable, suspicious aliases, reverse shells)
  local shhits=""
  shhits="$(grep -REn '(unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|alias[[:space:]]+(sudo|ls|ps|ss|netstat|su)=|/dev/tcp/|nc[[:space:]]+-[le]|bash[[:space:]]+-i|curl.*\|[[:space:]]*(sh|bash)|wget.*\|[[:space:]]*(sh|bash))' \
    /etc/profile /etc/profile.d /etc/bash.bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.bash_aliases 2>/dev/null | head -10)"
  if [[ -n "$shhits" ]]; then
    finding "SHELL-TAMPER" "Persistence" "FAIL" "suspicious command/alias/HISTFILE tamper in shell startup" \
      "Check $EVID/30-shell-startup.txt -- remove backdoor lines and re-enable history."
  fi

  # ld.so.preload == rootkit city
  if [[ -s /etc/ld.so.preload ]]; then
    finding "ROOTKIT-PRELOAD" "Persistence" "FAIL" "/etc/ld.so.preload is NOT empty: $(tr '\n' ' ' </etc/ld.so.preload)" \
      "This is a userland rootkit technique. Do not just delete it -- hash the library, note the path, report it, then remove."
  else
    finding "ROOTKIT-PRELOAD" "Persistence" "PASS" "/etc/ld.so.preload empty or absent"
  fi

  # cron (including dotfiles like non-empty .placeholder!)
  { echo "### /etc/crontab"; cat /etc/crontab 2>/dev/null
    echo; echo "### /etc/cron.d/"; for f in /etc/cron.d/* /etc/cron.d/.*; do [[ -f "$f" ]] && { echo "-- $f"; cat "$f"; }; done
    echo; echo "### cron.{hourly,daily,weekly,monthly}"
    ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
      for f in "$d"/.*; do
        [[ -f "$f" ]] || continue
        echo "-- dotfile: $f"
        cat "$f" 2>/dev/null
      done
    done
    echo; echo "### user crontabs"
    for d in /var/spool/cron/crontabs/* /var/spool/cron/*; do [[ -f "$d" ]] && { echo "-- $d"; cat "$d"; }; done 2>/dev/null
    echo; echo "### crontab -l (root)"; crontab -l 2>&1
    echo; echo "### at jobs"; atq 2>&1
  } >"$EVID/31-cron.txt"
  if grep -REq '(wget|curl|nc |ncat|/dev/tcp/|base64|python[23]? -c|perl -e|bash -i|ufw disable)' /etc/cron* /var/spool/cron 2>/dev/null; then
    finding "CRON-SUSPECT" "Persistence" "FAIL" "cron entry downloads/executes something" \
      "cat the offending file, screenshot it, then remove the entry. Cron-based downloaders are extremely common on CP images."
  fi
  local crondot
  for crondot in /etc/cron.hourly/.* /etc/cron.daily/.* /etc/cron.weekly/.* /etc/cron.monthly/.* /etc/cron.d/.*; do
    [[ -f "$crondot" ]] || continue
    if grep -Evq '^[[:space:]]*(#|$)' "$crondot" 2>/dev/null; then
      finding "CRON-DOT-$(basename "$crondot")" "Persistence" "FAIL" "active code inside hidden cron dotfile: $crondot" \
        "Hidden cron dotfiles (even .placeholder) are a classic persistence trick. Inspect and clean $crondot."
    fi
  done

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
    if grep -Eq 'ExecStart=.*(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/home\/.*\/\.|wget|curl|nc |ncat|socat|python[23]? -c|bash -c|/dev/tcp/)' "$u" 2>/dev/null; then
      finding "UNIT-$(basename "$u")" "Persistence" "FAIL" "$u ExecStart looks malicious" \
        "systemctl cat $(basename "$u") -- then disable + mask it and record the binary path."
    fi
  done

  # non-packaged /etc/init.d scripts (catches sysv backdoors)
  if [[ -d /etc/init.d ]] && command -v dpkg >/dev/null 2>&1; then
    local initf
    for initf in /etc/init.d/*; do
      [[ -f "$initf" ]] || continue
      case "$(basename "$initf")" in README|rc|rcS|skeleton|.legacy-bootordering) continue ;; esac
      if ! dpkg -S "$initf" >/dev/null 2>&1; then
        finding "INIT-$(basename "$initf")" "Persistence" "WARN" "non-packaged init script: $initf" \
          "Inspect $initf -- custom init scripts are often backdoors."
      fi
    done
  fi

  # processes with odd paths + non-packaged binary check
  ps -eo pid,ppid,user,etimes,cmd --sort=-etimes >"$EVID/33-processes.txt" 2>&1
  : >"$EVID/35-nonpackaged-procs.txt"
  while read -r pid ppid user et cmd; do
    [[ "$pid" == "PID" ]] && continue
    if [[ "$cmd" =~ ^(/tmp/|/var/tmp/|/dev/shm/|/home/[^/]+/\.) ]]; then
      finding "PROC-$pid" "Persistence" "FAIL" "pid $pid ($user) running from a writable dir: $cmd" \
        "Process running out of /tmp, /dev/shm or a dotdir = malware. ls -l /proc/$pid/exe, sha256sum it, note it, then kill."
    fi
    if [[ "$cmd" =~ (nc[[:space:]]+-[le]|ncat|socat.*exec|/dev/tcp/|cryptominer|xmrig|minerd|kdevtmpfsi|\bzod\b) ]]; then
      finding "PROC-$pid" "Persistence" "FAIL" "pid $pid suspicious: $cmd" "Reverse shell / miner / backdoor. Capture cmdline, hash the binary, kill it, then find how it starts."
    fi
  done < <(ps -eo pid,ppid,user,etimes,args 2>/dev/null)

  # flag listening binaries that are NOT owned by any distro package (catches zod, custom netcat, etc.)
  if command -v dpkg >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1; then
    local lpid exe real_exe
    while read -r lpid; do
      [[ "$lpid" =~ ^[0-9]+$ ]] || continue
      exe="$(readlink -f "/proc/$lpid/exe" 2>/dev/null)"
      [[ -n "$exe" && -f "$exe" ]] || continue
      if command -v dpkg >/dev/null 2>&1; then
        if ! dpkg -S "$exe" >/dev/null 2>&1; then
          real_exe="$(ps -p "$lpid" -o args= 2>/dev/null)"
          printf 'pid=%s exe=%s cmd=%s\n' "$lpid" "$exe" "$real_exe" >>"$EVID/35-nonpackaged-procs.txt"
          finding "PROC-UNPKG-$lpid" "Persistence" "WARN" "listening pid $lpid runs unpackaged binary: $exe" \
            "Verify if this binary belongs to a manually installed critical service or is a custom backdoor (e.g. zod/netcat)."
        fi
      elif command -v rpm >/dev/null 2>&1; then
        if ! rpm -qf "$exe" >/dev/null 2>&1; then
          real_exe="$(ps -p "$lpid" -o args= 2>/dev/null)"
          printf 'pid=%s exe=%s cmd=%s\n' "$lpid" "$exe" "$real_exe" >>"$EVID/35-nonpackaged-procs.txt"
          finding "PROC-UNPKG-$lpid" "Persistence" "WARN" "listening pid $lpid runs unpackaged binary: $exe" \
            "Verify if this binary belongs to a manually installed critical service or is a custom backdoor."
        fi
      fi
    done < <(awk -F'\t' '{print $4}' "$EVID/20-listening.tsv" 2>/dev/null | sort -u)
  fi

  # stray executables in /dev or /boot
  local devbin
  devbin="$(find /dev /boot -maxdepth 2 -type f -perm /111 2>/dev/null | grep -vE '^/boot/(vmlinuz|initrd|efi|grub)' | tr '\n' ' ')"
  [[ -n "$devbin" ]] && finding "BACKDOOR-DEVBOOT" "Persistence" "FAIL" "executable file(s) in /dev or /boot: $devbin" \
    "Inspect, hash, and remove backdoor executables hidden in /dev or /boot."

  # browser wrapper trojan / extension check
  { echo "### browser binaries"; file /usr/bin/firefox /usr/bin/chromium* /usr/bin/google-chrome* 2>/dev/null
    echo; echo "### firefox system addons"; ls -la /usr/lib/firefox-addons/extensions/ /usr/lib/firefox/browser/extensions/ 2>/dev/null
    echo; echo "### user mozilla profiles"; ls -la /home/*/.mozilla/firefox/ 2>/dev/null
  } >"$EVID/36-browser-check.txt"
  local bbin
  for bbin in /usr/bin/firefox /usr/bin/chromium /usr/bin/chromium-browser; do
    [[ -f "$bbin" ]] || continue
    if grep -qE '(curl |wget |nc |ncat|/dev/tcp/|python[23]? -c)' "$bbin" 2>/dev/null; then
      finding "BROWSER-TROJAN" "Persistence" "FAIL" "$bbin contains suspicious network/shell payload" \
        "Browser wrapper trojan detected! Reinstall browser package and inspect $bbin."
    fi
  done

  # deleted-but-running binaries
  ls -l /proc/[0-9]*/exe 2>/dev/null | grep -i '(deleted)' >"$EVID/34-deleted-exe.txt"
  if [[ -s "$EVID/34-deleted-exe.txt" ]]; then
    finding "PROC-DELETED" "Persistence" "FAIL" "running process(es) whose binary was deleted" \
      "Classic fileless malware. cat /proc/<pid>/cmdline, dump the binary with cat /proc/<pid>/exe > /root/evidence.bin, then kill."
  fi

  # ---- file integrity-ish checks (single-pass GNU find) ----------------------
  step "file permissions / SUID / world-writable / media / archives"
  : >"$EVID/40-suid-sgid.txt"
  : >"$EVID/41-world-writable.txt"
  : >"$EVID/42-ww-dirs.txt"
  : >"$EVID/43-unowned.txt"
  : >"$EVID/50-recent-files.txt"
  : >"$EVID/52-media-found.txt"
  : >"$EVID/53-archives-found.txt"

  if find --version 2>/dev/null | grep -qi 'GNU'; then
    local _suid_raw="$EVID/.suid-raw.txt" _ww_raw="$EVID/.ww-raw.txt" _wwd_raw="$EVID/.wwd-raw.txt"
    local _uo_raw="$EVID/.uo-raw.txt" _rec_raw="$EVID/.rec-raw.txt" _med_raw="$EVID/.med-raw.txt" _arc_raw="$EVID/.arc-raw.txt"
    : >"$_suid_raw"; : >"$_ww_raw"; : >"$_wwd_raw"; : >"$_uo_raw"; : >"$_rec_raw"; : >"$_med_raw"; : >"$_arc_raw"
    find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path /snap -o -path /var/lib/docker -o -path "$EVID" -o -path "$BKROOT" \) -prune -o \
      \( -type f \( -perm -4000 -o -perm -2000 \) -fprintf "$_suid_raw" '%M %u:%g %p\n' , \
         -type f -perm -0002 ! -perm -1000 -fprintf "$_ww_raw" '%M %u:%g %p\n' , \
         -type d -perm -0002 ! -perm -1000 -fprintf "$_wwd_raw" '%p\n' , \
         \( -nouser -o -nogroup \) -fprintf "$_uo_raw" '%p\n' , \
         -type f -mtime -180 ! -path '/var/lib/*' ! -path '/var/cache/*' -fprintf "$_rec_raw" '%T+ %M %u:%g %s %p\n' , \
         -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' \
            -o -iname '*.mov' -o -iname '*.wmv' -o -iname '*.flv' -o -iname '*.wav' \
            -o -iname '*.ogg' -o -iname '*.flac' -o -iname '*.m4a' -o -iname '*.m4v' \
            -o -iname '*.wma' -o -iname '*.aiff' -o -iname '*.mid' -o -iname '*.midi' \
            -o -iname '*.mpeg' -o -iname '*.mpg' -o -iname '*.3gp' -o -iname '*.swf' \
            -o -iname '*.torrent' -o -iname '*.pcap' \) ! -path '/usr/share/*' -fprintf "$_med_raw" '%p\n' , \
         \( -type f -o -type d \) \( -iname '*pyrdp*' -o -iname '*doona*' -o -iname '*xprobe*' \
            -o -iname '*backdoor*' -o -iname '*mimikatz*' -o -iname '*linpeas*' -o -iname '*metasploit*' \
            -o -iname '*sqlmap*' -o -iname '*impacket*' -o -iname '*responder*' -o -iname '*chisel*' \
            -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.tar.bz2' -o -iname '*.tar.xz' \
            -o -iname '*.zip' -o -iname '*.rar' -o -iname '*.7z' -o -iname '*.deb' -o -iname '*.rpm' \
            -o -iname '*.AppImage' \) ! -path '/usr/share/*' ! -path '/var/lib/apt/*' ! -path '/var/cache/*' ! -path '/usr/lib/*' \
            -fprintf "$_arc_raw" '%p\n' \) 2>/dev/null
    sort "$_suid_raw" >"$EVID/40-suid-sgid.txt"
    head -500 "$_ww_raw" >"$EVID/41-world-writable.txt"
    head -200 "$_wwd_raw" >"$EVID/42-ww-dirs.txt"
    head -200 "$_uo_raw" >"$EVID/43-unowned.txt"
    sort -r "$_rec_raw" | head -3000 >"$EVID/50-recent-files.txt"
    sort -u "$_med_raw" >"$EVID/52-media-found.txt"
    sort -u "$_arc_raw" | head -500 >"$EVID/53-archives-found.txt"
    rm -f "$_suid_raw" "$_ww_raw" "$_wwd_raw" "$_uo_raw" "$_rec_raw" "$_med_raw" "$_arc_raw"
  else
    find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path "$EVID" -o -path "$BKROOT" \) -prune -o \
      -type f \( -perm -4000 -o -perm -2000 \) -printf '%M %u:%g %p\n' 2>/dev/null | sort >"$EVID/40-suid-sgid.txt"
    find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path "$EVID" -o -path "$BKROOT" \) -prune -o \
      -type f -perm -0002 ! -perm -1000 -printf '%M %u:%g %p\n' 2>/dev/null | head -500 >"$EVID/41-world-writable.txt"
    find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -200 >"$EVID/42-ww-dirs.txt"
    find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -200 >"$EVID/43-unowned.txt"
    find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path "$EVID" -o -path "$BKROOT" -o -path /var/lib -o -path /var/cache \) -prune -o \
      -type f -mtime -180 -printf '%T+ %M %u:%g %s %p\n' 2>/dev/null | sort -r | head -3000 >"$EVID/50-recent-files.txt"
    find / -xdev -type f \( \
          -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' \
          -o -iname '*.mov' -o -iname '*.wmv' -o -iname '*.flv' -o -iname '*.wav' \
          -o -iname '*.ogg' -o -iname '*.flac' -o -iname '*.m4a' -o -iname '*.m4v' \
          -o -iname '*.torrent' -o -iname '*.pcap' \
          \) 2>/dev/null | grep -v '/usr/share/' >"$EVID/52-media-found.txt"
    find /home /root /opt /tmp /var/tmp /srv /var/www /usr/local -xdev \
      \( -iname '*pyrdp*' -o -iname '*doona*' -o -iname '*xprobe*' -o -iname '*backdoor*' \
         -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.zip' -o -iname '*.rar' -o -iname '*.7z' -o -iname '*.deb' \) \
      2>/dev/null | head -500 >"$EVID/53-archives-found.txt"
  fi

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

  local wwc; wwc="$(wc -l <"$EVID/41-world-writable.txt")"
  if (( wwc > 0 )); then
    finding "PERM-WW" "Permissions" "WARN" "$wwc world-writable file(s) without the sticky bit" \
      "chmod o-w on each one. world-writable /etc files and scripts in PATH are the scored ones."
  fi
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

  # hidden trick filenames in /home and /root (e.g. '...', '..passwords', '.  ')
  find /home /root -maxdepth 4 \( -name '...' -o -name '..?*' -o -name '. *' -o -iname '*.hacker*' \) 2>/dev/null >"$EVID/54-hidden-trick-files.txt"
  if [[ -s "$EVID/54-hidden-trick-files.txt" ]]; then
    finding "FILES-TRICK" "Files" "WARN" "suspicious hidden trick file(s)/dir(s) in /home or /root -> $EVID/54-hidden-trick-files.txt" \
      "Inspect $(head -3 "$EVID/54-hidden-trick-files.txt" | tr '\n' ' ') -- attackers hide tools/passwords in '...' or '..*' names."
  fi

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

  # package integrity check (debsums if installed, timeout-capped)
  if command -v debsums >/dev/null 2>&1; then
    timeout 25 debsums -c 2>/dev/null | head -100 >"$EVID/45-debsums.txt"
    if [[ -s "$EVID/45-debsums.txt" ]]; then
      finding "PKG-DEBSUMS" "Files" "WARN" "$(wc -l <"$EVID/45-debsums.txt") packaged file(s) modified from checksum -> $EVID/45-debsums.txt" \
        "Modified binaries in /usr/bin or /sbin indicate trojaned system tools. Inspect and reinstall affected packages."
    fi
  fi

  ok "recent files -> $EVID/50-recent-files.txt ($(wc -l <"$EVID/50-recent-files.txt") rows)"

  # ---- prohibited media & archive results ----------------------------------
  head -40 "$EVID/52-media-found.txt" | sed 's/^/    /'
  local mc; mc="$(grep -vc '^[[:space:]]*$' "$EVID/52-media-found.txt" 2>/dev/null)"
  [[ -z "$mc" ]] && mc=0
  if (( mc > 0 )); then
    finding "MEDIA" "Files" "WARN" "$mc prohibited-media candidate(s) -> $EVID/52-media-found.txt" \
      "Delete ONLY what the README calls prohibited. /usr/share backgrounds are already filtered out -- those are fine."
  else
    finding "MEDIA" "Files" "PASS" "no media files outside /usr/share"
  fi

  local ac; ac="$(grep -vc '^[[:space:]]*$' "$EVID/53-archives-found.txt" 2>/dev/null)"
  [[ -z "$ac" ]] && ac=0
  if (( ac > 0 )); then
    head -20 "$EVID/53-archives-found.txt" | sed 's/^/    /'
    finding "ARCHIVES" "Files" "WARN" "$ac archive/prohibited-tool candidate(s) -> $EVID/53-archives-found.txt" \
      "Check for unauthorized software archives (e.g. pyrdp, doona, xprobe, netcat tarballs/zips) in home/opt/tmp and remove if prohibited."
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

    # Batch pre-filter with xargs+grep to avoid spawning subshells on clean files.
    local pii_hits="$EVID/.pii-prefilter"
    head -4000 "$pii_files" | tr '\n' '\0' | xargs -0 -r grep -IlE "${pem_re}|${ssn_re}|${card_re}|${cred_keys}" 2>/dev/null >"$pii_hits" || true

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
    done <"$pii_hits"
    rm -f "$pii_hits"
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
  local pkg_cache="$EVID/.installed-pkgs"
  : >"$pkg_cache"
  case "$PKG" in
    apt)
      apt-mark showmanual >"$EVID/70-manual-packages.txt" 2>&1
      dpkg -l >"$EVID/70-dpkg.txt" 2>&1
      dpkg-query -W -f='${Package}\n' 2>/dev/null | sort -u >"$pkg_cache"
      zgrep -h . /var/log/dpkg.log* 2>/dev/null | tail -2000 >"$EVID/70-dpkg-log.txt"
      zgrep -h . /var/log/apt/history.log* 2>/dev/null >"$EVID/70-apt-history.txt"
      # insecure APT config / missing security pocket check
      if grep -REiq '(AllowUnauthenticated|AllowInsecureRepositories|Verify-Peer.*false|trusted=yes)' /etc/apt/apt.conf* /etc/apt/sources.list* 2>/dev/null; then
        finding "PKG-APT-SEC" "Updates" "FAIL" "insecure APT option (AllowUnauthenticated / trusted=yes) found in /etc/apt/" \
          "Remove AllowUnauthenticated/AllowInsecureRepositories/trusted=yes from /etc/apt/."
      fi
      if [[ -d /etc/apt ]] && ! grep -REq '^[^#]*security' /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null; then
        finding "PKG-APT-REPO" "Updates" "WARN" "no active security repository detected in /etc/apt/sources*" \
          "Uncomment or add the distro security repo in /etc/apt/sources.list so security updates actually install."
      fi
      ;;
    dnf|yum)
      dnf history list >"$EVID/70-dnf-history.txt" 2>&1 || yum history list >"$EVID/70-dnf-history.txt" 2>&1
      rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME:date}\n' | sort >"$EVID/70-rpm.txt" 2>&1
      rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort -u >"$pkg_cache"
      ;;
    zypper)
      rpm -qa >"$EVID/70-rpm.txt" 2>&1
      rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort -u >"$pkg_cache"
      ;;
    pacman)
      pacman -Qe >"$EVID/70-explicit.txt" 2>&1; pacman -Q >"$EVID/70-all.txt" 2>&1
      pacman -Qq 2>/dev/null | sort -u >"$pkg_cache"
      ;;
  esac
  local badpkgs="telnet telnetd telnetd-ssl inetutils-telnet inetutils-telnetd \
                 rsh-server rsh-client rlogin rexec ypserv nis tftp tftpd tftpd-hpa \
                 talk talkd inetutils-talk inetutils-talkd finger fingerd \
                 xinetd openbsd-inetd inetutils-inetd inetutils-ftpd \
                 nmap zenmap masscan nbtscan hping3 netdiscover arp-scan \
                 netcat netcat-traditional netcat-openbsd ncat pnetcat socat sbd \
                 john john-data hashcat hydra hydra-gtk medusa ncrack patator \
                 ophcrack ophcrack-cli crack crack-common fcrackzip lcrack pdfcrack rarcrack sipcrack \
                 aircrack-ng pyrit weplab reaver wifite bully cowpatty kismet \
                 metasploit-framework armitage beef-xss nikto sqlmap wpscan skipfish \
                 gobuster dirb ffuf wfuzz enum4linux smbmap responder \
                 wireshark wireshark-qt tshark tcpdump tcpflow ettercap-common ettercap-graphical \
                 bettercap dsniff driftnet yersinia irpas snort burpsuite zaproxy \
                 fakeroot maltego recon-ng theharvester amass \
                 proxychains proxychains4 tor torsocks macchanger \
                 doona xprobe xprobe2 pyrdp \
                 logkeys lkl uberkey thc-vlogger pykeylogger \
                 zeitgeist zeitgeist-core zeitgeist-datahub rhythmbox-plugin-zeitgeist \
                 vnc4server x11vnc tightvncserver tigervnc-standalone-server xrdp \
                 snmp snmpd autofs squid squid3 \
                 dovecot-core dovecot-pop3d dovecot-imapd courier-pop qpopper popa3d \
                 pure-ftpd proftpd-basic proftpd-core \
                 transmission-.* deluge.* qbittorrent bittorrent frostwire vuze azureus rtorrent ktorrent amule \
                 irssi hexchat weechat filezilla \
                 freeciv.* minetest.* supertux.* supertuxkart wesnoth.* \
                 gnome-games gnome-mines gnome-sudoku gnome-mahjongg gnome-nibbles gnome-robots \
                 gnome-taquin gnome-tetravex hitori iagno lightsoff five-or-more four-in-a-row \
                 swell-foop tali 2048 kmines kmahjongg kpat ksudoku \
                 aisleriot quadrapassel frozen-bubble 0ad xonotic openarena pingus hedgewars \
                 extremetuxracer armagetronad bastet nethack.* moon-buggy ninvaders bsdgames \
                 steam.* lutris"
  local bad_rx
  bad_rx="^($(printf '%s\n' $badpkgs | paste -sd'|' -))$"
  : >"$EVID/72-prohibited-packages.txt"
  if [[ -s "$pkg_cache" ]]; then
    grep -iE "$bad_rx" "$pkg_cache" 2>/dev/null | sort -u >"$EVID/72-prohibited-packages.txt"
  fi
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    case "$p" in
      telnet*|inetutils-telnet*|rsh-*|rlogin|rexec|ypserv|nis|tftp*|talk*|inetutils-talk*|finger*|xinetd|openbsd-inetd|inetutils-inetd)
        finding "PKG-$p" "Software" "FAIL" "$p is installed" "Insecure legacy daemon. Remove it (needs --aggressive or packages module) and confirm the port is closed." ;;
      *)
        finding "PKG-$p" "Software" "WARN" "$p is installed" \
          "Attack tooling / game / p2p / unauthorized daemon on a business host = policy violation. Confirm against the README, then purge and document it." ;;
    esac
  done <"$EVID/72-prohibited-packages.txt"
  rm -f "$pkg_cache"

  # manually installed stuff not from the distro
  find /usr/local/bin /usr/local/sbin /opt -maxdepth 2 -type f -perm /111 2>/dev/null >"$EVID/71-local-binaries.txt"
  (( $(wc -l <"$EVID/71-local-binaries.txt") > 0 )) && finding "PKG-LOCAL" "Software" "INFO" "$(wc -l <"$EVID/71-local-binaries.txt") binary(ies) outside the package manager" \
    "Anything in /usr/local/bin or /opt the package manager does not own deserves a look. sha256sum it and check the README."

  # SSH drop-in conflict scan
  if [[ -d /etc/ssh/sshd_config.d ]]; then
    local ssh_bad
    ssh_bad="$(grep -REin '^[[:space:]]*(PermitRootLogin[[:space:]]+yes|PermitEmptyPasswords[[:space:]]+yes|X11Forwarding[[:space:]]+yes)' /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -5)"
    [[ -n "$ssh_bad" ]] && finding "SSH-DROPIN" "SSH" "FAIL" "insecure directive in /etc/ssh/sshd_config.d/: $(echo "$ssh_bad" | tr '\n' ' ')" \
      "OpenSSH uses first-match-wins! Clean up conflicting drop-in files in /etc/ssh/sshd_config.d/."
  fi

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
  local made=0
  [[ -f "$SCRIPT_DIR/users.txt"  ]] || { (( DRY )) || { printf '# standard (non-admin) users from the README, one per line\n' >"$SCRIPT_DIR/users.txt"; made=1; } ; }
  [[ -f "$SCRIPT_DIR/admins.txt" ]] || { (( DRY )) || { printf '# administrators from the README, one per line\n'            >"$SCRIPT_DIR/admins.txt"; made=1; }; }
  [[ -f "$SCRIPT_DIR/groups.txt" ]] || { (( DRY )) || { printf '# custom groups from the README, format: groupname:user1,user2\n' >"$SCRIPT_DIR/groups.txt"; made=1; }; }
  (( made )) && warn "users.txt / admins.txt / groups.txt templates created next to the script."

  local -a A=() S=() G=()
  mapfile -t A < <(read_list "$SCRIPT_DIR/admins.txt" '# administrators from the README, one per line' || true)
  mapfile -t S < <(read_list "$SCRIPT_DIR/users.txt"  '# standard (non-admin) users from the README, one per line' || true)
  mapfile -t G < <(read_list "$SCRIPT_DIR/groups.txt" '# custom groups from the README, format: groupname:user1,user2' || true)
  local admin_grp="sudo"
  getent group sudo >/dev/null 2>&1 || { getent group wheel >/dev/null 2>&1 && admin_grp="wheel"; }

  if (( ${#A[@]} + ${#S[@]} == 0 )); then
    warn "users.txt / admins.txt are empty. fill them in from the README, then run users again."
    review "users.txt/admins.txt empty: account reconciliation skipped"
  else
    local -A isadmin=() isok=()
    local n
    for n in "${A[@]}"; do isadmin["$n"]=1; isok["$n"]=1; done
    for n in "${S[@]}"; do isok["$n"]=1; done
    local me="${SUDO_USER:-}"

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
        if command -v deluser >/dev/null 2>&1; then
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
        if command -v adduser >/dev/null 2>&1 && [[ "$PKG" == "apt" ]]; then
          act adduser --disabled-password --gecos "" "$n"
        else
          act useradd -m -s /bin/bash "$n"
        fi
      fi
    done
    mapfile -t real < <(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd)

    # 3. sudo / wheel / admin / nopasswdlogin membership
    local insudo ag
    for u in "${real[@]}"; do
      [[ -n "${isok[$u]:-}" ]] || continue
      insudo=0
      id -nG "$u" | tr ' ' '\n' | grep -qx "$admin_grp" && insudo=1
      if [[ -n "${isadmin[$u]:-}" ]]; then
        (( insudo )) || { ask "'$u' is an admin per the README but not in $admin_grp. Add?" && act usermod -aG "$admin_grp" "$u"; }
      else
        for ag in sudo wheel admin adm root nopasswdlogin; do
          getent group "$ag" >/dev/null 2>&1 || continue
          if id -nG "$u" | tr ' ' '\n' | grep -qx "$ag"; then
            ask "'$u' is in '$ag' but is a standard user. Remove from '$ag'?" && act gpasswd -d "$u" "$ag"
          fi
        done
      fi
    done
    say "current sudo/wheel/admin members:"; getent group sudo wheel admin nopasswdlogin 2>/dev/null | sed 's/^/    /'
  fi

  # 3b. custom groups from groups.txt + interactive group helper
  if (( ${#G[@]} > 0 )); then
    local gspec gname gmembers gm
    for gspec in "${G[@]}"; do
      gname="${gspec%%:*}"
      gmembers=""
      [[ "$gspec" == *:* ]] && gmembers="${gspec#*:}"
      [[ -n "$gname" ]] || continue
      if ! getent group "$gname" >/dev/null 2>&1; then
        act groupadd "$gname" && { ok "created group '$gname'"; change "group:$gname" "absent" "created"; }
      fi
      if [[ -n "$gmembers" ]]; then
        IFS=',' read -ra _gm_arr <<< "$gmembers"
        for gm in "${_gm_arr[@]}"; do
          [[ -n "$gm" ]] || continue
          id "$gm" &>/dev/null || { warn "groups.txt: user '$gm' does not exist"; continue; }
          if ! id -nG "$gm" | tr ' ' '\n' | grep -qx "$gname"; then
            act usermod -aG "$gname" "$gm" && ok "added '$gm' to '$gname'"
          fi
        done
      fi
    done
  fi
  if [[ -t 0 && $DRY -eq 0 && $PARANOID -eq 0 ]]; then
    if ask "Create a custom group or edit group membership interactively?"; then
      local cg cu
      read -r -p "  group name (blank to skip): " cg
      if [[ -n "$cg" ]]; then
        getent group "$cg" >/dev/null 2>&1 || { act groupadd "$cg" && ok "created group '$cg'"; }
        read -r -p "  comma-separated users to add to '$cg' (blank for none): " cu
        if [[ -n "$cu" ]]; then
          IFS=',' read -ra _cu_arr <<< "${cu//[[:space:]]/}"
          for u in "${_cu_arr[@]}"; do
            [[ -n "$u" ]] && id "$u" &>/dev/null && act usermod -aG "$cg" "$u"
          done
        fi
      fi
    fi
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

  # 6. empty password fields -> set password for root or lock (locking is reversible, deleting is not)
  while IFS=: read -r name pass rest; do
    if [[ -z "$pass" ]]; then
      if [[ $DRY -eq 1 || $PARANOID -eq 1 ]]; then warn "paranoid/dry: would lock/fix '$name' (empty password)"; continue; fi
      if [[ "$name" == "root" && -t 0 ]]; then
        warn "root has a BLANK password!"
        if ask "Set a strong password on root now? (No = prompt to lock root)"; then
          passwd root && { ok "root password set"; change "passwd:root" "empty" "set"; }
          continue
        fi
      fi
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
  for g in wheel sudo admin nopasswdlogin; do
    local m2; m2="$(getent group "$g" 2>/dev/null | cut -d: -f4)"
    [[ -n "$m2" ]] && finding "GRP-$g" "Accounts" "INFO" "$g members: $m2" \
      "Every member of $g has elevated/passwordless access. Verify each against the README authorized-user list."
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
    [PASS_MAX_DAYS]=90 [PASS_MIN_DAYS]=1 [PASS_MIN_LEN]=14 [PASS_WARN_AGE]=14
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
  ok "login.defs written"
  finding "LD-UMASK" "Accounts" "PASS" "login.defs UMASK=027"
  finding "LD-PASSLEN" "Accounts" "PASS" "login.defs PASS_MIN_LEN=14, MAX_DAYS=90"

  # 10. apply aging to existing interactive accounts + root + default inactive lock
  if [[ $DRY -eq 0 && $PARANOID -eq 0 ]]; then
    command -v useradd >/dev/null 2>&1 && useradd -D -f 30 >/dev/null 2>&1
    chage -M 90 -m 1 -W 14 root >/dev/null 2>&1 || true
    while IFS=: read -r name _ uid _ _ home shell; do
      (( uid < 1000 )) && continue
      [[ "$shell" =~ (nologin|false) ]] && continue
      chage -M 90 -m 1 -W 14 "$name" >/dev/null 2>&1 && say "  chage applied to $name"
    done < <(getent passwd)
  fi

  # 11. graphical login: guest + autologin (LightDM / GDM3 / MDM / SDDM)
  if [[ -d /etc/lightdm ]]; then
    act mkdir -p /etc/lightdm/lightdm.conf.d
    if [[ $DRY -eq 0 ]]; then
      printf '[Seat:*]\nallow-guest=false\ngreeter-allow-guest=false\nautologin-guest=false\nautologin-user=\nautologin-user-timeout=0\ngreeter-hide-users=true\ngreeter-show-manual-login=true\n' \
        > /etc/lightdm/lightdm.conf.d/99-cbptlinux.conf
      ok "LightDM: guest + autologin off"
    else
      say "[dry-run] lightdm guest/autologin off"
    fi
  fi
  if [[ -f /etc/gdm3/custom.conf ]]; then
    ensure_line /etc/gdm3/custom.conf "^[[:space:]]*#?[[:space:]]*AutomaticLoginEnable" "AutomaticLoginEnable=false"
    ensure_line /etc/gdm3/custom.conf "^[[:space:]]*#?[[:space:]]*TimedLoginEnable"     "TimedLoginEnable=false"
    if [[ $DRY -eq 0 ]]; then
      mkdir -p /etc/dconf/profile /etc/dconf/db/gdm.d
      printf 'user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n' >/etc/dconf/profile/gdm
      printf '[org/gnome/login-screen]\ndisable-user-list=true\ndisable-restart-buttons=true\nbanner-message-enable=true\n' >/etc/dconf/db/gdm.d/01-cbptlinux
      command -v dconf >/dev/null 2>&1 && dconf update >/dev/null 2>&1 || true
    fi
  fi
  if [[ -f /etc/mdm/mdm.conf ]]; then
    ensure_line /etc/mdm/mdm.conf "^[[:space:]]*#?[[:space:]]*AllowRoot" "AllowRoot=false"
    ensure_line /etc/mdm/mdm.conf "^[[:space:]]*#?[[:space:]]*AutomaticLoginEnable" "AutomaticLoginEnable=false"
    ensure_line /etc/mdm/mdm.conf "^[[:space:]]*#?[[:space:]]*TimedLoginEnable" "TimedLoginEnable=false"
  fi
  grep -rniE 'autologin|allow-guest' /etc/lightdm /etc/gdm3 /etc/mdm /etc/sddm.conf* 2>/dev/null | grep -v '^.*:\s*#' | sed 's/^/    /'
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

  local have_pwq=0 have_faillock=0 have_pwhist=0
  local so
  for so in /lib/x86_64-linux-gnu/security/pam_pwquality.so /lib64/security/pam_pwquality.so /lib/security/pam_pwquality.so; do
    [[ -f "$so" ]] && have_pwq=1
  done
  for so in /lib/x86_64-linux-gnu/security/pam_faillock.so /lib64/security/pam_faillock.so /lib/security/pam_faillock.so; do
    [[ -f "$so" ]] && have_faillock=1
  done
  for so in /lib/x86_64-linux-gnu/security/pam_pwhistory.so /lib64/security/pam_pwhistory.so /lib/security/pam_pwhistory.so; do
    [[ -f "$so" ]] && have_pwhist=1
  done

  # --- pwquality config (distro neutral, read by pam_pwquality) ---
  backup_file /etc/security/pwquality.conf
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
  ok "/etc/security/pwquality.conf written"
  finding "PAM-PWQ-CONF" "Passwords" "PASS" "pwquality: minlen 14, 4 classes, difok 4"

  # --- wire it into PAM ---
  local pwfile authfile acctfile
  if [[ -f /etc/pam.d/common-password ]]; then
    pwfile=/etc/pam.d/common-password; authfile=/etc/pam.d/common-auth
    acctfile=/etc/pam.d/common-account
  else
    pwfile=/etc/pam.d/password-auth; authfile=/etc/pam.d/system-auth
    acctfile="$authfile"
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

  local pwq_opts="retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4 enforce_for_root"
  if [[ $have_pwq -eq 1 ]]; then
    if [[ $DRY -eq 1 ]]; then
      say "[dry-run] wire pam_pwquality into $pwfile"
    elif grep -q 'pam_pwquality.so' "$pwfile"; then
      sed -i -E "s|^([[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_pwquality\\.so).*$|\\1 ${pwq_opts}|" "$pwfile"
    else
      # insert right after the "password" section header / before pam_unix password
      sed -i -E "0,/^password[[:space:]]/{s|^(password[[:space:]].*)$|password\\trequisite\\tpam_pwquality.so ${pwq_opts}\\n\\1|}" "$pwfile"
      grep -q 'pam_pwquality.so' "$pwfile" || printf 'password\trequisite\tpam_pwquality.so %s\n' "$pwq_opts" >>"$pwfile"
    fi
    ok "pam_pwquality wired into $pwfile"
    finding "PAM-PWQ" "Passwords" "PASS" "pam_pwquality active (inline + pwquality.conf)"
  else
    finding "PAM-PWQ" "Passwords" "WARN" "pam_pwquality module not present" \
      "Install libpam-pwquality (Debian/Ubuntu) or libpwquality (RHEL). Without it, minlen in login.defs is not enforced."
  fi

  # --- pwhistory (modern distros use pam_pwhistory in addition to pam_unix remember=) ---
  if [[ $have_pwhist -eq 1 ]]; then
    backup_file /etc/security/pwhistory.conf
    if [[ $DRY -eq 0 ]]; then
      mkdir -p /etc/security
      cat >/etc/security/pwhistory.conf <<'PWH'
# written by cbptlinux.sh
remember = 12
enforce_for_root
use_authtok
PWH
      chmod 644 /etc/security/pwhistory.conf
      local tmp_ph; tmp_ph="$(mktemp)"
      grep -v 'pam_pwhistory\.so' "$pwfile" >"$tmp_ph"
      awk 'BEGIN{done=0}
           /^[[:space:]]*password[[:space:]].*pam_unix\.so/ && !done {
             print "password\trequisite\t\tpam_pwhistory.so remember=12 use_authtok enforce_for_root"
             done=1
           }
           { print }' "$tmp_ph" >"$pwfile"
      rm -f "$tmp_ph"
      ok "pam_pwhistory wired into $pwfile + /etc/security/pwhistory.conf"
    else
      say "[dry-run] wire pam_pwhistory into $pwfile"
    fi
    finding "PAM-PWHISTORY" "Passwords" "PASS" "pam_pwhistory active (remember=12)"
  fi

  # pam_unix password options: remember + sha512 + rounds
  if grep -q 'pam_unix.so' "$pwfile"; then
    if [[ $DRY -eq 0 ]]; then
      sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/[[:space:]]+(use_authtok|nullok_secure|nullok|obscure|sha512|remember=[0-9]+|rounds=[0-9]+|md5|bigcrypt)//g' "$pwfile"
      sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s|$| sha512 rounds=100000 remember=12 use_authtok obscure|' "$pwfile"
    else
      say "[dry-run] pam_unix password options (sha512, remember=12)"
    fi
    ok "pam_unix password options set (sha512, remember=12)"
    finding "PAM-UNIX-HIST" "Passwords" "PASS" "password history = 12, sha512"
  fi

  # remove nullok and nullok_secure across PAM stacks -- it is what allows blank passwords
  local pf nullok_hit=0
  for pf in "$authfile" "$pwfile" /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/login /etc/pam.d/sshd; do
    [[ -f "$pf" ]] || continue
    if grep -qE 'nullok(_secure)?' "$pf"; then
      nullok_hit=1
      if [[ $DRY -eq 0 ]]; then
        backup_file "$pf"
        sed -i -E 's/[[:space:]]*nullok(_secure)?//g' "$pf"
        ok "removed nullok/nullok_secure from $pf"
      else
        say "[dry-run] remove nullok/nullok_secure from $pf"
      fi
    fi
  done
  if (( nullok_hit )); then
    finding "PAM-NULLOK" "Passwords" "PASS" "nullok/nullok_secure removed from PAM stacks"
  else
    finding "PAM-NULLOK" "Passwords" "PASS" "no nullok/nullok_secure in PAM stacks"
  fi

  # --- lockout ---
  if [[ $have_faillock -eq 1 ]]; then
    # faillock.conf (modern) + inline args so both conf-based and pam-file graders pass
    if [[ $DRY -eq 0 ]]; then
      mkdir -p /etc/security
      backup_file /etc/security/faillock.conf
      cat >/etc/security/faillock.conf <<'FL'
# written by cbptlinux.sh
deny = 5
fail_interval = 900
unlock_time = 900
audit
silent
no_magic_root
even_deny_root
root_unlock_time = 900
FL
      ok "/etc/security/faillock.conf written (deny=5, unlock=900s)"
    else
      say "[dry-run] write /etc/security/faillock.conf"
    fi

    # Wire it into the auth stack in the CORRECT positions.
    local wire=0 f="$authfile" nu nf
    local fl_pre="preauth silent deny=5 fail_interval=900 unlock_time=900 even_deny_root root_unlock_time=900"
    local fl_fail="authfail deny=5 fail_interval=900 unlock_time=900 even_deny_root root_unlock_time=900"
    [[ -f "$f" ]] || f=""
    if [[ -n "$f" ]]; then
      backup_file "$f"
      if [[ $DRY -eq 0 ]]; then
        cp -a "$f" "${f}.cbptlinuxbak-$STAMP" 2>/dev/null
        local tmp; tmp="$(mktemp)"
        # self-healing: strip any faillock lines from earlier/incorrect runs first
        grep -v 'pam_faillock\.so' "$f" >"$tmp"
        awk -v pre="$fl_pre" -v fail="$fl_fail" 'BEGIN{done=0}
             /^[[:space:]]*auth[[:space:]].*pam_unix\.so/ && !done {
               print "auth\trequired\t\tpam_faillock.so " pre
               print
               print "auth\t[default=die]\tpam_faillock.so " fail
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
    (( wire )) && finding "PAM-LOCKOUT" "Passwords" "PASS" "pam_faillock: 5 failures -> 15 min lockout, correctly positioned"

    # account stack: safe to append, all account modules run in order.
    if [[ $DRY -eq 0 ]]; then
      if [[ "$pwfile" == /etc/pam.d/common-password ]]; then
        sed -i '/^[[:space:]]*account[[:space:]]*required[[:space:]]*pam_faillock\.so[[:space:]]*$/d' "$pwfile"
      fi
      backup_file "$acctfile"
      grep -q 'pam_faillock\.so' "$acctfile" || printf 'account\trequired\tpam_faillock.so\n' >>"$acctfile"
    else
      say "[dry-run] account-stack faillock line"
    fi
  else
    # older: pam_tally2. same positioning rules apply.
    if [[ -f /lib/x86_64-linux-gnu/security/pam_tally2.so || -f /lib64/security/pam_tally2.so ]]; then
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
        backup_file "$acctfile"
        grep -q 'pam_tally2' "$acctfile" || printf 'account\trequired\tpam_tally2.so\n' >>"$acctfile"
      else
        say "[dry-run] pam_tally2 lockout"
      fi
      finding "PAM-LOCKOUT" "Passwords" "PASS" "pam_tally2: 5 failures -> 15 min lockout"
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
      finding "PAM-SU" "Passwords" "PASS" "su already restricted to a group"
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
          ok "restricted su to the wheel group ($wm)"
        else
          say "[dry-run] restrict su to wheel ($wm)"
        fi
        finding "PAM-SU" "Passwords" "PASS" "su restricted to wheel ($wm)"
      fi
    fi
  fi

  # --- umask + idle timeout everywhere ---
  step "umask + idle shell timeout"
  if [[ $DRY -eq 0 ]]; then
    for f in /etc/profile /etc/bash.bashrc /etc/login.defs; do
      [[ -f "$f" ]] && sed -i -E 's|^[[:space:]]*umask[[:space:]]+[0-9]+|umask 027|' "$f"
    done
    grep -q '^umask 027' /etc/profile || printf '\numask 027\n' >>/etc/profile
    [[ -f /etc/bash.bashrc ]] && { grep -q '^umask 027' /etc/bash.bashrc || printf '\numask 027\n' >>/etc/bash.bashrc; }
    mkdir -p /etc/profile.d
    cat >/etc/profile.d/99-cbptlinux-umask.sh <<'UM'
# cbptlinux.sh
umask 027
case "$-" in *i*) TMOUT=900; readonly TMOUT; export TMOUT ;; esac
UM
    chmod 644 /etc/profile.d/99-cbptlinux-umask.sh
  else
    say "[dry-run] umask 027 + TMOUT=900 in profile files"
  fi
  ok "umask 027 + idle timeout applied"
  finding "PERM-UMASK" "Passwords" "PASS" "umask 027"

  # core dumps
  backup_file /etc/security/limits.conf
  if ! grep -q '#cbptlinux' /etc/security/limits.conf 2>/dev/null; then
    if [[ $DRY -eq 0 ]]; then
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

  # verify referenced pam_*.so modules exist on disk (do NOT re-run pam-auth-update
  # after manual edits, since --package can overwrite our faillock/pwhistory wiring)
  if [[ $DRY -eq 0 ]]; then
    local mod missing_mod=0
    while read -r mod; do
      [[ -z "$mod" ]] && continue
      if [[ ! -f "/lib/x86_64-linux-gnu/security/$mod" && ! -f "/lib64/security/$mod" && ! -f "/lib/security/$mod" ]]; then
        warn "PAM module referenced in stack is missing on disk: $mod"
        missing_mod=1
      fi
    done < <(grep -oE 'pam_[a-zA-Z0-9_]+\.so' "$pwfile" "$authfile" 2>/dev/null | sort -u)
    (( missing_mod )) && finding "PAM-MODCHECK" "Passwords" "FAIL" "missing pam_*.so module referenced in PAM stack" \
      "Restore from ${pwfile}.cbptlinuxbak-$STAMP or install the missing PAM module."
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

  # prefer a drop-in that sorts FIRST (00-*) because OpenSSH uses first-match-wins.
  local dropin=/etc/ssh/sshd_config.d target="$cfg"
  if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d' "$cfg" 2>/dev/null; then
    [[ $DRY -eq 0 ]] && mkdir -p "$dropin"
    target="$dropin/00-cbptlinux.conf"
  else
    if ! grep -q '^Include' "$cfg"; then
      [[ $DRY -eq 0 ]] && mkdir -p "$dropin"
      if [[ $DRY -eq 0 ]]; then
        local _sshtmp; _sshtmp="$(mktemp)"
        { printf 'Include /etc/ssh/sshd_config.d/*.conf\n'; cat "$cfg"; } >"$_sshtmp" && cat "$_sshtmp" >"$cfg"
        rm -f "$_sshtmp"
      fi
      target="$dropin/00-cbptlinux.conf"
    fi
  fi
  [[ $DRY -eq 0 && -f "$dropin/99-cbptlinux.conf" && "$target" != "$dropin/99-cbptlinux.conf" ]] && rm -f "$dropin/99-cbptlinux.conf"
  if [[ -d "$dropin" ]]; then
    local _di
    for _di in "$dropin"/*.conf; do
      [[ -f "$_di" && "$_di" != "$target" ]] || continue
      if grep -qiE '^[[:space:]]*(PermitRootLogin[[:space:]]+yes|PermitEmptyPasswords[[:space:]]+yes|X11Forwarding[[:space:]]+yes)' "$_di" 2>/dev/null; then
        warn "conflicting insecure setting in $_di -- review or remove it"
      fi
    done
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
  local HOSTKEY="ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256"

  local k
  for k in "${!SSHD[@]}"; do
    # skip keys this openssh does not know, or sshd refuses to start
    case "$k" in
      DebianBanner) [[ "$DISTRO_ID" =~ (ubuntu|debian) ]] || continue ;;
      KbdInteractiveAuthentication) sshd -T 2>/dev/null | grep -qi kbdinteractiveauthentication || continue ;;
    esac
    ensure_line "$target" "^[[:space:]]*#?[[:space:]]*${k}[[:space:]]" "${k} ${SSHD[$k]}"
  done
  # also mirror top scored directives in main sshd_config so file-grepping scorers pass
  if [[ "$target" != "$cfg" ]]; then
    for k in PermitRootLogin PermitEmptyPasswords X11Forwarding Protocol MaxAuthTries LogLevel; do
      ensure_line "$cfg" "^[[:space:]]*#?[[:space:]]*${k}[[:space:]]" "${k} ${SSHD[$k]}"
    done
  fi
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*Ciphers[[:space:]]"          "Ciphers ${CIPHERS}"
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*MACs[[:space:]]"             "MACs ${MACS}"
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*KexAlgorithms[[:space:]]"    "KexAlgorithms ${KEX}"
  ensure_line "$target" "^[[:space:]]*#?[[:space:]]*HostKeyAlgorithms[[:space:]]" "HostKeyAlgorithms ${HOSTKEY}"

  # PasswordAuthentication: leave ON by default. flipping it off without keys
  # loaded is the #1 self-inflicted lockout in this competition.
  if [[ $AGGRESSIVE -eq 1 ]]; then
    if confirm "AGGRESSIVE: set PasswordAuthentication no? Only if key auth already works for your admin user."; then
      ensure_line "$target" "^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]" "PasswordAuthentication no"
      finding "SSH-PWAUTH" "SSH" "PASS" "PasswordAuthentication no"
    fi
  else
    ensure_line "$target" "^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]" "PasswordAuthentication yes"
    finding "SSH-PWAUTH" "SSH" "INFO" "PasswordAuthentication left ON" \
      "Re-run with --aggressive to disable password auth. Do NOT do it until key login is verified working."
  fi

  # login banner
  if [[ $DRY -eq 0 ]]; then
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
  finding "SSH-BANNER" "SSH" "PASS" "/etc/issue.net banner set"

  # weak host keys
  local removed=0
  for f in /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub; do
    if [[ -f "$f" ]]; then
      if [[ $DRY -eq 1 ]]; then say "[dry-run] remove $f"; else rm -f "$f"; fi
      removed=1
    fi
  done
  (( removed )) && { ok "removed DSA host keys"; finding "SSH-DSA" "SSH" "PASS" "DSA host keys removed"; }

  # any weak RSA key left?
  if [[ -f /etc/ssh/ssh_host_rsa_key ]] && command -v ssh-keygen >/dev/null 2>&1; then
    local bits; bits="$(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key 2>/dev/null | awk '{print $1}')"
    if [[ -n "$bits" && "$bits" -lt 2048 ]]; then
      warn "RSA host key is only $bits bits -- regenerating"
      if [[ $DRY -eq 0 && $PARANOID -eq 0 ]]; then
        rm -f /etc/ssh/ssh_host_rsa_key*; ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N '' -q
      fi
    fi
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
      [[ $DRY -eq 0 ]] && ssh-keygen -A >/dev/null 2>&1
    fi
  fi

  if [[ $DRY -eq 0 ]]; then
    chmod 600 "$cfg"; chmod 600 "$target" 2>/dev/null
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
    if systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1 || \
       systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || \
       service sshd reload >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1; then
      finding "SSH-RELOAD" "SSH" "PASS" "sshd config valid and reloaded"
    else
      warn "sshd config is valid but no reload/restart command succeeded -- restart it by hand"
      finding "SSH-RELOAD" "SSH" "WARN" "sshd config valid, reload failed" \
        "systemctl restart ssh (or service ssh restart) -- an unapplied sshd config scores zero."
    fi
  else
    err "sshd -t FAILED. Restoring $cfg from backup."
    sshd -t
    cp -a "$BKDIR/files/etc_ssh_sshd_config" "$cfg" 2>/dev/null
    [[ -f "$target" && "$target" != "$cfg" ]] && rm -f "$target"
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

  if [[ "$PKG" == "apt" ]] && ! command -v ufw >/dev/null 2>&1; then
    pkg_install ufw 2>/dev/null
  fi

  local fw=""
  command -v ufw >/dev/null 2>&1 && [[ -d /etc/ufw ]] && fw="ufw"
  if [[ -z "$fw" ]] && systemctl is-active firewalld >/dev/null 2>&1; then fw="firewalld"; fi
  if [[ -z "$fw" ]] && command -v nft >/dev/null 2>&1; then fw="nft"; fi
  [[ -z "$fw" ]] && command -v iptables >/dev/null 2>&1 && fw="iptables"

  local ssh_conn_port=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    read -r _ _ _ ssh_conn_port _ <<<"$SSH_CONNECTION"
  fi

  case "$fw" in
    ufw)
      say "using ufw"
      # start from a clean slate, then only open what is actually listening
      # AND not on the insecure list.
      act ufw --force reset
      act ufw default deny incoming
      act ufw default allow outgoing
      if [[ $DRY -eq 0 ]]; then
        [[ "$ssh_conn_port" =~ ^[0-9]+$ ]] && ufw allow "${ssh_conn_port}/tcp" >/dev/null 2>&1 && say "  preserved active SSH port $ssh_conn_port"
        local p
        while read -r laddr; do
          p="${laddr##*:}"
          [[ "$p" =~ ^[0-9]+$ ]] || continue
          case "$p" in
            22|80|443) ufw allow "$p" >/dev/null 2>&1 && say "  allowed $p" ;;
            21|23|69|110|111|135|139|143|445|512|513|514|993|995|1337|1433|2049|3128|3306|4444|5555|5900|5901|6667|6668|6669|12345|31337) warn "  NOT opening insecure port $p" ;;
            *) ufw allow "$p" >/dev/null 2>&1 && say "  allowed $p (verify against README)" ;;
          esac
        done < <(ss -tlnH 2>/dev/null | awk '{print $4}' | sort -u)
      else
        say "[dry-run] auto-allow the currently listening ports"
      fi
      act ufw logging medium
      act ufw --force enable
      if [[ $DRY -eq 1 ]]; then
        finding "FW-UFW" "Firewall" "INFO" "[dry-run] would enable ufw: default deny inbound, logging medium"
      elif ufw status 2>/dev/null | grep -qi 'Status: active'; then
        ufw status verbose
        finding "FW-UFW" "Firewall" "PASS" "ufw: default deny inbound, logging medium, enabled"
      else
        err "ufw did not come up active -- the firewall is NOT protecting the box"
        finding "FW-UFW" "Firewall" "FAIL" "ufw failed to enable" \
          "Run 'ufw --force enable' and read the iptables error. A firewall that did not apply scores zero."
      fi
      ;;
    firewalld)
      say "using firewalld"
      act firewall-cmd --set-default-zone=drop
      act firewall-cmd --permanent --zone=drop --remove-services="$(firewall-cmd --zone=drop --list-services 2>/dev/null | tr ' ' ',')"
      local s
      for s in ssh dhcpv6-client; do act firewall-cmd --permanent --zone=drop --add-service=$s; done
      act firewall-cmd --reload
      firewall-cmd --list-all
      if [[ $DRY -eq 1 ]]; then
        finding "FW-FIREWALLD" "Firewall" "INFO" "[dry-run] would set firewalld default zone = drop"
      elif firewall-cmd --state 2>/dev/null | grep -qi running; then
        finding "FW-FIREWALLD" "Firewall" "PASS" "firewalld default zone = drop"
      else
        err "firewalld is not running after the change"
        finding "FW-FIREWALLD" "Firewall" "FAIL" "firewalld did not apply" \
          "firewall-cmd --state; systemctl status firewalld -- a dead firewall scores zero."
      fi
      ;;
    *)
      say "using raw iptables/nft"
      pkg_install iptables 2>/dev/null
      command -v iptables >/dev/null 2>&1 || { warn "no firewall tooling available"; return; }
      if [[ $DRY -eq 0 ]]; then
        iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
        iptables -F; iptables -X
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 6/min -j ACCEPT
        [[ "$ssh_conn_port" =~ ^[0-9]+$ && "$ssh_conn_port" != "22" ]] && \
          iptables -A INPUT -p tcp --dport "$ssh_conn_port" -m conntrack --ctstate NEW -j ACCEPT
        local p
        while read -r laddr proto; do
          p="${laddr##*:}"
          [[ "$p" =~ ^[0-9]+$ ]] || continue
          [[ "$p" == 22 ]] && continue
          case "$p" in 21|23|69|110|111|135|139|143|445|512|513|514|993|995|1337|1433|2049|3128|3306|4444|5555|5900|5901|6667|6668|6669|12345|31337) warn "  NOT opening insecure port $p"; continue;; esac
          iptables -I INPUT 5 -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
          iptables -I INPUT 5 -p udp --dport "$p" -j ACCEPT
          say "  opened $p (verify against README)"
        done < <(ss -tulpnH 2>/dev/null | awk '{print $5,$1}' | sort -u)
        iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "cbptlinux-DROP: " --log-level 4
        mkdir -p /etc/iptables 2>/dev/null
        iptables-save >/etc/iptables/rules.v4 2>/dev/null || warn "could not persist iptables rules to /etc/iptables/rules.v4"
        pkg_install iptables-persistent netfilter-persistent 2>/dev/null
        iptables -L -n -v | head -40
      else
        say "[dry-run] default-DROP iptables ruleset + allow currently listening ports"
      fi
      if [[ $DRY -eq 1 ]]; then
        finding "FW-IPTABLES" "Firewall" "INFO" "[dry-run] would set iptables default DROP + save rules"
      elif iptables -S INPUT 2>/dev/null | head -1 | grep -q 'DROP'; then
        finding "FW-IPTABLES" "Firewall" "PASS" "iptables default DROP + rules saved to /etc/iptables/rules.v4"
      else
        err "iptables INPUT policy is not DROP after applying the ruleset"
        finding "FW-IPTABLES" "Firewall" "FAIL" "iptables default-DROP did not apply" \
          "iptables -S INPUT | head -1; iptables -L -n. a firewall that did not apply scores zero."
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

  # safe to disable basically everywhere (FTP moved to interactive/agg_off so critical FTP isn't killed blindly)
  local safe_off="telnet telnetd.socket telnet.socket openbsd-inetd inetd xinetd rsh.socket rlogin rlogin.socket \
                  rexec rexec.socket ypserv rpcbind rpcbind.socket avahi-daemon bluetooth cups-browsed \
                  nfs-server nfs-kernel-server whoopsie apport modemmanager \
                  snmpd tftpd tftpd-hpa talk talkd finger \
                  spice-vdagent spice-webdavd"
  # could be a critical service -> ask/confirm or --aggressive
  local agg_off="apache2 httpd nginx lighttpd mysql mariadb mysqld postgresql \
                 named bind9 samba smbd nmbd slapd dovecot dovecot.socket exim4 sendmail \
                 vsftpd proftpd pure-ftpd squid squid3 courier-pop courier-pop-ssl qpopper popa3d cyrus-imapd \
                 xrdp x11vnc vncserver tightvncserver isc-dhcp-server \
                 docker containerd libvirtd cups"

  local s st
  for s in $safe_off; do
    is_kept_service "$s" && continue
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.(service|socket)"; then
      st="$(systemctl is-active "$s" 2>/dev/null)"
      act systemctl stop "$s"
      act systemctl disable "$s"
      act systemctl mask "$s"
      finding "SVC-$s" "Services" "PASS" "$s stopped+disabled+masked (was $st)"
      change "service:$s" "$st" "masked"
    elif [[ -x /etc/init.d/$s ]]; then
      act service "$s" stop
      command -v update-rc.d >/dev/null && act update-rc.d "$s" disable
      command -v chkconfig >/dev/null && act chkconfig "$s" off
      finding "SVC-$s" "Services" "PASS" "$s (sysvinit) stopped+disabled"
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
        act systemctl stop "$s"
        act systemctl disable "$s"
        finding "SVC-$s" "Services" "PASS" "$s stopped+disabled by operator"
        change "service:$s" "$st" "disabled"
      else
        finding "SVC-$s" "Services" "SKIP" "$s left running by operator"
      fi
    done
  else
    # even in safe mode, prompt on commonly scored unwanted servers if interactive
    local maybe_off="vsftpd proftpd pure-ftpd squid squid3 dovecot dovecot.socket xrdp x11vnc"
    for s in $maybe_off; do
      is_kept_service "$s" && continue
      systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.(service|socket)" || continue
      st="$(systemctl is-active "$s" 2>/dev/null)"
      [[ "$st" == "active" ]] || continue
      if [[ -t 0 ]] && ask "'$s' is active. Stop+disable '$s'? (Say NO if the README lists it as a critical service)"; then
        act systemctl stop "$s"
        act systemctl disable "$s"
        finding "SVC-$s" "Services" "PASS" "$s stopped+disabled by operator"
        change "service:$s" "$st" "disabled"
      else
        finding "SVC-$s" "Services" "WARN" "$s is active (check README -- disable if unauthorized, harden if critical)"
      fi
    done
    finding "SVC-AGG" "Services" "INFO" "remaining web/db/mail/samba services left alone" \
      "Re-run with --aggressive if the README confirms none of them are critical. Otherwise HARDEN their configs instead of stopping them (apps module)."
  fi

  # things that should be running
  for s in rsyslog systemd-journald cron crond auditd sshd apparmor; do
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
      act systemctl enable "$s"
      act systemctl start "$s"
      st="$(systemctl is-active "$s" 2>/dev/null)"
      [[ "$st" == "active" ]] && finding "SVC-ON-$s" "Services" "PASS" "$s active+enabled" \
                              || finding "SVC-ON-$s" "Services" "WARN" "$s = $st" "systemctl status $s -- a dead logging, audit, or MAC daemon is a scored item."
    fi
  done

  # AppArmor profile enforcement (best effort)
  if command -v aa-enforce >/dev/null 2>&1 && [[ -d /etc/apparmor.d ]]; then
    if [[ $DRY -eq 0 ]]; then
      aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
    else
      say "[dry-run] aa-enforce /etc/apparmor.d/*"
    fi
  fi

  # mask Ctrl-Alt-Del reboot shortcut
  if command -v systemctl >/dev/null 2>&1; then
    act systemctl mask ctrl-alt-del.target >/dev/null 2>&1
    finding "SVC-CAD" "Services" "PASS" "ctrl-alt-del.target masked"
  fi
  if [[ -f /etc/init/control-alt-delete.conf ]] && [[ $DRY -eq 0 ]]; then
    backup_file /etc/init/control-alt-delete.conf
    sed -i 's/^\s*exec.*/exec false/' /etc/init/control-alt-delete.conf 2>/dev/null
  fi

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
        if grep -RIl '^[[:space:]]*deb[[:space:]]+cdrom:' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -q .; then
          if [[ $DRY -eq 0 ]]; then
            local _sf
            while IFS= read -r _sf; do
              [[ -f "$_sf" ]] || continue
              backup_file "$_sf"
              sed -i -E 's|^([[:space:]]*deb[[:space:]]+cdrom:)|#cbptlinux# \1|' "$_sf"
              ok "commented out cdrom: line in $_sf"
            done < <(grep -RIl '^[[:space:]]*deb[[:space:]]+cdrom:' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null)
          else
            say "[dry-run] comment out deb cdrom: lines in apt sources"
          fi
          finding "PKG-SOURCES" "Updates" "PASS" "cdrom: apt source lines commented out"
        fi
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
          finding "PKG-LOCK" "Updates" "WARN" "dpkg lock held" "ps aux | grep apt -- a stuck apt breaks the whole update chain and graders notice."
        fi
      fi
      act apt-get update && ok "apt-get update succeeded" || {
        warn "apt-get update failed"
        finding "PKG-UPDATE" "Updates" "FAIL" "apt-get update failed" \
          "Read the error. common causes: broken sources.list, cdrom entry, expired release, DNS. fixing updates is itself worth points."
      }
      if [[ $DRY -eq 0 ]]; then
        if [[ $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: full apt-get upgrade? can take 10+ min and may need a reboot."; then
          DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade 2>&1 | tail -20
          DEBIAN_FRONTEND=noninteractive apt-get -y autoremove 2>&1 | tail -5
          finding "PKG-UPGRADE" "Updates" "PASS" "full upgrade applied"
        else
          # security updates (only invoke apt-get install if there are security packages!)
          local sec_pkgs
          sec_pkgs="$(apt-get -s upgrade 2>/dev/null | grep -E '^Inst' | grep -i secur | awk '{print $2}' | head -80 | tr '\n' ' ')"
          if [[ -n "${sec_pkgs// /}" ]]; then
            DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --only-upgrade $sec_pkgs >/dev/null 2>&1
          fi
          # also targeted upgrade of frequently scored server/browser apps if already installed
          local key_apps="" ka
          for ka in openssh-server vsftpd chromium chromium-browser firefox firefox-esr sudo openssl \
                    apache2 nginx samba mysql-server mariadb-server postgresql bind9 postfix curl bash libssl3; do
            dpkg -s "$ka" >/dev/null 2>&1 && key_apps="$key_apps $ka"
          done
          if [[ -n "${key_apps// /}" ]]; then
            say "upgrading key installed apps:$key_apps"
            DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --only-upgrade $key_apps >/dev/null 2>&1 || true
          fi
          finding "PKG-UPGRADE" "Updates" "INFO" "security + key-app upgrades attempted" \
            "Run --aggressive for a full upgrade. unpatched packages are scored; so is a broken apt."
        fi
      else
        say "[dry-run] package upgrade"
      fi
      ;;
    dnf|yum)
      local mgr=dnf; command -v dnf >/dev/null || mgr=yum
      act $mgr makecache && ok "$mgr makecache ok" || warn "$mgr makecache failed"
      if [[ $AGGRESSIVE -eq 1 ]] && confirm "AGGRESSIVE: full $mgr upgrade?"; then
        act $mgr -y upgrade && finding "PKG-UPGRADE" "Updates" "PASS" "full upgrade applied"
        act $mgr -y autoremove
      else
        act $mgr -y --security upgrade
        finding "PKG-UPGRADE" "Updates" "INFO" "security-only upgrade attempted"
      fi
      if [[ "$mgr" == "dnf" ]]; then
        pkg_install dnf-automatic 2>/dev/null
        if [[ -f /etc/dnf/automatic.conf && $DRY -eq 0 ]]; then
          backup_file /etc/dnf/automatic.conf
          ensure_line /etc/dnf/automatic.conf '^[[:space:]]*#?[[:space:]]*apply_updates' 'apply_updates = yes'
          ensure_line /etc/dnf/automatic.conf '^[[:space:]]*#?[[:space:]]*download_updates' 'download_updates = yes'
          act systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
        fi
      fi
      ;;
    zypper) act zypper --non-interactive refresh; act zypper --non-interactive patch ;;
    pacman) act pacman -Sy; [[ $AGGRESSIVE -eq 1 ]] && act pacman -Su --noconfirm ;;
  esac

  # automatic security updates (apt) -- write BOTH 20auto-upgrades AND 10periodic,
  # and ensure -security origins are active in 50unattended-upgrades.
  if [[ "$PKG" == "apt" ]]; then
    pkg_install unattended-upgrades 2>/dev/null
    if [[ -d /etc/apt/apt.conf.d ]]; then
      backup_file /etc/apt/apt.conf.d/20auto-upgrades
      backup_file /etc/apt/apt.conf.d/10periodic
      if [[ $DRY -eq 0 ]]; then
        cat >/etc/apt/apt.conf.d/20auto-upgrades <<'AU'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
AU
        chmod 644 /etc/apt/apt.conf.d/20auto-upgrades
        cp -f /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/10periodic
        chmod 644 /etc/apt/apt.conf.d/10periodic
        if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
          backup_file /etc/apt/apt.conf.d/50unattended-upgrades
          sed -i -E 's|^[[:space:]]*//[[:space:]]*("\$\{distro_id\}[: ]\$\{distro_codename\}-security";)|\t\1|; s|^[[:space:]]*//[[:space:]]*("origin=Debian,codename=\$\{distro_codename\}-security,label=Debian-Security";)|\t\1|' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
        fi
        ok "unattended-upgrades (20auto-upgrades + 10periodic + 50unattended-upgrades) configured"
      else
        say "[dry-run] write 20auto-upgrades + 10periodic + tune 50unattended-upgrades"
      fi
      finding "PKG-AUTO" "Updates" "PASS" "unattended-upgrades daily check + security auto-install enabled"
    fi
  fi

  # remove the insecure legacy daemons
  local purge="telnet telnetd telnetd-ssl inetutils-telnet inetutils-telnetd \
               rsh-server rsh-client rlogin rexec ypserv nis tftpd tftpd-hpa talk talkd \
               inetutils-talk inetutils-talkd finger fingerd xinetd openbsd-inetd inetutils-inetd"
  local present="" p
  for p in $purge; do pkg_has "$p" 2>/dev/null && present="$present $p"; done
  if [[ -n "$present" ]]; then
    finding "PKG-INSECURE" "Software" "FAIL" "insecure daemons installed:$present" \
      "Remove them. they are almost always scored, and they almost never are a legitimate critical service."
    pkg_remove $present
  else
    finding "PKG-INSECURE" "Software" "PASS" "no legacy insecure daemons installed"
  fi

  # interactive purge helper for detected prohibited packages (from recon)
  if [[ -s "$EVID/72-prohibited-packages.txt" && -t 0 && $DRY -eq 0 ]]; then
    local bad_list
    bad_list="$(tr '\n' ' ' <"$EVID/72-prohibited-packages.txt")"
    if [[ -n "${bad_list// /}" ]]; then
      warn "prohibited software detected during recon: $bad_list"
      if ask "Interactively review & purge these detected packages one-by-one?"; then
        local bp
        while IFS= read -r bp; do
          [[ -z "$bp" ]] && continue
          if ask "  Purge package '$bp'?"; then
            case "$PKG" in
              apt)    DEBIAN_FRONTEND=noninteractive apt-get purge -y "$bp" >/dev/null 2>&1 && ok "purged $bp" ;;
              dnf)    dnf remove -y "$bp" >/dev/null 2>&1 && ok "removed $bp" ;;
              yum)    yum remove -y "$bp" >/dev/null 2>&1 && ok "removed $bp" ;;
              zypper) zypper --non-interactive remove "$bp" >/dev/null 2>&1 && ok "removed $bp" ;;
              pacman) pacman -Rns --noconfirm "$bp" >/dev/null 2>&1 && ok "removed $bp" ;;
            esac
            change "pkg:$bp" "installed" "purged"
          fi
        done <"$EVID/72-prohibited-packages.txt"
      fi
    fi
  fi
}

# ---------------------------------------------------------------------------
# SYSCTL
# ---------------------------------------------------------------------------
do_sysctl() {
  banner "KERNEL PARAMETERS (sysctl)"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: sysctl untouched"; return; }

  local f=/etc/sysctl.d/99-cyberpatriot.conf
  local fz=/etc/sysctl.d/99-zzz-cyberpatriot.conf
  [[ $DRY -eq 0 ]] && mkdir -p /etc/sysctl.d
  [[ -f /etc/sysctl.conf ]] && backup_file /etc/sysctl.conf

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
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.dad_transmits = 0
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
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
    # also mirror into 99-zzz-cyberpatriot.conf so Ubuntu/Debian's 99-sysctl.conf -> /etc/sysctl.conf cannot override us
    cp -f "$f" "$fz" && chmod 644 "$fz"
    # and sync top scored keys directly into /etc/sysctl.conf so file-grepping scorers also pass
    if [[ -f /etc/sysctl.conf ]]; then
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' 'net.ipv4.ip_forward = 0'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=' 'net.ipv4.tcp_syncookies = 1'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.tcp_rfc1337[[:space:]]*=' 'net.ipv4.tcp_rfc1337 = 1'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.conf\.all\.rp_filter[[:space:]]*=' 'net.ipv4.conf.all.rp_filter = 1'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.conf\.all\.accept_redirects[[:space:]]*=' 'net.ipv4.conf.all.accept_redirects = 0'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.conf\.all\.send_redirects[[:space:]]*=' 'net.ipv4.conf.all.send_redirects = 0'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.conf\.all\.accept_source_route[[:space:]]*=' 'net.ipv4.conf.all.accept_source_route = 0'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*net\.ipv4\.icmp_echo_ignore_broadcasts[[:space:]]*=' 'net.ipv4.icmp_echo_ignore_broadcasts = 1'
      ensure_line /etc/sysctl.conf '^[[:space:]]*#?[[:space:]]*kernel\.randomize_va_space[[:space:]]*=' 'kernel.randomize_va_space = 2'
    fi
    ok "wrote $f and $fz"
  else
    say "[dry-run] write $f and $fz"
  fi

  # /etc/host.conf anti-spoof
  if [[ -f /etc/host.conf ]]; then
    ensure_line /etc/host.conf '^[[:space:]]*#?[[:space:]]*nospoof[[:space:]]' 'nospoof on'
  fi

  # IP forwarding: if this box is meant to be a router (README), do not kill it
  if grep -qiE 'router|routing|gateway' /etc/sysctl.conf 2>/dev/null; then
    warn "/etc/sysctl.conf already mentions routing -- verify ip_forward=0 is correct for this image"
  fi

  if command -v sysctl >/dev/null 2>&1; then
    act sysctl --system
  else
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
    v="${v#=}"; v="$(echo "$v" | tr -d ' ')"
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
    printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' >/etc/systemd/coredump.conf.d/99-cp.conf 2>/dev/null
    chmod 644 /etc/systemd/coredump.conf.d/99-cp.conf 2>/dev/null
  fi

  finding "SYSCTL" "Kernel" "PASS" "99-cyberpatriot.conf applied"
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
  finding "PERM-IDENTITY" "Permissions" "PASS" "passwd 644, group 644, shadow 640 root:shadow"

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
  finding "PERM-SUDOERS" "Permissions" "PASS" "sudoers 440"

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
  finding "PERM-SSH" "Permissions" "PASS" "sshd_config 600, host keys 600"

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
    rm -f /etc/cron.deny /etc/at.deny 2>/dev/null && ok "  removed cron.deny/at.deny (allow-lists are safer)"
    if [[ ! -f /etc/cron.allow ]]; then
      printf 'root\n' >/etc/cron.allow; chmod 640 /etc/cron.allow; chown root:root /etc/cron.allow
      ok "  created /etc/cron.allow (root only)"
    fi
    if [[ ! -f /etc/at.allow ]]; then
      printf 'root\n' >/etc/at.allow; chmod 640 /etc/at.allow; chown root:root /etc/at.allow
    fi
  else
    say "[dry-run] cron.allow / at.allow"
  fi
  finding "PERM-CRON" "Permissions" "PASS" "cron dirs 750, crontab 644, allow-lists in place"

  # boot
  if [[ $DRY -eq 0 ]]; then
    [[ -d /boot ]] && { chmod 700 /boot 2>/dev/null; find /boot -type f -exec chmod 600 {} \; 2>/dev/null; chown -R root:root /boot 2>/dev/null; }
  fi
  setperm /boot/grub/grub.cfg 600 root root
  setperm /boot/grub2/grub.cfg 600 root root
  setperm /etc/grub.conf 600 root root
  finding "PERM-BOOT" "Permissions" "PASS" "/boot locked to 700/600"

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
  setperm /etc/securetty 600 root root
  setperm /etc/host.conf 644 root root
  setperm /var/log/wtmp 664 root utmp
  setperm /var/log/btmp 660 root utmp
  setperm /var/log/lastlog 664 root utmp
  [[ $DRY -eq 0 ]] && chmod 755 /etc 2>/dev/null
  finding "PERM-MISC" "Permissions" "PASS" "core config files normalized"

  # log directory
  if [[ -d /var/log && $DRY -eq 0 ]]; then
    chmod 755 /var/log; find /var/log -maxdepth 1 -type f -exec chmod 640 {} \; 2>/dev/null
  fi
  [[ -d /var/log/journal ]] && [[ $DRY -eq 0 ]] && chmod 2755 /var/log/journal 2>/dev/null

  # home dirs
  local name _ uid _ _ home shell
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
  done < <(getent passwd)
  finding "PERM-HOME" "Permissions" "PASS" "home dirs 750, .ssh 700, private keys 600"

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
      case "$d" in /tmp|/var/tmp|/dev/shm) chmod 1777 "$d" 2>/dev/null ;; *) chmod o-w "$d" 2>/dev/null ;; esac
    done < <(find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -500)
    chmod 1777 /tmp /var/tmp /dev/shm 2>/dev/null
  else
    say "[dry-run] world-writable sweep"
  fi
  finding "PERM-TMP" "Permissions" "PASS" "/tmp,/var/tmp,/dev/shm = 1777"

  # dangerous SUID: single-pass find matched against dangerous binaries
  local strip="nmap vim vim.basic vim.tiny vi nano emacs less more man gdb python python2 python2.7 python3 python3.9 python3.10 python3.11 perl ruby php php-cgi lua \
               socat nc nc.openbsd ncat netcat tcpdump strace ltrace find awk gawk mawk sed cp mv dd tar zip unzip gzip rsync scp ssh bash sh dash zsh ksh"
  local strip_rx="^($(echo "$strip" | tr -s ' ' '|'))$"
  local p removed=0
  if [[ $DRY -eq 0 ]]; then
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      if [[ "$(basename "$p")" =~ $strip_rx ]]; then
        chmod u-s "$p" 2>/dev/null && { removed=$((removed+1)); change "suid:$p" "4755" "0755"; warn "  stripped SUID: $p"; }
      fi
    done < <(find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path "$EVID" -o -path "$BKROOT" \) -prune -o -type f -perm -4000 -print 2>/dev/null)
  else
    say "[dry-run] single-pass SUID strip on dangerous binaries"
  fi
  (( removed > 0 )) && finding "PERM-SUID-STRIP" "Permissions" "PASS" "stripped SUID from $removed dangerous binary(ies)" \
                    || finding "PERM-SUID-STRIP" "Permissions" "PASS" "no dangerous SUID binaries found"

  # unowned (single pass)
  local uo_tmp; uo_tmp="$(mktemp)"
  find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -500 >"$uo_tmp"
  local uo; uo="$(wc -l <"$uo_tmp")"
  if (( uo > 0 )) && [[ $DRY -eq 0 ]]; then
    tr '\n' '\0' <"$uo_tmp" | xargs -0 -r chown root:root 2>/dev/null
    finding "PERM-UNOWNED-FIX" "Permissions" "PASS" "chowned $uo unowned file(s) to root:root"
  fi
  rm -f "$uo_tmp"

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
    [[ $DRY -eq 0 ]] && mkdir -p /etc/audit/rules.d
    [[ -f /etc/audit/auditd.conf ]] && backup_file /etc/audit/auditd.conf
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
    # -e 2 (immutable) is intentional, but it also means a re-run cannot
    # load updated rules until reboot. unlock just for the load; the rules
    # file ends with -e 2 and re-locks.
    if [[ $DRY -eq 0 ]] && command -v auditctl >/dev/null 2>&1; then
      auditctl -e 1 >/dev/null 2>&1 || true
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
  else
    finding "AUDIT-INSTALLED" "Audit" "FAIL" "auditd not installed" \
      "Install auditd. audit policy + rules are worth several points and auditd is the only way to get them."
  fi

  # ---- rsyslog ----
  step "rsyslog"
  if [[ -f /etc/rsyslog.conf ]]; then
    backup_file /etc/rsyslog.conf
    ensure_line /etc/rsyslog.conf '^[[:space:]]*\$FileCreateMode' '$FileCreateMode 0640'
    ensure_line /etc/rsyslog.conf '^[[:space:]]*\$UMASK'          '$UMASK 0027'
    grep -q 'authpriv' /etc/rsyslog.conf || { [[ $DRY -eq 0 ]] && printf 'auth,authpriv.*\t\t\t/var/log/auth.log\n' >>/etc/rsyslog.conf; }
    ok "rsyslog.conf tuned"
    finding "LOG-RSYSLOG" "Logging" "PASS" "FileCreateMode 0640, UMASK 0027"
    finding "LOG-REMOTE" "Logging" "INFO" "no remote syslog target configured" \
      "If the README names a log server, add: *.* @@loghost:514  to /etc/rsyslog.conf and restart. centralized logging is a common scored item."
    act systemctl restart rsyslog || act service rsyslog restart
  fi

  # journald: persist to disk
  if [[ -d /etc/systemd/journald.conf.d || -f /etc/systemd/journald.conf ]]; then
    if [[ $DRY -eq 0 ]]; then
      mkdir -p /etc/systemd/journald.conf.d
      backup_file /etc/systemd/journald.conf
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
    ok "journald set to persistent storage"
    finding "LOG-JOURNALD" "Logging" "PASS" "journald persistent, 2G cap, forwarded to syslog"
  fi

  # do NOT clear any log. ever.
  finding "LOG-INTACT" "Logging" "PASS" "no logs were cleared or truncated" \
    "Never run > /var/log/* or logrotate -f on a scored image. cleared logs look like the attacker covering tracks and can destroy forensic answers."

  # bash history: keep it, make it richer, do not disable it
  if [[ -f /etc/profile ]]; then
    if ! grep -q 'cbptlinux history' /etc/profile; then
      if [[ $DRY -eq 0 ]]; then
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
      ok "shell history now timestamped"
      finding "LOG-HIST" "Logging" "PASS" "HISTTIMEFORMAT set, histappend on"
    fi
  fi
}
# ---------------------------------------------------------------------------
# INSTALLED SERVER APPS -- config only, never their data directories
# ---------------------------------------------------------------------------
do_apps() {
  banner "INSTALLED SERVICES"
  [[ $PARANOID -eq 1 ]] && { warn "paranoid: app configs untouched"; return; }

  # ---- Apache ----
  local conf sec d
  for conf in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
    [[ -f "$conf" ]] || continue
    step "apache: $conf"
    backup_file "$conf"
    d="$(dirname "$conf")"
    sec=""
    [[ -d /etc/apache2/conf-available ]] && sec=/etc/apache2/conf-available/security-hardening.conf
    [[ -d /etc/httpd/conf.d ]] && sec=/etc/httpd/conf.d/security-hardening.conf
    if [[ -n "$sec" ]]; then
      if [[ $DRY -eq 0 ]]; then
        # Header directives below need mod_headers; stock Ubuntu ships it
        # available but not always enabled.
        command -v a2enmod >/dev/null 2>&1 && a2enmod headers >/dev/null 2>&1
        cat >"$sec" <<'APSEC'
# cbptlinux.sh
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
Header unset X-Powered-By
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
<Directory />
    Options -Indexes -FollowSymLinks -Includes -ExecCGI
    AllowOverride None
    Require all denied
</Directory>
<DirectoryMatch "/\.(git|svn|hg|env)">
    Require all denied
</DirectoryMatch>
LimitRequestBody 10485760
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
APSEC
        chmod 644 "$sec"
        [[ -d /etc/apache2/conf-enabled ]] && ln -sf "$sec" /etc/apache2/conf-enabled/security-hardening.conf 2>/dev/null
        # strip Options Indexes from any vhost/dir that still has it. anchor on
        # the directive itself: matching every "Options " also rewrites header
        # names (X-Content-Type-Options) and leaves mixed +/- option lists that
        # apache2ctl rejects.
        grep -RlE '^[[:space:]]*Options[[:space:]].*Indexes' /etc/apache2 /etc/httpd 2>/dev/null | \
          grep -vF -e "$sec" -e "/etc/apache2/conf-enabled/security-hardening.conf" | while read -r f; do
          backup_file "$f"
          sed -i -E '/^[[:space:]]*Options[[:space:]]/{
            s/(^|[[:space:]])[+-]?Indexes([[:space:]]|$)/\1/g
            s/^([[:space:]]*Options)[[:space:]]*$/\1 -Indexes/
          }' "$f" 2>/dev/null
          change "$f" "Options Indexes" "Options -Indexes"
        done
      else
        say "[dry-run] apache hardening drop-in"
      fi
      ok "apache: ServerTokens Prod, ServerSignature Off, TraceEnable Off, -Indexes"
      finding "APP-APACHE-SSL" "Apps" "INFO" "manual: verify TLS config" \
        "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1, SSLHonorCipherOrder on, HSTS header. check every vhost, not just the default."
      # restart and VERIFY -- an unapplied config is worth zero
      if apache2ctl configtest >/dev/null 2>&1 || apachectl configtest >/dev/null 2>&1; then
        act systemctl reload apache2 || act systemctl reload httpd
        ok "apache reloaded (configtest passed)"
        finding "APP-APACHE" "Apps" "PASS" "apache hardened via $sec"
      else
        err "apache configtest FAILED -- rolling back $sec"
        apache2ctl configtest 2>&1 || apachectl configtest 2>&1
        [[ $DRY -eq 0 ]] && { rm -f "$sec" /etc/apache2/conf-enabled/security-hardening.conf; }
        finding "APP-APACHE" "Apps" "FAIL" "apache config rejected, rolled back"
      fi
    else
      ensure_line "$conf" '^[[:space:]]*ServerTokens'    'ServerTokens Prod'
      ensure_line "$conf" '^[[:space:]]*ServerSignature' 'ServerSignature Off'
      ensure_line "$conf" '^[[:space:]]*TraceEnable'     'TraceEnable Off'
      finding "APP-APACHE" "Apps" "PASS" "apache hardened in $conf"
    fi
  done

  # ---- nginx ----
  if [[ -f /etc/nginx/nginx.conf ]]; then
    step "nginx"
    backup_file /etc/nginx/nginx.conf
    ensure_line /etc/nginx/nginx.conf '^[[:space:]]*#?[[:space:]]*server_tokens' '    server_tokens off;'
    # stock Ubuntu already has these in the http block; replacing them there
    # avoids a duplicate-directive fatal in the drop-in.
    if grep -qE '^[[:space:]]*ssl_protocols' /etc/nginx/nginx.conf 2>/dev/null; then
      ensure_line /etc/nginx/nginx.conf '^[[:space:]]*#?[[:space:]]*ssl_protocols' '    ssl_protocols TLSv1.2 TLSv1.3;'
    fi
    if grep -qE '^[[:space:]]*ssl_prefer_server_ciphers' /etc/nginx/nginx.conf 2>/dev/null; then
      ensure_line /etc/nginx/nginx.conf '^[[:space:]]*#?[[:space:]]*ssl_prefer_server_ciphers' '    ssl_prefer_server_ciphers on;'
    fi
    if [[ $DRY -eq 0 ]]; then
      mkdir -p /etc/nginx/conf.d
      cat >/etc/nginx/conf.d/99-cbptlinux.conf <<'NGX'
# cbptlinux.sh
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
client_max_body_size 10m;
client_body_timeout 10s;
client_header_timeout 10s;
send_timeout 10s;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
NGX
      grep -qE '^[[:space:]]*ssl_protocols' /etc/nginx/nginx.conf 2>/dev/null || \
        printf 'ssl_protocols TLSv1.2 TLSv1.3;\n' >>/etc/nginx/conf.d/99-cbptlinux.conf
      grep -qE '^[[:space:]]*ssl_prefer_server_ciphers' /etc/nginx/nginx.conf 2>/dev/null || \
        printf 'ssl_prefer_server_ciphers on;\n' >>/etc/nginx/conf.d/99-cbptlinux.conf
      grep -Rl 'autoindex on' /etc/nginx 2>/dev/null | while read -r f; do
        sed -i 's/autoindex on/autoindex off/g' "$f"; change "$f" "autoindex on" "autoindex off"
      done
    else
      say "[dry-run] nginx hardening drop-in"
    fi
    if nginx -t >/dev/null 2>&1; then
      act systemctl reload nginx && ok "nginx reloaded"
      finding "APP-NGINX" "Apps" "PASS" "nginx: tokens off, autoindex off, security headers, TLS1.2+"
    else
      err "nginx -t failed, removing drop-in"; nginx -t
      [[ $DRY -eq 0 ]] && rm -f /etc/nginx/conf.d/99-cbptlinux.conf
      finding "APP-NGINX" "Apps" "FAIL" "nginx config rejected, rolled back"
    fi
  fi

  # ---- MySQL / MariaDB ----
  local mycnf="" c drop=""
  for c in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf /etc/my.cnf.d/mariadb-server.cnf; do
    [[ -f "$c" ]] && mycnf="$mycnf $c"
  done
  if [[ -n "$mycnf" ]]; then
    step "mysql"
    for c in $mycnf; do backup_file "$c"; done
    [[ -d /etc/mysql/conf.d ]] && drop=/etc/mysql/conf.d/99-cbptlinux.cnf
    [[ -z "$drop" && -d /etc/my.cnf.d ]] && drop=/etc/my.cnf.d/99-cbptlinux.cnf
    if [[ -n "$drop" ]]; then
      if [[ $DRY -eq 0 ]]; then
        cat >"$drop" <<'MY'
# cbptlinux.sh
[mysqld]
bind-address = 127.0.0.1
local-infile = 0
skip-symbolic-links = 1
secure-file-priv = /var/lib/mysql-files
sql_mode = STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION
log-error = /var/log/mysql/error.log
# remove these only if the README says remote DB access is a business need:
# skip-networking
MY
        chmod 644 "$drop"
      else
        say "[dry-run] write $drop"
      fi
      ok "wrote $drop"
      finding "APP-MYSQL" "Apps" "PASS" "mysql: bind 127.0.0.1, local-infile off, no symlinks"
      finding "APP-MYSQL-DB" "Apps" "INFO" "manual SQL work required" \
        "mysql -u root -p -e \"SELECT user,host,plugin FROM mysql.user;\" -- remove anonymous ('') users, remove root@'%', drop the 'test' database, run mysql_secure_installation."
    else
      for c in $mycnf; do
        grep -q '^\s*local-infile' "$c" || { [[ $DRY -eq 0 ]] && sed -i '/^\[mysqld\]/a local-infile = 0\nskip-symbolic-links = 1' "$c"; }
        ensure_line "$c" '^[[:space:]]*bind-address' 'bind-address = 127.0.0.1'
      done
      finding "APP-MYSQL" "Apps" "PASS" "mysql: local-infile off, bind 127.0.0.1 (edited in place)"
    fi
    # restart carefully -- if it fails, say so loudly
    if [[ $DRY -eq 0 ]]; then
      if systemctl restart mysql >/dev/null 2>&1 || systemctl restart mysqld >/dev/null 2>&1 || systemctl restart mariadb >/dev/null 2>&1; then
        sleep 2
        if ss -tlnH 2>/dev/null | grep -q ':3306'; then ok "mysql back up on 3306"; else
          err "mysql did not come back. check: journalctl -u mysql -n 50"
          finding "APP-MYSQL-RESTART" "Apps" "FAIL" "mysql failed to restart after config change" \
            "Restore from $BKDIR/files/ and restart. a dead critical service costs far more than the hardening gained."
        fi
      fi
    fi
  fi

  # ---- PostgreSQL ----
  if [[ -d /etc/postgresql ]] || [[ -f /var/lib/pgsql/data/postgresql.conf ]]; then
    step "postgresql"
    local pgconf pghba
    pgconf="$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1)"
    pghba="$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)"
    [[ -z "$pgconf" && -f /var/lib/pgsql/data/postgresql.conf ]] && pgconf=/var/lib/pgsql/data/postgresql.conf
    [[ -z "$pghba" && -f /var/lib/pgsql/data/pg_hba.conf ]] && pghba=/var/lib/pgsql/data/pg_hba.conf
    [[ -n "$pgconf" ]] && { backup_file "$pgconf"
      ensure_line "$pgconf" "^[[:space:]]*#?[[:space:]]*listen_addresses" "listen_addresses = 'localhost'"
      ensure_line "$pgconf" "^[[:space:]]*#?[[:space:]]*log_connections" "log_connections = on"
      ensure_line "$pgconf" "^[[:space:]]*#?[[:space:]]*log_disconnections" "log_disconnections = on"
      ensure_line "$pgconf" "^[[:space:]]*#?[[:space:]]*log_statement" "log_statement = 'ddl'"
      finding "APP-PG" "Apps" "PASS" "postgres: listen localhost, connection logging on"; }
    if [[ -n "$pghba" ]]; then
      backup_file "$pghba"
      if grep -qE '^\s*(host|local)\s+all\s+all\s+(0\.0\.0\.0/0|::/0|all)\s+trust' "$pghba"; then
        finding "APP-PG-HBA" "Apps" "FAIL" "pg_hba.conf has a 'trust' entry" \
          "trust = no password. change it to scram-sha-256 and restart postgres."
        act sed -i -E 's/^(\s*(host|local)\s+all\s+all\s+(0\.0\.0\.0\/0|::\/0|all)\s+)trust/\1scram-sha-256/' "$pghba"
      else
        finding "APP-PG-HBA" "Apps" "PASS" "no trust auth in pg_hba.conf"
      fi
    fi
    act systemctl reload postgresql
  fi

  # ---- BIND ----
  local nc
  for nc in /etc/bind/named.conf.options /etc/named.conf; do
    [[ -f "$nc" ]] || continue
    step "bind"
    backup_file "$nc"
    local nb
    nb="$BKDIR/files/$(echo "${nc#/}" | tr '/' '_')"
    if [[ $DRY -eq 0 ]]; then
      # named.conf.options is a block; appending these at EOF (the old
      # ensure_line behaviour) makes named-checkconf reject the file. drop
      # any lines a previous run appended there, then insert inside "options {".
      sed -i -E '/^[[:space:]]*version[[:space:]]+"none"[[:space:]]*;?[[:space:]]*$/d; /^[[:space:]]*allow-transfer[[:space:]]*\{[[:space:]]*none;[[:space:]]*\};?[[:space:]]*$/d; /^[[:space:]]*allow-recursion[[:space:]]*\{[[:space:]]*(trusted|localhost)[^}]*\};?[[:space:]]*$/d' "$nc"
      grep -qE '^[[:space:]]*version[[:space:]]+"none"' "$nc" || \
        sed -i '0,/^[[:space:]]*options[[:space:]]*{/s//&\n    version "none";/' "$nc"
      grep -qE '^[[:space:]]*allow-transfer' "$nc" || \
        sed -i '0,/^[[:space:]]*options[[:space:]]*{/s//&\n    allow-transfer { none; };/' "$nc"
      grep -qE '^[[:space:]]*allow-recursion' "$nc" || \
        sed -i '0,/^[[:space:]]*options[[:space:]]*{/s//&\n    allow-recursion { localhost; localnets; };/' "$nc"
    else
      say "[dry-run] bind hardening"
    fi
    if named-checkconf >/dev/null 2>&1; then
      finding "APP-BIND" "Apps" "PASS" "bind: version hidden, transfers denied, recursion restricted"
      finding "APP-BIND-ACL" "Apps" "INFO" "manual: replace the built-in recursion ACL if a LAN needs it" \
        "allow-recursion is localhost+localnets. For a LAN resolver, add acl trusted { 10.0.0.0/8; 192.168.0.0/16; }; at the top of named.conf and use allow-recursion { trusted; };."
      act systemctl reload bind9 || act systemctl reload named
      ok "bind reloaded"
    else
      err "named-checkconf FAILED -- restoring $nc"
      named-checkconf 2>&1 | head -5
      [[ $DRY -eq 0 ]] && cp -a "$nb" "$nc" 2>/dev/null
      finding "APP-BIND" "Apps" "FAIL" "bind config rejected, restored" \
        "Re-run named-checkconf. If the error is in an included zone, fix that file; do not leave an options block outside its braces."
    fi
  done

  # ---- vsftpd ----
  local fc
  for fc in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [[ -f "$fc" ]] || continue
    step "vsftpd"
    backup_file "$fc"
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*anonymous_enable'   'anonymous_enable=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*anon_upload_enable' 'anon_upload_enable=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*local_enable'       'local_enable=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*chroot_local_user'   'chroot_local_user=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*allow_writeable_chroot' 'allow_writeable_chroot=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*ssl_enable'         'ssl_enable=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*allow_anon_ssl'     'allow_anon_ssl=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*force_local_data_ssl' 'force_local_data_ssl=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*force_local_logins_ssl' 'force_local_logins_ssl=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*xferlog_enable'      'xferlog_enable=YES'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*ls_recurse_enable'   'ls_recurse_enable=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*ascii_upload_enable' 'ascii_upload_enable=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*ascii_download_enable' 'ascii_download_enable=NO'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*idle_session_timeout' 'idle_session_timeout=600'
    ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*banner_file'         'banner_file=/etc/issue.net'
    if [[ -t 0 && $DRY -eq 0 ]] && ask "vsftpd: Does the README require local FTP users to log in as anonymous/guest (guest_enable=YES)?"; then
      ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*guest_enable'   'guest_enable=YES'
      ensure_line "$fc" '^[[:space:]]*#?[[:space:]]*guest_username' 'guest_username=ftp'
      finding "APP-FTP-GUEST" "Apps" "PASS" "vsftpd: guest_enable=YES, guest_username=ftp"
    else
      finding "APP-FTP-GUEST" "Apps" "INFO" "vsftpd guest_enable left as-is" \
        "If the scoring/README asks that 'FTP local users must log in as anonymous', add guest_enable=YES and guest_username=ftp to $fc and restart vsftpd."
    fi
    finding "APP-FTP" "Apps" "PASS" "vsftpd: anon off, chroot, TLS forced, logging on"
    act systemctl restart vsftpd
  done

  # ---- Squid / Dovecot presence hints ----
  [[ -f /etc/squid/squid.conf || -f /etc/squid3/squid.conf ]] && \
    finding "APP-SQUID" "Apps" "WARN" "Squid proxy config found" \
      "Squid proxy is frequently an unauthorized service. Stop+disable+purge squid unless required by README."
  [[ -d /etc/dovecot ]] && \
    finding "APP-DOVECOT" "Apps" "WARN" "Dovecot mail/POP3/IMAP config found" \
      "POP3/IMAP is frequently an unauthorized service. Stop+disable+purge dovecot unless required by README."

  # ---- Samba ----
  local sc=/etc/samba/smb.conf
  if [[ -f "$sc" ]]; then
    step "samba"
    backup_file "$sc"
    local sb
    sb="$BKDIR/files/$(echo "${sc#/}" | tr '/' '_')"
    if [[ $DRY -eq 0 ]]; then
      # these are [global] parameters. ensure_line appends at EOF, which is
      # the last share ([print$]) on the stock Debian/Ubuntu file, so
      # testparm warns and Samba ignores them.
      sed -i -E '/^[[:space:]]*(server min protocol|client min protocol|server signing|restrict anonymous|map to guest)[[:space:]]*=/d' "$sc"
      for l in '   server min protocol = SMB2_10' '   client min protocol = SMB2_10' \
               '   server signing = mandatory' '   restrict anonymous = 2' '   map to guest = Never'; do
        sed -i "/^\[global\]/a\\$l" "$sc"
      done
    else
      say "[dry-run] samba global hardening"
    fi
    if grep -qE '^\s*guest ok\s*=\s*yes' "$sc"; then
      finding "APP-SAMBA-GUEST" "Apps" "FAIL" "a share has guest ok = yes" \
        "Anonymous/guest SMB shares are almost always scored. set guest ok = no and give each user a smbpasswd."
    else
      finding "APP-SAMBA-GUEST" "Apps" "PASS" "no guest shares"
    fi
    if testparm -s >/dev/null 2>&1 && ! testparm -s 2>&1 | grep -q 'found in service section'; then
      act systemctl reload smbd
      ok "samba reloaded"
      finding "APP-SAMBA" "Apps" "PASS" "samba: SMB2+, mandatory signing, anon restricted"
    else
      err "testparm FAILED -- restoring $sc"
      testparm -s 2>&1 | head -5
      [[ $DRY -eq 0 ]] && cp -a "$sb" "$sc" 2>/dev/null
      finding "APP-SAMBA" "Apps" "FAIL" "samba config rejected, restored" \
        "testparm -s. Global parameters must be above the first share header."
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
    finding "APP-MAIL" "Apps" "PASS" "postfix: VRFY off, HELO required, TLS on, banner trimmed"
    postfix check >/dev/null 2>&1 && act systemctl reload postfix && ok "postfix reloaded"
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
    finding "APP-WP" "Apps" "PASS" "wp-config.php perms 640"
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
    finding "APP-PHP" "Apps" "PASS" "php.ini: expose_php off, errors off, url_include off, dangerous funcs disabled"
    warn "php: disable_functions can break a legit web app. if the README needs it, trim the list."
  done
  if [[ $DRY -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
    local phpsvc
    while read -r phpsvc; do
      [[ -n "$phpsvc" ]] && act systemctl reload "$phpsvc"
    done < <(systemctl list-units --type=service --plain --no-legend 'php*-fpm.service' 2>/dev/null | awk '{print $1}')
  fi

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

  # identity perms (no looser than target mode, so RHEL 000 shadow also passes)
  local f want got
  while read -r f want; do
    [[ -e "$f" ]] || continue
    got="$(stat -c '%a' "$f" 2>/dev/null)"
    if [[ "$got" =~ ^[0-7]{3,4}$ ]] && (( (8#${got: -3} & ~8#$want) == 0 )); then
      finding "VER-PERM-$(basename "$f")" "Verify" "PASS" "$f = $got (<= $want)"
    else
      finding "VER-PERM-$(basename "$f")" "Verify" "FAIL" "$f = $got, want no looser than $want"
    fi
  done < <(printf '%s\n' "/etc/passwd 644" "/etc/group 644" "/etc/shadow 640" "/etc/gshadow 640" \
                         "/etc/sudoers 440" "/etc/ssh/sshd_config 600" "/etc/crontab 644")

  # uid0 / empty pw / privileged primary GID / nopasswdlogin
  local u0 ep npw
  u0="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | tr '\n' ' ')"
  [[ -z "$u0" ]] && finding "VER-UID0" "Verify" "PASS" "no extra UID 0" || finding "VER-UID0" "Verify" "FAIL" "extra UID0: $u0"
  ep="$(awk -F: '($2==""){print $1}' /etc/shadow | tr '\n' ' ')"
  [[ -z "$ep" ]] && finding "VER-NOPASS" "Verify" "PASS" "no empty passwords" || finding "VER-NOPASS" "Verify" "FAIL" "empty passwords: $ep"
  npw="$(getent group nopasswdlogin 2>/dev/null | cut -d: -f4)"
  [[ -z "$npw" ]] && finding "VER-NOPASSWDLOGIN" "Verify" "PASS" "nopasswdlogin group empty" \
                  || finding "VER-NOPASSWDLOGIN" "Verify" "FAIL" "nopasswdlogin has members: $npw"

  # login.defs
  local kv k v
  for kv in "PASS_MAX_DAYS 90" "PASS_MIN_DAYS 1" "PASS_MIN_LEN 14" "PASS_WARN_AGE 14" "UMASK 027" "ENCRYPT_METHOD SHA512"; do
    k="${kv%% *}"; v="${kv##* }"
    got="$(grep -E "^\s*${k}\b" /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)"
    [[ "$got" == "$v" ]] && finding "VER-$k" "Verify" "PASS" "$k=$got" \
                        || finding "VER-$k" "Verify" "FAIL" "$k=$got (want $v)"
  done

  # pwquality + PAM checks (nullok, lockout, password history)
  if [[ -f /etc/security/pwquality.conf ]]; then
    local ml; ml="$(grep -E '^\s*minlen' /etc/security/pwquality.conf | awk '{print $3}')"
    [[ "$ml" -ge 14 ]] 2>/dev/null && finding "VER-PWQ" "Verify" "PASS" "pwquality minlen=$ml" \
                                   || finding "VER-PWQ" "Verify" "FAIL" "pwquality minlen=$ml"
  fi
  if grep -REq 'nullok(_secure)?' /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
    finding "VER-PAM-NULLOK" "Verify" "FAIL" "nullok still present in PAM stack"
  else
    finding "VER-PAM-NULLOK" "Verify" "PASS" "no nullok in PAM auth/password stacks"
  fi
  if grep -REq 'pam_(faillock|tally2)\.so' /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
    finding "VER-PAM-LOCKOUT" "Verify" "PASS" "PAM account lockout configured"
  else
    finding "VER-PAM-LOCKOUT" "Verify" "FAIL" "no pam_faillock/pam_tally2 in PAM auth stack"
  fi
  if grep -REq '(pam_pwhistory\.so|pam_unix\.so.*remember=)' /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
    finding "VER-PAM-HIST" "Verify" "PASS" "PAM password history configured"
  else
    finding "VER-PAM-HIST" "Verify" "FAIL" "no password history (remember=/pam_pwhistory) in PAM"
  fi

  # ssh -- read the EFFECTIVE config, not the file
  if command -v sshd >/dev/null 2>&1; then
    local t; t="$(sshd -T 2>/dev/null)"
    check_sshd() { local k="$1" want="$2"; local got; got="$(echo "$t" | awk -v k="$k" 'tolower($1)==k{print $2}')"
      if [[ "$got" == "$want" ]]; then finding "VER-SSH-$k" "Verify" "PASS" "$k=$got"
      else finding "VER-SSH-$k" "Verify" "FAIL" "$k=$got (want $want)"; fi; }
    check_sshd permitrootlogin no
    check_sshd permitemptypasswords no
    check_sshd x11forwarding no
    check_sshd maxauthtries 3
    check_sshd usepam yes
    check_sshd permituserenvironment no
    check_sshd ignorerhosts yes
    check_sshd hostbasedauthentication no
    local c; c="$(echo "$t" | awk 'tolower($1)=="ciphers"{print $2}')"
    if echo "$c" | grep -qE '3des|arcfour|cbc'; then
      finding "VER-SSH-CIPHERS" "Verify" "FAIL" "weak cipher still offered: $c"
    else
      finding "VER-SSH-CIPHERS" "Verify" "PASS" "ciphers OK"
    fi
    sshd -t >/dev/null 2>&1 && finding "VER-SSH-VALID" "Verify" "PASS" "sshd_config parses" \
                             || finding "VER-SSH-VALID" "Verify" "FAIL" "sshd_config is INVALID"
  fi

  # sysctl spot checks
  for kv in "net.ipv4.ip_forward 0" "net.ipv4.conf.all.accept_redirects 0" "net.ipv4.conf.all.send_redirects 0" \
            "net.ipv4.conf.all.accept_source_route 0" "net.ipv4.conf.all.log_martians 1" "net.ipv4.conf.all.rp_filter 1" \
            "net.ipv4.tcp_syncookies 1" "net.ipv4.tcp_rfc1337 1" "net.ipv4.icmp_echo_ignore_broadcasts 1" \
            "net.ipv4.icmp_ignore_bogus_error_responses 1" "kernel.randomize_va_space 2" "kernel.dmesg_restrict 1" \
            "kernel.kptr_restrict 2" "fs.protected_symlinks 1" "fs.protected_hardlinks 1" "fs.suid_dumpable 0"; do
    local k="${kv%% *}"; local v="${kv##* }"
    local got; got="$(sysctl_get "$k")"
    if [[ -z "$got" ]]; then
      finding "VER-$k" "Verify" "WARN" "$k unreadable" "Key absent on this kernel, or sysctl/procps is not installed. check /proc/sys/$(echo "$k" | tr '.' '/')."
    elif [[ "$got" == "$v" ]]; then finding "VER-$k" "Verify" "PASS" "$k=$got"
    else finding "VER-$k" "Verify" "FAIL" "$k=$got (want $v)" "sysctl -w $k=$v  -- and confirm it is in /etc/sysctl.d/99-cyberpatriot.conf so it survives a reboot."; fi
  done
  if [[ -f /etc/host.conf ]]; then
    grep -Eq '^[[:space:]]*nospoof[[:space:]]+on' /etc/host.conf 2>/dev/null && \
      finding "VER-HOSTCONF" "Verify" "PASS" "/etc/host.conf nospoof on" || \
      finding "VER-HOSTCONF" "Verify" "FAIL" "/etc/host.conf missing nospoof on"
  fi

  # firewall
  local fwup=0
  command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active' && fwup=1
  systemctl is-active firewalld >/dev/null 2>&1 && fwup=1
  command -v iptables >/dev/null 2>&1 && [[ "$(iptables -S INPUT 2>/dev/null | head -1)" =~ DROP ]] && fwup=1
  if (( fwup )); then
    finding "VER-FW" "Verify" "PASS" "a firewall is active with a default-deny inbound policy"
  else
    finding "VER-FW" "Verify" "FAIL" "no active default-deny firewall detected" \
      "Run --module firewall. if you already did: confirm the critical-service ports from the README are explicitly allowed, then verify with 'ufw status' / 'firewall-cmd --list-all' / 'iptables -L -n'. an unapplied firewall scores zero."
  fi

  # umask: read the persisted setting, not this shell's inherited umask (the
  # script runs with 022 by design, so the old check always warned after a fix)
  local um; um="$(awk '/^[[:space:]]*UMASK[[:space:]]/{print $2}' /etc/login.defs 2>/dev/null | tail -1)"
  [[ -n "$um" ]] || um="$(umask)"
  [[ "$um" == "0027" || "$um" == "027" ]] && finding "VER-UMASK" "Verify" "PASS" "umask=$um" \
                                          || finding "VER-UMASK" "Verify" "WARN" "umask=$um (want 0027)" "new shells need to source /etc/profile. log out and back in."

  # auto-updates (apt)
  if [[ "$PKG" == "apt" ]]; then
    if grep -qE 'Update-Package-Lists\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/10periodic 2>/dev/null && \
       grep -qE 'Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/10periodic 2>/dev/null; then
      finding "VER-AUTOUPD" "Verify" "PASS" "APT daily update check + unattended security upgrades enabled"
    else
      finding "VER-AUTOUPD" "Verify" "FAIL" "APT daily auto-update / unattended-upgrade not enabled"
    fi
  fi

  # auditd & AppArmor & ctrl-alt-del
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
  if command -v aa-status >/dev/null 2>&1; then
    systemctl is-active apparmor >/dev/null 2>&1 && finding "VER-APPARMOR" "Verify" "PASS" "apparmor active" \
                                                 || finding "VER-APPARMOR" "Verify" "WARN" "apparmor not active"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    [[ "$(systemctl is-enabled ctrl-alt-del.target 2>/dev/null)" == "masked" ]] && \
      finding "VER-CAD" "Verify" "PASS" "ctrl-alt-del.target masked"
  fi

  # logging
  systemctl is-active rsyslog >/dev/null 2>&1 && finding "VER-RSYSLOG" "Verify" "PASS" "rsyslog active" \
                                              || finding "VER-RSYSLOG" "Verify" "WARN" "rsyslog not active"
  grep -q 'Storage=persistent' /etc/systemd/journald.conf.d/99-cp.conf 2>/dev/null && \
    finding "VER-JOURNALD" "Verify" "PASS" "journald persistent" || finding "VER-JOURNALD" "Verify" "WARN" "journald not persistent"

  # leftover risks
  [[ -s /etc/ld.so.preload ]] && finding "VER-PRELOAD" "Verify" "FAIL" "/etc/ld.so.preload still populated"
  [[ -f /etc/cron.deny ]] && finding "VER-CRONDENY" "Verify" "WARN" "/etc/cron.deny still exists" "remove it and use /etc/cron.allow."

  # anything still listening that shouldn't be
  local p
  while read -r laddr; do
    p="${laddr##*:}"
    case "$p" in
      23|21|69|110|111|512|513|514|995|3128|4444|5900|31337) finding "VER-PORT-$p" "Verify" "FAIL" "port $p still listening" "stop + mask the service, then confirm with ss -tulpn (ignore if README requires it)." ;;
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
   in /home (ls -laR), chattr anomalies, /etc/hosts entries. all of these
   add up.

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
# MENU
# ---------------------------------------------------------------------------
do_menu() {
  while true; do
    banner "cbptlinux.sh $VERSION  --  $(hostname)  (${PRETTY_NAME:-$DISTRO_ID})"
    printf '\n'
    printf '   %sr%s) recon + evidence dump      (read only)\n' "$C_WHT" "$C_RST"
    printf '   %sb%s) baseline snapshot\n' "$C_WHT" "$C_RST"
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
      A) if confirm "Run the full safe pass now? (backup, recon, users, passwords, ssh, firewall, services, packages, sysctl, perms, audit, apps, verify)"; then
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
  banner "DONE"
  warn "now go read the README again and answer the forensic questions."
  warn "then restart every critical service and confirm it is listening."
}

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
usage() {
  sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
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
    --help|-h)       usage ;;
    --version|-V)    echo "cbptlinux.sh $VERSION"; exit 0 ;;
    --restore)       RESTORE_FROM="${2:-}"; shift 2 ;;
    --module|-m)     MODULE="${2:-}"; PHASE="module"; shift 2 ;;
    --evid-dir)      EVID="${2:-$EVID}"; REVIEW="$EVID/needs-review.txt"; shift 2 ;;
    --backup-dir)    BKROOT="${2:-$BKROOT}"; BKDIR="$BKROOT/$STAMP"; shift 2 ;;
    *) err "unknown option: $1"; usage ;;
  esac
done

main() {
  mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null
  : >>"$LOGFILE" 2>/dev/null || LOGFILE="/tmp/cbptlinux-$STAMP.log"
  mkdir -p "$EVID" "$BKROOT"

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
        backup)    do_backup ;;
        *) err "unknown module: $MODULE"; exit 1 ;;
      esac
      do_report
      ;;
    *) do_menu ;;
  esac
}

main "$@"
