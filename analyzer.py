"""
SSH connection, remote command execution, parsing, and application
correlation for the EC2 Resource Analyzer.

Design: one SSH connection is opened per analysis run. Two remote bash
scripts are executed over that single connection:

  1. build_phase1_script() - collects CPU/memory/disk/process/systemd/docker/
     journal data plus extra detail (cmdline/exe/cwd) for a bounded set of
     "interesting" PIDs (top CPU, top memory, systemd MainPIDs, docker PIDs).
  2. phase2 script - once Python has correlated candidate application/log
     directories from phase 1's output, a second small script sizes just
     those directories (bounded, with per-command timeouts).

All correlation, application identification, and health/finding logic
happens in Python, not bash, to keep it testable and maintainable.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import paramiko

# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class AnalysisError(Exception):
    """Raised for any user-facing failure (connection, auth, parsing)."""

    def __init__(self, title: str, reason: str, hints: Optional[List[str]] = None):
        super().__init__(reason)
        self.title = title
        self.reason = reason
        self.hints = hints or []


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

FIXED_DIRS = ["/", "/var", "/var/log", "/var/lib/docker", "/home", "/opt", "/tmp"]

PSEUDO_FS_TYPES = {
    "tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup",
    "cgroup2", "devpts", "mqueue", "fuse.lxcfs", "binfmt_misc", "tracefs",
    "debugfs", "securityfs", "pstore", "bpf", "autofs", "efivarfs",
}

# CPU/memory/disk health thresholds (percent)
WARNING_THRESHOLD = 70.0
CRITICAL_THRESHOLD = 85.0

MAX_APPDIR_CANDIDATES = 25
MAX_LOGDIR_CANDIDATES = 25

DIRSIZE_TIMEOUT = 8
APPDIR_TIMEOUT = 10
LOGDIR_TIMEOUT = 10
FIND_MAXDEPTH_LOG = 3


# --------------------------------------------------------------------------
# Remote script (phase 1)
# --------------------------------------------------------------------------

_PHASE1_SCRIPT_TEMPLATE = r"""#!/bin/bash
section() { echo "===SECTION:$1==="; }

section HOSTINFO
hostname 2>/dev/null
uname -srm 2>/dev/null

section LOADAVG
cat /proc/loadavg 2>/dev/null

section CPUCOUNT
nproc 2>/dev/null

section CPUSAMPLE
grep '^cpu ' /proc/stat 2>/dev/null
sleep 0.4
grep '^cpu ' /proc/stat 2>/dev/null

section MEMINFO
cat /proc/meminfo 2>/dev/null

section DISKFS
df -kPT 2>/dev/null || df -kP 2>/dev/null

section DIRSIZES
# Kick off all 7 scans concurrently (process substitution starts each `du`
# immediately, buffered through an in-kernel pipe on a fixed fd - no temp
# files ever touch disk), then read results back below in a fixed order.
# Total wait is bounded by the single slowest scan, not their sum, which
# matters a lot here since each of these can independently take seconds.
if [ -d / ]; then exec 10< <(timeout __DIRSIZE_TIMEOUT__ du -xk --max-depth=1 / 2>/dev/null); fi
if [ -d /var ]; then exec 11< <(timeout __DIRSIZE_TIMEOUT__ du -xk --max-depth=1 /var 2>/dev/null); fi
if [ -d /var/log ]; then exec 12< <(timeout __DIRSIZE_TIMEOUT__ du -xk --max-depth=1 /var/log 2>/dev/null); fi
if [ -d /var/lib/docker ]; then exec 13< <(timeout __DIRSIZE_TIMEOUT__ du -xk --max-depth=1 /var/lib/docker 2>/dev/null); fi
if [ -d /home ]; then exec 14< <(timeout __DIRSIZE_TIMEOUT__ du -xk --max-depth=1 /home 2>/dev/null); fi
if [ -d /opt ]; then exec 15< <(timeout __DIRSIZE_TIMEOUT__ du -xk --max-depth=1 /opt 2>/dev/null); fi
if [ -d /tmp ]; then exec 16< <(timeout __DIRSIZE_TIMEOUT__ du -xk --max-depth=1 /tmp 2>/dev/null); fi
if [ -d / ]; then echo "@@DIR:/@@"; cat <&10; fi
if [ -d /var ]; then echo "@@DIR:/var@@"; cat <&11; fi
if [ -d /var/log ]; then echo "@@DIR:/var/log@@"; cat <&12; fi
if [ -d /var/lib/docker ]; then echo "@@DIR:/var/lib/docker@@"; cat <&13; fi
if [ -d /home ]; then echo "@@DIR:/home@@"; cat <&14; fi
if [ -d /opt ]; then echo "@@DIR:/opt@@"; cat <&15; fi
if [ -d /tmp ]; then echo "@@DIR:/tmp@@"; cat <&16; fi

section PROCESSES
PS_OUT=$(ps -eo pid=,ppid=,user=,pcpu=,pmem=,rss=,etime=,comm= 2>/dev/null | awk '{$1=$1;print}')
echo "$PS_OUT"

section PORTS
# Listening TCP/UDP sockets with owning PID. Showing the PID for sockets
# owned by other users normally requires root. By default we do NOT attempt
# sudo at all (least privilege) - the user must explicitly opt in, since
# silently trying to elevate privileges on someone's server by default is
# not "highly secure" behavior even when sudo -n would just fail cleanly.
if command -v ss >/dev/null 2>&1; then
  echo "@@TOOL:ss@@"
  if [ "__USE_SUDO__" = "1" ]; then
    { sudo -n ss -H -tnlp 2>/dev/null || timeout 5 ss -H -tnlp 2>/dev/null; }
  else
    timeout 5 ss -H -tnlp 2>/dev/null
  fi
  echo "@@UDP@@"
  if [ "__USE_SUDO__" = "1" ]; then
    { sudo -n ss -H -unlp 2>/dev/null || timeout 5 ss -H -unlp 2>/dev/null; }
  else
    timeout 5 ss -H -unlp 2>/dev/null
  fi
elif command -v netstat >/dev/null 2>&1; then
  echo "@@TOOL:netstat@@"
  if [ "__USE_SUDO__" = "1" ]; then
    { sudo -n netstat -tnlp 2>/dev/null || timeout 5 netstat -tnlp 2>/dev/null; }
  else
    timeout 5 netstat -tnlp 2>/dev/null
  fi
  echo "@@UDP@@"
  if [ "__USE_SUDO__" = "1" ]; then
    { sudo -n netstat -unlp 2>/dev/null || timeout 5 netstat -unlp 2>/dev/null; }
  else
    timeout 5 netstat -unlp 2>/dev/null
  fi
else
  echo "@@UNAVAILABLE@@"
fi

section SYSTEMD
SYSTEMD_PIDS=""
if command -v systemctl >/dev/null 2>&1 && systemctl list-units >/dev/null 2>&1; then
  echo "@@AVAILABLE@@"
  UNITS=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}')
  if [ -n "$UNITS" ]; then
    # A single batched `systemctl show` for every unit at once, instead of
    # one (or three) systemctl invocations per unit - each systemctl call is
    # a real process spawn plus a D-Bus round trip, so with dozens of
    # running services that adds up fast. `Id` is requested first purely as
    # a reliable per-unit delimiter in the flat output stream.
    SHOW_OUT=$(systemctl show $UNITS -p Id,MainPID,WorkingDirectory,User,ActiveState,SubState --no-pager 2>/dev/null)
    echo "$SHOW_OUT"
    SYSTEMD_PIDS=$(echo "$SHOW_OUT" | grep '^MainPID=' | cut -d= -f2 | grep -v '^0$')
  fi
else
  echo "@@UNAVAILABLE@@"
fi

section PM2
# PM2 (a common Node.js process manager) tracks exact app names, scripts,
# and working directories - far more precise than guessing from cmdline.
# `pm2 jlist` only sees processes managed by the PM2 daemon for the
# *current* user, which matches our SSH login user; that's the common case
# since services normally run under the same user PM2 was started as.
PM2_PIDS=""
if command -v pm2 >/dev/null 2>&1; then
  echo "@@AVAILABLE@@"
  PM2_JSON=$(timeout 10 pm2 jlist 2>/dev/null)
  echo "$PM2_JSON"
  PM2_PIDS=$(echo "$PM2_JSON" | grep -oE '"pid":[0-9]+' | grep -oE '[0-9]+' | sort -un)
else
  echo "@@UNAVAILABLE@@"
fi

section DOCKER
DOCKER_PIDS=""
if command -v docker >/dev/null 2>&1 && timeout 5 docker info >/dev/null 2>&1; then
  echo "@@AVAILABLE@@"
  echo "@@PS@@"
  timeout 10 docker ps --format '{{json .}}' 2>/dev/null
  echo "@@STATS@@"
  timeout 15 docker stats --no-stream --format '{{json .}}' 2>/dev/null
  echo "@@DF@@"
  timeout 10 docker system df 2>/dev/null
  echo "@@PIDS@@"
  CIDS=$(timeout 10 docker ps -q 2>/dev/null)
  if [ -n "$CIDS" ]; then
    # One batched `docker inspect` for every container instead of two
    # separate inspect calls per container - each is a real process spawn
    # talking to the docker daemon, which adds up with many containers.
    while IFS='|' read -r cid pid logpath; do
      [ -z "$cid" ] && continue
      logsize=""
      if [ -n "$logpath" ]; then
        logsize=$(stat -c%s "$logpath" 2>/dev/null)
      fi
      echo "$cid|$pid|$logsize"
      if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        DOCKER_PIDS="$DOCKER_PIDS $pid"
      fi
    done < <(timeout 10 docker inspect --format '{{.Id}}|{{.State.Pid}}|{{.LogPath}}' $CIDS 2>/dev/null)
  fi
else
  echo "@@UNAVAILABLE@@"
fi

section JOURNAL
if command -v journalctl >/dev/null 2>&1; then
  echo "@@AVAILABLE@@"
  timeout 5 journalctl --disk-usage 2>/dev/null | tail -1
else
  echo "@@UNAVAILABLE@@"
fi

section PIDDETAIL
TOPCPU=$(echo "$PS_OUT" | sort -k4 -rn | head -25 | awk '{print $1}')
TOPMEM=$(echo "$PS_OUT" | sort -k5 -rn | head -25 | awk '{print $1}')
ALLPIDS=$(echo "$TOPCPU $TOPMEM $SYSTEMD_PIDS $DOCKER_PIDS $PM2_PIDS" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -un)
for pid in $ALLPIDS; do
  echo "@@PID:$pid@@"
  if [ -r "/proc/$pid/cmdline" ]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null
    echo
  else
    echo
  fi
  readlink -f "/proc/$pid/exe" 2>/dev/null
  echo
  readlink -f "/proc/$pid/cwd" 2>/dev/null
  echo
done

section END
echo DONE
"""


def build_phase1_script(use_sudo: bool = False) -> str:
    return (
        _PHASE1_SCRIPT_TEMPLATE
        .replace("__DIRSIZE_TIMEOUT__", str(DIRSIZE_TIMEOUT))
        .replace("__USE_SUDO__", "1" if use_sudo else "0")
    )


def build_phase2_script(appdirs: List[str], logdirs: List[str]) -> str:
    """Size every candidate application/log directory concurrently.

    Each `du`/`find` is started via process substitution on its own fixed
    file descriptor (an in-kernel pipe, never a temp file on disk) as soon
    as it's generated, so all of them run in parallel; results are then
    read back in a fixed, deterministic order. With a real application list
    (many app dirs, each with several log-directory candidates) this can
    turn what used to be dozens of sequential, individually-timed-out `du`/
    `find` calls - potentially minutes - into one wait bounded by whichever
    single directory is slowest.
    """
    appdirs = appdirs[:MAX_APPDIR_CANDIDATES]
    logdirs = logdirs[:MAX_LOGDIR_CANDIDATES]

    lines = ['#!/bin/bash', 'section() { echo "===SECTION:$1==="; }', '']
    fd = 20
    appdir_fds = []
    for d in appdirs:
        q = shlex.quote(d)
        lines.append(f'if [ -d {q} ]; then exec {fd}< <(timeout {APPDIR_TIMEOUT} du -xsk {q} 2>/dev/null); fi')
        appdir_fds.append(fd)
        fd += 1

    logdir_fds = []
    for d in logdirs:
        q = shlex.quote(d)
        lines.append(
            f'if [ -d {q} ]; then exec {fd}< <('
            f'timeout {LOGDIR_TIMEOUT} du -xsk {q} 2>/dev/null; '
            f"timeout {LOGDIR_TIMEOUT} find {q} -maxdepth {FIND_MAXDEPTH_LOG} -type f -printf '%s|%T@|%p\\n' 2>/dev/null "
            f"| sort -t'|' -k1 -rn | head -20"
            f'); fi'
        )
        logdir_fds.append(fd)
        fd += 1

    varlog_fd = fd
    lines.append(
        f"exec {varlog_fd}< <(timeout 10 find /var/log -maxdepth 2 -type f -printf '%s|%T@|%p\\n' 2>/dev/null "
        f"| sort -t'|' -k1 -rn | head -30)"
    )

    lines.append('')
    lines.append('section APPDIRS')
    for d, dfd in zip(appdirs, appdir_fds):
        q = shlex.quote(d)
        lines.append(f'if [ -d {q} ]; then echo "@@APPDIR:{d}@@"; cat <&{dfd}; fi')

    lines.append('')
    lines.append('section LOGDIRS')
    for d, dfd in zip(logdirs, logdir_fds):
        q = shlex.quote(d)
        lines.append(f'if [ -d {q} ]; then echo "@@LOGDIR:{d}@@"; cat <&{dfd}; fi')

    lines.append('')
    lines.append('section VARLOG_FILES')
    lines.append(f'cat <&{varlog_fd}')

    lines.append('')
    lines.append('section END')
    lines.append('echo DONE')
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# SSH connection helpers
# --------------------------------------------------------------------------


def _connect(host: str, username: str, port: int = 22, timeout: int = 10) -> paramiko.SSHClient:
    # No private key path is requested from the user for this MVP: we assume
    # the user's public key is already present in the server's
    # ~/.ssh/authorized_keys (the same precondition a plain `ssh user@host`
    # relies on), and authenticate the same way that command would -
    # via a running ssh-agent and/or the default keys in ~/.ssh/.
    client = paramiko.SSHClient()
    # `load_system_host_keys()` alone only reads the system-wide
    # /etc/ssh/ssh_known_hosts - it does NOT load the current user's own
    # ~/.ssh/known_hosts, which is where hosts trusted via a normal `ssh`
    # session actually get recorded. Without loading that too, the strict
    # check below would refuse every host a user has ever legitimately
    # connected to, making it unusable.
    client.load_system_host_keys()
    user_known_hosts = os.path.expanduser("~/.ssh/known_hosts")
    if os.path.isfile(user_known_hosts):
        client.load_host_keys(user_known_hosts)

    # Strict host-key verification: refuse to connect to a host that isn't
    # already trusted in ~/.ssh/known_hosts, exactly like a plain `ssh`
    # client would refuse (or prompt) on an unrecognized host key. Silently
    # auto-accepting an unknown key (paramiko's AutoAddPolicy, or even just
    # warning and proceeding) would leave every first connection to a new
    # server open to a man-in-the-middle - this app never does that.
    host_keys = client.get_host_keys()
    if not host_keys.lookup(host):
        raise AnalysisError(
            "Unknown Host Key",
            f"'{host}' is not yet trusted in your ~/.ssh/known_hosts, so this app "
            f"refuses to connect. Silently trusting an unrecognized host key would "
            f"expose you to a man-in-the-middle attack.",
            [
                f"Run `ssh {username}@{host}` once from a terminal, verify the "
                f"fingerprint, and accept it - that records it in ~/.ssh/known_hosts",
                "Then try Analyze Server again",
            ],
        )
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=True,
            allow_agent=True,
        )
    except paramiko.AuthenticationException:
        raise AnalysisError(
            "SSH Authentication Failed",
            f"Unable to authenticate as '{username}' using your SSH agent or default keys in ~/.ssh/.",
            [
                "Check the username is correct for this AMI (e.g. ubuntu, ec2-user)",
                "Check that a matching private key is loaded in ssh-agent (ssh-add -l) or present as ~/.ssh/id_rsa, id_ed25519, etc.",
                "Check the corresponding public key is present in ~/.ssh/authorized_keys on the server",
                "Try connecting once with a plain `ssh user@host` to confirm it works outside this app",
            ],
        )
    except socket.timeout:
        raise AnalysisError(
            "SSH Connection Timed Out",
            f"No response from {host}:{port} within {timeout}s.",
            [
                "Check the host/IP is correct",
                "If this is a private IP, ensure your laptop has a route via VPN/bastion",
                "Check the EC2 security group allows inbound SSH from your IP",
            ],
        )
    except socket.gaierror:
        raise AnalysisError(
            "Invalid Host",
            f"Could not resolve host '{host}'.",
            ["Check the hostname/IP is spelled correctly"],
        )
    except ConnectionRefusedError:
        raise AnalysisError(
            "Connection Refused",
            f"{host}:{port} refused the connection.",
            ["Check SSH is running on the server", "Check the port number", "Check security group / firewall rules"],
        )
    except paramiko.BadHostKeyException as e:
        raise AnalysisError(
            "Host Key Mismatch - Possible Security Risk",
            f"The key presented by '{host}' does NOT match the one recorded in your "
            f"~/.ssh/known_hosts. This usually means the server was rebuilt/redeployed "
            f"with a new host key, but it can also indicate a man-in-the-middle attack.",
            [
                "Do not proceed until you've confirmed this is expected (e.g. you just "
                "recreated this EC2 instance)",
                "If expected, remove the stale entry from ~/.ssh/known_hosts (or run "
                "`ssh-keygen -R <host>`) and reconnect once with a plain `ssh` client to "
                "record the new key",
                f"Details: {e}",
            ],
        )
    except paramiko.SSHException as e:
        raise AnalysisError("SSH Connection Failed", str(e), ["Check the EC2 security group allows inbound SSH"])
    except OSError as e:
        raise AnalysisError(
            "Network Error",
            str(e),
            ["Check network connectivity to the host",
             "If this is a private IP, ensure your laptop has a route via VPN/bastion"],
        )
    return client


# --------------------------------------------------------------------------
# Read-only safety guard
#
# This tool must never modify, delete, restart, or otherwise change
# anything on the remote server - it only reads and reports. Every command
# used anywhere in this file is one of: cat/readlink on /proc, ps, ss/
# netstat, df, du, find (read-only, no -delete), systemctl show/cat/
# list-units, docker ps/stats/inspect/system df, pm2 jlist, journalctl
# --disk-usage. None of these write, delete, or mutate remote state.
#
# This guard is defense-in-depth on top of that: every script is scanned
# immediately before being sent over SSH, and execution is refused if it
# contains a denylisted destructive command/verb combination, or redirects
# output to anything other than /dev/null. It runs on every request, not
# just at development time, so a future accidental change that introduces a
# mutating command is caught before it ever reaches the server.
# --------------------------------------------------------------------------

_DANGEROUS_STANDALONE_COMMANDS = {
    "rm", "mv", "chmod", "chown", "chattr", "kill", "pkill", "killall",
    "truncate", "shred", "fdisk", "parted", "wipefs", "dd", "reboot",
    "shutdown", "poweroff", "halt", "crontab", "passwd", "useradd", "userdel",
    "usermod", "groupadd", "groupdel", "iptables", "ufw", "firewall-cmd",
    "visudo", "mkswap", "swapoff", "mkfs",
}
_DANGEROUS_COMMAND_VERB_PAIRS = [
    ("docker", "rm"), ("docker", "stop"), ("docker", "kill"), ("docker", "restart"),
    ("docker", "prune"), ("docker", "rmi"), ("docker", "pause"), ("docker", "unpause"),
    ("systemctl", "stop"), ("systemctl", "restart"), ("systemctl", "kill"),
    ("systemctl", "disable"), ("systemctl", "mask"), ("systemctl", "enable"),
    ("systemctl", "reload"), ("apt-get", "remove"), ("apt-get", "purge"),
    ("apt", "remove"), ("apt", "purge"), ("yum", "remove"), ("dnf", "remove"),
    ("journalctl", "--vacuum"), ("journalctl", "--rotate"),
    ("pm2", "delete"), ("pm2", "kill"), ("pm2", "stop"), ("pm2", "restart"),
]
# A `>` that writes to something other than /dev/null or another file
# descriptor (`2>&1`, `>&2`). Those are fine (they discard or merge streams,
# never persist data); anything else isn't used anywhere in this codebase
# and would indicate an accidental file write.
_UNSAFE_REDIRECT_RE = re.compile(r">{1,2}\s*(?!/dev/null\b)(?!&)\S")


def _assert_script_is_safe(script: str) -> None:
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_.\-]*", script)
    for tok in tokens:
        if tok in _DANGEROUS_STANDALONE_COMMANDS:
            raise AnalysisError(
                "Internal Safety Check Failed",
                f"Refusing to execute the generated remote script: it contains the "
                f"potentially destructive command '{tok}'. This tool is strictly "
                f"read-only and this should never happen - please report it as a bug.",
                [],
            )
    for cmd, verb in _DANGEROUS_COMMAND_VERB_PAIRS:
        # Plain word verbs (e.g. "rm", "stop") need a real \b on both sides,
        # or they'd false-positive inside unrelated words ("format" contains
        # "rm"). Flag-style verbs starting with "-" (e.g. "--vacuum-size")
        # need a left boundary only, since \b doesn't work usefully right
        # after punctuation, and should still match as a prefix so a variant
        # like "--vacuum-size=1M" is caught too.
        verb_pattern = re.escape(verb)
        if re.match(r"^\w+$", verb):
            verb_pattern = rf"\b{verb_pattern}\b"
        else:
            verb_pattern = rf"(?<![\w-]){verb_pattern}"
        if re.search(rf"\b{re.escape(cmd)}\b[^\n]{{0,40}}{verb_pattern}", script):
            raise AnalysisError(
                "Internal Safety Check Failed",
                f"Refusing to execute the generated remote script: it combines "
                f"'{cmd}' with '{verb}'. This tool is strictly read-only and this "
                f"should never happen - please report it as a bug.",
                [],
            )
    m = _UNSAFE_REDIRECT_RE.search(script)
    if m:
        raise AnalysisError(
            "Internal Safety Check Failed",
            "Refusing to execute the generated remote script: it redirects output "
            "somewhere other than /dev/null, which this tool never legitimately "
            "does. This should never happen - please report it as a bug.",
            [],
        )


def _exec(client: paramiko.SSHClient, script: str, timeout: int = 45) -> Tuple[str, str, int]:
    _assert_script_is_safe(script)
    try:
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        return out, err, exit_status
    except socket.timeout:
        raise AnalysisError(
            "Remote Analysis Timed Out",
            f"The remote analysis command did not complete within {timeout}s.",
            ["The server may be under heavy load", "Try again, or investigate manually over SSH"],
        )


# --------------------------------------------------------------------------
# Section splitting
# --------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^===SECTION:([A-Z_]+)===\s*$", re.MULTILINE)


def parse_sections(raw: str) -> Dict[str, str]:
    parts = _SECTION_RE.split(raw)
    sections: Dict[str, str] = {}
    it = iter(parts[1:])
    for name, content in zip(it, it):
        sections[name] = content.strip("\n")
    return sections


# --------------------------------------------------------------------------
# Individual section parsers
# --------------------------------------------------------------------------


def parse_hostinfo(text: str) -> Dict[str, str]:
    lines = [l for l in text.splitlines() if l.strip()]
    return {
        "hostname": lines[0].strip() if len(lines) > 0 else "",
        "kernel": lines[1].strip() if len(lines) > 1 else "",
    }


def parse_loadavg(text: str) -> Dict[str, float]:
    parts = text.split()
    try:
        return {"load1": float(parts[0]), "load5": float(parts[1]), "load15": float(parts[2])}
    except (IndexError, ValueError):
        return {"load1": 0.0, "load5": 0.0, "load15": 0.0}


def parse_cpucount(text: str) -> int:
    try:
        return max(int(text.strip()), 1)
    except ValueError:
        return 1


def parse_cpu_usage(text: str) -> Optional[float]:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return None

    def fields(line: str) -> List[int]:
        return [int(x) for x in line.split()[1:]]

    try:
        a, b = fields(lines[0]), fields(lines[1])
    except ValueError:
        return None
    idle_a = a[3] + (a[4] if len(a) > 4 else 0)
    idle_b = b[3] + (b[4] if len(b) > 4 else 0)
    total_a, total_b = sum(a), sum(b)
    dt, di = total_b - total_a, idle_b - idle_a
    if dt <= 0:
        return 0.0
    return round((1 - di / dt) * 100, 1)


def parse_meminfo(text: str) -> Dict[str, Any]:
    info: Dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            info[m.group(1)] = int(m.group(2))
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    free = info.get("MemFree", 0)
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    used = max(total - available, 0)
    return {
        "total_kb": total,
        "used_kb": used,
        "available_kb": available,
        "free_kb": free,
        "swap_total_kb": swap_total,
        "swap_used_kb": max(swap_total - swap_free, 0),
        "usage_percent": round(used / total * 100, 1) if total else 0.0,
    }


def parse_diskfs(text: str) -> List[Dict[str, Any]]:
    lines = text.strip().splitlines()
    if not lines:
        return []
    header = lines[0].lower()
    has_type = "type" in header
    result: List[Dict[str, Any]] = []
    for line in lines[1:]:
        parts = line.split()
        if has_type and len(parts) >= 7:
            fs, ftype, size, used, avail, pct = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
            mount = " ".join(parts[6:])
        elif not has_type and len(parts) >= 6:
            fs, size, used, avail, pct = parts[0], parts[1], parts[2], parts[3], parts[4]
            mount = " ".join(parts[5:])
            ftype = ""
        else:
            continue
        if ftype.lower() in PSEUDO_FS_TYPES:
            continue
        try:
            size_kb, used_kb, avail_kb = int(size), int(used), int(avail)
        except ValueError:
            continue
        if size_kb == 0:
            continue
        pct_num = pct.strip("%")
        result.append({
            "filesystem": fs,
            "type": ftype,
            "mount": mount,
            "size_bytes": size_kb * 1024,
            "used_bytes": used_kb * 1024,
            "available_bytes": avail_kb * 1024,
            "usage_percent": float(pct_num) if pct_num.replace(".", "", 1).isdigit() else None,
        })
    return result


def parse_dirsizes(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse `du -xk --max-depth=1 <dir>` output per fixed directory.

    GNU du's --max-depth=1 output includes a final "grand total" line for
    the directory argument itself, in addition to one line per immediate
    child. That self-total line is split out as `total_bytes` rather than
    listed as a "child" (it isn't one - it's the directory's own total).
    """
    out: Dict[str, Dict[str, Any]] = {}
    blocks = re.split(r"@@DIR:(.*?)@@", text)
    it = iter(blocks[1:])
    for d, content in zip(it, it):
        dir_path = d.strip()
        entries = []
        for line in content.strip().splitlines():
            parts = line.split("\t", 1) if "\t" in line else line.split(None, 1)
            if len(parts) == 2:
                size_str, path = parts
                try:
                    entries.append({"path": path.strip(), "size_bytes": int(size_str) * 1024})
                except ValueError:
                    continue
        total_bytes = None
        children = []
        for e in entries:
            if e["path"].rstrip("/") == dir_path.rstrip("/"):
                total_bytes = e["size_bytes"]
            else:
                children.append(e)
        children.sort(key=lambda e: e["size_bytes"], reverse=True)
        if total_bytes is None and children:
            total_bytes = sum(c["size_bytes"] for c in children)
        out[dir_path] = {"total_bytes": total_bytes, "children": children}
    return out


def parse_processes(text: str) -> List[Dict[str, Any]]:
    procs = []
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) != 8:
            continue
        pid, ppid, user, pcpu, pmem, rss, etime, comm = parts
        try:
            procs.append({
                "pid": int(pid),
                "ppid": int(ppid),
                "user": user,
                "cpu_percent": float(pcpu),
                "mem_percent": float(pmem),
                "rss_kb": int(rss),
                "elapsed": etime,
                "comm": comm,
            })
        except ValueError:
            continue
    return procs


_LISTEN_ADDR_TOKEN_RE = re.compile(r"^(?:\[[0-9a-fA-F:]+\]|\*|[\d.]+):\d+$")
_SS_PID_RE = re.compile(r"pid=(\d+)")
_SS_PROC_RE = re.compile(r'\(\("([^"]+)"')
_NETSTAT_PID_PROC_RE = re.compile(r"\b(\d+)/(\S+)\s*$")


def _parse_listening_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one line of `ss -tnlp`/`ss -unlp` or `netstat -tnlp`/`netstat -unlp` output."""
    line = line.strip()
    if not line:
        return None
    if line.lower().startswith(("state", "proto", "active", "netid")):
        return None
    tokens = line.split()
    addr_tok = next((t for t in tokens if _LISTEN_ADDR_TOKEN_RE.match(t)), None)
    if not addr_tok:
        return None
    address, port_str = addr_tok.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        return None

    pid = None
    process = None
    pid_m = _SS_PID_RE.search(line)
    if pid_m:
        pid = int(pid_m.group(1))
        proc_m = _SS_PROC_RE.search(line)
        process = proc_m.group(1) if proc_m else None
    else:
        ns_m = _NETSTAT_PID_PROC_RE.search(line)
        if ns_m and ns_m.group(1) != "0":
            pid = int(ns_m.group(1))
            process = ns_m.group(2)

    return {"address": address.strip("[]"), "port": port, "pid": pid, "process": process}


def parse_ports(text: str) -> List[Dict[str, Any]]:
    """Parse the PORTS section: listening TCP sockets, then `@@UDP@@`, then listening UDP sockets."""
    text = text.strip()
    if not text or text.startswith("@@UNAVAILABLE@@"):
        return []
    tcp_part, _, udp_part = text.partition("@@UDP@@")
    tcp_part = re.sub(r"^@@TOOL:\w+@@", "", tcp_part.strip()).strip()

    ports: List[Dict[str, Any]] = []
    for line in tcp_part.splitlines():
        parsed = _parse_listening_line(line)
        if parsed:
            parsed["protocol"] = "tcp"
            ports.append(parsed)
    for line in udp_part.strip().splitlines():
        parsed = _parse_listening_line(line)
        if parsed:
            parsed["protocol"] = "udp"
            ports.append(parsed)
    return ports


_DOCKER_PUBLISHED_PORT_RE = re.compile(
    r"(?:(?P<host_ip>[0-9.]+|\[?::\]?):)?(?P<host_port>\d+)->(?P<container_port>\d+)/(?P<proto>tcp|udp)"
)
_DOCKER_EXPOSED_PORT_RE = re.compile(r"^(?P<container_port>\d+)/(?P<proto>tcp|udp)$")


def parse_docker_ports(raw: str) -> List[Dict[str, Any]]:
    """Parse the `Ports` field from `docker ps --format '{{json .}}'`.

    e.g. "0.0.0.0:8080->80/tcp, :::8080->80/tcp" (published) or "80/tcp" (exposed only).
    """
    result: List[Dict[str, Any]] = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        m = _DOCKER_PUBLISHED_PORT_RE.search(part)
        if m:
            result.append({
                "host_ip": m.group("host_ip") or "0.0.0.0",
                "host_port": int(m.group("host_port")),
                "container_port": int(m.group("container_port")),
                "protocol": m.group("proto"),
            })
            continue
        m2 = _DOCKER_EXPOSED_PORT_RE.match(part)
        if m2:
            result.append({
                "host_ip": None,
                "host_port": None,
                "container_port": int(m2.group("container_port")),
                "protocol": m2.group("proto"),
            })
    return result


def parse_systemd(text: str) -> Dict[str, Any]:
    """Parse a single batched `systemctl show <units...> -p Id,MainPID,...`
    call for every running unit at once. There is no reliable blank-line
    separator between units in this filtered-property form, so `Id=<unit>`
    (requested first) is used as the per-unit delimiter instead - it's the
    one property guaranteed to be unique and present for every unit."""
    text = text.strip()
    if not text or text.startswith("@@UNAVAILABLE@@"):
        return {"available": False, "services": []}
    body = text[len("@@AVAILABLE@@"):] if text.startswith("@@AVAILABLE@@") else text
    body = body.strip()
    if not body:
        return {"available": True, "services": []}
    blocks = re.split(r"(?m)^Id=", body)
    services = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        lines = block.splitlines()
        unit_name = lines[0].strip()
        if not unit_name:
            continue
        props: Dict[str, str] = {}
        for line in lines[1:]:
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                props[k] = v
        try:
            main_pid = int(props.get("MainPID", "0") or "0")
        except ValueError:
            main_pid = 0
        services.append({
            "name": unit_name,
            "main_pid": main_pid,
            "working_directory": props.get("WorkingDirectory", ""),
            "user": props.get("User", ""),
            "active_state": props.get("ActiveState", ""),
            "sub_state": props.get("SubState", ""),
            # ExecStart is no longer fetched separately (that was another
            # systemctl invocation per unit) - the live /proc cmdline
            # (fetched for every systemd MainPID) is a more accurate source
            # of "command" anyway, since it reflects what's actually
            # running rather than the static unit-file directive.
            "exec_start": "",
        })
    return {"available": True, "services": services}


def parse_docker(text: str) -> Dict[str, Any]:
    text = text.strip()
    if not text or text.startswith("@@UNAVAILABLE@@"):
        return {"available": False, "containers": [], "disk_usage_raw": ""}
    body = text[len("@@AVAILABLE@@"):] if text.startswith("@@AVAILABLE@@") else text

    ps_section, _, rest = body.partition("@@STATS@@")
    stats_section, _, rest2 = rest.partition("@@DF@@")
    df_section, _, pids_section = rest2.partition("@@PIDS@@")
    ps_section = ps_section.replace("@@PS@@", "").strip()

    containers: Dict[str, Dict[str, Any]] = {}
    for line in ps_section.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = obj.get("ID", "")
        containers[cid] = {
            "id": cid,
            "name": obj.get("Names", ""),
            "image": obj.get("Image", ""),
            "status": obj.get("Status", ""),
            "command": obj.get("Command", ""),
            "cpu_percent": None,
            "memory_usage": "",
            "memory_percent": None,
            "network_io": "",
            "block_io": "",
            "pid": None,
            "log_size_bytes": None,
            "ports": parse_docker_ports(obj.get("Ports", "")),
        }

    def _find_container(cid: str) -> Optional[Dict[str, Any]]:
        if cid in containers:
            return containers[cid]
        for k, v in containers.items():
            if k.startswith(cid) or cid.startswith(k):
                return v
        return None

    for line in stats_section.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = obj.get("ID", "") or obj.get("Container", "")
        target = _find_container(cid)
        if not target:
            continue
        try:
            target["cpu_percent"] = float(obj.get("CPUPerc", "0%").strip("%"))
        except ValueError:
            pass
        target["memory_usage"] = obj.get("MemUsage", "")
        try:
            target["memory_percent"] = float(obj.get("MemPerc", "0%").strip("%"))
        except ValueError:
            pass
        target["network_io"] = obj.get("NetIO", "")
        target["block_io"] = obj.get("BlockIO", "")

    for line in pids_section.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        bits = line.split("|")
        cid = bits[0] if bits else ""
        pid = bits[1] if len(bits) > 1 else ""
        logsize = bits[2] if len(bits) > 2 else ""
        target = _find_container(cid)
        if not target:
            continue
        try:
            target["pid"] = int(pid)
        except ValueError:
            target["pid"] = None
        try:
            target["log_size_bytes"] = int(logsize)
        except ValueError:
            target["log_size_bytes"] = None

    return {"available": True, "containers": list(containers.values()), "disk_usage_raw": df_section.strip()}


def parse_pm2(text: str) -> Dict[str, Any]:
    text = text.strip()
    if not text or text.startswith("@@UNAVAILABLE@@"):
        return {"available": False, "processes": []}
    body = text[len("@@AVAILABLE@@"):] if text.startswith("@@AVAILABLE@@") else text
    body = body.strip()
    if not body:
        return {"available": True, "processes": []}
    try:
        raw_list = json.loads(body)
    except json.JSONDecodeError:
        return {"available": True, "processes": []}

    processes = []
    for p in raw_list:
        env = p.get("pm2_env") or {}
        monit = p.get("monit") or {}
        pid = p.get("pid")
        processes.append({
            "name": p.get("name"),
            "pid": int(pid) if pid else None,
            "pm_id": p.get("pm_id"),
            "status": env.get("status", ""),
            "cwd": env.get("pm_cwd", ""),
            "exec_path": env.get("pm_exec_path", ""),
            "cpu_percent": monit.get("cpu"),
            "memory_bytes": monit.get("memory"),
        })
    return {"available": True, "processes": processes}


def parse_journal(text: str) -> Dict[str, Any]:
    text = text.strip()
    if not text or text.startswith("@@UNAVAILABLE@@"):
        return {"available": False, "disk_usage": ""}
    body = text[len("@@AVAILABLE@@"):] if text.startswith("@@AVAILABLE@@") else text
    return {"available": True, "disk_usage": body.strip()}


def parse_piddetail(text: str) -> Dict[int, Dict[str, str]]:
    out: Dict[int, Dict[str, str]] = {}
    blocks = re.split(r"@@PID:(\d+)@@", text)
    it = iter(blocks[1:])
    for pid_str, content in zip(it, it):
        lines = content.strip("\n").split("\n")
        cmdline = lines[0].strip() if len(lines) > 0 else ""
        exe = lines[1].strip() if len(lines) > 1 else ""
        cwd = lines[2].strip() if len(lines) > 2 else ""
        try:
            out[int(pid_str)] = {"cmdline": cmdline, "exe": exe, "cwd": cwd}
        except ValueError:
            continue
    return out


def parse_appdirs(text: str) -> Dict[str, Optional[int]]:
    result: Dict[str, Optional[int]] = {}
    blocks = re.split(r"@@APPDIR:(.*?)@@", text)
    it = iter(blocks[1:])
    for d, content in zip(it, it):
        content = content.strip()
        size_bytes = None
        if content:
            line = content.splitlines()[0]
            parts = line.split("\t", 1) if "\t" in line else line.split(None, 1)
            if parts:
                try:
                    size_bytes = int(parts[0]) * 1024
                except ValueError:
                    size_bytes = None
        result[d.strip()] = size_bytes
    return result


def parse_logdirs(text: str) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    blocks = re.split(r"@@LOGDIR:(.*?)@@", text)
    it = iter(blocks[1:])
    for d, content in zip(it, it):
        lines = [l for l in content.strip("\n").splitlines() if l.strip()]
        total_bytes = None
        files: List[Dict[str, Any]] = []
        if lines:
            first = lines[0]
            parts = first.split("\t", 1) if "\t" in first else first.split(None, 1)
            if parts:
                try:
                    total_bytes = int(parts[0]) * 1024
                except ValueError:
                    total_bytes = None
            for line in lines[1:]:
                bits = line.split("|", 2)
                if len(bits) == 3:
                    size_s, mtime_s, path = bits
                    try:
                        size = int(size_s)
                        mtime = float(mtime_s)
                    except ValueError:
                        continue
                    files.append({
                        "path": path,
                        "size_bytes": size,
                        "modified": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                    })
        result[d.strip()] = {"total_bytes": total_bytes, "files": files}
    return result


def parse_varlog_files(text: str) -> List[Dict[str, Any]]:
    files = []
    for line in text.strip().splitlines():
        bits = line.split("|", 2)
        if len(bits) == 3:
            size_s, mtime_s, path = bits
            try:
                size = int(size_s)
                mtime = float(mtime_s)
            except ValueError:
                continue
            files.append({
                "path": path,
                "size_bytes": size,
                "modified": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
            })
    return files


# --------------------------------------------------------------------------
# Application identification (command line -> name/technology/directory)
# --------------------------------------------------------------------------

_JAR_VERSION_RE = re.compile(r"-\d[\w.\-]*$")

_KNOWN_COMM = {
    "nginx": ("nginx", "Nginx"),
    "postgres": ("postgres", "PostgreSQL"),
    "postmaster": ("postgres", "PostgreSQL"),
    "mysqld": ("mysql", "MySQL"),
    "redis-server": ("redis", "Redis"),
    "mongod": ("mongodb", "MongoDB"),
    "sshd": ("sshd", "SSH Daemon"),
    "haproxy": ("haproxy", "HAProxy"),
    "dockerd": ("docker-engine", "Docker Engine"),
    "containerd": ("containerd", "Container Runtime"),
    "httpd": ("apache", "Apache HTTP Server"),
}


def identify_application(cmdline: str, exe: str, cwd: str, comm: str) -> Tuple[str, str, str, Dict[str, str]]:
    """Best-effort mapping from process info to (name, technology, directory, extra)."""
    cl = cmdline or ""
    tokens = cl.split()
    comm_l = (comm or "").lower()
    cwd = cwd or ""

    if "java" in comm_l:
        jar = None
        for i, t in enumerate(tokens):
            # A well-formed `-jar <path>` always has a real path next, never
            # another flag - guards against a malformed startup script where
            # JVM options land between `-jar` and the actual jar path (e.g.
            # `java -jar -Xms256m -Xmx512m app.jar`), which would otherwise
            # be misread as the jar being named "-Xms256m".
            if t == "-jar" and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                jar = tokens[i + 1]
                break
        if jar:
            base = os.path.basename(jar)
            name = re.sub(r"\.jar$", "", base, flags=re.IGNORECASE)
            name = _JAR_VERSION_RE.sub("", name) or name
            directory = os.path.dirname(jar) or cwd
            return name, "Java", directory, {"jar": base}
        # No (valid) -jar flag - look for -cp/-classpath and use the
        # directory of its first entry, otherwise fall back to cwd.
        directory = cwd
        for i, t in enumerate(tokens):
            if t in ("-cp", "-classpath", "--class-path") and i + 1 < len(tokens):
                first_entry = tokens[i + 1].split(os.pathsep)[0]
                if first_entry and not first_entry.startswith("-"):
                    if first_entry.endswith("/*"):
                        cp_dir = first_entry[:-2] or cwd  # strip trailing wildcard glob
                    elif first_entry.lower().endswith(".jar"):
                        cp_dir = os.path.dirname(first_entry) or cwd
                    else:
                        cp_dir = first_entry.rstrip("/") or cwd  # already a directory entry
                    # classpath entries conventionally point at a lib/build
                    # output dir one level under the actual project root.
                    if os.path.basename(cp_dir) in ("lib", "libs", "target", "build", "dist"):
                        cp_dir = os.path.dirname(cp_dir) or cp_dir
                    directory = cp_dir or cwd
                break
        name = os.path.basename(directory.rstrip("/")) if directory else "java-app"
        return name, "Java", directory, {}

    if "node" in comm_l:
        script = next((t for t in tokens[1:] if t.endswith(".js") and not t.startswith("-")), None)
        if script:
            directory = os.path.dirname(script) or cwd
            name = os.path.basename(directory.rstrip("/")) if directory else os.path.basename(script)
            return name, "Node.js", directory, {"entry": os.path.basename(script)}
        # No bare .js entry point (e.g. a wrapper like `node node_modules/.bin/next
        # start`, common for Next.js) - infer the project root from any
        # node_modules/.next path segment instead of falling back to a
        # meaningless generic name.
        project_root = None
        for t in tokens:
            for marker in ("node_modules/", ".next/"):
                if marker in t:
                    prefix = t.split(marker)[0]
                    if prefix.startswith("/"):
                        project_root = prefix.rstrip("/")
                    elif cwd:
                        project_root = os.path.normpath(os.path.join(cwd, prefix)).rstrip("/")
                    break
            if project_root:
                break
        directory = project_root or cwd
        name = os.path.basename(directory.rstrip("/")) if directory else "node-app"
        return name, "Node.js", directory, {}

    if "python" in comm_l:
        script = next((t for t in tokens[1:] if t.endswith(".py") and not t.startswith("-")), None)
        if script:
            directory = os.path.dirname(script) or cwd
            name = os.path.splitext(os.path.basename(script))[0]
            return name, "Python", directory, {"entry": os.path.basename(script)}
        if "gunicorn" in cl.lower() or "uwsgi" in cl.lower():
            return "gunicorn-app", "Python (WSGI)", cwd, {}
        name = os.path.basename(cwd.rstrip("/")) if cwd else "python-app"
        return name, "Python", cwd, {}

    base_comm = comm_l.lstrip("-")
    if base_comm in _KNOWN_COMM:
        name, tech = _KNOWN_COMM[base_comm]
        return name, tech, cwd, {}

    fallback = comm or (os.path.basename(exe) if exe else "unknown")
    return fallback, "Other", cwd, {}


_NOISE_COMM_PREFIXES = ("kworker", "ksoftirqd", "migration", "rcu_", "watchdog", "systemd", "idle_inject")

# Well-known OS/platform infrastructure - not "applications" in the sense a
# user cares about (their business services), so they're excluded from the
# Applications view. They still appear in full in the raw Systemd Services
# list, nothing is hidden - only decluttered from the correlated view.
_INFRA_NAMES = {
    "accounts-daemon", "acpid", "atd", "cron", "dbus", "dbus-daemon", "agetty", "getty",
    "irqbalance", "lvmetad", "lvm2-lvmetad", "lxcfs", "networkd-dispatcher", "polkit",
    "polkitd", "rsyslog", "rsyslogd", "snapd", "systemd", "systemd-journald", "systemd-logind",
    "systemd-networkd", "systemd-resolved", "systemd-timesyncd", "systemd-udevd",
    "unattended-upgrades", "ssh", "sshd", "amazon-ssm-agent", "user", "serial-getty",
}


def _is_infra_unit(unit_name: str) -> bool:
    base = re.sub(r"\.service$", "", unit_name)
    base = re.sub(r"@.*$", "", base)  # strip instance suffix, e.g. getty@tty1 -> getty
    if base.startswith("pm2-"):  # represented individually via PM2 correlation instead
        return True
    if base.startswith("snap."):
        return True
    return base in _INFRA_NAMES


def _is_infra_comm(comm: str) -> bool:
    # `comm` from `ps` is truncated to 15 chars, so match by prefix in either
    # direction (e.g. "networkd-dispat" is a truncation of "networkd-dispatcher").
    comm_l = (comm or "").lower()
    if not comm_l:
        return False
    return any(name.startswith(comm_l) or comm_l.startswith(name) for name in _INFRA_NAMES)


def _is_noise_process(cmdline: str, comm: str, pid: int = 0, ppid: int = 0) -> bool:
    comm_l = (comm or "").lower()
    if ppid == 2 or pid == 2:  # kernel thread (child of kthreadd) or kthreadd itself
        return True
    if not cmdline.strip():
        return any(comm_l.startswith(p) for p in _NOISE_COMM_PREFIXES) or comm_l in ("bash", "sh", "sudo")
    return _is_infra_comm(comm_l)


def _normalize_dir(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    path = path.strip()
    if not path or path in ("/", ".", "..", "/root", "/usr", "/usr/bin", "/usr/sbin", "/bin"):
        return None
    return path.rstrip("/") or "/"


def _to_gb(kb_or_bytes: Optional[int], from_bytes: bool = True) -> Optional[float]:
    if kb_or_bytes is None:
        return None
    val = kb_or_bytes if from_bytes else kb_or_bytes * 1024
    return round(val / (1024 ** 3), 2)


def _status_for(pct: Optional[float]) -> str:
    if pct is None:
        return "UNKNOWN"
    if pct >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if pct >= WARNING_THRESHOLD:
        return "WARNING"
    return "NORMAL"


# --------------------------------------------------------------------------
# Application correlation
# --------------------------------------------------------------------------


def correlate_applications(
    processes: List[Dict[str, Any]],
    detail_by_pid: Dict[int, Dict[str, str]],
    systemd: Dict[str, Any],
    docker: Dict[str, Any],
    ports: Optional[List[Dict[str, Any]]] = None,
    pm2: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    proc_by_pid = {p["pid"]: p for p in processes}
    apps: List[Dict[str, Any]] = []
    claimed_pids: set = set()

    ports = ports or []
    pm2 = pm2 or {"available": False, "processes": []}
    ports_by_pid: Dict[int, List[Dict[str, Any]]] = {}
    for p in ports:
        if p.get("pid"):
            ports_by_pid.setdefault(p["pid"], []).append(p)
    children_by_ppid: Dict[int, List[int]] = {}
    for proc in processes:
        children_by_ppid.setdefault(proc["ppid"], []).append(proc["pid"])

    def _descendants(pid: int) -> set:
        seen: set = set()
        stack = list(children_by_ppid.get(pid, []))
        while stack:
            cpid = stack.pop()
            if cpid in seen:
                continue
            seen.add(cpid)
            stack.extend(children_by_ppid.get(cpid, []))
        return seen

    def _finalize(app: Dict[str, Any]) -> None:
        """Fold an app's not-yet-claimed descendant processes (worker/render
        sub-processes spawned by the main tracked PID, common for PM2/Next.js
        apps) into its totals, so resource usage is reported per logical
        application rather than per raw OS process, and attach every port
        owned by the whole process subtree."""
        pid = app.get("pid")
        if not pid:
            app["ports"] = []
            return
        descendants = _descendants(pid) - claimed_pids
        if descendants:
            total_cpu = (app.get("cpu_percent") or 0) + sum(
                proc_by_pid[d]["cpu_percent"] for d in descendants if d in proc_by_pid
            )
            total_mem = (app.get("mem_percent") or 0) + sum(
                proc_by_pid[d]["mem_percent"] for d in descendants if d in proc_by_pid
            )
            total_rss = (app.get("rss_kb") or 0) + sum(
                proc_by_pid[d]["rss_kb"] for d in descendants if d in proc_by_pid
            )
            app["cpu_percent"] = round(total_cpu, 1)
            app["mem_percent"] = round(total_mem, 1)
            app["rss_kb"] = total_rss
            app["absorbed_pids"] = sorted(d for d in descendants if d in proc_by_pid)
            claimed_pids.update(descendants)
        all_pids = {pid} | descendants
        app["_all_pids"] = sorted(all_pids)
        found_ports = []
        for p in all_pids:
            found_ports.extend(ports_by_pid.get(p, []))
        app["ports"] = found_ports

    for svc in systemd.get("services", []):
        if _is_infra_unit(svc["name"]):
            continue
        pid = svc["main_pid"]
        if not pid:
            continue
        detail = detail_by_pid.get(pid, {})
        proc = proc_by_pid.get(pid, {})
        cwd = detail.get("cwd") or svc.get("working_directory", "")
        name, technology, directory, extra = identify_application(
            detail.get("cmdline", ""), detail.get("exe", ""), cwd, proc.get("comm", "")
        )
        if not directory:
            directory = svc.get("working_directory") or (os.path.dirname(detail.get("exe", "")) if detail.get("exe") else "")
        app = {
            "name": name,
            "technology": technology,
            "source": "systemd",
            "service_name": svc["name"],
            "service_status": f"{svc.get('active_state', '?')}/{svc.get('sub_state', '?')}",
            "pid": pid,
            "ppid": proc.get("ppid"),
            "user": proc.get("user") or svc.get("user", ""),
            "cpu_percent": proc.get("cpu_percent"),
            "mem_percent": proc.get("mem_percent"),
            "rss_kb": proc.get("rss_kb"),
            "elapsed": proc.get("elapsed"),
            "command": detail.get("cmdline") or svc.get("exec_start", ""),
            "exe": detail.get("exe", ""),
            "directory": _normalize_dir(directory),
            "extra": extra,
        }
        claimed_pids.add(pid)
        _finalize(app)
        apps.append(app)

    for p in pm2.get("processes", []):
        pid = p.get("pid")
        if not pid or pid in claimed_pids:
            continue
        proc = proc_by_pid.get(pid, {})
        detail = detail_by_pid.get(pid, {})
        directory = _normalize_dir(p.get("cwd") or detail.get("cwd") or "")
        app = {
            "name": p.get("name") or f"pm2-app-{pid}",
            "technology": "Node.js (PM2)",
            "source": "pm2",
            "pm2_status": p.get("status"),
            "pid": pid,
            "ppid": proc.get("ppid"),
            "user": proc.get("user", ""),
            "cpu_percent": proc.get("cpu_percent", p.get("cpu_percent")),
            "mem_percent": proc.get("mem_percent"),
            "rss_kb": proc.get("rss_kb") or (
                round(p["memory_bytes"] / 1024) if p.get("memory_bytes") else None
            ),
            "elapsed": proc.get("elapsed"),
            "command": detail.get("cmdline") or p.get("exec_path", ""),
            "exe": detail.get("exe", ""),
            "directory": directory,
            "extra": {},
        }
        claimed_pids.add(pid)
        _finalize(app)
        apps.append(app)

    for c in docker.get("containers", []):
        name = (c.get("name") or c.get("id") or "container").lstrip("/")
        image = c.get("image", "")
        mem_usage = c.get("memory_usage", "")
        app = {
            "name": name,
            "technology": f"Docker ({image.split(':')[0]})" if image else "Docker",
            "source": "docker",
            "container_id": c.get("id"),
            "container_status": c.get("status"),
            "pid": c.get("pid"),
            "ppid": None,
            "user": "",
            "cpu_percent": c.get("cpu_percent"),
            "mem_percent": c.get("memory_percent"),
            "rss_kb": None,
            "memory_usage_display": mem_usage,
            "elapsed": None,
            "command": c.get("command", ""),
            "exe": "",
            "directory": None,
            "docker_log_size_bytes": c.get("log_size_bytes"),
            "network_io": c.get("network_io", ""),
            "block_io": c.get("block_io", ""),
            "extra": {},
        }
        if c.get("pid"):
            claimed_pids.add(c["pid"])
        # Docker's own published-port metadata is authoritative for the
        # container's *published* ports - host `ss`/`netstat` may not see the
        # socket at all depending on whether the docker daemon uses a
        # userland proxy or pure iptables DNAT. We still fold in any ports
        # visible from the host for the container's process subtree, then
        # add the docker-reported ones on top.
        _finalize(app)
        app["ports"] = app["ports"] + c.get("ports", [])
        apps.append(app)

    ranked_cpu = sorted(processes, key=lambda p: p["cpu_percent"], reverse=True)[:15]
    ranked_mem = sorted(processes, key=lambda p: p["mem_percent"], reverse=True)[:15]
    seen_process_pids: set = set()
    for proc in ranked_cpu + ranked_mem:
        pid = proc["pid"]
        if pid in claimed_pids or pid in seen_process_pids:
            continue
        seen_process_pids.add(pid)
        detail = detail_by_pid.get(pid)
        if not detail:
            continue
        if _is_noise_process(detail.get("cmdline", ""), proc.get("comm", ""), pid, proc.get("ppid", 0)):
            continue
        name, technology, directory, extra = identify_application(
            detail.get("cmdline", ""), detail.get("exe", ""), detail.get("cwd", ""), proc.get("comm", "")
        )
        app = {
            "name": name,
            "technology": technology,
            "source": "process",
            "pid": pid,
            "ppid": proc.get("ppid"),
            "user": proc.get("user"),
            "cpu_percent": proc.get("cpu_percent"),
            "mem_percent": proc.get("mem_percent"),
            "rss_kb": proc.get("rss_kb"),
            "elapsed": proc.get("elapsed"),
            "command": detail.get("cmdline", ""),
            "exe": detail.get("exe", ""),
            "directory": _normalize_dir(directory),
            "extra": extra,
        }
        claimed_pids.add(pid)
        _finalize(app)
        apps.append(app)

    return apps


def build_port_map(ports: List[Dict[str, Any]], applications: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Consolidated, sorted view of every discovered listening port, each
    annotated with the application that owns it when correlation succeeded."""
    app_by_pid: Dict[int, Dict[str, Any]] = {}
    for app in applications:
        for pid in app.get("_all_pids") or ([app["pid"]] if app.get("pid") else []):
            app_by_pid.setdefault(pid, app)

    port_map: List[Dict[str, Any]] = []
    for p in ports:
        app = app_by_pid.get(p.get("pid")) if p.get("pid") else None
        port_map.append({
            "port": p["port"],
            "protocol": p["protocol"],
            "address": p["address"],
            "pid": p.get("pid"),
            "process": p.get("process"),
            "application": app["name"] if app else None,
            "technology": app["technology"] if app else None,
        })

    # Docker-published host ports aren't necessarily visible to ss/netstat
    # (see note above), so add them explicitly if not already present.
    seen_ports = {(e["protocol"], e["port"]) for e in port_map}
    for app in applications:
        if app.get("source") != "docker":
            continue
        for dp in app.get("ports", []):
            if dp.get("host_port") is None:
                continue
            key = (dp["protocol"], dp["host_port"])
            if key in seen_ports:
                continue
            seen_ports.add(key)
            port_map.append({
                "port": dp["host_port"],
                "protocol": dp["protocol"],
                "address": dp.get("host_ip") or "0.0.0.0",
                "pid": app.get("pid"),
                "process": None,
                "application": app["name"],
                "technology": app["technology"],
            })

    port_map.sort(key=lambda e: (e["port"], e["protocol"]))
    return port_map


def build_log_candidates(app: Dict[str, Any]) -> List[str]:
    candidates = []
    directory = app.get("directory")
    if directory:
        candidates.append(f"{directory}/logs")
        candidates.append(f"{directory}/log")
    candidates.append(f"/var/log/{app['name']}")
    seen = set()
    result = []
    for c in candidates:
        c = _normalize_dir(c)
        if c and c not in seen:
            seen.add(c)
            result.append(c)
    return result


# --------------------------------------------------------------------------
# Findings & health
# --------------------------------------------------------------------------


def compute_health(cpu_usage: Optional[float], load1: float, cores: int, mem_usage_pct: float,
                    disk_max_pct: Optional[float]) -> Dict[str, Any]:
    load_ratio_pct = (load1 / cores) * 100 if cores else 0
    cpu_effective = max(cpu_usage or 0.0, load_ratio_pct)
    return {
        "cpu": {"value": cpu_usage, "load_ratio_percent": round(load_ratio_pct, 1), "status": _status_for(cpu_effective)},
        "memory": {"value": mem_usage_pct, "status": _status_for(mem_usage_pct)},
        "disk": {"value": disk_max_pct, "status": _status_for(disk_max_pct)},
    }


def compute_findings(data: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    apps = data["applications"]

    port_map = data.get("network", {}).get("port_map", [])
    if port_map and all(p["pid"] is None for p in port_map):
        findings.append({
            "level": "warning",
            "message": "Could not determine which process owns any listening port - this usually "
                       "requires root (e.g. passwordless sudo) on the server for full visibility.",
        })

    for app in sorted(apps, key=lambda a: a.get("cpu_percent") or 0, reverse=True)[:5]:
        cpu = app.get("cpu_percent")
        if cpu and cpu >= 80:
            findings.append({"level": "warning", "message": f"{app['name']} is consuming {cpu:.0f}% CPU."})

    for app in sorted(apps, key=lambda a: a.get("rss_kb") or 0, reverse=True)[:5]:
        rss_gb = _to_gb(app.get("rss_kb"), from_bytes=False)
        if rss_gb and rss_gb >= 1.0:
            findings.append({"level": "warning", "message": f"{app['name']} is using {rss_gb:.1f} GB memory."})

    for app in apps:
        logs_bytes = app.get("disk", {}).get("logs_bytes") or 0
        if logs_bytes and _to_gb(logs_bytes) and _to_gb(logs_bytes) >= 1.0:
            findings.append({"level": "warning", "message": f"{app['name']} logs consume {_to_gb(logs_bytes):.1f} GB."})

    varlog_total = (data["disk"]["directories"].get("/var/log") or {}).get("total_bytes") or 0
    if varlog_total and _to_gb(varlog_total) and _to_gb(varlog_total) >= 1.0:
        findings.append({"level": "warning", "message": f"/var/log is using {_to_gb(varlog_total):.1f} GB."})

    critical_fs = [f for f in data["disk"]["filesystems"] if (f.get("usage_percent") or 0) >= CRITICAL_THRESHOLD]
    warning_fs = [f for f in data["disk"]["filesystems"] if WARNING_THRESHOLD <= (f.get("usage_percent") or 0) < CRITICAL_THRESHOLD]
    for f in critical_fs:
        findings.append({"level": "critical", "message": f"Filesystem {f['mount']} is {f['usage_percent']:.0f}% full."})
    for f in warning_fs:
        findings.append({"level": "warning", "message": f"Filesystem {f['mount']} is {f['usage_percent']:.0f}% full."})
    if not critical_fs:
        findings.append({"level": "ok", "message": "No filesystem is critically full."})

    if data["memory"]["usage_percent"] >= CRITICAL_THRESHOLD:
        findings.append({"level": "critical", "message": f"Memory usage is {data['memory']['usage_percent']:.0f}%."})
    if data["memory"]["swap_used_kb"] > 0:
        swap_gb = _to_gb(data["memory"]["swap_used_kb"], from_bytes=False)
        if swap_gb and swap_gb >= 0.5:
            findings.append({"level": "warning", "message": f"Swap usage is {swap_gb:.1f} GB - the host may be memory constrained."})

    return findings


# --------------------------------------------------------------------------
# Main orchestrator
# --------------------------------------------------------------------------


def analyze_server(host: str, username: str, port: int = 22, use_sudo: bool = False) -> Dict[str, Any]:
    if not host or not host.strip():
        raise AnalysisError("Missing Host", "Please provide the EC2 IP address or hostname.", [])
    if not username or not username.strip():
        raise AnalysisError("Missing Username", "Please provide the SSH username.", [])

    host = host.strip()
    username = username.strip()

    client = _connect(host, username, port=port)
    try:
        raw1, err1, code1 = _exec(client, build_phase1_script(use_sudo), timeout=45)
        sections1 = parse_sections(raw1)

        hostinfo = parse_hostinfo(sections1.get("HOSTINFO", ""))
        loadavg = parse_loadavg(sections1.get("LOADAVG", ""))
        cores = parse_cpucount(sections1.get("CPUCOUNT", ""))
        cpu_usage = parse_cpu_usage(sections1.get("CPUSAMPLE", ""))
        meminfo = parse_meminfo(sections1.get("MEMINFO", ""))
        filesystems = parse_diskfs(sections1.get("DISKFS", ""))
        dirsizes = parse_dirsizes(sections1.get("DIRSIZES", ""))
        processes = parse_processes(sections1.get("PROCESSES", ""))
        ports = parse_ports(sections1.get("PORTS", ""))
        systemd = parse_systemd(sections1.get("SYSTEMD", ""))
        pm2 = parse_pm2(sections1.get("PM2", ""))
        docker = parse_docker(sections1.get("DOCKER", ""))
        journal = parse_journal(sections1.get("JOURNAL", ""))
        detail_by_pid = parse_piddetail(sections1.get("PIDDETAIL", ""))

        applications = correlate_applications(processes, detail_by_pid, systemd, docker, ports, pm2)
        port_map = build_port_map(ports, applications)

        appdir_candidates: List[str] = []
        logdir_candidates: List[str] = []
        for app in applications:
            d = app.get("directory")
            if d and d not in appdir_candidates:
                appdir_candidates.append(d)
            for ld in build_log_candidates(app):
                if ld not in logdir_candidates:
                    logdir_candidates.append(ld)

        phase2_script = build_phase2_script(appdir_candidates, logdir_candidates)
        raw2, err2, code2 = _exec(client, phase2_script, timeout=90)
        sections2 = parse_sections(raw2)

        appdir_sizes = parse_appdirs(sections2.get("APPDIRS", ""))
        logdir_data = parse_logdirs(sections2.get("LOGDIRS", ""))
        varlog_files = parse_varlog_files(sections2.get("VARLOG_FILES", ""))

        for app in applications:
            app_files_bytes = appdir_sizes.get(app.get("directory"), None) if app.get("directory") else None
            candidates = build_log_candidates(app)
            logs_bytes_total = 0
            log_files: List[Dict[str, Any]] = []
            any_log_data = False
            for ld in candidates:
                entry = logdir_data.get(ld)
                if entry and entry.get("total_bytes") is not None:
                    any_log_data = True
                    logs_bytes_total += entry["total_bytes"]
                    log_files.extend(entry.get("files", []))
            if app.get("source") == "docker" and app.get("docker_log_size_bytes"):
                any_log_data = True
                logs_bytes_total += app["docker_log_size_bytes"]
            log_files.sort(key=lambda f: f["size_bytes"], reverse=True)
            app["disk"] = {
                "app_files_bytes": app_files_bytes,
                "logs_bytes": logs_bytes_total if any_log_data else None,
                "total_bytes": (app_files_bytes or 0) + (logs_bytes_total if any_log_data else 0) or None,
            }
            app["logs"] = {"directories_checked": candidates, "files": log_files[:15]}

        disk_max_pct = max((f["usage_percent"] for f in filesystems if f.get("usage_percent") is not None), default=None)
        health = compute_health(cpu_usage, loadavg["load1"], cores, meminfo["usage_percent"], disk_max_pct)

        top_cpu = sorted(processes, key=lambda p: p["cpu_percent"], reverse=True)[:10]
        top_mem = sorted(processes, key=lambda p: p["mem_percent"], reverse=True)[:10]

        result: Dict[str, Any] = {
            "server": {
                "host": host,
                "hostname": hostinfo["hostname"],
                "kernel": hostinfo["kernel"],
            },
            "cpu": {
                "cores": cores,
                "usage_percent": cpu_usage,
                "load_average": loadavg,
                "top_processes": top_cpu,
            },
            "memory": meminfo,
            "disk": {
                "filesystems": filesystems,
                "directories": dirsizes,
                "varlog_top_files": varlog_files,
            },
            "top_memory_processes": top_mem,
            "applications": applications,
            "docker": docker,
            "systemd": systemd,
            "journal": journal,
            "network": {"port_map": port_map},
            "health": health,
        }
        result["findings"] = compute_findings(result)
        return result
    finally:
        client.close()
