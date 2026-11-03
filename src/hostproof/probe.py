"""Read-only checks that run on the host being assessed.

This file uses only the Python standard library, because it gets sent to the
target and run there with `python3 -`, or installed there as one fixed file. It
imports nothing else from HostProof, and it enforces its own limits, so even a
compromised account allowed to run it through sudo can't use it to read secrets.
"""

import json
import os
import re
import shutil
import socket
import stat
import subprocess  # nosec B404
import sys

PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,127}$")
DIRECTIVE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._/+-]{1,255}$")
SENSITIVE_RE = re.compile(
    r"(shadow|/passwd-|/private/|_key$|\.key$|\.pem$|\.p12$|\.pfx$|credential|secret|token|\.ssh/)",
    re.IGNORECASE,
)
SERVICE_FILE = re.compile(r"/systemd/system/[^/]+\.(service|socket|timer)$")
SKIPPED_FILES = re.compile(r"(key|\.pem$)", re.IGNORECASE)
MAX_MATCHES = 20
MAX_LINE = 300
# State codes used in /proc/net: 0A means a TCP socket is listening, 07 is an unconnected UDP socket.
LISTENING = {"tcp": "0A", "tcp6": "0A", "udp": "07", "udp6": "07"}


def run(*command):
    """Run a fixed command without a shell. Returns (exit code, output)."""
    done = subprocess.run(  # nosec B603  # nosemgrep
        command, capture_output=True, text=True, timeout=20, check=False
    )
    return done.returncode, done.stdout


def strip_usr(path):
    """Treat /usr/bin/x and /bin/x as the same file, as most Linux systems now do."""
    return path[4:] if path.startswith("/usr/") else path


def package_status(package):
    if shutil.which("dpkg-query"):
        _, out = run("dpkg-query", "-W", "-f=${Status}|${Version}", package)
        if out.startswith("install ok installed|"):
            return {"installed": True, "version": out.split("|", 1)[1]}
        return {"installed": False, "version": ""}
    if shutil.which("rpm"):
        code, out = run("rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", package)
        return {"installed": code == 0, "version": out if code == 0 else ""}
    return None


def version_at_least(package, version):
    if not shutil.which("dpkg-query"):
        return None  # RPM comparison isn't implemented yet, so stay cautious.
    _, installed = run("dpkg-query", "-W", "-f=${Version}", package)
    if not installed:
        return None
    code, _ = run("dpkg", "--compare-versions", installed, "ge", version)
    return {"result": code == 0}


def package_files(package):
    """List the files a package installed."""
    if shutil.which("dpkg-query"):
        code, out = run("dpkg", "-L", package)
    elif shutil.which("rpm"):
        code, out = run("rpm", "-ql", package)
    else:
        return []
    return out.splitlines() if code == 0 else []


def setuid_files(files):
    """Find setuid or setgid files, which any local user may be able to run with raised privileges."""
    found = []
    for path in files:
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            continue
        if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
            found.append(path)
    return found


def service_units(files):
    """Return (services the package provides, those enabled to start)."""
    provided = sorted({path.rsplit("/", 1)[1] for path in files if SERVICE_FILE.search(path)})
    if not shutil.which("systemctl"):
        return provided, []
    enabled = []
    for unit in provided:
        _, state = run("systemctl", "is-enabled", unit)
        if state.strip() in {"enabled", "enabled-runtime", "generated"}:
            enabled.append(unit)
    return provided, enabled


def listening_sockets():
    """Map each listening socket's inode to its address, by reading /proc/net."""
    sockets = {}
    for protocol, state in LISTENING.items():
        try:
            with open(f"/proc/net/{protocol}", encoding="ascii") as handle:
                lines = handle.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9 and fields[3] == state:
                sockets[fields[9]] = decode_address(fields[1])
    return sockets


def decode_address(value):
    """Convert a /proc/net address such as 0100007F:0016 to 127.0.0.1:22."""
    address, port = value.split(":")
    raw = bytes.fromhex(address)
    if len(raw) == 4:
        host = socket.inet_ntoa(raw[::-1])
    else:
        words = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        host = "[" + socket.inet_ntop(socket.AF_INET6, words) + "]"
    return f"{host}:{int(port, 16)}"


def process_sockets(pid):
    """Return the socket inodes a process has open. Raises PermissionError if it can't tell."""
    inodes = set()
    for descriptor in os.listdir(f"/proc/{pid}/fd"):
        try:
            target = os.readlink(f"/proc/{pid}/fd/{descriptor}")
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])
    return inodes


def package_runtime(package):
    """Report what a package is doing right now on this host."""
    files = package_files(package)
    if not files:
        return None
    owned = {strip_usr(path) for path in files}
    provided, enabled = service_units(files)
    result = {
        "processes": [],
        "libraries": [],
        "services_enabled": enabled,
        "services_provided": provided,
        "setuid_files": setuid_files(files),
        "listeners": [],
        "complete": True,
        "uninspected": 0,
        "service_manager": "systemd" if shutil.which("systemctl") else "none",
        "listeners_known": os.path.exists("/proc/net/tcp"),
    }
    sockets = listening_sockets()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                if not handle.read(1):
                    continue  # Kernel threads have no command line and no package.
            exe = os.readlink(f"/proc/{entry}/exe")
            deleted = exe.endswith(" (deleted)")
            exe = exe.removesuffix(" (deleted)")
            uses_package = strip_usr(exe) in owned
            if uses_package:
                result["processes"].append({"pid": entry, "path": exe, "deleted": deleted})
            with open(f"/proc/{entry}/maps", encoding="utf-8", errors="replace") as handle:
                loaded = {}
                for line in handle:
                    fields = line.split()
                    if len(fields) >= 6 and ".so" in fields[5] and strip_usr(fields[5]) in owned:
                        loaded[fields[5]] = fields[-1] == "(deleted)"
            for path, stale in sorted(loaded.items()):
                result["libraries"].append({"pid": entry, "path": path, "deleted": stale, "used_by": exe})
            if uses_package or loaded:
                for inode in process_sockets(entry):
                    if inode in sockets:
                        result["listeners"].append(sockets[inode])
        except FileNotFoundError:
            continue  # The process exited while we were looking.
        except PermissionError:
            result["complete"] = False  # Usually means it's not running as root.
            result["uninspected"] += 1
    result["listeners"] = sorted(set(result["listeners"]))
    return result


def scan_text(name, text, directive):
    """Find active lines that set a directive. Comment lines never match."""
    pattern = re.compile(rf"^\s*{re.escape(directive)}(\s|=|$)", re.IGNORECASE)
    lines = text.splitlines()
    matches = []
    for number, line in enumerate(lines, start=1):
        if pattern.search(line):
            for context in range(max(1, number - 2), number):
                matches.append(f"{name}-{context}-{lines[context - 1]}"[:MAX_LINE])
            matches.append(f"{name}:{number}:{line}"[:MAX_LINE])
    return matches


def allowed_config_path(path):
    """Only non-sensitive paths under /etc can be searched."""
    return bool(PATH_RE.match(path)) and ".." not in path and path.startswith("/etc/") and not SENSITIVE_RE.search(path)


def config_directive(path, directive):
    """Enforce the limits, then search."""
    if not allowed_config_path(path) or not DIRECTIVE_RE.match(directive):
        return None
    return search_config(path, directive, "/etc/")


def search_config(path, directive, root):
    """Search one config file, or every file under a config directory."""
    if not os.path.exists(path):
        return {"exists": False, "matches": []}
    paths = [path]
    if os.path.isdir(path):
        paths = [
            os.path.join(folder, name)
            for folder, _, names in os.walk(path)
            for name in names
            if not SKIPPED_FILES.search(name)
        ]
    matches = []
    for item in sorted(paths):
        real = os.path.realpath(item)
        if not real.startswith(root) or SENSITIVE_RE.search(real):
            continue  # A symbolic link can't be used to reach anything outside the limits.
        try:
            with open(item, encoding="utf-8", errors="replace") as handle:
                matches += scan_text(item, handle.read(), directive)
        except PermissionError:
            return None
        except OSError:
            continue
    return {"exists": True, "matches": matches[:MAX_MATCHES]}


CHECKS = {
    "package_status": package_status,
    "version_at_least": version_at_least,
    "package_runtime": package_runtime,
    "config_directive": config_directive,
}


def run_check(name, args):
    """Refuse bad input here as well, as the probe may be run directly through sudo."""
    if name not in CHECKS or not isinstance(args, dict):
        return None
    if not all(isinstance(value, str) for value in args.values()):
        return None
    if "package" in args and not PACKAGE_RE.match(args["package"]):
        return None
    if "version" in args and not VERSION_RE.match(args["version"]):
        return None
    try:
        return CHECKS[name](**args)
    except TypeError:
        return None


if __name__ == "__main__":
    print(json.dumps(run_check(sys.argv[1], json.loads(sys.argv[2]))))
