"""Where evidence comes from: a remote host, this machine, or a saved snapshot."""

import atexit
import json
import os
import re
import shlex
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

import yaml

from .checks import validate
from .probe import MAX_MATCHES, scan_text

TIMEOUT_SECONDS = 60
SSH_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
SSH_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
PROBE_SOURCE = (Path(__file__).parent / "probe.py").read_text(encoding="utf-8")


class HostUnreachable(RuntimeError):
    """The host can't be reached, or can't run the probe."""


class LiveCollector:
    """Runs probe.py on a live host, sending the code in through standard input."""

    def __init__(self, host, command):
        self.host = host
        self.command = command
        self.cache = {}

    def run(self, check, args):
        """Return (status, result). The same check on the same package runs only once."""
        clean = validate(check, args)
        key = json.dumps([check, clean], sort_keys=True)
        if key not in self.cache:
            self.cache[key] = self._execute(check, clean)
        return self.cache[key]

    def preflight(self):
        """Confirm the probe can run, so one bad host is reported clearly and skipped."""
        status, result = self._execute("package_status", {"package": "python3"})
        if status == "error":
            raise HostUnreachable(str(result.get("message") or result))

    def build_argv(self, check, args):
        return [*self.command, "-", check, json.dumps(args)]

    def stdin_text(self):
        return PROBE_SOURCE

    def _execute(self, check, args):
        argv = self.build_argv(check, args)
        try:
            # Reviewed: no shell is used, and arguments are validated and passed as one JSON value.
            done = subprocess.run(  # nosec B603  # nosemgrep
                argv, input=self.stdin_text(), capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "error", {"message": type(exc).__name__}
        if done.returncode != 0:
            lines = done.stderr.strip().splitlines()
            return "error", {"exit_code": done.returncode, "message": lines[-1][:200] if lines else ""}
        try:
            result = json.loads(done.stdout)
        except ValueError:
            return "error", {"message": "unreadable probe output"}
        return ("unknown", {}) if result is None else ("ok", result)


class SshCollector(LiveCollector):
    """Runs the probe on a remote host over SSH. Nothing stays on the target.

    Host keys are always verified, and agent forwarding is off. The remote shell
    parses the command line, so every part of it is quoted.
    """

    def __init__(self, name, address, user, port=22, sudo=True, key=None, known_hosts=None, probe_path=None):
        if not SSH_USER_RE.match(user) or not SSH_HOST_RE.match(address):
            raise ValueError(f"invalid SSH user or address for {name}")
        if not 1 <= int(port) <= 65535:
            raise ValueError(f"invalid SSH port for {name}")
        if probe_path and not re.fullmatch(r"/[A-Za-z0-9._/-]+", probe_path):
            raise ValueError(f"invalid probe path for {name}")
        ssh = shutil.which("ssh")
        if ssh is None:
            raise ValueError("ssh was not found on PATH")
        options = {
            "BatchMode": "yes",
            "StrictHostKeyChecking": "yes",
            "PasswordAuthentication": "no",
            "ForwardAgent": "no",
            "ForwardX11": "no",
            "ConnectTimeout": "10",
        }
        if known_hosts:
            options["UserKnownHostsFile"] = str(known_hosts)
        command = [ssh, "-p", str(int(port))]
        if key:
            options["IdentitiesOnly"] = "yes"
            command += ["-i", private_copy(key)]
        for option, value in options.items():
            command += ["-o", f"{option}={value}"]
        super().__init__(name, [*command, f"{user}@{address}"])
        self.remote = [*(["sudo", "-n"] if sudo else []), "/usr/bin/python3", "-I"]
        self.probe_path = probe_path

    def build_argv(self, check, args):
        parts = [*self.remote, self.probe_path or "-", check, json.dumps(args)]
        return [*self.command, " ".join(shlex.quote(part) for part in parts)]

    def stdin_text(self):
        return "" if self.probe_path else PROBE_SOURCE


PRIVATE_COPIES = {}


def private_copy(path):
    """Copy a key to a private temporary file, as ssh refuses keys others can read.

    A key mounted into a container often has the wrong owner or mode.
    """
    if path not in PRIVATE_COPIES:
        data = Path(path).read_bytes()
        handle, name = tempfile.mkstemp(prefix="hostproof-key-")  # Created readable only by this user.
        with os.fdopen(handle, "wb") as output:
            output.write(data)
        atexit.register(lambda: os.path.exists(name) and os.remove(name))
        PRIVATE_COPIES[path] = name
    return PRIVATE_COPIES[path]


class SnapshotCollector:
    """Answers checks from a saved YAML description of a host. Nothing real is touched."""

    def __init__(self, data):
        self.data = data
        self.host = str(data["host"])

    def preflight(self):
        """A saved file is always reachable."""

    @classmethod
    def from_file(cls, path):
        return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    def run(self, check, args):
        clean = validate(check, args)
        packages = self.data.get("packages", {})
        if check == "config_directive":
            return self._config(clean["path"], clean["directive"])
        entry = packages.get(clean["package"])
        if check == "package_status":
            if entry is None:
                return "ok", {"installed": False, "version": ""}
            return "ok", {"installed": True, "version": str(entry.get("version", ""))}
        if check == "version_at_least":
            value = (entry or {}).get("fixed", {}).get(clean["version"])
            return ("unknown", {}) if value is None else ("ok", {"result": bool(value)})
        if entry is None or "runtime" not in entry:
            return "unknown", {}
        defaults = {
            "processes": [],
            "libraries": [],
            "services_enabled": [],
            "services_provided": [],
            "setuid_files": [],
            "listeners": [],
            "complete": True,
            "uninspected": 0,
            "service_manager": "systemd",
            "listeners_known": True,
        }
        return "ok", {**defaults, **entry["runtime"]}

    def _config(self, path, directive):
        prefix = path.rstrip("/") + "/"
        if any(item == path or item.startswith(prefix) for item in self.data.get("unreadable", [])):
            return "unknown", {}
        targets = {
            name: text
            for name, text in self.data.get("files", {}).items()
            if name == path or name.startswith(prefix)
        }
        if not targets:
            return "ok", {"exists": False, "matches": []}
        matches = []
        for name, text in sorted(targets.items()):
            matches += scan_text(name, text, directive)
        return "ok", {"exists": True, "matches": matches[:MAX_MATCHES]}


def make_collector(target):
    """Build a collector from `ssh:USER@ADDRESS`, `local` or `snapshot:FILE`."""
    if target == "local":
        return LiveCollector("local", [sys.executable, "-I"])
    if target.startswith("snapshot:"):
        return SnapshotCollector.from_file(target.removeprefix("snapshot:"))
    if target.startswith("ssh:"):
        user, _, address = target.removeprefix("ssh:").partition("@")
        if not address:
            raise ValueError("an SSH target must look like ssh:USER@ADDRESS")
        return SshCollector(address, address, user, sudo=user != "root")
    raise ValueError("target must be ssh:USER@ADDRESS, local or snapshot:FILE")
