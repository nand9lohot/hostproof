import json
import os
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ScriptedModel, host, run
from hostproof import probe
from hostproof.checks import CheckRejected, validate
from hostproof.collectors import HostUnreachable, LiveCollector, SnapshotCollector, SshCollector, make_collector, private_copy
from hostproof.models import Decision

needs_dpkg = pytest.mark.skipif(shutil.which("dpkg-query") is None, reason="needs a Debian-family host")
needs_system_python = pytest.mark.skipif(not Path("/usr/bin/python3").exists(), reason="needs /usr/bin/python3")


@pytest.mark.parametrize(
    "check,args",
    [
        ("run_shell", {"command": "id"}),
        ("file_mode", {"path": "/etc/hosts"}),
        ("package_status", {"package": "x; rm -rf /"}),
        ("package_status", {"package": "$(id)"}),
        ("package_status", {"package": "-x"}),
        ("package_status", {"package": "bash", "extra": "1"}),
        ("package_status", {"package": 123}),
        ("config_directive", {"path": "/etc/shadow", "directive": "root"}),
        ("config_directive", {"path": "/root/.bashrc", "directive": "x"}),
        ("config_directive", {"path": "/etc/../root/x", "directive": "x"}),
        ("config_directive", {"path": "/etc/ssh/ssh_host_rsa_key", "directive": "x"}),
        ("config_directive", {"path": "/etc/ssl/private/a.pem", "directive": "x"}),
        ("config_directive", {"path": "/etc/ssh", "directive": ".*"}),
        ("config_directive", {"path": "/etc/ssh", "directive": "a b"}),
    ],
)
def test_dangerous_requests_are_rejected(check, args):
    with pytest.raises(CheckRejected):
        validate(check, args)


def test_model_cannot_request_an_unlisted_check(finding, audit):
    plan = {"action": "check", "check": "run_shell", "args": {"command": "id"}}
    decision = Decision(status="under_investigation", confidence="low", reason="x")
    verdict = run(finding, ScriptedModel([decision], plans=[plan]), host("web01"), audit)
    assert [item.note for item in verdict.evidence if item.status == "rejected"][0].startswith("check not available")


def test_model_cannot_loop_forever(finding, audit):
    plan = {"action": "check", "check": "package_status", "args": {"package": "curl"}}
    decision = Decision(status="under_investigation", confidence="low", reason="x")
    model = ScriptedModel([decision], plans=[plan] * 100)
    run(finding, model, host("web01"), audit)
    assert len(model.plans) == 96


def test_comments_never_match():
    text = "# LoginGraceTime 0\n  LoginGraceTime 120\nLoginGraceTimeExtra 1\n"
    matches = probe.scan_text("/f", text, "LoginGraceTime")
    active = [line for line in matches if line.startswith("/f:")]
    assert active == ["/f:2:  LoginGraceTime 120"]


def test_config_search_skips_key_files(tmp_path):
    (tmp_path / "ssh_host_key").write_text("Port 1\n")
    (tmp_path / "cert.pem").write_text("Port 2\n")
    (tmp_path / "sshd_config").write_text("Port 3\n")
    matches = probe.search_config(str(tmp_path), "Port", os.path.realpath(tmp_path))["matches"]
    assert len(matches) == 1 and matches[0].endswith("Port 3")


def test_only_truly_enabled_units_count(monkeypatch):
    """Regression: static or alias units, such as ssh@.service, don't start by themselves."""
    states = {"ssh.service": "disabled", "ssh.socket": "disabled", "ssh@.service": "static", "sshd.service": "alias", "x.service": "enabled"}
    monkeypatch.setattr(probe.shutil, "which", lambda name: "/bin/systemctl")
    monkeypatch.setattr(probe, "run", lambda *cmd: (0, states[cmd[2]] + "\n"))
    files = [f"/lib/systemd/system/{name}" for name in states]
    provided, enabled = probe.service_units(files)
    assert enabled == ["x.service"] and len(provided) == 5


def test_probe_cannot_be_used_to_read_secrets_directly():
    """The probe may be allowed through sudo, so it enforces the limits itself."""
    for path in ("/etc/shadow", "/etc/ssl/private/a.pem", "/root/.bashrc", "/etc/../root/x", "/etc/ssh/ssh_host_rsa_key"):
        assert probe.run_check("config_directive", {"path": path, "directive": "root"}) is None
    assert probe.run_check("config_directive", {"path": "/etc/hosts", "directive": ".*"}) is None
    assert probe.run_check("run_shell", {"command": "id"}) is None
    assert probe.run_check("package_status", {"package": "-x"}) is None
    assert probe.run_check("package_status", {"nope": "x"}) is None
    assert probe.run_check("package_status", {"package": 1}) is None


def test_symbolic_link_cannot_escape_the_config_root(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("Secret 1\n")
    (root / "link").symlink_to(outside)
    (root / "real").write_text("Secret 2\n")
    matches = probe.search_config(str(root), "Secret", os.path.realpath(root) + "/")["matches"]
    assert len(matches) == 1 and matches[0].endswith("Secret 2")


def fake_tools(tmp_path, monkeypatch, sudo=False):
    """A stand-in ssh that runs the command through a shell, as a real remote host would."""
    log = tmp_path / "ssh.log"
    fake = tmp_path / "ssh"
    fake.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$@" > "{log}"\nfor last; do :; done\nexec sh -c "$last"\n'
    )
    fake.chmod(0o755)
    if sudo:
        fake_sudo = tmp_path / "sudo"
        fake_sudo.write_text(f'#!/bin/sh\necho sudo-used >> "{log}"\nshift\nexec "$@"\n')
        fake_sudo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    return log


@pytest.mark.skipif(shutil.which("python3") is None, reason="needs python3")
def test_ssh_target_runs_the_real_probe_through_a_shell(tmp_path, monkeypatch):
    """Uses a stand-in ssh, so it proves quoting and the probe, not a real SSH connection."""
    log = fake_tools(tmp_path, monkeypatch)
    collector = SshCollector("web01", "192.0.2.10", "hostproof", sudo=False)
    status, result = collector.run("package_status", {"package": "no-such-package-hp"})
    assert status == "ok" and result["installed"] is False
    argv = log.read_text().splitlines()
    assert "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv and "ForwardAgent=no" in argv
    assert "hostproof@192.0.2.10" in argv


def test_ssh_uses_sudo_when_asked(tmp_path, monkeypatch):
    log = fake_tools(tmp_path, monkeypatch, sudo=True)
    SshCollector("web01", "192.0.2.10", "hostproof").run("package_status", {"package": "curl"})
    assert "sudo-used" in log.read_text()


def test_fixed_probe_path_is_used_instead_of_sending_code(tmp_path, monkeypatch):
    fake_tools(tmp_path, monkeypatch)
    collector = SshCollector("web01", "192.0.2.10", "hostproof", probe_path="/opt/hostproof/probe.py")
    remote = collector.build_argv("package_status", {"package": "curl"})[-1]
    assert remote.startswith("sudo -n /usr/bin/python3 -I /opt/hostproof/probe.py package_status")
    assert collector.stdin_text() == ""


def test_remote_command_quotes_hostile_values(tmp_path, monkeypatch):
    fake_tools(tmp_path, monkeypatch)
    collector = SshCollector("web01", "192.0.2.10", "hostproof", sudo=False)
    remote = collector.build_argv("package_status", {"package": "x'; touch /tmp/pwned; '"})[-1]
    marker = tmp_path / "args"
    subprocess.run(["sh", "-c", f"printf '%s\\n' {remote.split(' - ')[1]} > {marker}"], check=True)
    lines = marker.read_text().splitlines()
    assert lines[0] == "package_status" and json.loads(lines[1])["package"].startswith("x'")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"user": "-oProxyCommand=x", "address": "a"},
        {"user": "u", "address": "-oProxyCommand=x"},
        {"user": "u;id", "address": "a"},
        {"user": "u", "address": "a b"},
        {"user": "u", "address": "a", "port": 70000},
        {"user": "u", "address": "a", "probe_path": "/x; id"},
    ],
)
def test_ssh_refuses_values_that_could_become_options(tmp_path, monkeypatch, kwargs):
    fake_tools(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        SshCollector("n", **kwargs)


def test_ssh_target_string(tmp_path, monkeypatch):
    fake_tools(tmp_path, monkeypatch)
    assert make_collector("ssh:root@192.0.2.1").remote == ["/usr/bin/python3", "-I"]
    assert make_collector("ssh:lab@192.0.2.1").remote == ["sudo", "-n", "/usr/bin/python3", "-I"]
    with pytest.raises(ValueError):
        make_collector("ssh:noaddress")


def test_preflight_reports_the_reason(tmp_path):
    fake = tmp_path / "broken"
    fake.write_text('#!/bin/sh\necho "Permission denied (publickey)." >&2\nexit 255\n')
    fake.chmod(0o755)
    with pytest.raises(HostUnreachable, match="Permission denied"):
        LiveCollector("x", [str(fake)]).preflight()


def test_key_copy_is_private(tmp_path):
    key = tmp_path / "id"
    key.write_text("data")
    key.chmod(0o644)
    copy = private_copy(str(key))
    assert Path(copy).read_text() == "data"
    assert stat.S_IMODE(os.stat(copy).st_mode) == 0o600


def test_address_decoding():
    assert probe.decode_address("0100007F:0016") == "127.0.0.1:22"
    assert probe.decode_address("00000000:0050") == "0.0.0.0:80"
    assert probe.decode_address("00000000000000000000000001000000:0016") == "[::1]:22"


def test_snapshot_handles_missing_data():
    collector = SnapshotCollector({"host": "x", "packages": {"a": {"version": "1"}}})
    assert collector.run("package_runtime", {"package": "a"})[0] == "unknown"
    assert collector.run("version_at_least", {"package": "a", "version": "2"})[0] == "unknown"


def test_make_collector_rejects_bad_targets():
    for target in ("ssh:host", "docker:bad;name", "docker:-it"):
        with pytest.raises(ValueError):
            make_collector(target)


def test_malicious_arguments_never_reach_the_probe(tmp_path):
    marker = tmp_path / "pwned"
    collector = LiveCollector("t", [sys.executable, "-I"])
    with pytest.raises(CheckRejected):
        collector.run("package_status", {"package": f"x'; touch {marker}; '"})
    assert not marker.exists()


def test_results_are_cached_per_run():
    calls = []
    collector = LiveCollector("t", [sys.executable, "-I"])
    collector._execute = lambda check, args: calls.append(check) or ("ok", {"installed": True})
    for _ in range(3):
        collector.run("package_status", {"package": "curl"})
    assert len(calls) == 1


def test_missing_python_on_target_is_an_error_not_a_verdict(tmp_path):
    collector = LiveCollector("t", ["/no/such/python"])
    assert collector.run("package_status", {"package": "curl"})[0] == "error"


@needs_dpkg
def test_live_checks_on_this_host():
    collector = make_collector("local")
    status, result = collector.run("package_status", {"package": "dpkg"})
    assert status == "ok" and result["installed"] is True and result["version"]
    assert collector.run("package_status", {"package": "no-such-package-lv"})[1]["installed"] is False
    assert collector.run("version_at_least", {"package": "dpkg", "version": "0.1"})[1]["result"] is True
    assert collector.run("version_at_least", {"package": "dpkg", "version": "999:1"})[1]["result"] is False
    assert collector.run("package_runtime", {"package": "no-such-package-lv"})[0] == "unknown"


@needs_dpkg
def test_live_runtime_detects_a_real_process():
    sleep_path = shutil.which("sleep")
    owner = subprocess.run(["dpkg", "-S", os.path.realpath(sleep_path)], capture_output=True, text=True)
    if owner.returncode != 0:
        pytest.skip("sleep isn't owned by a package here")
    package = owner.stdout.split(":")[0]
    process = subprocess.Popen([sleep_path, "30"])
    try:
        status, result = make_collector("local").run("package_runtime", {"package": package})
    finally:
        process.terminate()
        process.wait()
    assert status == "ok"
    assert str(process.pid) in {item["pid"] for item in result["processes"]}


@needs_dpkg
@needs_system_python
def test_live_runtime_links_a_library_to_its_process_and_port():
    """A real server: python3 listening on a port, and a library it has loaded."""
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
    script = (
        "import socket,time,ssl\n"
        f"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',{port}));s.listen()\n"
        "print('up',flush=True);time.sleep(30)\n"
    )
    server = subprocess.Popen(["/usr/bin/python3", "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        server.stdout.readline()
        maps = Path(f"/proc/{server.pid}/maps").read_text()
        library = next(line.split()[5] for line in maps.splitlines() if "libssl" in line or "libcrypto" in line)
        owner = subprocess.run(["dpkg", "-S", library], capture_output=True, text=True)
        if owner.returncode != 0:
            owner = subprocess.run(["dpkg", "-S", library.removeprefix("/usr")], capture_output=True, text=True)
        package = owner.stdout.split(":")[0]
        _, result = make_collector("local").run("package_runtime", {"package": package})
    finally:
        server.terminate()
        server.wait()
    assert str(server.pid) in {item["pid"] for item in result["libraries"]}
    assert f"127.0.0.1:{port}" in result["listeners"]
