"""Read the list of hosts to assess."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from .collectors import SshCollector, make_collector


class HostEntry(BaseModel):
    """One host. A host has either an address, reached over SSH, or a target such as `local`."""

    model_config = ConfigDict(extra="forbid")

    name: str
    findings: str
    address: str | None = None
    target: str | None = None
    user: str = "hostproof"
    port: int = 22
    sudo: bool = True
    key: str | None = None
    known_hosts: str | None = None
    probe_path: str | None = None


def resolve(base, value):
    """Treat relative paths as relative to the inventory file."""
    return str((base / value).resolve()) if value else None


def load_inventory(path):
    """Return a list of (collector, findings path), one for each host."""
    base = Path(path).resolve().parent
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    defaults = data.get("defaults") or {}
    entries = [HostEntry.model_validate({**defaults, **host}) for host in data.get("hosts") or []]
    if not entries:
        raise ValueError("the inventory lists no hosts")
    names = [entry.name for entry in entries]
    if len(set(names)) != len(names):
        raise ValueError("host names in the inventory must be unique")
    hosts = []
    for entry in entries:
        if bool(entry.address) == bool(entry.target):
            raise ValueError(f"{entry.name} needs either an address or a target")
        if entry.address:
            collector = SshCollector(
                entry.name,
                entry.address,
                entry.user,
                entry.port,
                entry.sudo,
                resolve(base, entry.key),
                resolve(base, entry.known_hosts),
                entry.probe_path,
            )
        else:
            collector = make_collector(entry.target)
            collector.host = entry.name
        hosts.append((collector, resolve(base, entry.findings)))
    return hosts
