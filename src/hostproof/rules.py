"""Plain-code decisions that need no AI: exposure ranking and the clear-cut verdicts."""

from .models import Decision

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
EXPOSURE_ORDER = ["network", "running", "local", "unknown", "enabled", "dormant", "none"]
EXPOSURE_MEANING = {
    "network": "Reachable: code from this package is listening on a non-loopback address",
    "running": "Running: code is in memory, but not listening beyond this host",
    "local": "Local: has setuid or setgid files that local users could run",
    "unknown": "Unknown: the evidence is incomplete",
    "enabled": "Enabled: not running now, but set to start",
    "dormant": "Dormant: installed, with nothing running or enabled",
    "none": "Not present: the package isn't installed",
}


def find(evidence, check, package):
    """Return the first evidence item for this check and package, if it succeeded."""
    for item in evidence:
        if item.check == check and item.args.get("package") == package and item.status == "ok":
            return item
    return None


def is_loopback(address):
    return address.startswith(("127.", "[::1]"))


def exposure_of(package, evidence):
    """Rank how reachable this package's code is. Unknown ranks above dormant, to stay cautious."""
    status = find(evidence, "package_status", package)
    if status is None:
        return "unknown"
    if not status.result["installed"]:
        return "none"
    item = find(evidence, "package_runtime", package)
    if item is None:
        return "unknown"
    runtime = item.result
    if any(not is_loopback(address) for address in runtime["listeners"]):
        return "network"
    if runtime["processes"] or runtime["libraries"] or runtime["listeners"]:
        return "running"
    if runtime["setuid_files"]:
        return "local"
    if not runtime["complete"] or not runtime["listeners_known"]:
        return "unknown"
    return "enabled" if runtime["services_enabled"] else "dormant"


def urgency(verdict):
    """Sort key: most exposed first, then the most severe."""
    return EXPOSURE_ORDER.index(verdict.exposure), SEVERITY_ORDER.get(verdict.finding.severity.upper(), 4)


def priority(verdict):
    """Report order: anything not dismissed comes first, then by urgency."""
    return verdict.status == "not_affected", *urgency(verdict)


def stale_code(runtime):
    """True if a running process or loaded library was replaced on disk but is still in memory."""
    return any(item["deleted"] for item in [*runtime["processes"], *runtime["libraries"]])


def clear_cut_decision(package, evidence):
    """Decide the cases that need no reasoning. Returns None if the model should look at it."""
    status = find(evidence, "package_status", package)
    version = find(evidence, "version_at_least", package)
    runtime = find(evidence, "package_runtime", package)
    ids = [item.id for item in (status, version, runtime) if item]

    if status and not status.result["installed"]:
        return Decision(
            status="not_affected",
            justification="component_not_present",
            evidence_ids=ids,
            confidence="high",
            reason="The flagged package is not installed on this host.",
        )
    if version and version.result["result"] and runtime and runtime.result["complete"]:
        if stale_code(runtime.result):
            return Decision(
                status="affected",
                evidence_ids=ids,
                confidence="high",
                reason="The fix is installed, but old code is still in memory. Restart what's using it.",
            )
        return Decision(
            status="not_affected",
            justification="vulnerable_code_not_present",
            evidence_ids=ids,
            confidence="high",
            reason="The installed version includes the fix, and no old code is still running.",
        )
    return None
