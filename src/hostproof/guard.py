"""The policy guard: rules every verdict must pass, however it was reached.

The model never has the last word. Even a fully prompt-injected model can't get
`not_affected` for a host where the evidence shows the code running.

The rules read all collected evidence, not just what the model cited, so
cherry-picking doesn't help. They can't judge whether a config line is really an
effective mitigation, which is why every verdict still needs human review.
"""

from .rules import find, stale_code


def running_code(runtime):
    """List the reasons this package's code can't be called idle."""
    reasons = []
    if runtime["processes"]:
        reasons.append("processes from the package are running")
    if runtime["libraries"]:
        reasons.append("libraries from the package are loaded")
    if runtime["services_enabled"]:
        reasons.append("services from the package are enabled")
    if runtime["listeners"]:
        reasons.append("the package has network listeners")
    if runtime["setuid_files"]:
        reasons.append("the package has setuid or setgid files any local user could run")
    return reasons


def check_decision(decision, finding, evidence):
    """Return the list of broken rules. An empty list means the decision is allowed."""
    violations = []
    known_ids = {item.id: item for item in evidence}

    missing = [item for item in decision.evidence_ids if item not in known_ids]
    if missing:
        violations.append(f"cited evidence does not exist: {missing}")
    if decision.status != "under_investigation" and not decision.evidence_ids:
        violations.append("a verdict must cite evidence")
    if decision.status != "not_affected" and decision.justification:
        violations.append("only not_affected can carry a justification")

    status = find(evidence, "package_status", finding.package)
    version = find(evidence, "version_at_least", finding.package)
    runtime_item = find(evidence, "package_runtime", finding.package)
    installed = status.result["installed"] if status else None
    fixed = version.result["result"] if version else None
    runtime = runtime_item.result if runtime_item else None

    if decision.status == "affected":
        if installed is False:
            violations.append("cannot be affected: the package is not installed")
        if fixed is True and not (runtime and stale_code(runtime)):
            violations.append("cannot be affected: the installed version includes the fix")

    if decision.status != "not_affected":
        return violations

    if decision.confidence == "low":
        violations.append("not_affected needs medium or high confidence")

    justification = decision.justification
    if justification is None:
        violations.append("not_affected needs a justification")
    elif justification == "component_not_present":
        if installed is not False:
            violations.append("component_not_present needs evidence the package is absent")
    elif justification == "vulnerable_code_not_present":
        if fixed is not True:
            violations.append("vulnerable_code_not_present needs evidence the fix is installed")
        if runtime is None:
            violations.append("cannot confirm the fixed code is what's running")
        elif not runtime["complete"]:
            violations.append("the runtime check could not inspect every process")
        elif stale_code(runtime):
            violations.append("the fix is on disk, but running code predates it: restart needed")
    elif justification == "vulnerable_code_not_in_execute_path":
        if installed is not True:
            violations.append("execute-path claims need evidence the package is installed")
        if runtime is None:
            violations.append("execute-path claims need a successful runtime check")
        else:
            violations.extend(running_code(runtime))
            if not runtime["complete"]:
                violations.append("the runtime check could not inspect every process")
            if not runtime["listeners_known"]:
                violations.append("listeners could not be checked")
            # Idle only means something for a disabled service. A command or
            # library can be started or loaded at any moment.
            if not runtime["services_provided"]:
                violations.append("the package is not a service, so being idle now proves nothing")
    elif justification == "inline_mitigations_already_exist":
        cited = [known_ids[item] for item in decision.evidence_ids if item in known_ids]
        proven = [
            item
            for item in cited
            if item.check == "config_directive" and item.status == "ok" and item.result["matches"]
        ]
        if not proven:
            violations.append("a mitigation claim must cite a config line found on the host")
    else:
        violations.append(f"{justification} cannot be verified automatically; a person must decide")

    return violations
