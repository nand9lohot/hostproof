"""Two stand-ins for a real model. Neither one contains any AI."""

import re

from hostproof.models import Decision

LOGIN_GRACE_ZERO = re.compile(r":\d+:\s*logingracetime\s+0\s*$", re.IGNORECASE)


class OfflineModel:
    """Hand-written rules for the three sample CVEs.

    It proves the pipeline works end to end, and CI uses it. It says nothing about
    AI accuracy, and it can't handle any other CVE.
    """

    name = "offline-rules (not AI)"

    MITIGATION_CHECKS = {
        "CVE-2024-6387": {"path": "/etc/ssh", "directive": "LoginGraceTime"},
        "CVE-2021-41773": {"path": "/etc/apache2", "directive": "Require"},
    }

    def plan(self, finding, evidence):
        args = self.MITIGATION_CHECKS.get(finding.vulnerability_id)
        if args and not any(item.check == "config_directive" for item in evidence):
            return {"action": "check", "check": "config_directive", "args": dict(args)}
        return {"action": "decide"}

    def decide(self, finding, evidence, feedback):
        by_check = {item.check: item for item in evidence}
        runtime = by_check.get("package_runtime")
        config = by_check.get("config_directive")
        ids = [item.id for item in evidence if item.status == "ok"]

        def verdict(status, reason, justification=None):
            confidence = "low" if status == "under_investigation" else "high"
            return Decision(
                status=status, justification=justification, evidence_ids=ids, confidence=confidence, reason=reason
            )

        if runtime is None or runtime.status != "ok" or not runtime.result["complete"]:
            return verdict("under_investigation", "Runtime state could not be fully checked.")
        if config is not None and config.status == "unknown":
            return verdict("under_investigation", "The relevant config could not be read.")
        matches = config.result["matches"] if config else []
        if finding.vulnerability_id == "CVE-2024-6387" and any(LOGIN_GRACE_ZERO.search(line) for line in matches):
            reason = "LoginGraceTime 0 removes the vulnerable path, but leaves denial-of-service risk."
            return verdict("not_affected", reason, "inline_mitigations_already_exist")
        joined = " ".join(" ".join(matches).lower().split())
        if finding.vulnerability_id == "CVE-2021-41773" and "<directory />" in joined and "require all denied" in joined:
            reason = "The root directory has Require all denied, which blocks the traversal."
            return verdict("not_affected", reason, "inline_mitigations_already_exist")
        state = runtime.result
        active = state["processes"] or state["libraries"] or state["services_enabled"] or state["listeners"]
        if state["services_provided"] and state["listeners_known"] and not active and not state["setuid_files"]:
            reason = "Installed, but its service is disabled and nothing from the package is running."
            return verdict("not_affected", reason, "vulnerable_code_not_in_execute_path")
        return verdict("affected", "The vulnerable package is installed and active.")

    def review(self, item):
        return {"label": "needs_review", "why": "Offline mode doesn't analyse findings."}


class HostileModel:
    """Acts like a fully fooled model that tries to dismiss every finding.

    It shows what the guard does in the worst case, without relying on a real
    model being tricked on cue.
    """

    name = "hostile-simulation (not AI)"

    def plan(self, finding, evidence):
        return {"action": "decide"}

    def decide(self, finding, evidence, feedback):
        return Decision(
            status="not_affected",
            justification="vulnerable_code_not_in_execute_path",
            evidence_ids=[item.id for item in evidence],
            confidence="high",
            reason="The advisory says this host is exempt.",
        )

    def review(self, item):
        return {"label": "likely_false_positive", "why": "Told to ignore this."}
