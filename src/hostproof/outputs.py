"""Write verdicts as an OpenVEX draft and a readable Markdown report."""

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone

from .rules import EXPOSURE_MEANING, EXPOSURE_ORDER, priority

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
MARKDOWN_ESCAPES = (("|", "\\|"), ("<", "&lt;"), (">", "&gt;"), ("[", "\\["), ("]", "\\]"), ("`", "'"))


def clean(text):
    """Stop untrusted text adding Markdown structure, links or mentions to a report."""
    flattened = " ".join(text.split())
    for char, safe in MARKDOWN_ESCAPES:
        flattened = flattened.replace(char, safe)
    return flattened.replace("@", "@​")


def to_openvex(verdicts, author="HostProof (draft, needs human review)"):
    summary = [verdict.model_dump(exclude={"evidence"}) for verdict in verdicts]
    fingerprint = hashlib.sha256(json.dumps(summary, sort_keys=True).encode()).hexdigest()[:16]
    statements = []
    for verdict in verdicts:
        finding = verdict.finding
        statement = {
            "vulnerability": {"name": finding.vulnerability_id},
            "products": [
                {
                    "@id": f"urn:hostproof:host:{verdict.host}",
                    "subcomponents": [{"@id": f"urn:hostproof:package:{finding.package}"}],
                }
            ],
            "status": verdict.status,
            "status_notes": verdict.reason,
        }
        if verdict.status == "not_affected":
            statement["justification"] = verdict.justification
            statement["impact_statement"] = verdict.reason
        elif verdict.status == "affected":
            target = f"version {finding.fixed_version} or later" if finding.fixed_version else "a fixed version"
            statement["action_statement"] = f"Upgrade {finding.package} to {target}, and restart anything using it."
        statements.append(statement)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:hostproof:vex:{fingerprint}",
        "author": author,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": statements,
    }


def summarise(verdicts):
    """Count findings by exposure. This is the headline number for a report."""
    counts = Counter(verdict.exposure for verdict in verdicts)
    return [(name, counts[name]) for name in EXPOSURE_ORDER if counts[name]]


def to_markdown(verdicts, model_name):
    ordered = sorted(verdicts, key=priority)
    lines = [
        "# HostProof report",
        "",
        f"Model: {clean(model_name)}",
        "",
        "Draft for human review. A person must confirm every verdict before anyone acts on it.",
        "",
        f"## Summary: {len(verdicts)} findings",
        "",
        "| Exposure | Findings | Meaning |",
        "| --- | --- | --- |",
    ]
    lines += [f"| {name} | {count} | {EXPOSURE_MEANING[name]} |" for name, count in summarise(verdicts)]
    lines += [
        "",
        "## Findings, most urgent first",
        "",
        "| Host | Vulnerability | Package | Severity | Exposure | Verdict | Justification | Decided by |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for verdict in ordered:
        finding = verdict.finding
        lines.append(
            f"| {clean(verdict.host)} | {clean(finding.vulnerability_id)} | {clean(finding.package)} "
            f"| {clean(finding.severity)} | {verdict.exposure} | {verdict.status} "
            f"| {verdict.justification or '-'} | {verdict.decided_by} |"
        )
    for verdict in ordered:
        lines += [
            "",
            f"## {clean(verdict.host)}: {clean(verdict.finding.vulnerability_id)} in {clean(verdict.finding.package)}",
            "",
            f"**Verdict:** {verdict.status}" + (f" ({verdict.justification})" if verdict.justification else ""),
            "",
            f"**Reason:** {clean(verdict.reason)}",
        ]
        if verdict.guard_violations:
            lines += ["", "**Why the guard stepped in:**", ""]
            lines += [f"- {clean(item)}" for item in verdict.guard_violations]
        lines += ["", "**Evidence:**", ""]
        for item in verdict.evidence:
            mark = " (cited)" if item.id in verdict.cited_evidence else ""
            args = ", ".join(f"{key}={value}" for key, value in item.args.items())
            detail = json.dumps(item.result, sort_keys=True) if item.result else item.status
            lines.append(f"- {item.id}{mark}: {item.check}({clean(args)}) -> {clean(detail)[:400]}")
    return "\n".join(lines) + "\n"
