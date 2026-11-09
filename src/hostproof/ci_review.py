"""Advisory AI review of scanner results in CI.

Pass or fail is decided by the scanners and the CI gate job, never here. Scanner
output can contain attacker-controlled text, so a fooled model must only be able
to produce a wrong comment. It has no way to change a build result.
"""

import json
from pathlib import Path

from .llm import ModelError
from .outputs import clean

MAX_FINDINGS = 20
VALID_LABELS = {"likely_real", "likely_false_positive", "needs_review"}


def read_sarif(folder):
    items = []
    for path in sorted(Path(folder).rglob("*.sarif")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            items.append({"tool": path.name, "rule": "unreadable", "message": "SARIF could not be read", "location": ""})
            continue
        for run in data.get("runs", []):
            tool = str(run.get("tool", {}).get("driver", {}).get("name", path.stem))
            for result in run.get("results", []):
                location = ""
                places = result.get("locations") or []
                if places:
                    physical = places[0].get("physicalLocation", {})
                    file = physical.get("artifactLocation", {}).get("uri", "")
                    line = physical.get("region", {}).get("startLine", "")
                    location = f"{file}:{line}"
                items.append(
                    {
                        "tool": tool[:60],
                        "rule": str(result.get("ruleId", ""))[:120],
                        "message": str(result.get("message", {}).get("text", ""))[:800],
                        "location": location[:200],
                    }
                )
    return items


def review_summary(items, model):
    lines = [
        "## AI review of security scan results",
        "",
        "Advisory only. Scanner results decide whether this build passes, and this review can't change that.",
        "",
    ]
    if not items:
        lines.append("All scanners came back clean, so there was nothing to review.")
        return "\n".join(lines) + "\n"

    lines += [
        f"Model: {clean(model.name) if model else 'none'}",
        "",
        "| Tool | Rule | Location | AI label | Why |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in items[:MAX_FINDINGS]:
        try:
            if model is None:
                raise ModelError("no model")
            answer = model.review(item)
            label = answer.get("label")
            label = label if label in VALID_LABELS else "needs_review"
            why = str(answer.get("why", ""))[:300]
        except ModelError:
            label, why = "needs_review", "The model was unavailable."
        lines.append(
            f"| {clean(item['tool'])} | {clean(item['rule'])} | {clean(item['location'])} | {label} | {clean(why)} |"
        )
    if len(items) > MAX_FINDINGS:
        lines += ["", f"{len(items) - MAX_FINDINGS} more findings were not reviewed. See the scanner results."]
    return "\n".join(lines) + "\n"
