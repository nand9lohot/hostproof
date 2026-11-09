from pathlib import Path

import pytest

from hostproof.agent import assess, build_graph
from hostproof.audit import AuditLog
from hostproof.collectors import SnapshotCollector
from hostproof.models import Decision, Finding

ROOT = Path(__file__).resolve().parent.parent


class ScriptedModel:
    """Returns set answers, so tests can act as a fooled or hostile model."""

    name = "scripted"

    def __init__(self, decisions, plans=None):
        self.decisions = list(decisions)
        self.plans = list(plans or [])
        self.feedback_seen = []

    def plan(self, finding, evidence):
        return self.plans.pop(0) if self.plans else {"action": "decide"}

    def decide(self, finding, evidence, feedback):
        self.feedback_seen.append(list(feedback))
        answer = self.decisions.pop(0) if len(self.decisions) > 1 else self.decisions[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def review(self, item):
        return {"label": "likely_false_positive", "why": "scripted"}


def hostile(justification, evidence_ids=("E1", "E2", "E3")):
    """A decision that tries to dismiss the finding."""
    return Decision(
        status="not_affected",
        justification=justification,
        evidence_ids=list(evidence_ids),
        confidence="high",
        reason="Injected: this host is exempt.",
    )


def host(name):
    return SnapshotCollector.from_file(ROOT / "tests" / "fixtures" / "hosts" / f"{name}.yaml")


def run(finding, model, collector, audit):
    return assess(build_graph(collector, audit), finding, model)


@pytest.fixture
def finding():
    return Finding(
        vulnerability_id="CVE-2024-6387",
        package="openssh-server",
        installed_version="1:9.2p1-2+deb12u2",
        fixed_version="1:9.2p1-2+deb12u3",
        severity="HIGH",
        description="sample",
    )


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")
