"""The most important tests: a hostile model must not be able to dismiss a live finding."""

import pytest

from conftest import ScriptedModel, host, hostile, run
from hostproof.guard import check_decision
from hostproof.llm import ModelError
from hostproof.models import Decision, Evidence
from standins import HostileModel

ALL_JUSTIFICATIONS = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]


def facts(installed=True, fixed=False, **runtime):
    defaults = {
        "processes": [], "libraries": [], "services_enabled": [], "services_provided": ["x.service"],
        "setuid_files": [], "listeners": [], "complete": True, "listeners_known": True,
    }
    package = {"package": "pkg"}
    return [
        Evidence(id="E1", check="package_status", args=package, status="ok", result={"installed": installed}),
        Evidence(id="E2", check="version_at_least", args={**package, "version": "2"}, status="ok", result={"result": fixed}),
        Evidence(id="E3", check="package_runtime", args=package, status="ok", result={**defaults, **runtime}),
    ]


@pytest.fixture
def pkg(finding):
    return finding.model_copy(update={"package": "pkg"})


@pytest.mark.parametrize("justification", ALL_JUSTIFICATIONS)
def test_hostile_model_cannot_dismiss_running_service(finding, audit, justification):
    verdict = run(finding, ScriptedModel([hostile(justification)]), host("web01"), audit)
    assert verdict.status == "under_investigation"
    assert verdict.decided_by == "guard"
    assert verdict.model_status == "not_affected"


def test_attack_simulation_is_blocked(finding, audit):
    verdict = run(finding, HostileModel(), host("web01"), audit)
    assert verdict.status == "under_investigation" and verdict.decided_by == "guard"


def test_unrestarted_patch_is_affected_without_asking_a_model(finding, audit):
    model = ScriptedModel([hostile("vulnerable_code_not_present")])
    verdict = run(finding, model, host("patched02"), audit)
    assert verdict.status == "affected" and verdict.decided_by == "rules"
    assert model.feedback_seen == []


def test_fabricated_evidence_id_is_rejected(pkg):
    violations = check_decision(hostile("component_not_present", ["E99"]), pkg, facts(installed=False))
    assert any("does not exist" in item for item in violations)


def test_verdict_must_cite_evidence(pkg):
    assert check_decision(hostile("component_not_present", []), pkg, facts(installed=False))


def test_low_confidence_cannot_dismiss(pkg):
    decision = hostile("component_not_present").model_copy(update={"confidence": "low"})
    assert check_decision(decision, pkg, facts(installed=False))


def test_cannot_claim_absent_when_installed(pkg):
    assert check_decision(hostile("component_not_present"), pkg, facts())


def test_cannot_claim_fix_when_old_code_is_running(pkg):
    stale = [{"pid": "1", "path": "/x", "deleted": True}]
    assert check_decision(hostile("vulnerable_code_not_present"), pkg, facts(fixed=True, processes=stale))


def test_cannot_claim_affected_when_absent(pkg):
    decision = Decision(status="affected", evidence_ids=["E1"], confidence="high")
    assert check_decision(decision, pkg, facts(installed=False))


@pytest.mark.parametrize(
    "runtime,expected",
    [
        ({"setuid_files": ["/usr/bin/sudo"]}, "setuid"),
        ({"services_provided": []}, "not a service"),
        ({"services_enabled": ["x.service"]}, "enabled"),
        ({"libraries": [{"pid": "1", "path": "/l.so", "deleted": False}]}, "libraries"),
        ({"listeners": ["0.0.0.0:22"]}, "listeners"),
        ({"complete": False}, "every process"),
        ({"listeners_known": False}, "listeners could not"),
    ],
)
def test_idle_claim_needs_a_truly_idle_disabled_service(pkg, runtime, expected):
    violations = check_decision(hostile("vulnerable_code_not_in_execute_path"), pkg, facts(**runtime))
    assert any(expected in item for item in violations)


def test_idle_disabled_service_can_be_dismissed(pkg):
    assert check_decision(hostile("vulnerable_code_not_in_execute_path"), pkg, facts()) == []


def test_retry_gets_the_broken_rules_as_feedback(finding, audit):
    good = Decision(status="affected", evidence_ids=["E1", "E3"], confidence="high", reason="Running.")
    model = ScriptedModel([hostile("component_not_present"), good])
    verdict = run(finding, model, host("web01"), audit)
    assert verdict.status == "affected" and verdict.decided_by == "model"
    assert model.feedback_seen[0] == []
    assert "absent" in model.feedback_seen[1][0]


def test_model_failure_fails_safe(finding, audit):
    verdict = run(finding, ScriptedModel([ModelError("connection refused")]), host("web01"), audit)
    assert verdict.status == "under_investigation"
    assert "connection refused" in verdict.reason


def test_known_limit_guard_cannot_judge_a_mitigations_meaning(finding, audit):
    """Documents a real limit, and why every verdict still goes to a person.

    A fooled model can cite a real but harmless config line as a mitigation. The
    guard confirms the line exists, not that it helps. If this test ever fails
    because the guard got smarter, update docs/THREAT_MODEL.md as well.
    """
    plan = {"action": "check", "check": "config_directive", "args": {"path": "/etc/ssh", "directive": "Port"}}
    decision = hostile("inline_mitigations_already_exist", ["E4"])
    verdict = run(finding, ScriptedModel([decision], plans=[plan]), host("web01"), audit)
    assert verdict.status == "not_affected"
    assert verdict.review_required is True
