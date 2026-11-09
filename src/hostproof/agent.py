"""The agent, built as a LangGraph state machine.

    baseline -> clear_cut -> plan <-> run_check
                    |          |
                    |          v
                    |        decide -> guard --> finish
                    |          ^          |        ^
                    |          +-- retry -+        |
                    +------------------------------+
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from .audit import AuditLog
from .checks import MODEL_CHECKS, CheckRejected
from .collectors import HostUnreachable
from .guard import check_decision
from .llm import ModelError
from .models import Decision, Evidence, Finding, Verdict
from .rules import clear_cut_decision, exposure_of, urgency

MAX_EXTRA_CHECKS = 4
MAX_RETRIES = 1


@dataclass
class HostJob:
    """One host to assess: how to reach it, its findings, and its own audit log."""

    collector: object
    findings: list[Finding]
    audit: AuditLog


class State(TypedDict, total=False):
    finding: Finding
    model: object
    evidence: list[Evidence]
    extra_checks: int
    next_check: dict | None
    decision: Decision | None
    first_decision: Decision | None
    decided_by_rules: bool
    violations: list[str]
    retries: int
    model_error: str
    verdict: Verdict


def build_graph(collector, audit):
    """Create the graph for one host. It's reused for every finding on that host."""

    def collect(check, args, evidence, origin):
        evidence_id = f"E{len(evidence) + 1}"
        try:
            status, result = collector.run(check, args)
            item = Evidence(id=evidence_id, check=check, args=args, status=status, result=result)
        except CheckRejected as exc:
            item = Evidence(id=evidence_id, check=check, args={}, status="rejected", note=str(exc))
        audit.write("check", origin=origin, evidence=item.model_dump())
        return item

    def baseline(state):
        """Always run these checks, so the guard has facts the model didn't choose."""
        finding = state["finding"]
        audit.write("finding", host=collector.host, finding=finding.model_dump())
        evidence = []
        package = finding.package
        evidence.append(collect("package_status", {"package": package}, evidence, "baseline"))
        if finding.fixed_version:
            args = {"package": package, "version": finding.fixed_version}
            evidence.append(collect("version_at_least", args, evidence, "baseline"))
        evidence.append(collect("package_runtime", {"package": package}, evidence, "baseline"))
        return {"evidence": evidence, "extra_checks": 0, "retries": 0, "violations": []}

    def clear_cut(state):
        """Settle simple cases with plain code, without spending any model time."""
        decision = clear_cut_decision(state["finding"].package, state["evidence"])
        return {"decision": decision, "decided_by_rules": decision is not None}

    def after_clear_cut(state):
        if state["decided_by_rules"]:
            return "guard"
        return "plan" if state.get("model") else "finish"

    def plan(state):
        """Ask the model whether it wants one more check."""
        if state["extra_checks"] >= MAX_EXTRA_CHECKS:
            return {"next_check": None}
        try:
            step = state["model"].plan(state["finding"], state["evidence"])
        except ModelError as exc:
            return {"next_check": None, "model_error": str(exc)}
        audit.write("plan", step=step)
        return {"next_check": step if step.get("action") == "check" else None}

    def run_check(state):
        """Run the check the model asked for, if it's allowed."""
        step = state["next_check"]
        check = str(step.get("check", ""))
        args = step.get("args") or {}
        evidence = list(state["evidence"])
        if check not in MODEL_CHECKS:
            note = f"check not available to the model: {check[:60]!r}"
            item = Evidence(id=f"E{len(evidence) + 1}", check="rejected", args={}, status="rejected", note=note)
            audit.write("check", origin="model", evidence=item.model_dump())
            evidence.append(item)
        elif not any(item.check == check and item.args == args for item in evidence):
            evidence.append(collect(check, args, evidence, "model"))
        # This count goes up even for a repeat request, so a model can't loop forever.
        return {"evidence": evidence, "extra_checks": state["extra_checks"] + 1}

    def decide(state):
        """Ask the model for a verdict, passing along any rules it just broke."""
        if state.get("model_error"):
            return {"decision": None}
        try:
            decision = state["model"].decide(state["finding"], state["evidence"], state["violations"])
        except ModelError as exc:
            return {"decision": None, "model_error": str(exc)}
        audit.write("decision", decision=decision.model_dump())
        update = {"decision": decision}
        if state.get("first_decision") is None:
            update["first_decision"] = decision
        return update

    def guard(state):
        """Check the decision against the evidence, using plain rules."""
        decision = state["decision"]
        if decision is None:
            return {"violations": [state.get("model_error", "no decision was produced")]}
        violations = check_decision(decision, state["finding"], state["evidence"])
        audit.write("guard", violations=violations)
        return {"violations": violations, "retries": state["retries"] + (1 if violations else 0)}

    def after_guard(state):
        if not state["violations"] or state["decision"] is None or state["decided_by_rules"]:
            return "finish"
        return "decide" if state["retries"] <= MAX_RETRIES else "finish"

    def finish(state):
        """Build the verdict. Anything that isn't settled stays with a person."""
        decision = state.get("decision")
        first = state.get("first_decision")
        violations = state["violations"]
        shared = {
            "host": collector.host,
            "finding": state["finding"],
            "exposure": exposure_of(state["finding"].package, state["evidence"]),
            "evidence": state["evidence"],
            "model_status": first.status if first else None,
            "model_justification": first.justification if first else None,
        }
        if decision is not None and not violations:
            verdict = Verdict(
                **shared,
                status=decision.status,
                justification=decision.justification,
                confidence=decision.confidence,
                reason=decision.reason,
                cited_evidence=decision.evidence_ids,
                decided_by="rules" if state["decided_by_rules"] else "model",
            )
        else:
            if state.get("model_error"):
                reason = f"The model failed, so a person needs to assess this: {state['model_error'][:200]}"
            elif state.get("model"):
                reason = "No verdict passed the policy guard, so a person needs to assess this."
            else:
                reason = "The code is present, but it was ranked without model analysis. A person should assess it."
            verdict = Verdict(
                **shared,
                status="under_investigation",
                confidence="low",
                reason=reason,
                cited_evidence=[],
                decided_by="guard" if state.get("model") else "person",
                guard_violations=violations,
            )
        audit.write("verdict", verdict=verdict.model_dump(exclude={"evidence", "finding"}))
        return {"verdict": verdict}

    graph = StateGraph(State)
    for node in (baseline, clear_cut, plan, run_check, decide, guard, finish):
        graph.add_node(node.__name__, node)
    graph.add_edge(START, "baseline")
    graph.add_edge("baseline", "clear_cut")
    graph.add_conditional_edges("clear_cut", after_clear_cut)
    graph.add_conditional_edges("plan", lambda state: "run_check" if state.get("next_check") else "decide")
    graph.add_edge("run_check", "plan")
    graph.add_edge("decide", "guard")
    graph.add_conditional_edges("guard", after_guard)
    graph.add_edge("finish", END)
    return graph.compile()


def assess(graph, finding, model):
    """Run the agent for one finding. Pass model=None to use plain rules only."""
    final = graph.invoke({"finding": finding, "model": model}, {"recursion_limit": 40})
    return final["verdict"]


def first_pass(job):
    """Check one host and apply the plain rules. Returns (graph, verdicts, failure)."""
    try:
        job.collector.preflight()
    except HostUnreachable as exc:
        return None, [], str(exc)
    graph = build_graph(job.collector, job.audit)
    return graph, [assess(graph, finding, None) for finding in job.findings], None


def assess_fleet(jobs, model, max_model_findings, workers=8):
    """Assess every host, then spend model time on the most exposed findings first.

    The first pass runs on hosts in parallel, and uses no model. A local model can
    take a minute per finding, so only the top unresolved findings across the whole
    fleet go to it, one at a time. Returns (verdicts, failures), where failures maps
    each unreachable host to its error.
    """
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(first_pass, jobs))
    verdicts = []
    graphs = []
    failures = {}
    for job, (graph, host_verdicts, failure) in zip(jobs, results):
        if failure is not None:
            failures[job.collector.host] = failure
        verdicts += host_verdicts
        graphs += [graph] * len(host_verdicts)
    if model is not None:
        unresolved = [index for index, verdict in enumerate(verdicts) if verdict.decided_by == "person"]
        unresolved.sort(key=lambda index: urgency(verdicts[index]))
        for index in unresolved[:max_model_findings]:
            verdicts[index] = assess(graphs[index], verdicts[index].finding, model)
    return verdicts, failures
