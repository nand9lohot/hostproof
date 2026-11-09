"""The command line interface."""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .agent import HostJob, assess_fleet
from .audit import AuditLog, verify
from .ci_review import read_sarif, review_summary
from .collectors import make_collector
from .evaluate import load_cases, run_eval, to_markdown as eval_markdown
from .findings import load_findings
from .inventory import load_inventory
from .llm import DEFAULT_MODEL, DEFAULT_URL, OllamaModel
from .outputs import summarise, to_markdown, to_openvex
from .rules import EXPOSURE_MEANING, priority

STYLES = {"affected": "red", "not_affected": "green", "under_investigation": "yellow"}
RULES_ONLY = "Rules only, with no AI. Clear-cut findings get a verdict, and the rest are ranked for a person."


def add_model_args(parser, default):
    parser.add_argument("--llm", choices=["ollama", "none"], default=default)
    parser.add_argument("--model", default=os.environ.get("HOSTPROOF_MODEL", DEFAULT_MODEL), help="Ollama model name")
    parser.add_argument("--ollama-url", default=os.environ.get("HOSTPROOF_OLLAMA_URL", DEFAULT_URL))
    parser.add_argument(
        "--allow-remote-llm",
        action="store_true",
        default=os.environ.get("HOSTPROOF_ALLOW_REMOTE_LLM") == "1",
        help="allow sending host evidence to an Ollama server that isn't on this machine",
    )


def make_model(args, preflight=True):
    if args.llm == "none":
        return None
    model = OllamaModel(args.model, args.ollama_url, args.allow_remote_llm)
    if preflight:
        model.preflight()
    return model


def model_name(model):
    return model.name if model else "none (rules only)"


def show_verdicts(console, verdicts, limit):
    table = Table(title="Findings, most urgent first (draft, needs human review)")
    for name in ("Host", "Vulnerability", "Package", "Exposure", "Verdict", "Why", "By"):
        table.add_column(name, overflow="fold")
    ordered = sorted(verdicts, key=priority)
    for verdict in ordered[:limit]:
        colour = STYLES[verdict.status]
        status = f"[{colour}]{verdict.status}[/{colour}]"
        if verdict.justification:
            status += f"\n{verdict.justification}"
        why = verdict.reason
        if verdict.guard_violations:
            why += "\nGuard: " + "; ".join(verdict.guard_violations)
        finding = verdict.finding
        table.add_row(verdict.host, finding.vulnerability_id, finding.package, verdict.exposure, status, why, verdict.decided_by)
    console.print(table)
    if len(ordered) > limit:
        console.print(f"Showing the top {limit} of {len(ordered)}. The report has them all.")


def cmd_scan(args, console):
    model = make_model(args)
    if model is None:
        console.print(f"[yellow]{RULES_ONLY}[/yellow]")
    if bool(args.inventory) == bool(args.target):
        raise ValueError("use either --inventory, or --target with --findings")
    if args.inventory:
        hosts = load_inventory(args.inventory)
    else:
        if not args.findings:
            raise ValueError("--target needs --findings")
        hosts = [(make_collector(target), args.findings) for target in args.target]
    out = Path(args.out) / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    jobs = []
    for collector, findings_path in hosts:
        audit_name = re.sub(r"[^A-Za-z0-9._-]", "_", collector.host)
        jobs.append(HostJob(collector, load_findings(findings_path), AuditLog(out / "audit" / f"{audit_name}.jsonl")))
    total = sum(len(job.findings) for job in jobs)
    console.print(f"Assessing {total} findings on {len(jobs)} host(s), using up to {args.workers} at a time...")
    verdicts, failures = assess_fleet(jobs, model, args.max_model_findings, args.workers)

    show_verdicts(console, verdicts, args.show)
    console.print(f"\n{len(verdicts)} findings by exposure:")
    for name, count in summarise(verdicts):
        console.print(f"  {count:>5}  {EXPOSURE_MEANING[name]}", highlight=False)

    unknown = sum(verdict.exposure == "unknown" for verdict in verdicts)
    if unknown > len(verdicts) / 2:
        console.print(
            "[yellow]Most findings are unknown, usually because some processes couldn't be inspected. "
            "Scan as root for a complete picture.[/yellow]"
        )

    for host, reason in failures.items():
        console.print(f"[red]Not assessed: {host}: {reason}[/red]", highlight=False)

    (out / "vex.json").write_text(json.dumps(to_openvex(verdicts), indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(to_markdown(verdicts, model_name(model)), encoding="utf-8")
    console.print(f"\nWrote OpenVEX, report and audit logs to {out}")
    return 3 if failures else 0


def cmd_eval(args, console):
    model = make_model(args)
    if model is None:
        console.print(f"[yellow]These aren't AI accuracy results. {RULES_ONLY}[/yellow]")
    results = run_eval(load_cases(args.cases), model)
    text = eval_markdown(results, model_name(model))
    console.print(text, markup=False)
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    unsafe = sum(item.unsafe for item in results)
    if args.fail_on_unsafe and unsafe:
        console.print(f"[red]{unsafe} unsafe dismissal(s) got past the guard.[/red]")
        return 1
    return 0


def cmd_review(args, console):
    text = review_summary(read_sarif(args.sarif_dir), make_model(args, preflight=False))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    console.print(text, markup=False)
    return 0  # Advisory by design: this never fails a build.


def cmd_verify(args, console):
    valid, message = verify(args.path)
    console.print(("Valid: " if valid else "TAMPERED: ") + message, markup=False)
    return 0 if valid else 1


def build_parser():
    parser = argparse.ArgumentParser(prog="hostproof", description="An LLM agent that validates scanner findings against Linux hosts. Don't trust the finding. Verify the host.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="assess scanner findings on one or more hosts")
    scan.add_argument("--inventory", help="YAML file listing hosts and their reports")
    scan.add_argument("--findings", help="Trivy JSON or native findings file, used with --target")
    scan.add_argument("--target", action="append", help="ssh:USER@ADDRESS, local or snapshot:FILE (repeatable)")
    scan.add_argument("--out", default="runs")
    scan.add_argument("--max-model-findings", type=int, default=25, help="across all hosts, most exposed first")
    scan.add_argument("--workers", type=int, default=8, help="hosts to check at the same time")
    scan.add_argument("--show", type=int, default=20, help="rows to show on screen")
    add_model_args(scan, "ollama")
    scan.set_defaults(func=cmd_scan)

    evaluate = commands.add_parser("eval", help="score the agent on labelled cases")
    evaluate.add_argument("--cases", default="tests/fixtures/regression_cases.yaml")
    evaluate.add_argument("--out", help="write results to this Markdown file")
    evaluate.add_argument("--fail-on-unsafe", action="store_true")
    add_model_args(evaluate, "ollama")
    evaluate.set_defaults(func=cmd_eval)

    review = commands.add_parser("ci-review", help="advisory AI review of SARIF scanner results")
    review.add_argument("--sarif-dir", required=True)
    review.add_argument("--out")
    add_model_args(review, "ollama")
    review.set_defaults(func=cmd_review)

    audit = commands.add_parser("verify-audit", help="check an audit log hasn't been altered")
    audit.add_argument("path")
    audit.set_defaults(func=cmd_verify)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    console = Console(width=120)
    try:
        return args.func(args, console)
    except (ValueError, OSError, RuntimeError) as exc:
        console.print(f"Error: {exc}", highlight=False, markup=False)
        return 2


if __name__ == "__main__":
    sys.exit(main())
