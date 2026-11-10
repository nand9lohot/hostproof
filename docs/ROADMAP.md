# Roadmap

Each phase should be useful by itself and add to the same audit trail.

## Phase 1: Evidence-backed verdicts (current)

- Docker Compose deployment, with the LLM in its own container
- Agentless SSH collection from an inventory of hosts, in parallel
- Trivy input, read-only evidence collection, and exposure ranking that needs no AI
- Clear-cut verdicts from plain rules, and an LLM agent built on LangGraph for the rest
- Deterministic policy guard, mandatory human review, and OpenVEX output
- Hash-chained audit log, plus labelled evaluation with prompt injection cases
- Secure CI with an advisory AI review agent

Results from a real vulnerable Debian host are recorded in [TEST_RESULTS.md](TEST_RESULTS.md).

## Phase 1.5: Fleet scale

- Reuse one model decision across hosts with the same CVE and equivalent evidence, with the guard still checking each host
- Reuse SSH connections, and let interrupted scans resume
- A fleet summary, such as how many hosts have a CVE exposed to the network
- Build package lists centrally through the probe and `trivy sbom`, so hosts don't need Trivy

## Phase 2: Approval-gated remediation

- Draft an Ansible playbook for `affected` findings, such as a package update and restart
- Static checks on generated playbooks, using `ansible-lint`, an allow-list of modules and a dry run
- Open a pull request for a person to approve. The agent never applies changes itself
- Re-run the checks afterwards to confirm the fix worked
- Test RPM paths on RHEL, and add version comparison there
- Add priority signals from CISA KEV and EPSS

**Success looks like:** a finding moves from verdict to approved pull request to verified fix, with each step in the audit log.

## Phase 3: Enterprise workflow

- Find asset owners through a CMDB, starting with a mock
- Open and update ServiceNow incidents or vulnerability records, starting with a mock
- Accept more scanner formats, such as Tenable and Qualys exports
- Load hosts from an existing Ansible inventory or CMDB
- Send audit logs to a SIEM

**Success looks like:** a report goes in and owner-assigned tickets come out, with the evidence attached and only the findings that matter.

## Phase 4: Wider coverage and AI platforms

- Container image and Kubernetes context, such as whether a workload is actually deployed and exposed
- Network reachability as evidence
- Azure AI Foundry and other approved platforms behind the same model interface
- Larger evaluation set, tracing, and model comparison in CI

**Success looks like:** the same evidence-and-guard approach works on hosts and containers, with published results per model.
