# Threat model

## What needs protecting

- The hosts being assessed
- Host data such as configs, package lists and process details
- The integrity of verdicts, since a false `not_affected` could leave a real vulnerability unpatched
- This repository and its build pipeline

## Where trust ends

| Input | Trusted? | Why |
| --- | --- | --- |
| Advisory and scanner text | No | Anyone can publish a package or influence advisory text |
| Host evidence (config lines, process paths) | No | An attacker on the host can alter what it reports |
| Model output | No | It can be fooled or simply wrong |
| Allow-list, guard rules, fixed scripts | Yes | Reviewed code in this repository |

## Threats and controls

| Threat | Control | What remains |
| --- | --- | --- |
| Prompt injection pushes a false `not_affected` | The guard checks verdicts against all collected evidence | **A fooled model can cite a real but harmless config line as a mitigation. Human review is the control for this** |
| Model breaks out of the data block | Random tag on each block, plus the guard | Tags are defence in depth, not a guarantee |
| Model requests a harmful action | It can only name allow-listed read-only checks | None known within the allow-list |
| Command injection through arguments | Regex validation, arguments sent as one JSON value, no shell | No shell is involved. A bug in the probe itself is covered by review and tests |
| Evidence collection reads secrets | Sensitive paths refused, only matching lines returned, key files skipped | A secret on a line that matches a requested directive could be returned to the model. The model is local by default |
| Host data sent to a third party | Remote model URLs refused unless opted in, and the Compose setup keeps the model on a private network with no published port | The Ollama container keeps outbound access so it can download models |
| Agent loops or overloads a host | At most 4 extra checks per finding, with timeouts | Large fleets would need rate limits in a later phase |
| Probe code run on the target | Standard-library Python that only reads. A fixed, root-owned copy can be used with a narrow sudo rule, and it enforces its own limits | Sending the probe over SSH needs a sudo rule equal to full root, so that's for labs only |
| Controller compromised | Dedicated SSH key, host key checking, no agent forwarding, hardened container, and read-only checks with the fixed probe | **An attacker with the key and a lab-style sudo rule would have root on those hosts. Production should use the fixed probe and `from=` restrictions** |
| Man-in-the-middle on SSH | `StrictHostKeyChecking=yes`, so unknown hosts are refused | Depends on how `known_hosts` was first collected |
| Symbolic link used to reach secrets | The probe checks each file's real path before reading | None known |
| Compromised host lies about its state | Not solved | **The tool trusts what the host reports. A compromised host needs incident response, not this tool** |
| Audit log altered | Hash chain detects edits | An attacker who rewrites the whole file could rebuild the chain. Sending logs elsewhere is planned |
| Malicious text in reports or PR comments | Markdown, links, HTML and mentions neutralised | Reviewers should still read critically |
| Scanner output manipulates CI | The AI job has no write access and the gate ignores it | A misleading comment is possible, but it can't change a result |
| Supply chain attack on CI tools | Actions pinned to commit hashes, dependencies hash-locked, Dependabot enabled | Scanner tools installed by pip are version-pinned, not hash-pinned. Container images are pinned by tag |

## Mapping

| Framework item | Where it's addressed |
| --- | --- |
| OWASP LLM01: Prompt Injection | Guard, data tagging, injection cases |
| OWASP LLM05: Improper Output Handling | Schema validation, report sanitising |
| OWASP LLM06: Excessive Agency | Read-only allow-list, no remediation in Phase 1, human review |
| MITRE ATLAS AML.T0051: LLM Prompt Injection | Injection evaluation cases |

## Out of scope for Phase 1

Authentication and multi-user access, because it's a command line tool run by one operator. Also remediation, since it doesn't change anything on a host.
