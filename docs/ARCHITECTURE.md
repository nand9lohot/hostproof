# Architecture

HostProof is an LLM agent, built with LangGraph and Ollama, that tests scanner findings against what's really happening on a host.

## The parts

```mermaid
flowchart LR
    subgraph U[Untrusted input]
      R[Scanner reports]
    end
    subgraph C[Controller: Docker Compose]
      subgraph HP[HostProof container]
        I[Inventory: inventory.py]
        A[Agent: agent.py]
        V[Allow-list: checks.py]
        CL[SSH collector: collectors.py]
        K[Clear-cut rules: rules.py]
        G[Policy guard: guard.py]
        L[Ollama client: llm.py]
        W[Report, OpenVEX, audit logs]
      end
      subgraph LM[LLM container]
        O[(Ollama and local model)]
      end
    end
    subgraph H[Each Linux host]
      P[probe.py, read-only]
      S[proc, package database, config files]
    end
    R -->|findings| A
    I -->|hosts| A
    A -->|asks for a check| V
    V -->|validated| CL
    CL -->|SSH, host key verified| P
    P -->|reads| S
    P -->|JSON evidence| CL
    A --> K
    A <-->|prompts and JSON| L
    L <-->|private network| O
    A -->|proposed verdict| G
    G -->|accepted or downgraded| W
    W --> Q[Person reviews]
```

## The agent's flow

```mermaid
stateDiagram-v2
    [*] --> baseline
    baseline --> clear_cut
    clear_cut --> guard: settled by rules
    clear_cut --> finish: no model
    clear_cut --> plan: needs reasoning
    plan --> run_check: wants evidence
    run_check --> plan
    plan --> decide: ready
    decide --> guard
    guard --> decide: broke a rule, one retry
    guard --> finish
    finish --> [*]
```

## Who decides what

| Decision | Made by | Can the model change it? |
| --- | --- | --- |
| Which checks exist | `checks.py` | No |
| Baseline facts | `probe.py` | No |
| Exposure ranking | `rules.py` | No |
| Clear-cut verdicts | `rules.py` | No |
| Which extra check to run | Model, within the allow-list | Yes, within limits |
| Harder verdicts | Model proposes, guard checks | Only if the evidence allows it |
| Final action | A person | No |

## The trust boundaries

1. **Scanner report to agent:** advisory text can contain prompt injection, so it's length-limited and tagged as data.
2. **Model to agent:** model output is untrusted, so requests go through the allow-list and verdicts go through the guard.
3. **Agent to host:** only four read-only checks exist. Arguments are validated on both sides, and SSH host keys are always verified.
4. **Host to agent:** a host's data is treated as untrusted too. A compromised host can lie, so this is prioritisation rather than forensics.
5. **Agent to report:** untrusted text is sanitised before it's written to Markdown.
