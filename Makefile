.PHONY: install test eval

MODEL ?= qwen2.5:7b
PY := .venv/bin

install:
	python3 -m venv .venv
	$(PY)/pip install --require-hashes -r requirements-dev.txt
	$(PY)/pip install --no-deps -e .

test:
	$(PY)/pytest

# Scores a local Ollama model on the synthetic regression cases.
eval:
	$(PY)/hostproof eval --llm ollama --model $(MODEL) --out results/eval-$(subst :,-,$(subst /,-,$(MODEL))).md
