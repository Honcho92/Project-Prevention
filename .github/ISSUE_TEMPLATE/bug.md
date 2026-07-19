---
name: Bug report
about: Something is broken in the code, not in the detection logic
title: "[Bug] "
labels: bug
assignees: ''
---

## What happened

What went wrong? Include the command you ran, the error you got, and what
you expected to happen.

## How to reproduce

Step-by-step:

1. `cd scam-shield`
2. `PYTHONPATH=. python -m scam_shield demo`
3. See error: ...

## Environment

- OS: (Windows 10 / 11, macOS, Linux)
- Python version: `python --version`
- Ollama version (if relevant): `curl http://localhost:11434/api/version`
- Scam-Shield version: (look at `scam_shield/__init__.py`)

## Logs / output

Paste the full error output or stack trace. Wrap in triple backticks.
