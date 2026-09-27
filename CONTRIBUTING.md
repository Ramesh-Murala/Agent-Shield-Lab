# Contributing

Thank you for improving AgentShield Lab. Small, test-backed pull requests are welcome.

1. Refine a rule in `agentshield/scanner.py` and add benign and malicious fixtures in `evaluation/cases.json`.
2. Add meaningful Python tests in `tests/` and run `python -m pytest -q` and `python -m evaluation.run --check`.
3. Generate the static sample gallery with `python scripts/build_static.py` if its output changes.
4. Explain false-positive tradeoffs in the pull request.

Please do not include real credentials, personal data, or live exfiltration endpoints in test fixtures.
