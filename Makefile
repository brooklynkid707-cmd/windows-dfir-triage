PY ?= python3

.PHONY: install data test demo clean

install:
	$(PY) -m pip install -r requirements.txt

data: ## regenerate the synthetic case, ground truth and evidence manifest
	$(PY) scripts/generate_case.py
	$(PY) -m dfirt manifest case --out examples/MANIFEST.json

test:
	$(PY) -m pytest -q

demo: ## verify evidence, triage, and write every committed example under examples/
	$(PY) -m dfirt verify case --manifest examples/MANIFEST.json
	$(PY) -m dfirt proctree case/WS-ACCT-07
	$(PY) -m dfirt execution case svchost.exe
	$(PY) -m dfirt execution case procexp64.exe
	$(PY) -m dfirt sigma case
	$(PY) -m dfirt timeline case --csv examples/timeline.csv
	$(PY) -m dfirt timeline case --key-events --md examples/timeline-key-events.md
	$(PY) -m dfirt triage case --manifest examples/MANIFEST.json --out examples/triage-report.md --json examples/findings.json --score tests/ground_truth.json --score-out examples/score.md

clean:
	rm -rf output/* .pytest_cache
	touch output/.gitkeep
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
