PYTHON ?= python

.PHONY: setup check lint format test demo

setup:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install --no-deps -e .

check:
	$(PYTHON) scripts/check.py

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m ruff format .

test:
	$(PYTHON) -m pytest

demo:
	$(PYTHON) -m wids_ai.cli analyze data/pcaps
