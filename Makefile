# =============================================================================
# BGP Hijack Lab — Makefile
# Manages environment setup, topology lifecycle, experiments, and reporting.
# =============================================================================

PYTHON     := python3
VENV       := .venv
PIP        := $(VENV)/bin/pip
PYTEST     := $(VENV)/bin/pytest
MININET_BIN:= sudo mn

.PHONY: all help setup install clean topology attack-1 attack-2 attack-3 \
        monitor test lint report

# --------------------------------------------------------------------------- #
# Default target: show help
# --------------------------------------------------------------------------- #
help:
	@echo ""
	@echo "  BGP Hijack Simulation Lab — Available Targets"
	@echo "  ─────────────────────────────────────────────"
	@echo "  make setup      — Create virtualenv and install dependencies"
	@echo "  make install    — Install Python packages only"
	@echo "  make topology   — Start the Mininet BGP topology"
	@echo "  make monitor    — Start the BGP monitor daemon"
	@echo "  make attack-1   — Launch exact-prefix hijack (Attack Scenario 1)"
	@echo "  make attack-2   — Launch subprefix hijack   (Attack Scenario 2)"
	@echo "  make attack-3   — Launch AS-path manip      (Attack Scenario 3)"
	@echo "  make test       — Run unit test suite"
	@echo "  make report     — Generate analysis figures and summary report"
	@echo "  make clean      — Remove build artifacts and __pycache__"
	@echo ""

# --------------------------------------------------------------------------- #
# Environment setup
# --------------------------------------------------------------------------- #
setup:
	@echo "[setup] Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@echo "[setup] Installing dependencies..."
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "[setup] Done. Activate with: source $(VENV)/bin/activate"

install:
	$(PIP) install -r requirements.txt

# --------------------------------------------------------------------------- #
# Lab lifecycle
# --------------------------------------------------------------------------- #
topology:
	@echo "[lab] Starting Mininet BGP topology (requires sudo)..."
	sudo $(PYTHON) src/topology/builder.py

monitor:
	@echo "[lab] Starting BGP monitor daemon..."
	$(PYTHON) -m src.monitor.daemon --db data/bgp_events.db

attack-1:
	@echo "[attack] Launching Attack 1 — Exact Prefix Hijack..."
	$(PYTHON) -m src.attacker.controller --scenario exact_prefix

attack-2:
	@echo "[attack] Launching Attack 2 — Subprefix Hijack..."
	$(PYTHON) -m src.attacker.controller --scenario subprefix

attack-3:
	@echo "[attack] Launching Attack 3 — AS Path Manipulation..."
	$(PYTHON) -m src.attacker.controller --scenario path_manipulation

# --------------------------------------------------------------------------- #
# Testing
# --------------------------------------------------------------------------- #
test:
	@echo "[test] Running test suite..."
	$(PYTEST) tests/ -v --cov=src --cov-report=term-missing

test-monitor:
	$(PYTEST) tests/test_monitor.py -v

test-rov:
	$(PYTEST) tests/test_rov.py -v

# --------------------------------------------------------------------------- #
# Analysis & Reporting
# --------------------------------------------------------------------------- #
report:
	@echo "[report] Generating analysis figures..."
	$(PYTHON) src/analysis/generate_report.py --db data/bgp_events.db --output reports/

# --------------------------------------------------------------------------- #
# Cleanup
# --------------------------------------------------------------------------- #
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .coverage
	@echo "[clean] Done."

clean-all: clean
	rm -rf $(VENV) data/*.db reports/*.png