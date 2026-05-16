# BGP Hijack Simulation & Detection Lab

A fully reproducible lab for staging, observing, and detecting BGP hijacking attacks inside a software-defined mini-internet.

This repository builds a realistic network security lab using Mininet and FRRouting. It simulates a six-AS topology, executes hijack scenarios, applies two detection engines on each BGP UPDATE, and generates analysis figures from the recorded events.

---

## Key Features

- Real FRRouting `bgpd` instances running inside Mininet namespaces
- Six autonomous systems with a victim, attacker, transit, and legitimate peers
- Three attack scenarios:
  - Exact prefix hijack
  - More-specific subprefix hijack
  - AS path manipulation / route leak
- Two detection engines:
  - Behavioral anomaly detection
  - RPKI Route Origin Validation (ROV)
- Event logging to SQLite and automated report generation
- Dry-run mode for environments without live Mininet/FRR

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Project Structure](#project-structure)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Running the Lab](#running-the-lab)
6. [Attack Scenarios](#attack-scenarios)
7. [Detection Methods](#detection-methods)
8. [Analysis & Reporting](#analysis--reporting)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)
11. [File Reference](#file-reference)

---

## How It Works

The lab builds a miniature internet with six AS routers:

- `AS1` — core transit
- `AS2` — regional ISP west
- `AS3` — regional ISP east
- `AS10` — victim AS owning `10.10.0.0/16`
- `AS20` — legitimate peer
- `AS99` — attacker AS

The topology runs inside Mininet. Each AS uses FRRouting to establish eBGP sessions. A monitoring pipeline receives BGP UPDATEs and applies both:

- Route Origin Validation via `src.monitor.rov_engine`
- Baseline anomaly detection via `src.monitor.anomaly_detector`

All detection results are written to `data/bgp_events.db` and can be analyzed by `src.analysis.generate_report.py`.

---

## Project Structure

```
bgp-hijack-lab/
├── config/
│   ├── roas.json
│   └── frr/
│       ├── as1/
│       ├── as2/
│       ├── as3/
│       ├── as10/
│       ├── as20/
│       └── as99/
├── data/
├── docs/
├── reports/
├── requirements.txt
├── Makefile
├── Dockerfile
├── pyproject.toml
└── src/
    ├── analysis/
    │   └── generate_report.py
    ├── attacker/
    │   └── controller.py
    ├── monitor/
    │   ├── anomaly_detector.py
    │   ├── models.py
    │   ├── monitor.py
    │   └── rov_engine.py
    ├── topology/
    │   └── builder.py
    └── utils/
        └── experiment_runner.py
```

---

## Requirements

### Software

- Ubuntu 24.04 LTS (recommended)
- Python 3.12
- Mininet
- FRRouting (FRR)
- Open vSwitch
- Python dependencies from `requirements.txt`

### Hardware

- 4 GB RAM minimum
- 8 GB RAM recommended
- 5 GB disk minimum

---

## Installation

1. Clone the repository:

```bash 
git clone <your-repo-url> bgp-hijack-lab
cd bgp-hijack-lab
mkdir -p data reports
```

2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

3. Install Mininet and FRRouting using your distribution package manager.

> If you are on Ubuntu 24.04, follow the supported Mininet and FRR installation steps used in this lab.

---

## Running the Lab

### Option A — Dry-run simulation

Use this to exercise the full detection pipeline without a live Mininet topology.

```bash
source .venv/bin/activate
PYTHONPATH=. python3 -m src.utils.experiment_runner --db data/bgp_events.db
PYTHONPATH=. python3 -m src.analysis.generate_report --db data/bgp_events.db --output reports/
```

This runs the baseline, executes the three hijack scenarios in simulated mode, writes `data/bgp_events.db`, and generates figures in `reports/`.

### Option B — Live topology with Mininet + FRR

1. Start the topology as root:

```bash
source .venv/bin/activate
sudo python3 src/topology/builder.py
```

2. In another terminal, run the experiment in live mode:

```bash
cd /home/amaima/bgp-hijack-lab
source .venv/bin/activate
PYTHONPATH=. python3 -m src.utils.experiment_runner --db data/bgp_events.db --live
PYTHONPATH=. python3 -m src.analysis.generate_report --db data/bgp_events.db --output reports/
```

3. When finished, stop the topology from the Mininet prompt:

```bash
mininet> exit
```

### Manual attack runner

The attack controller module can launch individual hijack scenarios for testing.

```bash
PYTHONPATH=. python3 -m src.attacker.controller --scenario exact_prefix
PYTHONPATH=. python3 -m src.attacker.controller --scenario subprefix
PYTHONPATH=. python3 -m src.attacker.controller --scenario path_manipulation
```

> Note: the current CLI path is primarily useful for exercise/testing rather than a fully instrumented live attack injection interface.

---

## Attack Scenarios

| Scenario | Description | Detection Behavior |
|---|---|---|
| Exact prefix hijack | AS99 announces `10.10.0.0/16` | Detected by anomaly; RPKI returns INVALID |
| Subprefix hijack | AS99 announces `10.10.1.0/24` | Detected by anomaly; RPKI depends on ROA `maxLength` |
| AS path manipulation | AS99 announces victim prefix with a forged AS_PATH | Detected by anomaly; RPKI may return VALID |

---

## Detection Methods

### Behavioral anomaly detection

Builds a baseline of legitimate prefix origins, then flags deviations such as:

- a known prefix announced by a new origin AS
- a new/unauthorized prefix
- an unexpected AS path

### RPKI Route Origin Validation

Validates every announcement against the lab ROA database in `config/roas.json`.
Results include:

- `VALID`
- `INVALID`
- `NOT_FOUND`

This is implemented in `src.monitor.rov_engine`.

---

## Analysis & Reporting

Generate figures and a summary report from the SQLite event database:

```bash
PYTHONPATH=. python3 -m src.analysis.generate_report --db data/bgp_events.db --output reports/
```

Output files include:

- `reports/detection_latency.png`
- `reports/detection_coverage.png`
- `reports/rov_distribution.png`
- `reports/event_timeline.png`
- `reports/summary_report.txt`

---

## Testing

Run the full test suite:

```bash
source .venv/bin/activate
PYTHONPATH=. python3 -m pytest tests/ -v --cov=src --cov-report=html
```

Run the monitor unit tests only:

```bash
PYTHONPATH=. python3 -m pytest tests/test_monitor.py -v
```

---

## Troubleshooting

- `ModuleNotFoundError: No module named 'src'`
  - Ensure you run commands from the repository root and set `PYTHONPATH=.`.

- `Mininet / FRR` issues
  - Verify `mininet` and `frr` are installed and available on Ubuntu 24.04.

- `BGP sessions do not converge`
  - Check `/tmp/frr-logs/asX/bgpd-stderr.log` and `/tmp/frr-logs/asX/zebra-stderr.log`.

- `Stale Mininet state`

```bash
sudo mn -c
sudo pkill -9 -f bgpd 2>/dev/null
sudo pkill -9 -f zebra 2>/dev/null
sudo systemctl restart frr
```

---

## File Reference

| File | Purpose |
|---|---|
| `src/utils/experiment_runner.py` | Orchestrates baseline, attack scenarios, detection, and metrics collection |
| `src/analysis/generate_report.py` | Generates charts and a text summary from the event database |
| `src/topology/builder.py` | Builds the Mininet + FRR lab topology on Ubuntu 24.04 |
| `src/attacker/controller.py` | Defines the three hijack attack scenarios |
| `src/monitor/monitor.py` | Central BGP monitor engine and event persistence |
| `src/monitor/anomaly_detector.py` | Baseline learning and anomaly detection logic |
| `src/monitor/rov_engine.py` | RPKI ROV validation engine |
| `config/roas.json` | Lab ROA database used for RPKI validation |
| `config/frr/` | Static FRR configuration for each AS |

---

## Makefile Targets

- `make setup` — create venv and install Python dependencies
- `make topology` — start the Mininet BGP topology
- `make attack-1` / `make attack-2` / `make attack-3` — launch attack scenarios
- `make report` — generate analysis figures
- `make test` — run tests with coverage
- `make clean` — remove caches and artifacts

---

## Notes

- The default experiment runner uses dry-run mode when `--live` is not provided.
- The lab is designed to keep all traffic inside the host machine; no real Internet traffic is emitted.
