# BGP Hijack Lab Dashboard - Integration Guide

## Overview

This document provides complete instructions for setting up and running the unified **BGP Hijack Lab Dashboard**, a full-stack React + FastAPI application that serves as the control center for the entire lab environment.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  React Dashboard (Port 5173)             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Topology   │  │    Attack    │  │  Detection   │  │
│  │   Control    │  │ Orchestrator │  │     Feed     │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│           │                │                │            │
│           └────────────────┼────────────────┘            │
│                            │                             │
│                     HTTP + WebSocket                     │
│                      /api/* routes                       │
└─────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│            FastAPI Backend (Port 8000)                  │
│  ┌──────────────────────────────────────────────────┐  │
│  │         REST API Endpoints                       │  │
│  │  • /api/topology/* (init, reset, status)         │  │
│  │  • /api/attack/* (launch, reset)                 │  │
│  │  • /api/monitor/* (start, stop, subscribe)       │  │
│  │  • /api/analytics/* (detections, latency, ROV)   │  │
│  │  • /ws/events (WebSocket for real-time events)   │  │
│  └──────────────────────────────────────────────────┘  │
│           │                  │                 │         │
│           ▼                  ▼                 ▼         │
│   ┌────────────────┐  ┌─────────────┐  ┌─────────────┐ │
│   │ Topology Build │  │ ROV Engine  │  │  Anomaly    │ │
│   │  (Mininet)     │  │ (RPKI)      │  │  Detector   │ │
│   └────────────────┘  └─────────────┘  └─────────────┘ │
│                                                          │
│   ┌───────────────────┐  ┌────────────────────────┐    │
│   │ Attack Controller │  │ Monitoring Daemon      │    │
│   │ (vtysh injector)  │  │ (BGP UPDATE listener)  │    │
│   └───────────────────┘  └────────────────────────┘    │
│                                                          │
│   ┌──────────────────────────────────────────────┐    │
│   │ SQLite Database: data/bgp_events.db           │    │
│   └──────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
        ┌──────────────────┐  ┌──────────────┐
        │ Mininet Topology │  │ FRR Routers  │
        │ (Live Mode)      │  │ (AS1-AS99)   │
        └──────────────────┘  └──────────────┘
```

---

## Installation & Setup

### Phase 1: Backend Setup

#### 1.1 Update Python Dependencies

```bash
cd /home/amaima/bgp-hijack-lab
pip install --upgrade -r requirements.txt
```

This installs FastAPI, Uvicorn, and other required packages.

#### 1.2 Verify Backend Installation

```bash
python3 -c "import fastapi; import uvicorn; print('✓ FastAPI ready')"
```

#### 1.3 Create Required Directories

```bash
mkdir -p reports data frontend
```

### Phase 2: Frontend Setup

#### 2.1 Navigate to Frontend Directory

```bash
cd /home/amaima/bgp-hijack-lab/frontend
```

#### 2.2 Install Node.js Dependencies

```bash
npm install
```

This installs:
- React 18
- Tailwind CSS
- Lucide-React (icon library)
- Recharts (charting)
- jsPDF (PDF export)
- Vite (build tool)

#### 2.3 Verify Frontend Installation

```bash
npm run build
```

---

## Running the Dashboard

### Option A: Development Mode (Recommended for testing)

**Terminal 1 - Start the Backend API Server:**

```bash
cd /home/amaima/bgp-hijack-lab
PYTHONPATH=. python3 -m src.api.server
```

Expected output:
```
[INFO] Starting BGP Hijack Lab API Server...
[INFO] API Documentation: http://localhost:8000/docs
[INFO] Application startup complete [added 42 routes]
```

**Terminal 2 - Start the Frontend Dev Server:**

```bash
cd /home/amaima/bgp-hijack-lab/frontend
npm run dev
```

Expected output:
```
  VITE v5.0.7  ready in 245 ms

  ➜  Local:   http://localhost:5173/
  ➜  press h + enter to show help
```

**Terminal 3 (Optional) - Start Mininet Topology (Live Mode):**

```bash
cd /home/amaima/bgp-hijack-lab
source .venv/bin/activate
sudo python3 src/topology/builder.py
```

Then, open your browser to **http://localhost:5173**

### Option B: Production Build

```bash
# Build frontend
cd /home/amaima/bgp-hijack-lab/frontend
npm run build

# Serve production build (requires Node.js)
npm run preview

# In another terminal, start the backend
cd /home/amaima/bgp-hijack-lab
PYTHONPATH=. python3 -m src.api.server --host 0.0.0.0 --port 8000
```

---

## Dashboard Features & Usage

### 1. Topology Control Center

**Location:** Left panel of dashboard

**Features:**
- Interactive 6-AS topology visualization with SVG rendering
- Real-time LED status indicators:
  - 🟢 **ACTIVE**: AS is running and responsive
  - 🟡 **ATTACKING**: AS is launching or participating in attack
  - ⚫ **IDLE**: AS is down or not initialized
- Status grid showing each AS state

**Control Buttons:**

| Button | Action | Conditions |
|--------|--------|-----------|
| Initialize Topology | Sets up Mininet, FRR instances, ROA database | Only in baseline state |
| Start Monitoring | Activates BGP UPDATE listener & detection engines | After initialization |
| Reset Network | Returns network to clean baseline state | Always available |

**Example Workflow:**
1. Click "Initialize Topology"
2. Watch AS nodes turn green as they come online
3. Click "Start Monitoring" when all ASes are active
4. System begins listening for BGP UPDATEs

### 2. Attack Orchestrator

**Location:** Center panel of dashboard

**Three Poisoning Scenarios:**

#### Scenario 1: Exact Prefix Hijack (🎯)
- **Description:** AS99 announces `10.10.0.0/16` exactly
- **Victim Impact:** All traffic to victim prefix diverted to attacker
- **Detection:** Both ROV (INVALID) and anomaly detector trigger
- **Difficulty:** Easy

#### Scenario 2: Subprefix Injection (📍)
- **Description:** AS99 announces `10.10.1.0/24` (more-specific)
- **Victim Impact:** Only specific subnet traffic diverted
- **Detection:** ROV marks INVALID if ROA `maxLength` is restrictive
- **Difficulty:** Medium

#### Scenario 3: AS Path Leak (🔗)
- **Description:** AS99 announces victim prefix with forged path (AS99→AS10)
- **Victim Impact:** Looks legitimate via AS_PATH inspection
- **Detection:** Anomaly detector catches unauthorized origin
- **Difficulty:** Hard

**Live Console Log:**

- Displays all operations in terminal-style format
- Color-coded output:
  - 🟢 `[✓]` = Success
  - 🔴 `[✗]` = Error
  - 🟡 `[!]` = Warning
  - 🔵 `[INFO]` = Information

**Example Attack Flow:**
```
[INFO] Launching: Exact Prefix Hijack
[INFO] Injecting: 10.10.0.0/16 from AS99
[✓] Poisoning injection active (T0=1234567890.123)
[✓] AS_PATH: AS99←AS2←AS1
[✓] [DETECTION] Anomaly detected in 45ms
[✓] [ROV] INVALID certificate returned
```

### 3. Real-time Detection Feed

**Location:** Right panel of dashboard

**Features:**

- **Detection Engine Toggles:**
  - 🟢 ROV Engine (RPKI Validation) - Enable/Disable
  - 🟢 Anomaly Detector (Baseline Learning) - Enable/Disable

- **Filter Options:**
  - All Detections
  - Anomalies Only
  - ROV Results Only

- **Detection Stream Display:**
  - Prefix (CIDR notation)
  - Origin AS
  - AS_PATH (← indicates progression)
  - ROV Badge: **VALID** (🟢), **INVALID** (🔴), **NOT_FOUND** (🟡)
  - Anomaly Badge: **ANOMALY** (🟠) if detected
  - Timestamp (HH:MM:SS)

**Example Detection Entry:**
```
10.10.0.0/16
Origin: AS99
AS_PATH: AS99←AS2←AS1
[INVALID]  [ANOMALY]  14:32:01
```

### 4. Analytics Dashboard

**Bottom Panel - Two Charts:**

#### Chart 1: Detection Latency (Line Chart)
- **X-Axis:** Time (14:30, 14:31, 14:32...)
- **Y-Axis:** Latency in milliseconds (0-100ms range)
- **Data Series:** Detection latency per UPDATE
- **Interpretation:** Lower latency = faster threat detection
- **Goal:** Keep under 100ms for real-time response

#### Chart 2: ROV Distribution (Pie Chart)
- **VALID** (🟢 68%): Legitimate route origins
- **INVALID** (🔴 24%): Forged/unauthorized origins
- **NOT_FOUND** (🟡 8%): Routes not in ROA database
- **Interpretation:** High INVALID rate indicates successful detection

### 5. Export & Reporting

**PDF Report Button (Top-right)**

Click **"Export PDF"** to generate a lab report containing:
- Timestamp and system state
- ROV engine status (ENABLED/DISABLED)
- Anomaly detector status (ENABLED/DISABLED)
- Detection statistics (counts and percentages)
- Filename: `bgp-hijack-report.pdf`

---

## API Endpoints Reference

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/status` | Current lab state |

### Topology Control

| Method | Endpoint | Request Body | Description |
|--------|----------|--------------|-------------|
| POST | `/api/topology/init` | `TopologyInitRequest` | Initialize BGP topology |
| POST | `/api/topology/reset` | - | Reset network to baseline |

**Request Example:**
```json
POST /api/topology/init
{
  "live_mode": false,
  "timeout_sec": 30
}
```

**Response:**
```json
{
  "success": true,
  "message": "Topology initialized successfully",
  "roa_count": 42,
  "as_count": 6,
  "timestamp": 1234567890.123
}
```

### Attack Orchestration

| Method | Endpoint | Request Body | Description |
|--------|----------|--------------|-------------|
| POST | `/api/attack/launch` | `AttackLaunchRequest` | Launch poisoning attack |
| POST | `/api/attack/reset` | - | Withdraw all poisoned prefixes |

**Request Example:**
```json
POST /api/attack/launch
{
  "scenario": "exact_prefix",
  "target_prefix": "10.10.0.0/16",
  "attacker_as": 99
}
```

**Response:**
```json
{
  "success": true,
  "scenario": "exact_prefix",
  "timestamp": 1234567890.123,
  "detection_latency_ms": 45,
  "as_path": [99, 2, 1]
}
```

### Monitoring

| Method | Endpoint | Request Body | Description |
|--------|----------|--------------|-------------|
| POST | `/api/monitor/start` | `MonitorStartRequest` | Start monitoring |
| POST | `/api/monitor/stop` | - | Stop monitoring |

### Analytics

| Method | Endpoint | Query Params | Description |
|--------|----------|--------------|-------------|
| GET | `/api/analytics/detections` | `limit=100&offset=0&filter_type=all` | Retrieve detection events |
| GET | `/api/analytics/rov-distribution` | - | Get ROV result distribution |
| GET | `/api/analytics/latency-timeline` | `interval_minutes=5` | Get latency timeline |

### Reporting

| Method | Endpoint | Request Body | Description |
|--------|----------|--------------|-------------|
| POST | `/api/report/generate` | `ReportGenerateRequest` | Generate PDF/JSON report |
| GET | `/api/report/download/{name}` | - | Download generated report |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scenarios` | List all attack scenarios |
| GET | `/api/as-topology` | Get 6-AS topology config |
| WebSocket | `/ws/events` | Real-time event stream |

---

## Integration with Python Scripts

### Automatic Integrations

The FastAPI backend automatically bridges to your existing Python modules:

1. **Topology Builder**
   - Calls: `src/topology/builder.py`
   - Initializes Mininet and FRR instances
   - Loads ROA database

2. **Attack Controller**
   - Calls: `src/attacker/controller.py`
   - Functions: `exact_prefix_hijack()`, `subprefix_hijack()`, `path_manipulation_attack()`
   - Injects vtysh commands into AS99

3. **ROV Engine**
   - Calls: `src/monitor/rov_engine.py`
   - Validates routes against `config/roas.json`
   - Returns VALID/INVALID/NOT_FOUND

4. **Anomaly Detector**
   - Calls: `src/monitor/anomaly_detector.py`
   - Learns baseline in initial phase
   - Detects deviations during attack phase

5. **Report Generator**
   - Calls: `src/analysis/generate_report.py`
   - Reads from SQLite: `data/bgp_events.db`
   - Generates charts and summary

### Custom Integration Points

To add custom logic, modify these functions in `src/api/server.py`:

```python
@app.post("/api/attack/launch")
async def launch_attack(request: AttackLaunchRequest):
    # Add custom logic here
    attack_func = scenario_commands.get(request.scenario)
    # Execute attack
```

---

## Troubleshooting

### Frontend Issues

**Problem:** Dashboard won't load at http://localhost:5173

```bash
# Check if Vite server is running
lsof -i :5173

# Restart with verbose logging
npm run dev -- --host 0.0.0.0 --port 5173
```

**Problem:** API calls returning 404 or CORS errors

```bash
# Verify backend is running on port 8000
lsof -i :8000

# Check if proxy is configured correctly
cat frontend/vite.config.js  # Should have /api proxy
```

### Backend Issues

**Problem:** FastAPI server won't start

```bash
# Check Python version
python3 --version  # Should be 3.8+

# Verify imports
python3 -c "from fastapi import FastAPI; print('OK')"

# Check port 8000 is available
lsof -i :8000
```

**Problem:** Topology initialization fails

```bash
# Verify topology builder works
PYTHONPATH=. python3 -m src.topology.builder

# Check Mininet is installed
which mininet

# Check FRR installation
which vtysh
```

### General Debugging

**Enable verbose logging:**

```bash
# Backend
PYTHONPATH=. python3 -m src.api.server --log-level debug

# Frontend
npm run dev -- --debug
```

**Check database:**

```bash
# Open SQLite database
sqlite3 data/bgp_events.db "SELECT * FROM events LIMIT 10;"
```

**Monitor API calls:**

```bash
# In browser, open DevTools (F12)
# Go to Network tab
# Watch requests to /api/* endpoints
```

---

## Advanced Usage

### Programmatic Dashboard Control

You can control the dashboard programmatically via the API:

```python
import requests
import json

BASE_URL = "http://localhost:8000/api"

# Initialize topology
response = requests.post(f"{BASE_URL}/topology/init", json={
    "live_mode": False,
    "timeout_sec": 30
})
print(response.json())

# Launch attack
response = requests.post(f"{BASE_URL}/attack/launch", json={
    "scenario": "exact_prefix",
    "target_prefix": "10.10.0.0/16",
    "attacker_as": 99
})
print(response.json())

# Get detections
response = requests.get(f"{BASE_URL}/analytics/detections", params={
    "limit": 50,
    "filter_type": "anomaly"
})
print(response.json())
```

### WebSocket Real-time Monitoring

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8000/ws/events');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event:', data);
  
  if (data.type === 'attack_launched') {
    console.log('Attack started:', data.scenario);
  }
  if (data.type === 'detection') {
    console.log('Detection:', data.prefix, data.rov_result);
  }
};
```

### Custom Monitoring Dashboard

Extend the dashboard by adding new components:

1. Create new `.jsx` component in `frontend/src/components/`
2. Import in `BGPHijackDashboard.jsx`
3. Add API endpoints in `src/api/server.py`
4. Wire up event handlers

---

## Performance & Optimization

### Dashboard Performance

- **Latency Goal:** <50ms for API responses
- **WebSocket Events:** Max 10/second for UI stability
- **Chart Re-renders:** Debounced to 1/second

### Backend Optimization

- FastAPI runs on Uvicorn with multiple workers
- Async/await for non-blocking I/O
- Connection pooling for database

### Frontend Optimization

- Vite achieves <100ms dev rebuild
- React hooks prevent unnecessary re-renders
- Recharts optimize large datasets

---

## Support & Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI Schema:** http://localhost:8000/openapi.json

---

## Next Steps

1. ✅ Run backend: `python3 -m src.api.server`
2. ✅ Run frontend: `npm run dev` (in `frontend/`)
3. ✅ Open browser: http://localhost:5173
4. ✅ Click "Initialize Topology"
5. ✅ Click "Start Monitoring"
6. ✅ Launch an attack scenario
7. ✅ Watch detections appear in real-time
8. ✅ Generate PDF report when done

---

## Quick Reference

### Common Commands

```bash
# Backend
python3 -m src.api.server                    # Start API server
PYTHONPATH=. python3 -m src.utils.experiment_runner --db data/bgp_events.db --live

# Frontend
cd frontend && npm run dev                   # Dev server
npm run build                                # Production build
npm run lint                                 # Check code quality

# Database
sqlite3 data/bgp_events.db ".tables"         # List tables
sqlite3 data/bgp_events.db "SELECT COUNT(*) FROM events;"

# Topology (Live)
sudo python3 src/topology/builder.py         # Start Mininet
sudo mn -c                                   # Clean Mininet state
```

---

**Dashboard Version:** 1.0.0  
**Last Updated:** 2026-05-15  
**Maintained By:** BGP Hijack Lab Team
