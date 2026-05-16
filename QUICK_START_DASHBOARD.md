# BGP Hijack Lab Dashboard - Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Install Dependencies (2 min)

```bash
cd /home/amaima/bgp-hijack-lab

# Backend dependencies
pip install -r requirements.txt

# Frontend dependencies
cd frontend
npm install
cd ..
```

### Step 2: Start Backend API (1 min)

```bash
# Terminal 1
PYTHONPATH=. python3 -m src.api.server
```

You should see:
```
[INFO] Starting BGP Hijack Lab API Server...
[INFO] API Documentation: http://localhost:8000/docs
Uvicorn running on http://0.0.0.0:8000
```

### Step 3: Start Frontend (1 min)

```bash
# Terminal 2
cd frontend
npm run dev
```

You should see:
```
VITE v5.0.7  ready in 245 ms
➜  Local:   http://localhost:5173/
```

### Step 4: Open Dashboard (1 min)

Open browser to: **http://localhost:5173**

---

## 🎮 First Run Walkthrough

### 1️⃣ Initialize Topology

```
1. Click "Initialize Topology" button (left panel)
2. Wait for all 6 AS nodes to turn GREEN (🟢)
3. Check console: "[✓] Topology initialized successfully"
```

### 2️⃣ Start Monitoring

```
1. Click "Start Monitoring" button
2. Check console: "[✓] Monitor started. Listening for BGP UPDATEs..."
3. Detection feed is now active (right panel)
```

### 3️⃣ Launch Attack

```
1. Choose a poisoning scenario (center panel):
   - 🎯 Exact Prefix Hijack
   - 📍 Subprefix Injection  
   - 🔗 AS Path Leak

2. Click the button
3. Watch console for attack timeline:
   [ATTACK] Launching: Exact Prefix Hijack
   [INFO] Poisoning injection active (T0=...)
   [DETECTION] Anomaly detected in 45ms
   [ROV] INVALID certificate returned
```

### 4️⃣ View Detections

```
1. Check Real-time Detection Feed (right panel)
2. See badges:
   - 🟢 VALID (green) = Legitimate route
   - 🔴 INVALID (red) = Forged route detected
   - 🟡 NOT_FOUND (yellow) = Route not in ROA
   - 🟠 ANOMALY (orange) = Baseline violation

3. Toggle engines to enable/disable:
   - ROV Engine (RPKI Validation)
   - Anomaly Detector (Baseline Learning)
```

### 5️⃣ View Analytics

```
1. Bottom panel shows two charts:
   - Detection Latency (line chart) = speed of detection
   - ROV Distribution (pie chart) = validation results

2. High INVALID% = Good detection coverage
3. Low latency = Fast threat response
```

### 6️⃣ Export Report

```
1. Click "Export PDF" (top right)
2. File saved as: bgp-hijack-report.pdf
3. Contains: state, statistics, detection counts
```

### 7️⃣ Reset Network

```
1. Click "Reset Network" to go back to baseline
2. All attack indicators clear
3. Ready for next scenario
```

---

## 🧰 Common Tasks

### View API Documentation

Go to: **http://localhost:8000/docs**

Interactive Swagger UI showing all endpoints with request/response examples.

### Test API from Command Line

```bash
# Initialize topology
curl -X POST http://localhost:8000/api/topology/init \
  -H "Content-Type: application/json" \
  -d '{"live_mode": false}'

# Launch exact prefix hijack
curl -X POST http://localhost:8000/api/attack/launch \
  -H "Content-Type: application/json" \
  -d '{
    "scenario": "exact_prefix",
    "target_prefix": "10.10.0.0/16"
  }'

# Get detection statistics
curl http://localhost:8000/api/analytics/rov-distribution
```

### Debug Mode

```bash
# Backend with verbose logging
python3 -m src.api.server --log-level debug

# Frontend with verbose logging
cd frontend && npm run dev -- --debug
```

### Kill Stuck Processes

```bash
# Kill backend
lsof -i :8000 | grep LISTEN | awk '{print $2}' | xargs kill -9

# Kill frontend
lsof -i :5173 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

---

## 🚨 Troubleshooting

| Problem | Solution |
|---------|----------|
| `Cannot find module 'src'` | Run from repo root: `cd /home/amaima/bgp-hijack-lab` |
| Port 8000 already in use | `kill $(lsof -t -i:8000)` |
| Port 5173 already in use | `kill $(lsof -t -i:5173)` |
| React components not rendering | Check browser console (F12 > Console tab) |
| API calls return 404 | Verify backend is running on port 8000 |
| Dashboard loads but buttons disabled | Click "Initialize Topology" first |

---

## 📚 Key Files

| File | Purpose |
|------|---------|
| `frontend/src/components/BGPHijackDashboard.jsx` | Main React component (2000+ lines) |
| `src/api/server.py` | FastAPI backend with all endpoints |
| `frontend/vite.config.js` | Frontend build config with /api proxy |
| `DASHBOARD_INTEGRATION.md` | Full documentation (20+ pages) |

---

## 🌐 URLs

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:5173 |
| API Server | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| API Docs (ReDoc) | http://localhost:8000/redoc |
| WebSocket | ws://localhost:8000/ws/events |

---

## 💡 Tips

- **Dark Mode:** Dashboard uses slate/zinc with emerald/rose accents (optimized for eyes at night)
- **Domain-Specific Labels:** Uses BGP terminology, not generic UI labels
- **Real-time Updates:** WebSocket streams detection events as they happen
- **State Machine:** Baseline → Attacking → Mitigating (clear state flow)
- **Scannable UI:** High contrast, clear sections, visual hierarchy

---

## 🎓 Next Steps

1. Read [DASHBOARD_INTEGRATION.md](DASHBOARD_INTEGRATION.md) for detailed API reference
2. Explore [http://localhost:8000/docs](http://localhost:8000/docs) for interactive API testing
3. Try all 3 attack scenarios to understand different detection methods
4. Enable/disable ROV and Anomaly engines to see their effect
5. Generate PDF reports and analyze detection patterns

---

## 📞 Support

- **Backend Issues:** Check [DASHBOARD_INTEGRATION.md#Troubleshooting](DASHBOARD_INTEGRATION.md#troubleshooting)
- **Frontend Issues:** Check browser DevTools (F12 → Console, Network tabs)
- **API Questions:** Open interactive docs at http://localhost:8000/docs

---

**Dashboard Ready! 🎉**

Start with: `python3 -m src.api.server` + `npm run dev`
