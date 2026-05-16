# 🎯 BGP Hijack Lab Dashboard - Start Here

## Welcome! 👋

You now have a **complete, production-ready web dashboard** for your BGP Hijacking Simulation Lab. This file will guide you to the right documentation for your needs.

---

## ⚡ Super Quick Start (Choose One)

### Option 1: Fully Automated (Recommended)
```bash
cd /home/amaima/bgp-hijack-lab
./setup-dashboard.sh       # Install everything (first time only)
./start-dashboard.sh       # Start both services
# Open http://localhost:5173
```

### Option 2: Manual Setup (3 terminals)
```bash
# Terminal 1: Backend
cd /home/amaima/bgp-hijack-lab
PYTHONPATH=. python3 -m src.api.server

# Terminal 2: Frontend
cd /home/amaima/bgp-hijack-lab/frontend
npm install  # first time only
npm run dev

# Then open http://localhost:5173
```

### Option 3: With Live Mininet (add a 3rd terminal)
```bash
# Terminal 3 (after backend + frontend are running)
cd /home/amaima/bgp-hijack-lab
sudo python3 src/topology/builder.py
```

---

## 📚 Documentation - Pick Your Path

### 🏃 "I Just Want It Running" (5 minutes)
→ Read: **[QUICK_START_DASHBOARD.md](QUICK_START_DASHBOARD.md)**
- Step-by-step setup
- First-run walkthrough
- Common tasks
- Troubleshooting

### 🎓 "I Want to Understand It" (30 minutes)
→ Read: **[DASHBOARD_README.md](DASHBOARD_README.md)**
- Architecture overview
- Feature explanations
- Dashboard walkthrough
- API reference

### 📖 "I Need Everything" (comprehensive)
→ Read: **[DASHBOARD_INTEGRATION.md](DASHBOARD_INTEGRATION.md)**
- Complete technical documentation
- Installation phases
- All endpoints detailed
- Advanced usage
- Performance optimization

### 💻 "I'm Developing This"
→ Read: **[frontend/README.md](frontend/README.md)**
- Frontend setup
- Build process
- Project structure
- Dev commands

### 📋 "What's Included?" (checklist)
→ Read: **[DASHBOARD_DELIVERY_SUMMARY.md](DASHBOARD_DELIVERY_SUMMARY.md)**
- Complete file manifest
- What was delivered
- Capabilities checklist
- Next steps

---

## 🗂️ File Structure

```
Dashboard Files:
├── setup-dashboard.sh                  ← Run this first (one time)
├── start-dashboard.sh                  ← Run this to start services
│
├── frontend/                           ← React app
│   ├── src/
│   │   ├── components/
│   │   │   └── BGPHijackDashboard.jsx  ← Main component (2000+ lines)
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── package.json
│   ├── vite.config.js
│   └── README.md
│
├── src/api/                            ← Backend
│   ├── server.py                       ← FastAPI app (800+ lines)
│   └── __init__.py
│
└── Documentation:
    ├── QUICK_START_DASHBOARD.md        ← START HERE (5 min read)
    ├── DASHBOARD_README.md             ← Overview & features
    ├── DASHBOARD_INTEGRATION.md        ← Complete reference
    ├── DASHBOARD_DELIVERY_SUMMARY.md   ← What you got
    └── THIS FILE (Dashboard.START_HERE.md)
```

---

## 🚀 First Time Setup

### Step 1: Automated Setup (Recommended)
```bash
cd /home/amaima/bgp-hijack-lab
chmod +x setup-dashboard.sh start-dashboard.sh
./setup-dashboard.sh
```

Expected output:
```
✓ All dependencies found
✓ Python 3.x
✓ Frontend dependencies already installed
✓ Backend dependencies ready
```

### Step 2: Start Services
```bash
./start-dashboard.sh
```

Expected output:
```
✓ Backend ready at http://localhost:8000
✓ Frontend ready at http://localhost:5173
```

### Step 3: Open Dashboard
Open browser to: **http://localhost:5173**

---

## 🎮 First Run Steps

Once the dashboard loads:

1. **Click "Initialize Topology"**
   - Watch AS nodes turn green
   - All 6 ASes come online

2. **Click "Start Monitoring"**
   - BGP UPDATE listener active
   - Ready for attacks

3. **Choose an Attack Scenario**
   - 🎯 Exact Prefix Hijack
   - 📍 Subprefix Injection
   - 🔗 AS Path Leak

4. **Watch Detections Appear**
   - Check Real-time Detection Feed
   - See INVALID/ANOMALY badges
   - View latency in charts

5. **Export Report**
   - Click "Export PDF" button
   - Report generated with statistics

6. **Reset Network**
   - Click "Reset Network"
   - Back to baseline for next scenario

---

## 🌐 URLs

| Service | URL |
|---------|-----|
| **Dashboard** | http://localhost:5173 |
| **API Server** | http://localhost:8000 |
| **API Docs** | http://localhost:8000/docs |
| **ReDoc** | http://localhost:8000/redoc |

---

## 🆘 Quick Troubleshooting

### Port Already in Use
```bash
# Kill old process
lsof -i :5173 | grep LISTEN | awk '{print $2}' | xargs kill -9
lsof -i :8000 | grep LISTEN | awk '{print $2}' | xargs kill -9

# Then run start-dashboard.sh again
./start-dashboard.sh
```

### Backend Won't Start
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Reinstall dependencies
pip install -r requirements.txt

# Try starting manually
PYTHONPATH=. python3 -m src.api.server
```

### Frontend Won't Load
```bash
# Check if Vite is running
lsof -i :5173

# Clear node_modules and reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### API Calls Failing
```bash
# Test backend health
curl http://localhost:8000/api/health

# Check browser console (F12)
# Check Network tab for API errors
```

For more help: See **QUICK_START_DASHBOARD.md** or **DASHBOARD_INTEGRATION.md**

---

## 💡 What This Dashboard Does

### Topology Control
- Initialize 6-AS network
- Real-time status monitoring
- Network reset

### Attack Orchestration
- Launch 3 different BGP attacks
- Live console output
- Withdraw attacks

### Detection Monitoring
- Real-time BGP UPDATE stream
- ROV (RPKI) validation results
- Anomaly detection alerts
- Event filtering

### Analytics
- Detection latency chart
- ROV distribution statistics
- PDF report export

### API-First Design
- All features available via REST API
- WebSocket for real-time updates
- Full Swagger documentation

---

## 🎯 Common Commands

```bash
# One-time setup
./setup-dashboard.sh

# Start everything
./start-dashboard.sh

# Stop everything
Ctrl+C  # Stops both services

# Manual start (if not using start-dashboard.sh)
# Terminal 1:
PYTHONPATH=. python3 -m src.api.server

# Terminal 2:
cd frontend && npm run dev

# Build for production
cd frontend
npm run build    # Creates dist/ folder
npm run preview  # Test production build
```

---

## 📚 Learn More

| Need | Document | Read Time |
|------|----------|-----------|
| Quick setup | QUICK_START_DASHBOARD.md | 5 min |
| Overview | DASHBOARD_README.md | 15 min |
| Details | DASHBOARD_INTEGRATION.md | 30 min |
| Code | frontend/README.md | 10 min |
| Everything | DASHBOARD_DELIVERY_SUMMARY.md | 20 min |

---

## ✅ What You Have

- ✅ Fully functional React dashboard
- ✅ FastAPI backend with 15+ endpoints
- ✅ Real-time detection streaming
- ✅ 3 attack scenarios
- ✅ Analytics with charts
- ✅ PDF report export
- ✅ Complete documentation
- ✅ Automated setup scripts

---

## 🎓 Next Steps

1. **Right Now:** Run `./setup-dashboard.sh && ./start-dashboard.sh`
2. **Then:** Open http://localhost:5173
3. **Try:** Click through all features
4. **Read:** QUICK_START_DASHBOARD.md when ready
5. **Explore:** Check API docs at http://localhost:8000/docs
6. **Learn:** Read DASHBOARD_INTEGRATION.md for details

---

## 🏁 Ready?

```bash
cd /home/amaima/bgp-hijack-lab
./setup-dashboard.sh
./start-dashboard.sh
# Open http://localhost:5173
```

**That's it!** Your dashboard is now running. 🎉

---

## 📞 Reference

- **Questions?** Check the appropriate documentation above
- **Error?** See troubleshooting in QUICK_START_DASHBOARD.md
- **API?** Visit http://localhost:8000/docs
- **More info?** Read DASHBOARD_INTEGRATION.md

---

**Version:** 1.0.0  
**Status:** ✅ Ready to Use  
**Last Updated:** 2026-05-15

🚀 **Let's go build something amazing with BGP security research!**
