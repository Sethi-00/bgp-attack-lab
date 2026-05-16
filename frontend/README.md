# BGP Hijack Dashboard Frontend

## Quick Start

### Installation

```bash
cd frontend
npm install
```

### Development

```bash
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

### Build for Production

```bash
npm run build
npm run preview
```

## Configuration

Create a `.env.local` file:

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_API_TIMEOUT=30000
```

## Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   └── BGPHijackDashboard.jsx    # Main dashboard component
│   ├── App.jsx                        # Root app component
│   ├── main.jsx                       # Entry point
│   └── index.css                      # Tailwind styles
├── package.json
├── vite.config.js
├── tailwind.config.js
├── postcss.config.js
└── index.html
```

## Features

- **Topology Visualization**: Interactive 6-AS network diagram with LED status indicators
- **Attack Orchestrator**: Buttons for all 3 hijack scenarios (Exact Prefix, Subprefix, AS Path Leak)
- **Real-time Detection Feed**: Streaming BGP UPDATE display with ROV/Anomaly badges
- **Console Logging**: Live terminal output from Python backend
- **Analytics Dashboard**: Detection latency chart and ROV distribution pie chart
- **PDF Export**: Generate lab reports
- **Dark Mode Terminal Aesthetic**: Slate/zinc with emerald/rose accents

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
