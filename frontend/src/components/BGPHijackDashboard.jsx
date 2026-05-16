/**
 * BGP Hijack Lab Dashboard
 * ========================
 * A unified control center for the BGP Hijacking Simulation & Detection Lab
 * Built with React, Tailwind CSS, Lucide-React, and Recharts
 * 
 * Features:
 * - Topology Control Center with real-time AS status
 * - Attack Orchestrator with 3 hijack scenarios
 * - Real-time Detection Feed with ROV/Anomaly badges
 * - Analytics Dashboard with detection latency & ROV distribution
 * - PDF Report Export
 * 
 * State Flow: Baseline → Attack → Mitigation
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Play, Stop, RotateCcw, AlertTriangle, CheckCircle2, TrendingUp,
  Activity, Zap, Network, Download, Eye, EyeOff, Terminal, Filter
} from 'lucide-react';
import {
  LineChart, Line, PieChart, Pie, Cell, ResponsiveContainer,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend
} from 'recharts';
import jsPDF from 'jspdf';

// ============================================================================
// Constants
// ============================================================================

const AS_CONFIG = {
  AS1: { label: 'Transit Core', color: '#3b82f6', x: 50, y: 20 },
  AS2: { label: 'ISP West', color: '#8b5cf6', x: 20, y: 50 },
  AS3: { label: 'ISP East', color: '#8b5cf6', x: 80, y: 50 },
  AS10: { label: 'Victim', color: '#ef4444', x: 50, y: 80 },
  AS20: { label: 'Peer', color: '#10b981', x: 65, y: 65 },
  AS99: { label: 'Attacker', color: '#f97316', x: 35, y: 65 }
};

const ATTACK_SCENARIOS = [
  {
    id: 'exact_prefix',
    title: 'Exact Prefix Hijack',
    description: 'AS99 announces 10.10.0.0/16 (victim prefix)',
    icon: '🎯',
    command: 'exact_prefix'
  },
  {
    id: 'subprefix',
    title: 'Subprefix Injection',
    description: 'AS99 announces 10.10.1.0/24 (more-specific)',
    icon: '📍',
    command: 'subprefix'
  },
  {
    id: 'path_manipulation',
    title: 'AS Path Leak',
    description: 'AS99 forges AS_PATH with victim origin',
    icon: '🔗',
    command: 'path_manipulation'
  }
];

const SAMPLE_DETECTIONS = [
  { prefix: '10.10.0.0/16', origin: 'AS99', path: 'AS99←AS2←AS1', rov: 'INVALID', anomaly: true, timestamp: '14:32:01' },
  { prefix: '10.10.1.0/24', origin: 'AS99', path: 'AS99←AS2←AS1', rov: 'INVALID', anomaly: true, timestamp: '14:32:03' },
  { prefix: '192.0.2.0/24', origin: 'AS20', path: 'AS20←AS1', rov: 'VALID', anomaly: false, timestamp: '14:32:05' },
  { prefix: '198.51.100.0/24', origin: 'AS2', path: 'AS2←AS1', rov: 'VALID', anomaly: false, timestamp: '14:32:07' },
];

// ============================================================================
// Main Dashboard Component
// ============================================================================

export default function BGPHijackDashboard() {
  // State Management
  const [systemState, setSystemState] = useState('baseline'); // baseline, attacking, mitigating
  const [asStatus, setAsStatus] = useState(
    Object.keys(AS_CONFIG).reduce((acc, as) => ({ ...acc, [as]: 'idle' }), {})
  );
  const [consoleLog, setConsoleLog] = useState([
    '[SYSTEM] BGP Hijack Lab Dashboard initialized...',
    '[SYSTEM] Waiting for topology initialization',
  ]);
  const [detectionFeed, setDetectionFeed] = useState(SAMPLE_DETECTIONS);
  const [rovEnabled, setRovEnabled] = useState(true);
  const [anomalyEnabled, setAnomalyEnabled] = useState(true);
  const [selectedFilter, setSelectedFilter] = useState('all');
  const [detectionLatencyData, setDetectionLatencyData] = useState([
    { time: '14:30', latency_ms: 45, detection: 'ROV' },
    { time: '14:31', latency_ms: 52, detection: 'Anomaly' },
    { time: '14:32', latency_ms: 38, detection: 'ROV' },
    { time: '14:33', latency_ms: 61, detection: 'Anomaly' },
    { time: '14:34', latency_ms: 43, detection: 'ROV' },
  ]);
  const [rovDistribution, setRovDistribution] = useState([
    { name: 'VALID', value: 68, color: '#10b981' },
    { name: 'INVALID', value: 24, color: '#ef4444' },
    { name: 'NOT_FOUND', value: 8, color: '#f59e0b' },
  ]);

  const consoleEndRef = useRef(null);

  // Auto-scroll console log
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [consoleLog]);

  // ========================================================================
  // API Integration Stubs
  // ========================================================================

  const callBackend = async (endpoint, method = 'POST', data = null) => {
    try {
      const url = `http://localhost:8000/api/${endpoint}`;
      const options = {
        method,
        headers: { 'Content-Type': 'application/json' },
      };
      if (data) options.body = JSON.stringify(data);

      const response = await fetch(url, options);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      addConsoleLog(`[ERROR] Backend call failed: ${error.message}`, 'error');
      return null;
    }
  };

  const addConsoleLog = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = {
      info: '[INFO]',
      success: '[✓]',
      error: '[✗]',
      warning: '[!]'
    }[type] || '[•]';

    setConsoleLog(prev => [...prev, `${prefix} ${message}`].slice(-50));
  };

  const updateAsStatus = (as, status) => {
    setAsStatus(prev => ({ ...prev, [as]: status }));
  };

  // ========================================================================
  // Topology Control Functions
  // ========================================================================

  const initializeTopology = async () => {
    addConsoleLog('Initializing BGP topology...');
    setSystemState('baseline');
    
    // Update AS statuses sequentially
    for (const as of Object.keys(AS_CONFIG)) {
      await new Promise(resolve => setTimeout(resolve, 200));
      updateAsStatus(as, 'active');
    }

    const result = await callBackend('topology/init');
    if (result?.success) {
      addConsoleLog('Topology initialized successfully', 'success');
      addConsoleLog(`Loaded baseline ROA database: ${result.roa_count} entries`);
    }
  };

  const startMonitoring = async () => {
    addConsoleLog('Starting BGP monitoring daemon...');
    const result = await callBackend('monitor/start');
    if (result?.success) {
      addConsoleLog('Monitor started. Listening for BGP UPDATEs...', 'success');
      // Simulate incoming detections
      simulateDetections();
    }
  };

  const resetNetwork = async () => {
    addConsoleLog('Resetting network state...');
    setSystemState('baseline');
    setDetectionFeed([]);

    const result = await callBackend('topology/reset');
    if (result?.success) {
      addConsoleLog('Network reset complete', 'success');
      setAsStatus(Object.keys(AS_CONFIG).reduce((acc, as) => ({ ...acc, [as]: 'idle' }), {}));
    }
  };

  // ========================================================================
  // Attack Orchestration Functions
  // ========================================================================

  const launchAttack = async (scenario) => {
    const scenarioConfig = ATTACK_SCENARIOS.find(s => s.id === scenario);
    addConsoleLog(`[ATTACK] Launching: ${scenarioConfig.title}`);
    setSystemState('attacking');
    updateAsStatus('AS99', 'attacking');

    const result = await callBackend('attack/launch', 'POST', {
      scenario: scenario,
      target_prefix: '10.10.0.0/16'
    });

    if (result?.success) {
      addConsoleLog(`Poisoning injection active (T0=${result.timestamp})`, 'warning');
      addConsoleLog(`AS_PATH: ${result.as_path.join('←')}`, 'warning');
      
      // Simulate detections appearing
      setTimeout(() => {
        addConsoleLog(`[DETECTION] Anomaly detected in ${result.detection_latency_ms}ms`, 'success');
        if (rovEnabled) {
          addConsoleLog('[ROV] INVALID certificate returned', 'success');
        }
      }, 500);
    }
  };

  const resetPrefixes = async () => {
    addConsoleLog('Withdrawing all poisoned prefixes...');
    const result = await callBackend('attack/reset');
    if (result?.success) {
      addConsoleLog('All prefixes withdrawn. Network returned to baseline.', 'success');
      setSystemState('baseline');
      updateAsStatus('AS99', 'idle');
    }
  };

  // ========================================================================
  // Detection Feed & Analytics
  // ========================================================================

  const simulateDetections = () => {
    const interval = setInterval(() => {
      const newDetection = {
        prefix: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.0.0/16`,
        origin: `AS${Math.random() > 0.7 ? 99 : [1, 2, 3, 10, 20][Math.floor(Math.random() * 5)]}`,
        path: 'AS99←AS2←AS1',
        rov: ['VALID', 'INVALID', 'NOT_FOUND'][Math.floor(Math.random() * 3)],
        anomaly: Math.random() > 0.6,
        timestamp: new Date().toLocaleTimeString()
      };
      setDetectionFeed(prev => [...prev.slice(-19), newDetection]);
    }, 1500);

    return () => clearInterval(interval);
  };

  const exportPDFReport = () => {
    const pdf = new jsPDF();
    pdf.setFont('helvetica');
    pdf.setFontSize(16);
    pdf.text('BGP Hijack Lab Report', 10, 10);

    pdf.setFontSize(12);
    pdf.text(`Report Generated: ${new Date().toLocaleString()}`, 10, 20);
    pdf.text(`System State: ${systemState.toUpperCase()}`, 10, 30);
    pdf.text(`ROV Engine: ${rovEnabled ? 'ENABLED' : 'DISABLED'}`, 10, 40);
    pdf.text(`Anomaly Detector: ${anomalyEnabled ? 'ENABLED' : 'DISABLED'}`, 10, 50);

    pdf.text('Detection Statistics:', 10, 65);
    const validCount = rovDistribution[0].value;
    const invalidCount = rovDistribution[1].value;
    const notFoundCount = rovDistribution[2].value;
    const total = validCount + invalidCount + notFoundCount;

    pdf.setFontSize(10);
    pdf.text(`VALID: ${validCount} (${((validCount/total)*100).toFixed(1)}%)`, 15, 75);
    pdf.text(`INVALID: ${invalidCount} (${((invalidCount/total)*100).toFixed(1)}%)`, 15, 85);
    pdf.text(`NOT_FOUND: ${notFoundCount} (${((notFoundCount/total)*100).toFixed(1)}%)`, 15, 95);

    pdf.save('bgp-hijack-report.pdf');
    addConsoleLog('PDF report exported successfully', 'success');
  };

  const filteredDetections = selectedFilter === 'all'
    ? detectionFeed
    : detectionFeed.filter(d => selectedFilter === 'anomaly' ? d.anomaly : !d.anomaly);

  // ========================================================================
  // Render: Topology SVG with LED Indicators
  // ========================================================================

  const TopologySVG = () => (
    <svg viewBox="0 0 100 100" className="w-full h-full">
      {/* Links */}
      <line x1="50" y1="20" x2="50" y2="80" stroke="#64748b" strokeWidth="0.5" strokeDasharray="2" />
      <line x1="50" y1="20" x2="20" y2="50" stroke="#64748b" strokeWidth="0.5" strokeDasharray="2" />
      <line x1="50" y1="20" x2="80" y2="50" stroke="#64748b" strokeWidth="0.5" strokeDasharray="2" />
      <line x1="20" y1="50" x2="50" y2="80" stroke="#64748b" strokeWidth="0.5" strokeDasharray="2" />
      <line x1="80" y1="50" x2="50" y2="80" stroke="#64748b" strokeWidth="0.5" strokeDasharray="2" />
      <line x1="35" y1="65" x2="50" y2="80" stroke="#64748b" strokeWidth="0.5" strokeDasharray="2" />
      <line x1="65" y1="65" x2="50" y2="80" stroke="#64748b" strokeWidth="0.5" strokeDasharray="2" />

      {/* AS Nodes */}
      {Object.entries(AS_CONFIG).map(([as, config]) => (
        <g key={as}>
          {/* Circle */}
          <circle
            cx={config.x}
            cy={config.y}
            r="5"
            fill={config.color}
            opacity={asStatus[as] === 'idle' ? 0.3 : 0.9}
            className="transition-all"
          />
          {/* Status LED */}
          <circle
            cx={config.x + 4}
            cy={config.y - 4}
            r="1"
            fill={
              asStatus[as] === 'attacking' ? '#fbbf24' :
              asStatus[as] === 'active' ? '#10b981' :
              '#6b7280'
            }
            className="animate-pulse"
          />
          {/* Label */}
          <text
            x={config.x}
            y={config.y + 8}
            textAnchor="middle"
            fontSize="2.5"
            fill="#e2e8f0"
            className="font-bold"
          >
            {as}
          </text>
        </g>
      ))}
    </svg>
  );

  // ========================================================================
  // Main Render
  // ========================================================================

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-mono p-4">
      {/* Header */}
      <div className="mb-6 border-b border-emerald-900/50 pb-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-emerald-400 flex items-center gap-2">
              <Network className="w-8 h-8" />
              BGP Hijack Lab
            </h1>
            <p className="text-slate-400 text-sm mt-1">Unified Control Center v1.0</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs px-3 py-1 bg-slate-900 border border-emerald-900/50 rounded text-emerald-400">
              State: {systemState.toUpperCase()}
            </span>
            <button
              onClick={exportPDFReport}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-700/50 rounded text-emerald-400 transition"
            >
              <Download className="w-4 h-4" />
              Export PDF
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        {/* ======================================================================
            1. TOPOLOGY CONTROL CENTER
            ====================================================================== */}
        <div className="lg:col-span-1 border border-slate-800 bg-slate-900/50 rounded-lg p-4">
          <h2 className="text-emerald-400 font-bold mb-4 flex items-center gap-2">
            <Network className="w-5 h-5" />
            Topology Control
          </h2>

          {/* Topology SVG */}
          <div className="bg-slate-950/80 border border-slate-800 rounded p-3 mb-4 h-48">
            <TopologySVG />
          </div>

          {/* Status Grid */}
          <div className="grid grid-cols-2 gap-2 mb-4">
            {Object.entries(AS_CONFIG).map(([as, config]) => (
              <div key={as} className="text-xs bg-slate-800/50 border border-slate-700/50 rounded p-2">
                <div className="font-bold text-slate-300">{as}</div>
                <div className="text-emerald-400 flex items-center gap-1 mt-1">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      asStatus[as] === 'attacking' ? 'bg-yellow-500 animate-pulse' :
                      asStatus[as] === 'active' ? 'bg-green-500' :
                      'bg-gray-600'
                    }`}
                  />
                  {asStatus[as] === 'attacking' ? 'ATTACKING' : asStatus[as] === 'active' ? 'ACTIVE' : 'IDLE'}
                </div>
              </div>
            ))}
          </div>

          {/* Control Buttons */}
          <div className="space-y-2">
            <button
              onClick={initializeTopology}
              disabled={systemState !== 'baseline'}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-emerald-900/40 hover:bg-emerald-900/60 disabled:opacity-50 disabled:cursor-not-allowed border border-emerald-700/50 rounded text-emerald-400 transition font-bold text-sm"
            >
              <Play className="w-4 h-4" />
              Initialize Topology
            </button>
            <button
              onClick={startMonitoring}
              disabled={systemState === 'baseline' && !Object.values(asStatus).some(s => s === 'active')}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-blue-900/40 hover:bg-blue-900/60 disabled:opacity-50 disabled:cursor-not-allowed border border-blue-700/50 rounded text-blue-400 transition font-bold text-sm"
            >
              <Activity className="w-4 h-4" />
              Start Monitoring
            </button>
            <button
              onClick={resetNetwork}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-rose-900/40 hover:bg-rose-900/60 border border-rose-700/50 rounded text-rose-400 transition font-bold text-sm"
            >
              <RotateCcw className="w-4 h-4" />
              Reset Network
            </button>
          </div>
        </div>

        {/* ======================================================================
            2. ATTACK ORCHESTRATOR
            ====================================================================== */}
        <div className="lg:col-span-1 border border-slate-800 bg-slate-900/50 rounded-lg p-4">
          <h2 className="text-rose-400 font-bold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Attack Orchestrator
          </h2>

          {/* Poisoning Scenarios */}
          <div className="space-y-2 mb-4">
            {ATTACK_SCENARIOS.map(scenario => (
              <button
                key={scenario.id}
                onClick={() => launchAttack(scenario.id)}
                disabled={systemState !== 'baseline'}
                className="w-full text-left p-3 bg-slate-800/50 hover:bg-slate-700/50 disabled:opacity-50 disabled:cursor-not-allowed border border-slate-700/50 hover:border-rose-700/50 rounded transition"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-bold text-rose-400 flex items-center gap-2">
                      <span>{scenario.icon}</span>
                      {scenario.title}
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{scenario.description}</p>
                  </div>
                  <Zap className="w-4 h-4 text-rose-400 mt-1" />
                </div>
              </button>
            ))}
          </div>

          {/* Reset Button */}
          <button
            onClick={resetPrefixes}
            disabled={systemState === 'baseline'}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 mb-4 bg-slate-800/50 hover:bg-slate-700/50 disabled:opacity-50 disabled:cursor-not-allowed border border-slate-700/50 rounded text-slate-400 transition font-bold text-sm"
          >
            <RotateCcw className="w-4 h-4" />
            Reset Prefixes
          </button>

          {/* Console Log */}
          <div className="text-xs">
            <label className="block text-slate-400 font-bold mb-2">Console Output</label>
            <div className="bg-slate-950/80 border border-slate-800 rounded p-3 h-64 overflow-y-auto font-mono text-xs">
              {consoleLog.map((log, i) => (
                <div
                  key={i}
                  className={
                    log.includes('[✓]') ? 'text-emerald-400' :
                    log.includes('[✗]') ? 'text-rose-400' :
                    log.includes('[!]') ? 'text-yellow-400' :
                    log.includes('[ERROR]') ? 'text-rose-500' :
                    'text-slate-400'
                  }
                >
                  {log}
                </div>
              ))}
              <div ref={consoleEndRef} />
            </div>
          </div>
        </div>

        {/* ======================================================================
            3. DETECTION FEED & CONTROLS
            ====================================================================== */}
        <div className="lg:col-span-1 border border-slate-800 bg-slate-900/50 rounded-lg p-4">
          <h2 className="text-cyan-400 font-bold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5" />
            Detection Feed
          </h2>

          {/* Detection Engine Toggles */}
          <div className="space-y-2 mb-4">
            <div className="flex items-center justify-between p-2 bg-slate-800/50 border border-slate-700/50 rounded">
              <div>
                <div className="font-bold text-cyan-400 text-sm">ROV Engine</div>
                <div className="text-xs text-slate-400">RPKI Validation</div>
              </div>
              <button
                onClick={() => setRovEnabled(!rovEnabled)}
                className={`px-3 py-1 rounded text-xs font-bold transition ${
                  rovEnabled
                    ? 'bg-emerald-900/40 border border-emerald-700/50 text-emerald-400'
                    : 'bg-slate-700/40 border border-slate-600/50 text-slate-400'
                }`}
              >
                {rovEnabled ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
              </button>
            </div>

            <div className="flex items-center justify-between p-2 bg-slate-800/50 border border-slate-700/50 rounded">
              <div>
                <div className="font-bold text-cyan-400 text-sm">Anomaly Detector</div>
                <div className="text-xs text-slate-400">Baseline Detection</div>
              </div>
              <button
                onClick={() => setAnomalyEnabled(!anomalyEnabled)}
                className={`px-3 py-1 rounded text-xs font-bold transition ${
                  anomalyEnabled
                    ? 'bg-emerald-900/40 border border-emerald-700/50 text-emerald-400'
                    : 'bg-slate-700/40 border border-slate-600/50 text-slate-400'
                }`}
              >
                {anomalyEnabled ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
              </button>
            </div>
          </div>

          {/* Filter */}
          <div className="mb-3 flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <select
              value={selectedFilter}
              onChange={(e) => setSelectedFilter(e.target.value)}
              className="flex-1 text-xs bg-slate-800/50 border border-slate-700/50 rounded px-2 py-1 text-slate-300"
            >
              <option value="all">All Detections</option>
              <option value="anomaly">Anomalies Only</option>
              <option value="rov">ROV Results</option>
            </select>
          </div>

          {/* Detection Stream */}
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {filteredDetections.map((detection, idx) => (
              <div key={idx} className="text-xs bg-slate-800/50 border border-slate-700/50 rounded p-2">
                <div className="flex items-start justify-between mb-1">
                  <code className="text-cyan-400 font-bold">{detection.prefix}</code>
                  <span className="text-slate-500 text-xs">{detection.timestamp}</span>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-slate-400">Origin:</span>
                  <span className="text-emerald-400">{detection.origin}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold ${
                      detection.rov === 'VALID'
                        ? 'bg-emerald-900/40 text-emerald-400 border border-emerald-700/50'
                        : detection.rov === 'INVALID'
                        ? 'bg-rose-900/40 text-rose-400 border border-rose-700/50'
                        : 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/50'
                    }`}
                  >
                    {detection.rov}
                  </span>
                  {detection.anomaly && (
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-900/40 text-orange-400 border border-orange-700/50">
                      ANOMALY
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ======================================================================
          4. ANALYTICS & CHARTING ROW
          ====================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Detection Latency Chart */}
        <div className="border border-slate-800 bg-slate-900/50 rounded-lg p-4">
          <h3 className="text-teal-400 font-bold mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Detection Latency (ms)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={detectionLatencyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="latency_ms"
                stroke="#14b8a6"
                dot={{ fill: '#14b8a6' }}
                isAnimationActive={true}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* ROV Distribution Pie Chart */}
        <div className="border border-slate-800 bg-slate-900/50 rounded-lg p-4">
          <h3 className="text-purple-400 font-bold mb-4 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5" />
            ROV Distribution
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={rovDistribution}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={(entry) => `${entry.name}: ${entry.value}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {rovDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-500 text-center">
        <p>BGP Hijack Lab Control Center • Real-time Monitoring & Attack Orchestration</p>
      </div>
    </div>
  );
}
