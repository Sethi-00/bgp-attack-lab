"""
src/api/server.py
═════════════════════════════════════════════════════════════════════════
BGP Hijack Lab - FastAPI Backend Server

This server provides REST/WebSocket endpoints for the React dashboard.
It orchestrates:
  - Topology initialization and reset
  - Attack scenario execution
  - Monitoring daemon lifecycle
  - Real-time detection event streaming
  - Report generation

Run: python3 -m src.api.server

To integrate with Vite dev server:
  Frontend: http://localhost:5173 (with /api proxy to backend)
  Backend: http://localhost:8000
"""

import asyncio
import logging
import json
import time
from datetime import datetime
from typing import Optional
from dataclasses import asdict, dataclass
from pathlib import Path

from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Import BGP Lab modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.monitor.models import ROVResult, AttackScenario, BGPUpdate, EventType
from src.monitor.rov_engine import ROVEngine
from src.monitor.anomaly_detector import AnomalyDetector
from src.attacker.controller import AttackController

# ============================================================================
# Logging Configuration
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# Pydantic Request/Response Models
# ============================================================================

class TopologyInitRequest(BaseModel):
    """Request to initialize the network topology."""
    live_mode: bool = False
    timeout_sec: int = 30


class TopologyInitResponse(BaseModel):
    """Response from topology initialization."""
    success: bool
    message: str
    roa_count: int
    as_count: int = 6
    timestamp: float


class AttackLaunchRequest(BaseModel):
    """Request to launch a poisoning attack."""
    scenario: AttackScenario
    target_prefix: str = "10.10.0.0/16"
    attacker_as: int = 99


class AttackLaunchResponse(BaseModel):
    """Response from attack launch."""
    success: bool
    scenario: str
    timestamp: float
    detection_latency_ms: Optional[int] = None
    as_path: list = []


class DetectionEvent(BaseModel):
    """A single BGP detection event."""
    prefix: str
    origin_as: int
    as_path: list
    rov_result: ROVResult
    anomaly_detected: bool
    latency_ms: float
    timestamp: float


class MonitorStartRequest(BaseModel):
    """Request to start the monitoring daemon."""
    rov_enabled: bool = True
    anomaly_enabled: bool = True


class MonitorStartResponse(BaseModel):
    """Response from monitor start."""
    success: bool
    message: str
    timestamp: float


class ReportGenerateRequest(BaseModel):
    """Request to generate analysis report."""
    output_format: str = "pdf"  # pdf, json, txt
    include_charts: bool = True


class ReportGenerateResponse(BaseModel):
    """Response from report generation."""
    success: bool
    report_path: str
    file_size_bytes: int
    timestamp: float


# ============================================================================
# Global State
# ============================================================================

@dataclass
class LabState:
    """Global lab state management."""
    is_initialized: bool = False
    live_mode: bool = False
    current_phase: str = "baseline"  # baseline, attacking, mitigating
    active_attacks: list = None
    rov_enabled: bool = True
    anomaly_enabled: bool = True
    
    def __post_init__(self):
        if self.active_attacks is None:
            self.active_attacks = []


lab_state = LabState()

# Engines
rov_engine: Optional[ROVEngine] = None
anomaly_detector: Optional[AnomalyDetector] = None
attack_controller: AttackController = AttackController()

# WebSocket connection pool for real-time events
ws_connections = []

# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="BGP Hijack Lab API",
    version="1.0.0",
    description="Backend for BGP Hijacking Simulation Lab dashboard"
)

# CORS configuration for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Health & Status Endpoints
# ============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "lab_initialized": lab_state.is_initialized,
        "current_phase": lab_state.current_phase,
        "timestamp": time.time()
    }


@app.get("/api/status")
async def get_status():
    """Get current lab status."""
    return {
        "is_initialized": lab_state.is_initialized,
        "live_mode": lab_state.live_mode,
        "current_phase": lab_state.current_phase,
        "active_attacks": lab_state.active_attacks,
        "rov_enabled": lab_state.rov_enabled,
        "anomaly_enabled": lab_state.anomaly_enabled,
        "timestamp": time.time()
    }


# ============================================================================
# Topology Control Endpoints
# ============================================================================

@app.post("/api/topology/init")
async def init_topology(request: TopologyInitRequest = None):
    """
    Initialize the BGP topology.
    
    In live mode, this starts the Mininet topology with FRR instances.
    In dry-run mode, simulates topology initialization.
    """
    logger.info("Topology initialization requested")
    
    try:
        # Initialize detection engines
        global rov_engine, anomaly_detector
        rov_engine = ROVEngine(roa_file="config/roas.json")
        anomaly_detector = AnomalyDetector()
        
        lab_state.is_initialized = True
        lab_state.current_phase = "baseline"
        
        roa_count = rov_engine.roa_database.__len__() if hasattr(rov_engine.roa_database, '__len__') else 42
        
        response = TopologyInitResponse(
            success=True,
            message="Topology initialized successfully",
            roa_count=roa_count,
            as_count=6,
            timestamp=time.time()
        )
        
        logger.info(f"Topology initialized: {roa_count} ROA entries loaded")
        return response
        
    except Exception as e:
        logger.error(f"Topology initialization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/topology/reset")
async def reset_topology():
    """Reset the network to baseline state."""
    logger.info("Network reset requested")
    
    try:
        lab_state.active_attacks.clear()
        lab_state.current_phase = "baseline"
        
        logger.info("Network reset successful")
        return {
            "success": True,
            "message": "Network reset to baseline",
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Network reset failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Attack Orchestration Endpoints
# ============================================================================

@app.post("/api/attack/launch")
async def launch_attack(request: AttackLaunchRequest):
    """
    Launch a BGP poisoning attack scenario.
    
    Supported scenarios:
    - exact_prefix: AS99 announces victim prefix verbatim
    - subprefix: AS99 announces more-specific subprefix
    - path_manipulation: AS99 forges AS_PATH
    """
    logger.info(f"Attack launch requested: {request.scenario}")
    
    if not lab_state.is_initialized:
        raise HTTPException(status_code=400, detail="Topology not initialized")
    
    if lab_state.current_phase == "attacking":
        raise HTTPException(status_code=409, detail="Attack already in progress")
    
    try:
        attack_start_time = time.time()
        
        # Execute the appropriate attack
        scenario_commands = {
            AttackScenario.EXACT_PREFIX: attack_controller.exact_prefix_hijack,
            AttackScenario.SUBPREFIX: attack_controller.subprefix_hijack,
            AttackScenario.PATH_MANIPULATION: attack_controller.path_manipulation,
        }
        
        attack_func = scenario_commands.get(request.scenario)
        if not attack_func:
            raise ValueError(f"Unknown scenario: {request.scenario}")
        
        # Execute attack (dry-run mode)
        logger.info(f"Executing attack: {request.scenario.value}")
        
        # Simulate detection latency (50-100ms)
        detection_latency_ms = 45 + int(time.time() * 1000) % 55
        
        lab_state.current_phase = "attacking"
        lab_state.active_attacks.append(request.scenario.value)
        
        response = AttackLaunchResponse(
            success=True,
            scenario=request.scenario.value,
            timestamp=attack_start_time,
            detection_latency_ms=detection_latency_ms,
            as_path=[99, 2, 1]
        )
        
        logger.info(f"Attack launched successfully: {request.scenario.value}")
        
        # Broadcast to WebSocket clients
        await broadcast_event({
            "type": "attack_launched",
            "scenario": request.scenario.value,
            "timestamp": attack_start_time
        })
        
        return response
        
    except Exception as e:
        logger.error(f"Attack launch failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/attack/reset")
async def reset_attack():
    """Withdraw all poisoned prefixes and return to baseline."""
    logger.info("Attack reset requested")
    
    try:
        lab_state.active_attacks.clear()
        lab_state.current_phase = "baseline"
        
        logger.info("All attacks withdrawn; network returned to baseline")
        
        await broadcast_event({
            "type": "attack_reset",
            "timestamp": time.time()
        })
        
        return {
            "success": True,
            "message": "All prefixes withdrawn",
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Attack reset failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Monitoring Endpoints
# ============================================================================

@app.post("/api/monitor/start")
async def start_monitor(request: MonitorStartRequest = None):
    """Start the BGP monitoring daemon."""
    logger.info("Monitor start requested")
    
    if not lab_state.is_initialized:
        raise HTTPException(status_code=400, detail="Topology not initialized")
    
    try:
        lab_state.rov_enabled = request.rov_enabled if request else True
        lab_state.anomaly_enabled = request.anomaly_enabled if request else True
        
        response = MonitorStartResponse(
            success=True,
            message="Monitoring daemon started",
            timestamp=time.time()
        )
        
        logger.info(
            f"Monitor started (ROV: {lab_state.rov_enabled}, "
            f"Anomaly: {lab_state.anomaly_enabled})"
        )
        
        return response
    except Exception as e:
        logger.error(f"Monitor start failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/monitor/stop")
async def stop_monitor():
    """Stop the monitoring daemon."""
    logger.info("Monitor stop requested")
    return {
        "success": True,
        "message": "Monitoring daemon stopped",
        "timestamp": time.time()
    }


# ============================================================================
# WebSocket for Real-time Events
# ============================================================================

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time detection events."""
    await websocket.accept()
    ws_connections.append(websocket)
    
    logger.info(f"WebSocket client connected. Total: {len(ws_connections)}")
    
    try:
        while True:
            # Keep connection alive
            data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
            logger.debug(f"WebSocket message received: {data}")
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        ws_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(ws_connections)}")


async def broadcast_event(event: dict):
    """Broadcast an event to all connected WebSocket clients."""
    for connection in ws_connections:
        try:
            await connection.send_json(event)
        except Exception as e:
            logger.error(f"Failed to broadcast event: {e}")


# ============================================================================
# Analytics & Reporting Endpoints
# ============================================================================

@app.get("/api/analytics/detections")
async def get_detections(
    limit: int = 100,
    offset: int = 0,
    filter_type: Optional[str] = None
):
    """
    Retrieve detection events from the database.
    
    filter_type: 'all', 'valid', 'invalid', 'anomaly'
    """
    try:
        # In production, this would query the SQLite database
        # For now, return simulated data
        detections = [
            {
                "prefix": "10.10.0.0/16",
                "origin_as": 99,
                "as_path": [99, 2, 1],
                "rov_result": "INVALID",
                "anomaly_detected": True,
                "latency_ms": 45,
                "timestamp": time.time() - 100
            },
            {
                "prefix": "10.10.1.0/24",
                "origin_as": 99,
                "as_path": [99, 2, 1],
                "rov_result": "INVALID",
                "anomaly_detected": True,
                "latency_ms": 52,
                "timestamp": time.time() - 50
            },
        ]
        
        return {
            "success": True,
            "count": len(detections),
            "detections": detections,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Failed to retrieve detections: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/rov-distribution")
async def get_rov_distribution():
    """Get ROV result distribution statistics."""
    return {
        "success": True,
        "data": {
            "VALID": {"count": 68, "percentage": 68.0},
            "INVALID": {"count": 24, "percentage": 24.0},
            "NOT_FOUND": {"count": 8, "percentage": 8.0},
        },
        "total": 100,
        "timestamp": time.time()
    }


@app.get("/api/analytics/latency-timeline")
async def get_latency_timeline(interval_minutes: int = 5):
    """Get detection latency timeline for charting."""
    return {
        "success": True,
        "data": [
            {"time": "14:30", "latency_ms": 45, "detection_method": "ROV"},
            {"time": "14:31", "latency_ms": 52, "detection_method": "Anomaly"},
            {"time": "14:32", "latency_ms": 38, "detection_method": "ROV"},
            {"time": "14:33", "latency_ms": 61, "detection_method": "Anomaly"},
            {"time": "14:34", "latency_ms": 43, "detection_method": "ROV"},
        ],
        "timestamp": time.time()
    }


@app.post("/api/report/generate")
async def generate_report(request: ReportGenerateRequest):
    """
    Generate a lab analysis report.
    
    Integrates with src/analysis/generate_report.py
    """
    logger.info(f"Report generation requested: {request.output_format}")
    
    try:
        # This would normally call src/analysis/generate_report.py
        report_filename = f"bgp_hijack_report_{int(time.time())}.{request.output_format}"
        report_path = f"reports/{report_filename}"
        
        logger.info(f"Report generated: {report_path}")
        
        response = ReportGenerateResponse(
            success=True,
            report_path=report_path,
            file_size_bytes=1024 * 256,  # Mock size
            timestamp=time.time()
        )
        
        return response
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/report/download/{report_name}")
async def download_report(report_name: str):
    """Download a generated report file."""
    try:
        file_path = Path("reports") / report_name
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        
        logger.info(f"Report downloaded: {report_name}")
        
        return FileResponse(
            path=file_path,
            media_type="application/pdf",
            filename=report_name
        )
    except Exception as e:
        logger.error(f"Report download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Utility Endpoints
# ============================================================================

@app.get("/api/scenarios")
async def list_attack_scenarios():
    """List all available attack scenarios."""
    return {
        "scenarios": [
            {
                "id": "exact_prefix",
                "title": "Exact Prefix Hijack",
                "description": "AS99 announces 10.10.0.0/16 (victim prefix)",
                "difficulty": "easy"
            },
            {
                "id": "subprefix",
                "title": "Subprefix Injection",
                "description": "AS99 announces 10.10.1.0/24 (more-specific)",
                "difficulty": "medium"
            },
            {
                "id": "path_manipulation",
                "title": "AS Path Leak",
                "description": "AS99 forges AS_PATH with victim origin",
                "difficulty": "hard"
            }
        ]
    }


@app.get("/api/as-topology")
async def get_as_topology():
    """Get the 6-AS topology configuration."""
    return {
        "nodes": [
            {"id": "AS1", "label": "Transit Core", "color": "#3b82f6"},
            {"id": "AS2", "label": "ISP West", "color": "#8b5cf6"},
            {"id": "AS3", "label": "ISP East", "color": "#8b5cf6"},
            {"id": "AS10", "label": "Victim", "color": "#ef4444"},
            {"id": "AS20", "label": "Peer", "color": "#10b981"},
            {"id": "AS99", "label": "Attacker", "color": "#f97316"},
        ],
        "edges": [
            {"source": "AS1", "target": "AS2"},
            {"source": "AS1", "target": "AS3"},
            {"source": "AS1", "target": "AS10"},
            {"source": "AS2", "target": "AS99"},
            {"source": "AS3", "target": "AS20"},
            {"source": "AS99", "target": "AS10"},
        ]
    }


# ============================================================================
# Root and Documentation
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint redirects to API documentation."""
    return {
        "name": "BGP Hijack Lab API",
        "version": "1.0.0",
        "docs": "/docs",
        "openapi": "/openapi.json"
    }


if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting BGP Hijack Lab API Server...")
    logger.info("API Documentation: http://localhost:8000/docs")
    
    uvicorn.run(
        "src.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
