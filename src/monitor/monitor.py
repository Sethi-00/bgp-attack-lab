"""
src/monitor/monitor.py
───────────────────────
BGP Monitor — Orchestrator
───────────────────────────
The BGPMonitor is the central class that ties together:
  - ROV Engine (RPKI validation)
  - Anomaly Detector (baseline deviation)
  - SQLite event store (persistent log)
  - Real-time alerting (console + extensible)

It receives BGPUpdate objects from any source (live FRR socket, replay
file, or unit test mock) and runs both detection pipelines synchronously,
writing results to the database and emitting alerts.

Usage (standalone):
    db    = build_lab_roa_database("data/bgp_events.db")
    rov   = ROVEngine(db)
    det   = AnomalyDetector()
    mon   = BGPMonitor(rov_engine=rov, anomaly_detector=det,
                       db_path="data/bgp_events.db")
    mon.start_baseline_window(duration_s=30)
    mon.start_detection_window()
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from typing import Callable, Optional

from src.monitor.anomaly_detector import AnomalyDetector

# Known peering relationships in the lab topology.
# Used by the path manipulation detector in _process_inner().
# Keys = ASN, values = set of directly peering ASNs.
LAB_KNOWN_TOPOLOGY: dict[int, set[int]] = {
    1:  {2, 3},
    2:  {1, 10, 99},
    3:  {1, 20, 99},
    10: {2},
    20: {3},
    99: {2, 3},
}
from src.monitor.models import BGPUpdate, DetectionEvent, EventType, ROVResult
from src.monitor.rov_engine import ROVEngine

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Event Store
# --------------------------------------------------------------------------- #

class EventStore:
    """
    SQLite-backed persistent store for all BGP detection events.
    Schema mirrors the data needed for the analysis scripts in Phase 5.
    """

    _DDL = """
        CREATE TABLE IF NOT EXISTS bgp_events (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp         REAL    NOT NULL,
            event_type        TEXT    NOT NULL,
            prefix            TEXT    NOT NULL,
            origin_as         INTEGER NOT NULL,
            as_path           TEXT    NOT NULL,
            announcing_router TEXT,
            is_anomaly        INTEGER NOT NULL DEFAULT 0,  -- boolean
            anomaly_reason    TEXT,
            rov_result        TEXT    NOT NULL,
            rov_reason        TEXT,
            detection_latency REAL                        -- seconds from attack start
        );

        CREATE INDEX IF NOT EXISTS idx_prefix     ON bgp_events(prefix);
        CREATE INDEX IF NOT EXISTS idx_origin_as  ON bgp_events(origin_as);
        CREATE INDEX IF NOT EXISTS idx_rov_result ON bgp_events(rov_result);
        CREATE INDEX IF NOT EXISTS idx_timestamp  ON bgp_events(timestamp);
    """

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        # WAL mode: allows concurrent reads during writes, prevents SQLITE_BUSY
        # under multi-scenario sequential experiment runs.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")  # safe + faster than FULL
        self._conn.executescript(self._DDL)
        self._conn.commit()
        self._write_lock = threading.Lock()  # serialise writes from any thread
        logger.info("EventStore ready at %s (WAL mode)", db_path)

    def record(self, event: DetectionEvent) -> int:
        """
        Persist a DetectionEvent.  Returns the new row ID.
        Thread-safe: protected by write lock.
        """
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO bgp_events
                  (timestamp, event_type, prefix, origin_as, as_path,
                   announcing_router, is_anomaly, anomaly_reason,
                   rov_result, rov_reason, detection_latency)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.update.timestamp,
                    event.update.event_type.value,
                    event.update.prefix,
                    event.update.origin_as,
                    str(event.update.as_path),
                    event.update.announcing_router,
                    int(event.is_anomaly),
                    event.anomaly_reason,
                    event.rov_result.value,
                    event.rov_reason,
                    event.detection_latency_s,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def close(self) -> None:
        """Close the SQLite connection. Safe to call multiple times."""
        if not getattr(self, '_closed', False):
            self._conn.close()
            self._closed = True


# --------------------------------------------------------------------------- #
# BGP Monitor
# --------------------------------------------------------------------------- #

class BGPMonitor:
    """
    Orchestrates the BGP detection pipeline for a single experiment run.

    The monitor has two phases:
      1. Baseline window — all received UPDATEs are fed to the AnomalyDetector
         for learning. ROV validation still runs (for integrity checking) but
         anomaly alerts are suppressed.
      2. Detection window — all received UPDATEs are checked against both the
         anomaly detector and the ROV engine. Alerts are emitted and logged.

    Alert hooks:
        Register callables via on_alert() to receive DetectionEvent objects
        in real time (e.g., send to SIEM, push to dashboard, write to file).
    """

    def __init__(
        self,
        rov_engine:       ROVEngine,
        anomaly_detector: AnomalyDetector,
        db_path:          str = ":memory:",
        attack_start_time: Optional[float] = None,
    ):
        self._rov       = rov_engine
        self._detector  = anomaly_detector
        self._store     = EventStore(db_path)
        self._attack_t0 = attack_start_time

        # Alert hook registry — callables receive DetectionEvent
        self._alert_hooks: list[Callable[[DetectionEvent], None]] = [
            self._default_alert_log,
        ]

        self._detection_active = False
        self._events_processed = 0
        self._alerts_fired     = 0

    # ── Phase Control ─────────────────────────────────────────────────────── #

    def start_baseline_window(self, duration_s: float) -> None:
        """
        Run the baseline learning phase for `duration_s` seconds.
        During this window, process() learns without alerting.

        NOTE: In a real deployment you would pass live UPDATE objects here.
              In the experiment protocol, call this before launching attacks.
        """
        logger.info("Baseline window started (duration=%.0fs)", duration_s)
        self._detection_active = False

    def tick_baseline(self, update: BGPUpdate) -> None:
        """Feed an UPDATE to the anomaly detector during the learning phase."""
        self._detector.learn(update)

    def start_detection_window(self) -> None:
        """
        Freeze the baseline (if not already frozen) and switch to active detection.
        All subsequent process() calls will emit alerts.
        Safe to call even if the detector is already frozen.
        """
        if self._detector.is_learning():
            self._detector.freeze_baseline()
        self._detection_active = True
        logger.info("Detection window started. Baseline stats: %s",
                    self._detector.stats())

    def mark_attack_start(self, t0: Optional[float] = None) -> None:
        """Record the attack start timestamp for latency calculations."""
        self._attack_t0 = t0 if t0 is not None else time.time()
        logger.info("Attack start time recorded: %.3f", self._attack_t0)

    # ── Core Processing ───────────────────────────────────────────────────── #

    def process(self, update: BGPUpdate) -> DetectionEvent:
        """
        Run the full detection pipeline on a single BGP UPDATE.

        Steps:
          1. Route Origin Validation via ROV engine
          2. Anomaly detection via AnomalyDetector (only if detection is active)
          3. Compute detection latency if attack start time is known
          4. Persist event to SQLite
          5. Fire alert hooks for actionable events

        Args:
            update: A validated BGPUpdate object.

        Returns:
            DetectionEvent with full detection results.

        Security note:
            This method must never raise. Any exception is caught, logged,
            and a safe NotFound/no-anomaly event is returned to ensure the
            monitor stays running even if a single UPDATE is malformed.
        """
        try:
            return self._process_inner(update)
        except Exception as exc:                           # noqa: BLE001
            logger.error(
                "Monitor pipeline error for prefix=%s: %s",
                getattr(update, "prefix", "UNKNOWN"), exc, exc_info=True,
            )
            # Return a safe sentinel event so callers always get a result
            return DetectionEvent(
                update=update,
                is_anomaly=False,
                anomaly_reason=f"Pipeline error: {exc}",
                rov_result=ROVResult.NOT_FOUND,
                rov_reason=f"Pipeline error: {exc}",
            )

    def _process_inner(self, update: BGPUpdate) -> DetectionEvent:
        self._events_processed += 1

        # ── 0. WITHDRAW events: skip ROV and anomaly detection ───────────── #
        # A WITHDRAW message removes a route — there is nothing to validate.
        # Running ROV on a withdrawal would always return NOT_FOUND and could
        # generate false anomaly alerts as baseline prefixes disappear.
        if update.event_type == EventType.WITHDRAW:
            event = DetectionEvent(
                update=update,
                is_anomaly=False,
                anomaly_reason=None,
                rov_result=ROVResult.NOT_FOUND,
                rov_reason="WITHDRAW event — ROV not applicable",
            )
            self._store.record(event)
            return event

        # ── 1. ROV (runs for ANNOUNCE events only) ───────────────────────── #
        rov_result, rov_reason = self._rov.validate(update)

        # ── 2. Anomaly detection (detection window only) ─────────────────── #
        is_anomaly    = False
        anomaly_reason: Optional[str] = None

        if self._detection_active:
            is_anomaly, anomaly_reason = self._detector.detect(update)

            # ── 2b. AS path manipulation detection ──────────────────────── #
            # detect() only checks prefix/origin anomalies. Path manipulation
            # (Attack 3) stuffs a legitimate origin AS so detect() sees nothing
            # wrong. detect_path_manipulation() checks AS relationships against
            # the known lab topology and catches forged paths.
            # Run it as a second pass only when detect() found no anomaly.
            if not is_anomaly and len(update.as_path) > 1:
                path_anom, path_reason = self._detector.detect_path_manipulation(
                    update, LAB_KNOWN_TOPOLOGY
                )
                if path_anom:
                    is_anomaly    = True
                    anomaly_reason = f"[PATH] {path_reason}"

        elif not self._detection_active and not self._detector.is_learning():
            # Edge case: detection not yet active but baseline already frozen
            is_anomaly, anomaly_reason = self._detector.detect(update)

        # ── 3. Detection latency ─────────────────────────────────────────── #
        latency: Optional[float] = None
        if self._attack_t0 is not None and (is_anomaly or rov_result == ROVResult.INVALID):
            latency = update.timestamp - self._attack_t0
            if latency < 0:
                latency = 0.0   # Clock skew guard

        # ── 4. Build event ──────────────────────────────────────────────────#
        event = DetectionEvent(
            update=update,
            is_anomaly=is_anomaly,
            anomaly_reason=anomaly_reason if is_anomaly else None,
            rov_result=rov_result,
            rov_reason=rov_reason,
            detection_latency_s=latency,
        )

        # ── 5. Persist ───────────────────────────────────────────────────── #
        self._store.record(event)

        # ── 6. Alert hooks ───────────────────────────────────────────────── #
        if is_anomaly or rov_result == ROVResult.INVALID:
            self._alerts_fired += 1
            for hook in self._alert_hooks:
                try:
                    hook(event)
                except Exception as hook_exc:              # noqa: BLE001
                    logger.error("Alert hook failed: %s", hook_exc)

        return event

    # ── Alert Hooks ───────────────────────────────────────────────────────── #

    def on_alert(self, hook: Callable[[DetectionEvent], None]) -> None:
        """
        Register a callable to be invoked whenever an alert fires.

        Args:
            hook: Function accepting a DetectionEvent.
                  Must not raise (exceptions are caught and logged).
        """
        self._alert_hooks.append(hook)

    def _default_alert_log(self, event: DetectionEvent) -> None:
        """Built-in alert handler: formatted log line to stdout."""
        lines = []
        if event.is_anomaly:
            lines.append(
                f"[ALERT][ANOMALY] prefix={event.update.prefix} "
                f"origin_as={event.update.origin_as} "
                f"reason={event.anomaly_reason}"
            )
        if event.rov_result == ROVResult.INVALID:
            lines.append(
                f"[ALERT][RPKI-INVALID] prefix={event.update.prefix} "
                f"origin_as={event.update.origin_as} "
                f"reason={event.rov_reason}"
            )
        if event.detection_latency_s is not None:
            lines.append(f"         ↳ detection latency: {event.detection_latency_s:.3f}s")

        for line in lines:
            logger.warning(line)

    # ── Diagnostics ───────────────────────────────────────────────────────── #

    def stats(self) -> dict:
        return {
            "events_processed": self._events_processed,
            "alerts_fired":     self._alerts_fired,
            "detection_active": self._detection_active,
            "detector_stats":   self._detector.stats(),
        }

    def close(self) -> None:
        """Close the event store. Safe to call multiple times."""
        if not getattr(self, '_closed', False):
            self._store.close()
            self._closed = True