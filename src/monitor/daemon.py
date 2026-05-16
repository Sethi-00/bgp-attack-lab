"""
src/monitor/daemon.py
──────────────────────
Lightweight BGP Monitor daemon entrypoint.

This CLI boots the lab detection pipeline, learns a short baseline of
legitimate BGP announcements, and then enters a live-ready state.

In dry-run mode, it can optionally inject a synthetic sample attack to
exercise the RPKI and anomaly pipeline without needing a live Mininet
topology.
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from src.monitor.anomaly_detector import AnomalyDetector
from src.monitor.models import BGPUpdate, EventType
from src.monitor.monitor import BGPMonitor
from src.monitor.rov_engine import ROVEngine, build_lab_roa_database

logger = logging.getLogger(__name__)

BASELINE_UPDATES = [
    ("10.10.0.0/16", 10, [1, 2, 10]),
    ("10.20.0.0/16", 20, [1, 3, 20]),
    ("172.16.2.0/24", 2, [1, 2]),
    ("172.16.3.0/24", 3, [1, 3]),
]


def _learn_baseline(monitor: BGPMonitor, duration_s: int = 30) -> None:
    """Feed known-good BGP updates into the anomaly detector."""
    deadline = time.time() + duration_s
    index = 0

    logger.info("Starting baseline learning for %ds", duration_s)
    while time.time() < deadline:
        prefix, origin_as, as_path = BASELINE_UPDATES[index % len(BASELINE_UPDATES)]
        update = BGPUpdate(
            prefix=prefix,
            origin_as=origin_as,
            as_path=as_path,
            announcing_router="10.0.12.1",
            timestamp=time.time(),
        )
        monitor.tick_baseline(update)
        index += 1
        time.sleep(1)

    monitor.start_detection_window()
    logger.info("Baseline learning complete. Detection window active.")


def _inject_sample_attack(monitor: BGPMonitor) -> None:
    """Inject one synthetic hijack into the monitor pipeline for verification."""
    update = BGPUpdate(
        prefix="10.10.0.0/16",
        origin_as=99,
        as_path=[1, 2, 99],
        announcing_router="10.0.12.1",
        timestamp=time.time(),
    )
    event = monitor.process(update)
    logger.info(
        "Synthetic attack processed: anomaly=%s, rov=%s, latency=%s",
        event.is_anomaly,
        event.rov_result.value,
        event.detection_latency_s,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="BGP Monitor Daemon")
    parser.add_argument("--db", default="data/bgp_events.db",
                        help="SQLite event database path")
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="Run without live Mininet topology")
    parser.add_argument("--live", action="store_true", default=False,
                        help="Run in live mode with an external update source")
    parser.add_argument("--baseline", type=int, default=30,
                        help="Baseline learning duration in seconds")
    parser.add_argument("--inject-attack", action="store_true", default=False,
                        help="Inject one synthetic attack after baseline")
    args = parser.parse_args()

    dry_run = not args.live
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    logger.info("Initializing BGP Monitor daemon (db=%s, dry_run=%s)", args.db, dry_run)
    roa_db = build_lab_roa_database(db_path=str(Path(args.db).with_suffix("_roa.db")))
    rov_engine = ROVEngine(roa_db)
    detector = AnomalyDetector()
    monitor = BGPMonitor(rov_engine=rov_engine, anomaly_detector=detector, db_path=args.db)

    _learn_baseline(monitor, duration_s=args.baseline)

    if args.inject_attack:
        _inject_sample_attack(monitor)

    logger.info("Monitor daemon ready. Press CTRL+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down monitor daemon.")
        monitor.close()


if __name__ == "__main__":
    main()
