"""
src/utils/experiment_runner.py
───────────────────────────────
Experiment Runner
──────────────────
Orchestrates the full 4-phase experiment protocol described in the scope
document (Phase 4, §4.1). Runs all three attack scenarios sequentially,
collects metrics, and writes a structured JSON results file.

This script is the bridge between the topology (Mininet/FRR) and the
analysis pipeline (generate_report.py). It should be run AFTER the
topology is up and BEFORE generate_report.py.

Protocol for each scenario:
  1. Reset routing table to baseline state (withdraw previous attack)
  2. Record T0 = attack launch time on the monitor
  3. Execute attack
  4. Poll routing tables every 2s for 60s (propagation window)
  5. Record: which ASes route to attacker vs victim
  6. Withdraw attack, record recovery time
  7. Sleep 15s for convergence before next scenario

Usage (inside a running Mininet topology session):
    python3 -m src.utils.experiment_runner --db data/bgp_events.db

Or via Makefile:
    make experiment
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from src.attacker.controller import AttackController, AttackResult
from src.monitor.anomaly_detector import AnomalyDetector
from src.monitor.models import BGPUpdate, ROVResult
from src.monitor.monitor import BGPMonitor
from src.monitor.rov_engine import ROVEngine, build_lab_roa_database

logger = logging.getLogger(__name__)

# ── Timing constants (seconds) ─────────────────────────────────────────────── #
BASELINE_WINDOW_S    = 30   # How long to observe clean traffic before attacks
ATTACK_WINDOW_S      = 60   # How long to observe each attack
RECOVERY_POLL_S      = 2    # Routing table poll interval during recovery
BETWEEN_SCENARIOS_S  = 15   # Convergence sleep between scenarios


# --------------------------------------------------------------------------- #
# Routing Table Poller
# --------------------------------------------------------------------------- #

def poll_routing_tables(net, target_prefix: str) -> dict[str, str]:
    """
    Query all AS routers for their best route to target_prefix.

    Args:
        net:           Live Mininet network object.
        target_prefix: The IP prefix being hijacked (e.g. "10.10.0.0/16").

    Returns:
        Dict mapping AS name → "victim" | "attacker" | "unknown" | "no_route".
    """
    if net is None:
        # Dry-run: return simulated result
        return {
            "as1":  "attacker",
            "as2":  "attacker",
            "as3":  "victim",
            "as20": "victim",
        }

    results = {}
    victim_asn   = 10
    attacker_asn = 99

    # Use -N to target per-namespace bgpd socket, not the system FRR daemon
    RUN_BASE = "/tmp/frr-run"

    for as_name in ("as1", "as2", "as3", "as10", "as20"):
        try:
            node    = net.get(as_name)
            run_dir = f"{RUN_BASE}/{as_name}"
            output  = node.cmd(
                f"vtysh -N {run_dir} -c 'show ip bgp {target_prefix}' 2>/dev/null"
            )
            if not output or "Network not in table" in output:
                results[as_name] = "no_route"
            elif f"AS{attacker_asn}" in output or f" {attacker_asn} " in output:
                results[as_name] = "attacker"
            elif f"AS{victim_asn}" in output or f" {victim_asn} " in output:
                results[as_name] = "victim"
            else:
                results[as_name] = "unknown"
        except Exception as exc:   # noqa: BLE001
            logger.warning("Could not poll %s: %s", as_name, exc)
            results[as_name] = "error"

    return results


def propagation_scope_pct(routing_snapshot: dict[str, str]) -> float:
    """
    Calculate what percentage of ASes are routing to the attacker.

    Args:
        routing_snapshot: Output from poll_routing_tables().

    Returns:
        Float 0.0–100.0 representing percentage routing to attacker.
    """
    if not routing_snapshot:
        return 0.0
    attacker_count = sum(1 for v in routing_snapshot.values() if v == "attacker")
    return 100.0 * attacker_count / len(routing_snapshot)


# --------------------------------------------------------------------------- #
# Scenario Runner
# --------------------------------------------------------------------------- #

@dataclass
class ScenarioMetrics:
    """Raw metrics collected during a single attack scenario run."""
    scenario:                 str
    attack_start_s:           float
    target_prefix:            str
    first_anomaly_alert_s:    Optional[float] = None   # Absolute timestamp
    first_rpki_invalid_s:     Optional[float] = None
    propagation_snapshots:    list[dict]       = field(default_factory=list)
    peak_propagation_pct:     float            = 0.0
    withdrawal_time_s:        Optional[float]  = None
    recovery_time_s:          Optional[float]  = None
    rpki_evaded:              bool             = False


def run_scenario(
    scenario_name:  str,
    attack_fn,                           # Callable → AttackResult
    monitor:        BGPMonitor,
    net=None,
    simulate_updates: bool = True,
) -> ScenarioMetrics:
    """
    Execute one attack scenario and collect all metrics.

    Args:
        scenario_name:    Human-readable label.
        attack_fn:        Callable that launches the attack (returns AttackResult).
        monitor:          Running BGPMonitor instance.
        net:              Live Mininet net (None = dry-run mode).
        simulate_updates: If True (no live FRR), inject synthetic BGP updates
                          into the monitor to simulate what would be observed.

    Returns:
        ScenarioMetrics with all collected data.
    """
    logger.info("=" * 60)
    logger.info("SCENARIO: %s", scenario_name)
    logger.info("=" * 60)

    # ── 1. Launch attack ───────────────────────────────────────────────────
    result: AttackResult = attack_fn()
    metrics = ScenarioMetrics(
        scenario=scenario_name,
        attack_start_s=result.attack_start_s,
        target_prefix=result.target_prefix,
    )
    monitor.mark_attack_start(result.attack_start_s)

    # Snapshot alerts_fired BEFORE this scenario so we measure delta, not total.
    # Without this, scenarios 2 and 3 always appear to detect instantly because
    # the counter accumulated from earlier scenarios never resets.
    alerts_at_scenario_start = monitor.stats()["alerts_fired"]

    # ── 2. Observation window ──────────────────────────────────────────────
    deadline = time.time() + ATTACK_WINDOW_S
    first_anomaly_found = False
    first_rpki_found    = False

    while time.time() < deadline:
        poll_time = time.time()

        # In live mode: monitor receives updates via BGP session (async)
        # In simulation mode: inject a synthetic malicious update
        if simulate_updates:
            detection_event = _inject_simulated_update(monitor, result, poll_time)
        else:
            detection_event = None

        # Poll routing tables
        snapshot = poll_routing_tables(net, result.target_prefix)
        pct = propagation_scope_pct(snapshot)
        metrics.propagation_snapshots.append({
            "time_s":    poll_time - result.attack_start_s,
            "routing":   snapshot,
            "scope_pct": pct,
        })
        metrics.peak_propagation_pct = max(metrics.peak_propagation_pct, pct)

        # Record first anomaly detection — compare against pre-scenario snapshot
        mon_stats = monitor.stats()
        new_alerts = mon_stats["alerts_fired"] - alerts_at_scenario_start
        if not first_anomaly_found and new_alerts > 0:
            metrics.first_anomaly_alert_s = poll_time
            first_anomaly_found = True
            logger.info("  [+] First anomaly alert at T+%.2fs",
                        poll_time - result.attack_start_s)

        # BUG L fix: track first RPKI INVALID detection from returned event
        if not first_rpki_found and detection_event is not None:
            if detection_event.rov_result == ROVResult.INVALID:
                metrics.first_rpki_invalid_s = poll_time
                first_rpki_found = True
                logger.info("  [+] First RPKI INVALID at T+%.2fs",
                            poll_time - result.attack_start_s)

        time.sleep(RECOVERY_POLL_S)

    # ── 3. Withdraw attack ──────────────────────────────────────────────────
    controller = AttackController()
    t_withdraw = controller.withdraw_all(
        prefixes=[result.target_prefix], net=net
    )
    metrics.withdrawal_time_s = t_withdraw

    # ── 4. Wait for recovery ────────────────────────────────────────────────
    logger.info("  Waiting for routing table recovery...")
    recovery_deadline = time.time() + 30
    while time.time() < recovery_deadline:
        snapshot = poll_routing_tables(net, result.target_prefix)
        pct = propagation_scope_pct(snapshot)
        if pct == 0.0:
            metrics.recovery_time_s = time.time() - t_withdraw
            logger.info("  [+] Routing table recovered in %.2fs",
                        metrics.recovery_time_s)
            break
        time.sleep(RECOVERY_POLL_S)

    logger.info("  Peak propagation: %.1f%% of ASes routed to attacker",
                metrics.peak_propagation_pct)

    return metrics


def _inject_simulated_update(monitor: BGPMonitor, result: AttackResult, ts: float):
    """
    In dry-run mode (no live Mininet), inject a synthetic malicious BGP UPDATE
    so the monitor's detection pipeline processes something.

    Returns:
        DetectionEvent from monitor.process(), or None on error.
    """
    try:
        prefix    = result.target_prefix
        # Attacker always ends the path
        as_path   = [1, 2, 99]
        origin_as = 99

        # For path manipulation scenario, stuff AS10 at end
        if result.scenario == "path_manipulation":
            as_path   = [1, 2, 99, 10]
            origin_as = 10

        update = BGPUpdate(
            prefix=prefix,
            origin_as=origin_as,
            as_path=as_path,
            announcing_router="10.0.12.1",
            timestamp=ts,
        )
        return monitor.process(update)
    except Exception as exc:   # noqa: BLE001
        logger.debug("Simulated update injection error: %s", exc)
    return None


# --------------------------------------------------------------------------- #
# Full Experiment Orchestrator
# --------------------------------------------------------------------------- #

def run_full_experiment(
    db_path:  str = "data/bgp_events.db",
    net=None,
    dry_run:  bool = True,
) -> list[ScenarioMetrics]:
    """
    Run all three attack scenarios end-to-end.

    Args:
        db_path:  Path to the SQLite event database.
        net:      Live Mininet network (None = dry-run mode).
        dry_run:  If True, skip actual vtysh calls (unit-testable mode).

    Returns:
        List of ScenarioMetrics — one per scenario.
    """
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    # ── Setup detection pipeline ────────────────────────────────────────────
    roa_db   = build_lab_roa_database(db_path=db_path.replace(".db", "_roa.db"))
    rov      = ROVEngine(roa_db)
    detector = AnomalyDetector(min_baseline_observations=1)
    monitor  = BGPMonitor(rov_engine=rov, anomaly_detector=detector, db_path=db_path)

    # ── Baseline window ─────────────────────────────────────────────────────
    logger.info("[EXPERIMENT] Starting baseline window (%ds)...", BASELINE_WINDOW_S)
    _learn_baseline(monitor, BASELINE_WINDOW_S)
    monitor.start_detection_window()

    # ── Attack scenarios ────────────────────────────────────────────────────
    controller = AttackController()
    all_metrics: list[ScenarioMetrics] = []

    scenarios = [
        (
            "Attack 1: Exact Prefix Hijack",
            lambda: controller.exact_prefix_hijack(
                victim_prefix="10.10.0.0/16", net=None if dry_run else net
            ),
        ),
        (
            "Attack 2: Subprefix Hijack",
            lambda: controller.subprefix_hijack(
                subprefix="10.10.1.0/24", net=None if dry_run else net
            ),
        ),
        (
            "Attack 3: AS Path Manipulation",
            lambda: controller.path_manipulation(
                victim_prefix="10.10.0.0/16",
                victim_asn=10,
                net=None if dry_run else net,
            ),
        ),
    ]

    for scenario_name, attack_fn in scenarios:
        try:
            metrics = run_scenario(
                scenario_name=scenario_name,
                attack_fn=attack_fn,
                monitor=monitor,
                net=net,
                simulate_updates=dry_run,
            )
            all_metrics.append(metrics)
        except Exception as exc:   # noqa: BLE001
            logger.error("Scenario '%s' failed: %s", scenario_name, exc, exc_info=True)
        finally:
            logger.info("Sleeping %ds between scenarios...", BETWEEN_SCENARIOS_S)
            time.sleep(BETWEEN_SCENARIOS_S)

    # ── Save results ────────────────────────────────────────────────────────
    results_path = Path(db_path).parent / "experiment_results.json"
    with open(results_path, "w") as fh:
        json.dump([asdict(m) for m in all_metrics], fh, indent=2, default=str)
    logger.info("[EXPERIMENT] Results saved to %s", results_path)

    monitor.close()
    return all_metrics


def _learn_baseline(monitor: BGPMonitor, duration_s: float) -> None:
    """Feed legitimate BGP updates into the monitor during the baseline window."""
    deadline = time.time() + duration_s
    legit_prefixes = [
        ("10.10.0.0/16", 10, [1, 2, 10]),
        ("10.20.0.0/16", 20, [1, 3, 20]),
        ("172.16.2.0/24", 2, [1, 2]),
        ("172.16.3.0/24", 3, [1, 3]),
    ]
    i = 0
    while time.time() < deadline:
        prefix, origin, path = legit_prefixes[i % len(legit_prefixes)]
        try:
            update = BGPUpdate(
                prefix=prefix,
                origin_as=origin,
                as_path=path,
                announcing_router="10.0.12.1",
                timestamp=time.time(),
            )
            monitor.tick_baseline(update)
        except Exception as exc:   # noqa: BLE001
            logger.debug("Baseline feed error: %s", exc)
        i += 1
        time.sleep(1)


# --------------------------------------------------------------------------- #
# CLI Entry Point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="BGP Hijack Lab — Experiment Runner")
    parser.add_argument("--db",      default="data/bgp_events.db")
    parser.add_argument("--dry-run",  action="store_true",  default=True,
                        help="Run without live Mininet — use simulated updates (default)")
    parser.add_argument("--live",     action="store_true",  default=False,
                        help="Run with live Mininet topology (overrides --dry-run)")
    args = parser.parse_args()

    # --live takes precedence over --dry-run
    dry_run = not args.live
    results = run_full_experiment(db_path=args.db, dry_run=dry_run)
    print(f"\n[DONE] {len(results)} scenarios completed.")
    for m in results:
        anom_lat = (
            f"{m.first_anomaly_alert_s - m.attack_start_s:.2f}s"
            if m.first_anomaly_alert_s else "NOT DETECTED"
        )
        print(f"  {m.scenario:<35} anomaly={anom_lat:<18} peak_scope={m.peak_propagation_pct:.1f}%")