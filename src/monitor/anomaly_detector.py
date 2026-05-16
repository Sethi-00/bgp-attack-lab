"""
src/monitor/anomaly_detector.py
────────────────────────────────
BGP Anomaly Detector
──────────────────────
Implements prefix-origin anomaly detection: flags BGP UPDATE messages
where a prefix is being announced by an AS that has not previously
announced that prefix during the baseline learning window.

This mirrors the approach used by production BGP monitoring systems
such as BGPmon, ARTEMIS, and Cloudflare Radar, adapted for the lab scale.

Design decisions:
  - Baseline is a dict mapping prefix → set[origin_as] (memory-efficient)
  - Detection is O(1) per UPDATE once baseline is loaded
  - The detector is stateless between restarts unless a snapshot is persisted
  - False positive rate depends heavily on baseline window duration (configurable)
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path

from src.monitor.models import BGPUpdate

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Anomaly Detector
# --------------------------------------------------------------------------- #

class AnomalyDetector:
    """
    BGP prefix-origin anomaly detector.

    Lifecycle:
      1. Call learn(update) for each UPDATE during the baseline window.
      2. Call detect(update) for each UPDATE during the experiment window.
         Returns (is_anomaly: bool, reason: str).

    The baseline can be saved to / loaded from JSON for reproducibility.

    Thread safety:
      Not thread-safe. If concurrent UPDATE streams are used, wrap with a lock.
    """

    def __init__(self, min_baseline_observations: int = 1):
        """
        Args:
            min_baseline_observations:
                Minimum number of times a prefix→AS mapping must be seen
                during baseline learning before it is considered 'known'.
                Setting this to 1 (default) means any prefix seen once is
                accepted. Increasing it reduces false positives in noisy
                baseline periods.
        """
        # prefix → {origin_as: observation_count}
        self._baseline: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._min_obs = min_baseline_observations
        self._learning_mode = True       # True = learn, False = detect
        self._observation_count = 0
        self._false_positives_count = 0  # alerts fired during known-clean window

    # ── Baseline Management ────────────────────────────────────────────────── #

    def learn(self, update: BGPUpdate) -> None:
        """
        Record a BGP UPDATE into the baseline.
        Should only be called during the known-clean baseline window.

        Args:
            update: A validated BGPUpdate received during baseline period.

        Raises:
            RuntimeError: If called after freeze_baseline() — calling learn()
            post-freeze would silently contaminate the detection baseline.
        """
        if not self._learning_mode:
            raise RuntimeError(
                "learn() called after freeze_baseline(). "
                "Calling learn() post-freeze would contaminate the detection "
                "baseline. Create a new AnomalyDetector if re-learning is needed."
            )
        self._baseline[update.prefix][update.origin_as] += 1
        self._observation_count += 1
        logger.debug("[BASELINE] prefix=%s origin_as=%d (total_obs=%d)",
                     update.prefix, update.origin_as, self._observation_count)

    def freeze_baseline(self) -> None:
        """
        Switch from learning mode to detection mode.
        Must be called before any detect() calls.
        """
        self._learning_mode = False
        known_prefixes = len(self._baseline)
        logger.info(
            "[BASELINE] Frozen. Known prefixes: %d, total observations: %d, "
            "min_obs threshold: %d",
            known_prefixes, self._observation_count, self._min_obs,
        )

    def is_learning(self) -> bool:
        return self._learning_mode

    def known_origins(self, prefix: str) -> set[int]:
        """
        Return the set of ASNs that have legitimately announced this prefix
        during the baseline window (meeting the min_obs threshold).
        """
        obs_map = self._baseline.get(prefix, {})
        return {asn for asn, count in obs_map.items() if count >= self._min_obs}

    # ── Detection ─────────────────────────────────────────────────────────── #

    def detect(self, update: BGPUpdate) -> tuple[bool, str]:
        """
        Check a BGP UPDATE against the learned baseline.

        Args:
            update: A validated BGPUpdate received during the experiment window.

        Returns:
            (is_anomaly, reason)
              - is_anomaly: True if this UPDATE should be flagged.
              - reason: Human-readable explanation.

        Raises:
            RuntimeError: If called before freeze_baseline().

        Detection logic:
          1. If we have seen this prefix before: check if the origin AS
             is in the known-origins set. If not → anomaly.
          2. If we have never seen this prefix before: flag as anomaly
             (a brand-new prefix appearing post-baseline is suspicious).
        """
        if self._learning_mode:
            raise RuntimeError(
                "detect() called before freeze_baseline(). "
                "Call freeze_baseline() after the learning window."
            )

        prefix    = update.prefix
        origin_as = update.origin_as

        known = self.known_origins(prefix)

        if not known:
            # Prefix was never seen during baseline — new prefix announcement
            reason = (
                f"Prefix {prefix} was not observed during baseline learning. "
                f"New prefix announced by AS{origin_as}."
            )
            logger.warning("[ANOMALY] NEW PREFIX — %s", reason)
            return True, reason

        if origin_as not in known:
            # Prefix known but this AS has never announced it before
            reason = (
                f"Prefix {prefix} announced by AS{origin_as} but baseline "
                f"shows only these origin ASes: {sorted(known)}. "
                f"Possible BGP hijack."
            )
            logger.warning("[ANOMALY] UNEXPECTED ORIGIN — %s", reason)
            return True, reason

        logger.debug("[DETECT] No anomaly: prefix=%s origin_as=%d", prefix, origin_as)
        return False, "No anomaly — origin AS matches baseline."

    # ── AS Path Analysis ──────────────────────────────────────────────────── #

    def detect_path_manipulation(
        self, update: BGPUpdate, known_topology: dict[int, set[int]]
    ) -> tuple[bool, str]:
        """
        Detect AS path anomalies: paths that traverse AS relationships not
        seen in the baseline topology.

        This catches Attack Scenario 3 (AS path manipulation) which pure
        prefix-origin detection misses — the prefix origin looks legitimate
        but the AS_PATH contains unexpected AS relationships.

        Args:
            update:          The BGP UPDATE to analyse.
            known_topology:  Adjacency dict {as: {peers}} from baseline.

        Returns:
            (is_anomaly, reason)
        """
        path = update.as_path
        anomalous_links: list[str] = []

        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            # Check both directions: BGP peering is symmetric, so AS A peers
            # with AS B means AS B also peers with AS A.
            src_known_peers = known_topology.get(src, set())
            dst_known_peers = known_topology.get(dst, set())
            link_known = (dst in src_known_peers) or (src in dst_known_peers)
            if not link_known:
                anomalous_links.append(f"AS{src}→AS{dst}")

        if anomalous_links:
            reason = (
                f"AS_PATH contains unknown peering relationships: "
                f"{', '.join(anomalous_links)}. "
                f"Full path: {path}"
            )
            logger.warning("[ANOMALY] PATH MANIPULATION — %s", reason)
            return True, reason

        return False, "AS_PATH consistent with known topology."

    # ── Persistence ───────────────────────────────────────────────────────── #

    def save_baseline(self, path: Path) -> None:
        """
        Serialize the baseline to a JSON file for reproducible experiments.
        Allows skipping the learning phase in subsequent runs.

        Raises:
            RuntimeError: If called before freeze_baseline(). Saving an
            unfrozen baseline produces a file that load_baseline() will
            open in detection mode — but the data was collected in learning
            mode and may be incomplete or inconsistent.
        """
        if self._learning_mode:
            raise RuntimeError(
                "save_baseline() called before freeze_baseline(). "
                "Freeze the baseline first to ensure it is complete."
            )
        # Convert defaultdicts to plain dicts for JSON serialisation
        serialisable = {
            prefix: dict(asn_counts)
            for prefix, asn_counts in self._baseline.items()
        }
        payload = {
            "min_baseline_observations": self._min_obs,
            "observation_count": self._observation_count,
            "baseline": serialisable,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2))
        logger.info("Baseline saved to %s (%d prefixes)", path, len(self._baseline))

    @classmethod
    def load_baseline(cls, path: Path) -> AnomalyDetector:
        """
        Deserialise a previously saved baseline.

        Args:
            path: Path to a JSON file written by save_baseline().

        Returns:
            An AnomalyDetector in frozen (detection) mode.
        """
        if not path.exists():
            raise FileNotFoundError(f"Baseline file not found: {path}")

        payload = json.loads(path.read_text())
        detector = cls(min_baseline_observations=payload.get("min_baseline_observations", 1))
        detector._observation_count = payload.get("observation_count", 0)

        for prefix, asn_counts in payload["baseline"].items():
            for asn_str, count in asn_counts.items():
                detector._baseline[prefix][int(asn_str)] = count

        detector.freeze_baseline()
        logger.info("Baseline loaded from %s", path)
        return detector

    def increment_false_positive(self) -> None:
        """
        Manually record that an alert was a confirmed false positive.
        Call this when an operator verifies that a flagged UPDATE was legitimate.
        Used to track false positive rate for the experiment metrics.
        """
        self._false_positives_count += 1

    # ── Diagnostics ──────────────────────────────────────────────────────── #

    def stats(self) -> dict:
        """Return diagnostic summary dict."""
        return {
            "learning_mode":         self._learning_mode,
            "known_prefixes":        len(self._baseline),
            "total_observations":    self._observation_count,
            "min_obs_threshold":     self._min_obs,
            "false_positives":       self._false_positives_count,
        }