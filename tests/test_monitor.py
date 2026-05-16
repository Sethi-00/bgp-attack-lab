"""
tests/test_monitor.py
──────────────────────
Unit tests for the BGP Monitor core engine.

Covers:
  - BGPUpdate model validation (valid + invalid inputs)
  - RouteOriginAuthorization model validation
  - ROVEngine validation logic (Valid, Invalid, NotFound)
  - RPKI evasion scenario (maxLength gap)
  - AnomalyDetector baseline learning and detection
  - AnomalyDetector AS path manipulation detection
  - BGPMonitor integration (ROV + anomaly in one pipeline)
  - Detection latency calculation
  - Edge cases: empty AS path, invalid CIDR, out-of-range ASN

Run with:
    pytest tests/test_monitor.py -v
"""

from __future__ import annotations

import time
import pytest
from freezegun import freeze_time

from src.monitor.models import (
    BGPUpdate,
    RouteOriginAuthorization,
    ROVResult,
    EventType,
)
from src.monitor.rov_engine import ROVEngine, ROADatabase, build_lab_roa_database
from src.monitor.anomaly_detector import AnomalyDetector
from src.monitor.monitor import BGPMonitor


# ============================================================================ #
# Fixtures
# ============================================================================ #

@pytest.fixture
def lab_roa_db() -> ROADatabase:
    """Fully populated in-memory ROA database matching the lab topology."""
    return build_lab_roa_database(db_path=":memory:")


@pytest.fixture
def rov(lab_roa_db) -> ROVEngine:
    return ROVEngine(lab_roa_db)


@pytest.fixture
def detector() -> AnomalyDetector:
    """A freshly initialised AnomalyDetector in learning mode."""
    return AnomalyDetector(min_baseline_observations=1)


def make_update(
    prefix:    str = "10.10.0.0/16",
    origin_as: int = 10,
    as_path:   list[int] | None = None,
    router:    str = "172.16.2.1",
    ts:        float | None = None,
) -> BGPUpdate:
    """Factory for BGPUpdate test objects."""
    return BGPUpdate(
        prefix=prefix,
        origin_as=origin_as,
        as_path=as_path or [1, 2, origin_as],
        announcing_router=router,
        timestamp=ts or time.time(),
    )


# ============================================================================ #
# BGPUpdate Model Validation
# ============================================================================ #

class TestBGPUpdateModel:

    def test_valid_update_accepted(self):
        u = make_update("10.10.0.0/16", 10, [1, 2, 10])
        assert u.prefix == "10.10.0.0/16"
        assert u.origin_as == 10

    def test_invalid_cidr_rejected(self):
        with pytest.raises(ValueError, match="Invalid IP prefix"):
            BGPUpdate(
                prefix="not-a-prefix",
                origin_as=10,
                as_path=[10],
                announcing_router="1.1.1.1",
                timestamp=time.time(),
            )

    def test_asn_zero_rejected(self):
        with pytest.raises(ValueError, match="ASN 0 is outside"):
            make_update(origin_as=0, as_path=[0])

    def test_asn_too_large_rejected(self):
        with pytest.raises(ValueError, match="outside the valid range"):
            make_update(origin_as=2**32, as_path=[2**32])

    def test_empty_as_path_rejected(self):
        with pytest.raises(ValueError, match="AS_PATH must contain"):
            BGPUpdate(
                prefix="10.10.0.0/16",
                origin_as=10,
                as_path=[],
                announcing_router="1.1.1.1",
                timestamp=time.time(),
            )

    def test_origin_as_must_match_path_tail(self):
        with pytest.raises(ValueError, match="must match the last element"):
            make_update(prefix="10.10.0.0/16", origin_as=10, as_path=[1, 2, 99])

    def test_network_property_returns_parsed_network(self):
        u = make_update("10.10.0.0/16", 10, [10])
        import ipaddress
        assert u.network == ipaddress.ip_network("10.10.0.0/16")


# ============================================================================ #
# RouteOriginAuthorization Model Validation
# ============================================================================ #

class TestROAModel:

    def test_valid_roa_accepted(self):
        roa = RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=16)
        assert roa.origin_as == 10

    def test_invalid_prefix_rejected(self):
        with pytest.raises(ValueError):
            RouteOriginAuthorization(prefix="badprefix", origin_as=10, max_length=16)

    def test_max_length_shorter_than_prefix_rejected(self):
        # ROA maxLength=/8 for a /16 prefix makes no sense
        with pytest.raises(ValueError, match="cannot be shorter than"):
            RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=8)

    def test_max_length_out_of_range_rejected(self):
        with pytest.raises(ValueError):
            RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=33)

    def test_ipv6_roa_max_length_supports_128(self):
        """IPv6 ROAs may use maxLength up to /128, not /32."""
        roa = RouteOriginAuthorization(
            prefix="2001:db8::/32",
            origin_as=10,
            max_length=64,
        )
        assert roa.max_length == 64


# ============================================================================ #
# ROV Engine — Core Validation Logic
# ============================================================================ #

class TestROVEngine:

    # ── VALID ──────────────────────────────────────────────────────────────── #

    def test_legitimate_announcement_is_valid(self, rov):
        """AS10 announcing its own /16 → VALID."""
        u = make_update("10.10.0.0/16", origin_as=10, as_path=[1, 2, 10])
        result, reason = rov.validate(u)
        assert result == ROVResult.VALID
        assert "matches ROA" in reason

    def test_more_specific_within_max_length_is_valid(self, rov):
        """
        AS20 ROA has maxLength=/24. AS20 announcing a /20 should be VALID
        because /20 ≤ /24 (more specific than base but within maxLength).
        """
        u = make_update("10.20.1.0/24", origin_as=20, as_path=[1, 3, 20])
        result, _ = rov.validate(u)
        assert result == ROVResult.VALID

    # ── INVALID ────────────────────────────────────────────────────────────── #

    def test_wrong_origin_as_is_invalid(self, rov):
        """AS99 announcing AS10's prefix → INVALID (wrong origin AS)."""
        u = make_update("10.10.0.0/16", origin_as=99, as_path=[1, 2, 99])
        result, reason = rov.validate(u)
        assert result == ROVResult.INVALID
        assert "RPKI INVALID" in reason

    def test_subprefix_exceeding_max_length_is_invalid(self, rov):
        """
        Victim's ROA has maxLength=/16 (tight config).
        Attacker announces /24 within the victim's /16 → INVALID.
        This is the correct RPKI response to a subprefix hijack.
        """
        # lab_roa_db fixture has AS10 ROA with maxLength=16
        u = make_update("10.10.1.0/24", origin_as=10, as_path=[1, 2, 10])
        result, reason = rov.validate(u)
        assert result == ROVResult.INVALID
        assert "maxLength" in reason

    def test_wrong_as_and_too_specific_is_invalid(self, rov):
        """Both wrong AS and too-specific prefix → INVALID."""
        u = make_update("10.10.1.0/24", origin_as=99, as_path=[1, 2, 99])
        result, reason = rov.validate(u)
        assert result == ROVResult.INVALID

    # ── NOT_FOUND ──────────────────────────────────────────────────────────── #

    def test_unrouted_prefix_is_not_found(self, rov):
        """A prefix with no covering ROA → NOT_FOUND."""
        u = make_update("192.168.99.0/24", origin_as=500, as_path=[500])
        result, reason = rov.validate(u)
        assert result == ROVResult.NOT_FOUND
        assert "No ROA covers" in reason

    def test_attacker_prefix_outside_any_roa_is_not_found(self, rov):
        """AS99 announcing a completely new prefix not in any ROA → NOT_FOUND."""
        u = make_update("203.0.113.0/24", origin_as=99, as_path=[99])
        result, _ = rov.validate(u)
        assert result == ROVResult.NOT_FOUND

    # ── RPKI Evasion Scenario (Critical Lab Finding) ──────────────────────── #

    def test_rpki_evasion_via_max_length_misconfiguration(self):
        """
        RPKI evasion: attacker announces /24 subprefix of victim's /16.
        If the ROA has maxLength=/24 (misconfigured), ROV returns VALID
        even though the attacker is not the legitimate origin AS.

        This is a documented real-world RPKI weakness.
        Expected result: ROV returns VALID for attacker's announcement — evasion!
        """
        # Create an ROA with an over-broad maxLength
        db = ROADatabase(":memory:")
        misconfigured_roa = RouteOriginAuthorization(
            prefix="10.10.0.0/16",
            origin_as=10,
            max_length=24,   # ← Common misconfiguration: too broad
        )
        db.insert_roa(misconfigured_roa)
        rov_engine = ROVEngine(db)

        # Attacker announces a /24 within the victim's /16 — but with VICTIM's AS
        # (path stuffing: attacker inserts victim ASN at end of path)
        attacker_update = make_update(
            prefix="10.10.1.0/24",
            origin_as=10,        # ← Attacker stuffs AS10 into path
            as_path=[1, 2, 99, 10],
        )

        result, reason = rov_engine.validate(attacker_update)

        # This should be VALID — demonstrating the evasion
        assert result == ROVResult.VALID, (
            f"Expected VALID (demonstrating RPKI evasion) but got {result}. "
            f"Reason: {reason}"
        )

    # ── Batch Validation ──────────────────────────────────────────────────── #

    def test_batch_validate_returns_correct_count(self, rov):
        updates = [
            make_update("10.10.0.0/16", 10, [10]),
            make_update("10.10.0.0/16", 99, [99]),
            make_update("9.9.9.9/32",   99, [99]),
        ]
        results = rov.batch_validate(updates)
        assert len(results) == 3
        assert results[0][1] == ROVResult.VALID
        assert results[1][1] == ROVResult.INVALID
        assert results[2][1] == ROVResult.NOT_FOUND


# ============================================================================ #
# Anomaly Detector
# ============================================================================ #

class TestAnomalyDetector:

    def _frozen_detector(self, baseline_updates: list[BGPUpdate]) -> AnomalyDetector:
        """Helper: build a detector, learn updates, freeze, return it."""
        det = AnomalyDetector(min_baseline_observations=1)
        for u in baseline_updates:
            det.learn(u)
        det.freeze_baseline()
        return det

    # ── Baseline Learning ─────────────────────────────────────────────────── #

    def test_detect_before_freeze_raises(self, detector):
        update = make_update("10.10.0.0/16", 10, [10])
        with pytest.raises(RuntimeError, match="freeze_baseline"):
            detector.detect(update)

    def test_known_origin_is_not_anomaly(self):
        baseline = [make_update("10.10.0.0/16", 10, [10])]
        det = self._frozen_detector(baseline)
        result, reason = det.detect(make_update("10.10.0.0/16", 10, [10]))
        assert result is False
        assert "No anomaly" in reason

    def test_new_origin_as_is_anomaly(self):
        """AS99 announcing a prefix normally originated by AS10 → anomaly."""
        baseline = [make_update("10.10.0.0/16", 10, [10])]
        det = self._frozen_detector(baseline)
        result, reason = det.detect(make_update("10.10.0.0/16", 99, [99]))
        assert result is True
        assert "AS10" in reason or "10" in reason

    def test_new_prefix_not_in_baseline_is_anomaly(self):
        """A prefix that never appeared during baseline → anomaly."""
        baseline = [make_update("10.10.0.0/16", 10, [10])]
        det = self._frozen_detector(baseline)
        result, reason = det.detect(make_update("10.20.0.0/16", 99, [99]))
        assert result is True
        assert "not observed during baseline" in reason

    # ── min_baseline_observations ─────────────────────────────────────────── #

    def test_min_obs_threshold_filters_noise(self):
        """
        With min_obs=3, a prefix seen only once in baseline is NOT considered
        'known' and triggers an anomaly on subsequent detection.
        """
        det = AnomalyDetector(min_baseline_observations=3)
        det.learn(make_update("10.10.0.0/16", 10, [10]))  # Only 1 observation
        det.freeze_baseline()

        result, reason = det.detect(make_update("10.10.0.0/16", 10, [10]))
        assert result is True  # Not enough baseline observations

    # ── AS Path Manipulation ──────────────────────────────────────────────── #

    def test_path_manipulation_detected(self):
        """An AS relationship not seen in baseline topology is flagged."""
        det = AnomalyDetector()
        det.freeze_baseline()

        known_topology = {
            1: {2, 3},
            2: {1, 10, 99},
            3: {1, 20, 99},
            10: {2},
            20: {3},
        }

        # AS99 → AS10 is not a known link (99 peers with 2 and 3, not 10)
        manipulated = make_update("10.10.0.0/16", 10, [1, 2, 99, 10])
        is_anom, reason = det.detect_path_manipulation(manipulated, known_topology)
        assert is_anom is True
        assert "AS99→AS10" in reason

    def test_legitimate_path_not_flagged(self):
        """A path that follows known topology is not flagged."""
        det = AnomalyDetector()
        det.freeze_baseline()

        known_topology = {1: {2, 3}, 2: {1, 10}, 10: {2}}
        legit = make_update("10.10.0.0/16", 10, [1, 2, 10])
        is_anom, _ = det.detect_path_manipulation(legit, known_topology)
        assert is_anom is False

    # ── Persistence ───────────────────────────────────────────────────────── #

    def test_save_and_load_baseline(self, tmp_path):
        baseline = [
            make_update("10.10.0.0/16", 10, [10]),
            make_update("10.20.0.0/16", 20, [20]),
        ]
        det = self._frozen_detector(baseline)

        save_path = tmp_path / "baseline.json"
        det.save_baseline(save_path)
        assert save_path.exists()

        loaded = AnomalyDetector.load_baseline(save_path)
        assert loaded.known_origins("10.10.0.0/16") == {10}
        assert loaded.known_origins("10.20.0.0/16") == {20}

    def test_load_missing_baseline_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            AnomalyDetector.load_baseline(tmp_path / "nonexistent.json")


# ============================================================================ #
# BGPMonitor Integration
# ============================================================================ #

class TestBGPMonitor:

    @pytest.fixture
    def monitor(self, lab_roa_db):
        rov  = ROVEngine(lab_roa_db)
        det  = AnomalyDetector()
        det.learn(make_update("10.10.0.0/16", 10, [10]))
        det.freeze_baseline()
        return BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")

    def test_legitimate_update_no_alert(self, monitor):
        u = make_update("10.10.0.0/16", 10, [10])
        event = monitor.process(u)
        assert event.is_anomaly is False
        assert event.rov_result == ROVResult.VALID

    def test_hijack_triggers_both_alerts(self, monitor):
        """An exact-prefix hijack from AS99 should flag both anomaly and RPKI."""
        u = make_update("10.10.0.0/16", origin_as=99, as_path=[1, 2, 99])
        event = monitor.process(u)
        assert event.is_anomaly is True
        assert event.rov_result == ROVResult.INVALID

    def test_detection_latency_computed(self, lab_roa_db):
        """When attack_start_time is set, detection latency is calculated."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()

        t0 = time.time() - 5.0  # Attack started 5 seconds ago
        mon = BGPMonitor(
            rov_engine=rov,
            anomaly_detector=det,
            db_path=":memory:",
            attack_start_time=t0,
        )
        u = make_update(
            "10.10.0.0/16", origin_as=99, as_path=[99],
            ts=time.time(),
        )
        event = mon.process(u)
        assert event.detection_latency_s is not None
        assert 4.0 < event.detection_latency_s < 10.0   # ~5s with tolerance

    def test_monitor_stats_track_events(self, monitor):
        for _ in range(3):
            monitor.process(make_update("10.10.0.0/16", 10, [10]))
        stats = monitor.stats()
        assert stats["events_processed"] == 3

    def test_alert_hook_fires_on_hijack(self, monitor):
        """Custom alert hooks should receive DetectionEvents on alerts."""
        received = []
        monitor.on_alert(lambda e: received.append(e))

        hijack = make_update("10.10.0.0/16", 99, [99])
        monitor.process(hijack)

        assert len(received) >= 1
        assert received[0].rov_result == ROVResult.INVALID

    def test_malformed_update_does_not_crash_monitor(self, monitor):
        """
        Security review finding: if ROV or anomaly detector throws internally,
        the monitor must still return a safe event (not propagate exception).
        """
        # Force an exception by passing an object that will fail deep in pipeline
        # We simulate this by temporarily breaking the detector
        original_detect = monitor._detector.detect
        monitor._detector.detect = lambda u: (_ for _ in ()).throw(RuntimeError("simulated crash"))

        u = make_update("10.10.0.0/16", 10, [10])
        # Should NOT raise — monitor catches and returns safe event
        event = monitor.process(u)
        assert event is not None

        # Restore
        monitor._detector.detect = original_detect


# ============================================================================ #
# ROA Database
# ============================================================================ #

class TestROADatabase:

    def test_insert_and_retrieve_roa(self):
        db  = ROADatabase(":memory:")
        roa = RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=16)
        db.insert_roa(roa)
        all_roas = db.all_roas()
        assert len(all_roas) == 1
        assert all_roas[0].origin_as == 10

    def test_covering_roas_returns_parent(self):
        db  = ROADatabase(":memory:")
        roa = RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=24)
        db.insert_roa(roa)
        # Query a child prefix — should find the parent ROA
        covering = db.covering_roas("10.10.1.0/24")
        assert len(covering) == 1
        assert covering[0].prefix == "10.10.0.0/16"

    def test_non_covering_roa_not_returned(self):
        db  = ROADatabase(":memory:")
        roa = RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=24)
        db.insert_roa(roa)
        # Completely different prefix — no covering ROA
        covering = db.covering_roas("192.168.1.0/24")
        assert covering == []

    def test_load_from_json(self, tmp_path):
        import json
        data = [
            {"prefix": "10.0.0.0/8", "origin_as": 1, "max_length": 16},
            {"prefix": "172.16.0.0/12", "origin_as": 2, "max_length": 16},
        ]
        json_file = tmp_path / "roas.json"
        json_file.write_text(json.dumps(data))

        db    = ROADatabase(":memory:")
        count = db.load_from_json(json_file)
        assert count == 2
        assert len(db.all_roas()) == 2

    def test_load_from_missing_json_raises(self, tmp_path):
        db = ROADatabase(":memory:")
        with pytest.raises(FileNotFoundError):
            db.load_from_json(tmp_path / "missing.json")


# ============================================================================ #
# Regression Tests — Bug Fixes
# ============================================================================ #

class TestBugFixes:
    """Regression tests for every bug found during the audit pass."""

    # ── BUG 1: t0=0.0 falsy check ─────────────────────────────────────────── #
    def test_mark_attack_start_zero_epoch_is_valid(self, lab_roa_db):
        """t0=0.0 must NOT be replaced with time.time() (it's a valid timestamp)."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")
        mon.mark_attack_start(t0=0.0)
        assert mon._attack_t0 == 0.0, "t0=0.0 was incorrectly replaced by time.time()"

    def test_mark_attack_start_none_uses_current_time(self, lab_roa_db):
        """When t0 is None, mark_attack_start should use the current time."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")
        before = time.time()
        mon.mark_attack_start(t0=None)
        after = time.time()
        assert before <= mon._attack_t0 <= after

    # ── BUG 2: IPv6 prefix in ROV engine ──────────────────────────────────── #
    def test_rov_engine_handles_ipv6_prefix_gracefully(self, rov):
        """IPv6 update against IPv4 ROA database must return NOT_FOUND, not crash."""
        import time as _time
        ipv6_update = BGPUpdate(
            prefix="2001:db8::/32",
            origin_as=99,
            as_path=[1, 99],
            announcing_router="10.0.12.1",
            timestamp=_time.time(),
        )
        result, reason = rov.validate(ipv6_update)
        assert result == ROVResult.NOT_FOUND
        assert "crash" not in reason.lower()

    # ── BUG 3: _comment field in roas.json ────────────────────────────────── #
    def test_load_from_json_ignores_comment_fields(self, tmp_path):
        """roas.json entries with _comment keys must load without error."""
        import json
        data = [
            {
                "prefix": "10.10.0.0/16",
                "origin_as": 10,
                "max_length": 16,
                "_comment": "This is a comment — must be silently ignored",
            }
        ]
        json_file = tmp_path / "roas_with_comments.json"
        json_file.write_text(json.dumps(data))

        db    = ROADatabase(":memory:")
        count = db.load_from_json(json_file)
        assert count == 1, f"Expected 1 ROA loaded, got {count}"
        loaded = db.all_roas()
        assert loaded[0].origin_as == 10

    # ── BUG 4+6: Thread safety — write lock exists ────────────────────────── #
    def test_event_store_has_write_lock(self):
        """EventStore must have a threading.Lock for concurrent write safety."""
        from src.monitor.monitor import EventStore
        import threading
        store = EventStore(":memory:")
        assert hasattr(store, "_write_lock"), "EventStore missing _write_lock attribute"
        assert isinstance(store._write_lock, type(threading.Lock()))

    def test_roa_database_has_write_lock(self):
        """ROADatabase must have a threading.Lock."""
        import threading
        db = ROADatabase(":memory:")
        assert hasattr(db, "_write_lock"), "ROADatabase missing _write_lock attribute"

    # ── BUG 8: zebra.conf exists for each AS ─────────────────────────────── #
    def test_zebra_conf_exists_for_all_ases(self):
        """Every AS must have a zebra.conf alongside bgpd.conf."""
        from pathlib import Path
        frr_dir = Path(__file__).parent.parent / "config" / "frr"
        for asn in (1, 2, 3, 10, 20, 99):
            zebra = frr_dir / f"as{asn}" / "zebra.conf"
            assert zebra.exists(), f"Missing zebra.conf for AS{asn} at {zebra}"
            bgpd  = frr_dir / f"as{asn}" / "bgpd.conf"
            assert bgpd.exists(),  f"Missing bgpd.conf for AS{asn} at {bgpd}"

    # ── Additional edge case: empty ROA database ──────────────────────────── #
    def test_rov_on_empty_roa_database_returns_not_found(self):
        """ROV against an empty ROA database must return NOT_FOUND, never crash."""
        empty_db  = ROADatabase(":memory:")
        rov_empty = ROVEngine(empty_db)
        u = make_update("10.10.0.0/16", 10, [10])
        result, _ = rov_empty.validate(u)
        assert result == ROVResult.NOT_FOUND

    # ── Additional edge case: duplicate ROA insert ────────────────────────── #
    def test_duplicate_roa_insert_does_not_raise(self):
        """INSERT OR REPLACE must not raise on duplicate (prefix, origin_as)."""
        db  = ROADatabase(":memory:")
        roa = RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=16)
        db.insert_roa(roa)
        db.insert_roa(roa)  # second insert — should not raise
        assert len(db.all_roas()) == 1

    # ── Additional edge case: withdrawal UPDATE type ──────────────────────── #
    def test_withdrawal_event_type_stored_correctly(self, lab_roa_db):
        """A WITHDRAW event_type must survive round-trip through the monitor."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")
        u = BGPUpdate(
            prefix="10.10.0.0/16",
            origin_as=10,
            as_path=[1, 2, 10],
            announcing_router="10.0.12.1",
            timestamp=time.time(),
            event_type=EventType.WITHDRAW,
        )
        event = mon.process(u)
        assert event.update.event_type == EventType.WITHDRAW


# ============================================================================ #
# Regression Tests — Round 2 Bug Fixes
# ============================================================================ #

class TestBugFixesRound2:
    """Regression tests for the second audit pass (10 additional bugs)."""

    # ── BUG 1 & 2: network property type hint ─────────────────────────────── #
    def test_bgpupdate_network_property_returns_correct_type(self):
        """BGPUpdate.network must return the right type for both IPv4 and IPv6."""
        import ipaddress
        u4 = make_update("10.10.0.0/16", 10, [10])
        assert isinstance(u4.network, ipaddress.IPv4Network)

    def test_bgpupdate_network_property_ipv6(self):
        """BGPUpdate.network must handle IPv6 prefix without raising."""
        import ipaddress, time as _time
        u6 = BGPUpdate(
            prefix="2001:db8::/32",
            origin_as=10,
            as_path=[10],
            announcing_router="::1",
            timestamp=_time.time(),
        )
        assert isinstance(u6.network, ipaddress.IPv6Network)

    def test_roa_network_property_returns_correct_type(self):
        """ROA.network must return the right type for IPv4."""
        import ipaddress
        roa = RouteOriginAuthorization(prefix="10.10.0.0/16", origin_as=10, max_length=16)
        assert isinstance(roa.network, ipaddress.IPv4Network)

    # ── BUG 3: latency falsy check on t0=0.0 ─────────────────────────────── #
    def test_latency_computed_when_attack_t0_is_zero(self, lab_roa_db):
        """t0=0.0 is a valid epoch timestamp — latency must still be computed."""
        import time as _time
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det,
                         db_path=":memory:", attack_start_time=0.0)
        hijack = make_update("10.10.0.0/16", 99, [99], ts=1.5)
        event  = mon.process(hijack)
        # Latency = 1.5 - 0.0 = 1.5s — should NOT be None
        assert event.detection_latency_s is not None, (
            "Latency was None for t0=0.0 — falsy check bug not fixed"
        )
        assert abs(event.detection_latency_s - 1.5) < 0.01

    # ── BUG 6: alerts_fired counter not reset between scenarios ──────────── #
    def test_alerts_fired_is_cumulative_across_calls(self, lab_roa_db):
        """
        alerts_fired is cumulative by design — callers must snapshot before
        a scenario and compute delta. This test documents the expected behavior.
        """
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")

        # Fire one alert
        mon.process(make_update("10.10.0.0/16", 99, [99]))
        assert mon.stats()["alerts_fired"] == 1

        # Fire another — counter accumulates, not resets
        mon.process(make_update("10.10.0.0/16", 99, [99]))
        assert mon.stats()["alerts_fired"] == 2

        # Caller must snapshot before scenario and compute delta
        snapshot = mon.stats()["alerts_fired"]
        mon.process(make_update("10.10.0.0/16", 99, [99]))
        new_in_scenario = mon.stats()["alerts_fired"] - snapshot
        assert new_in_scenario == 1

    # ── BUG 7: false_positives_count wired up ───────────────────────────── #
    def test_false_positive_count_starts_at_zero(self):
        """AnomalyDetector must start with false_positives=0."""
        det = AnomalyDetector()
        assert det.stats()["false_positives"] == 0

    def test_false_positive_increment(self):
        """increment_false_positive must increment the counter."""
        det = AnomalyDetector()
        det.increment_false_positive()
        det.increment_false_positive()
        assert det.stats()["false_positives"] == 2

    # ── BUG 8: _baseline_deadline removed from monitor ───────────────────── #
    def test_baseline_deadline_attribute_does_not_exist(self, lab_roa_db):
        """_baseline_deadline was dead state — must not exist after fix."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")
        mon.start_baseline_window(duration_s=30)
        assert not hasattr(mon, "_baseline_deadline"), (
            "_baseline_deadline still present — dead state not removed"
        )

    # ── BUG 3 complementary: latency is None when no attack_t0 set ───────── #
    def test_latency_is_none_when_no_attack_start_set(self, lab_roa_db):
        """When attack_start_time is not set, latency must be None."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det,
                         db_path=":memory:", attack_start_time=None)
        event = mon.process(make_update("10.10.0.0/16", 99, [99]))
        assert event.detection_latency_s is None


# ============================================================================ #
# Regression Tests — Round 3 Bug Fixes
# ============================================================================ #

class TestBugFixesRound3:
    """Regression tests for the third and final audit pass."""

    # ── BUG A: announcing_router validated as IP ───────────────────────────── #
    def test_announcing_router_must_be_valid_ip(self):
        """announcing_router must reject non-IP strings."""
        with pytest.raises(ValueError, match="announcing_router"):
            BGPUpdate(
                prefix="10.0.0.0/8", origin_as=1, as_path=[1],
                announcing_router="NOT_AN_IP", timestamp=time.time(),
            )

    def test_announcing_router_valid_ipv4(self):
        """announcing_router accepts a valid IPv4 address."""
        u = make_update()
        assert u.announcing_router == "172.16.2.1"

    # ── BUG B: timestamp validated as non-negative ────────────────────────── #
    def test_timestamp_negative_rejected(self):
        """Negative timestamps must be rejected."""
        with pytest.raises(ValueError, match="timestamp"):
            BGPUpdate(
                prefix="10.0.0.0/8", origin_as=1, as_path=[1],
                announcing_router="1.2.3.4", timestamp=-1.0,
            )

    def test_timestamp_zero_accepted(self):
        """timestamp=0.0 is a valid Unix epoch value."""
        u = BGPUpdate(
            prefix="10.0.0.0/8", origin_as=1, as_path=[1],
            announcing_router="1.2.3.4", timestamp=0.0,
        )
        assert u.timestamp == 0.0

    # ── BUG D: ROA origin_as=0 rejected ───────────────────────────────────── #
    def test_roa_origin_as_zero_rejected(self):
        """ROA origin_as=0 is not a valid ASN and must be rejected."""
        with pytest.raises(ValueError, match="origin_as"):
            RouteOriginAuthorization(prefix="10.0.0.0/8", origin_as=0, max_length=8)

    def test_roa_origin_as_valid(self):
        """ROA with a valid ASN must be accepted."""
        roa = RouteOriginAuthorization(prefix="10.0.0.0/8", origin_as=1, max_length=8)
        assert roa.origin_as == 1

    # ── BUG F: learn() blocked after freeze_baseline() ───────────────────── #
    def test_learn_after_freeze_raises(self):
        """learn() must raise RuntimeError after freeze_baseline()."""
        det = AnomalyDetector()
        det.freeze_baseline()
        with pytest.raises(RuntimeError, match="learn\\(\\) called after freeze_baseline"):
            det.learn(make_update())

    # ── BUG G: WITHDRAW events skip ROV and anomaly detection ────────────── #
    def test_withdraw_event_skips_rov(self, lab_roa_db):
        """WITHDRAW events must return NOT_FOUND without running ROV pipeline."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")
        withdraw = BGPUpdate(
            prefix="10.10.0.0/16", origin_as=10, as_path=[1, 2, 10],
            announcing_router="10.0.12.1", timestamp=time.time(),
            event_type=EventType.WITHDRAW,
        )
        event = mon.process(withdraw)
        assert event.is_anomaly is False
        assert "WITHDRAW" in event.rov_reason

    def test_withdraw_event_no_alert_fired(self, lab_roa_db):
        """WITHDRAW events must never fire alerts."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")
        alerts_before = mon.stats()["alerts_fired"]
        withdraw = BGPUpdate(
            prefix="10.10.0.0/16", origin_as=99, as_path=[1, 2, 99],
            announcing_router="10.0.12.1", timestamp=time.time(),
            event_type=EventType.WITHDRAW,
        )
        mon.process(withdraw)
        assert mon.stats()["alerts_fired"] == alerts_before

    # ── BUG I: double close is safe ───────────────────────────────────────── #
    def test_monitor_close_twice_is_safe(self, lab_roa_db):
        """BGPMonitor.close() called twice must not raise."""
        rov = ROVEngine(lab_roa_db)
        det = AnomalyDetector()
        det.freeze_baseline()
        mon = BGPMonitor(rov_engine=rov, anomaly_detector=det, db_path=":memory:")
        mon.close()
        mon.close()   # must not raise

    # ── BUG J: save_baseline before freeze raises ─────────────────────────── #
    def test_save_baseline_before_freeze_raises(self, tmp_path):
        """save_baseline() must raise if called before freeze_baseline()."""
        det = AnomalyDetector()
        with pytest.raises(RuntimeError, match="freeze_baseline"):
            det.save_baseline(tmp_path / "baseline.json")

    def test_save_baseline_after_freeze_succeeds(self, tmp_path):
        """save_baseline() must succeed after freeze_baseline()."""
        det = AnomalyDetector()
        det.learn(make_update())
        det.freeze_baseline()
        path = tmp_path / "baseline.json"
        det.save_baseline(path)
        assert path.exists()

    # ── BUG M: next_hop validated as IP ──────────────────────────────────── #
    def test_next_hop_garbage_value_rejected(self):
        """next_hop must reject non-IP strings."""
        with pytest.raises(ValueError, match="next_hop"):
            BGPUpdate(
                prefix="10.0.0.0/8", origin_as=1, as_path=[1],
                announcing_router="1.2.3.4", timestamp=time.time(),
                next_hop="GARBAGE_VALUE",
            )

    def test_next_hop_none_accepted(self):
        """next_hop=None (omitted) must be accepted."""
        u = make_update()
        assert u.next_hop is None

    def test_next_hop_valid_ip_accepted(self):
        """next_hop with a valid IP must be accepted."""
        u = BGPUpdate(
            prefix="10.0.0.0/8", origin_as=1, as_path=[1],
            announcing_router="1.2.3.4", timestamp=time.time(),
            next_hop="10.0.12.1",
        )
        assert u.next_hop == "10.0.12.1"

    # ── Pyflakes clean — verify no import errors ──────────────────────────── #
    def test_all_modules_import_cleanly(self):
        """All source modules must import without errors."""
        import importlib
        for module in [
            "src.monitor.models",
            "src.monitor.rov_engine",
            "src.monitor.anomaly_detector",
            "src.monitor.monitor",
            "src.attacker.controller",
            "src.analysis.generate_report",
            "src.utils.experiment_runner",
        ]:
            importlib.import_module(module)   # raises ImportError if broken