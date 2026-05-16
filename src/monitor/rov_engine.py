"""
src/monitor/rov_engine.py
─────────────────────────
Route Origin Validation (ROV) Engine
──────────────────────────────────────
Implements BGP prefix/origin validation against a local ROA database,
following the validation algorithm defined in RFC 6483 §2.

The engine is intentionally decoupled from networking concerns so it can
be unit-tested in isolation and reused across multiple monitor instances.

RFC reference:
    RFC 6483 — Validation of Route Origination Using the Resource
               Certificate Public Key Infrastructure (PKI) and ROAs
"""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import threading
from pathlib import Path

from src.monitor.models import (
    BGPUpdate,
    RouteOriginAuthorization,
    ROVResult,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# ROA Database (in-memory + optional SQLite persistence)
# --------------------------------------------------------------------------- #

class ROADatabase:
    """
    ROA database backed by SQLite with serialised writes.

    In a production RPKI deployment, ROAs are fetched via RRDP/rsync from
    Regional Internet Registry repositories and cryptographically verified.
    For this lab, we populate the database with hand-crafted ROAs that
    represent the lab topology's address space.

    Thread safety: writes (insert_roa) are serialised with a threading.Lock
    to prevent concurrent INSERT conflicts. Reads (all_roas, covering_roas)
    do NOT hold the write lock — under SQLite WAL mode, readers never block
    writers and writers never block readers, so this is safe. A reader may
    see a snapshot that excludes an in-flight write, which is acceptable
    for this lab (ROA table is populated once at startup, then read-only).
    The database is the single source of truth for all ROV queries.
    """

    _CREATE_TABLE = """
        CREATE TABLE IF NOT EXISTS roas (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix      TEXT    NOT NULL,
            origin_as   INTEGER NOT NULL,
            max_length  INTEGER NOT NULL,
            source      TEXT    DEFAULT 'lab',
            created_at  REAL    DEFAULT (unixepoch('now')),
            UNIQUE(prefix, origin_as)
        );
    """

    def __init__(self, db_path: str = ":memory:"):
        """
        Args:
            db_path: Path to SQLite file, or ':memory:' for in-process testing.
        """
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(self._CREATE_TABLE)
        self._conn.commit()
        self._write_lock = threading.Lock()
        logger.info("ROA database initialised (path=%s)", db_path)

    # ── Write ──────────────────────────────────────────────────────────────── #

    def insert_roa(self, roa: RouteOriginAuthorization, source: str = "lab") -> None:
        """
        Insert or replace a ROA entry.

        Args:
            roa:    Validated RouteOriginAuthorization model.
            source: Label for audit trail (e.g. 'lab', 'rpki-rir').

        Raises:
            ValueError: If the ROA is already present with different parameters.
        """
        try:
            with self._write_lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO roas (prefix, origin_as, max_length, source) "
                    "VALUES (?, ?, ?, ?)",
                    (roa.prefix, roa.origin_as, roa.max_length, source),
                )
                self._conn.commit()
            logger.debug("ROA inserted: prefix=%s AS=%d maxLen=/%d",
                         roa.prefix, roa.origin_as, roa.max_length)
        except sqlite3.Error as exc:
            logger.error("Failed to insert ROA %s: %s", roa.prefix, exc)
            raise

    def load_from_json(self, json_path: Path) -> int:
        """
        Bulk-load ROAs from a JSON file.

        Expected format:
            [
              {"prefix": "10.10.0.0/16", "origin_as": 10, "max_length": 24},
              ...
            ]

        Returns:
            Number of ROAs loaded.
        """
        if not json_path.exists():
            raise FileNotFoundError(f"ROA file not found: {json_path}")

        with open(json_path) as fh:
            raw = json.load(fh)

        # Known ROA fields — strip comment/metadata keys (e.g. "_comment")
        # before passing to Pydantic to avoid unexpected-field errors.
        ROA_FIELDS = {"prefix", "origin_as", "max_length"}
        count = 0
        for entry in raw:
            try:
                clean = {k: v for k, v in entry.items() if k in ROA_FIELDS}
                roa = RouteOriginAuthorization(**clean)
                self.insert_roa(roa)
                count += 1
            except Exception as exc:                       # noqa: BLE001
                logger.warning("Skipping invalid ROA entry %s: %s", entry, exc)

        logger.info("Loaded %d ROAs from %s", count, json_path)
        return count

    def all_roas(self) -> list[RouteOriginAuthorization]:
        """Return all ROAs as validated model objects."""
        rows = self._conn.execute(
            "SELECT prefix, origin_as, max_length FROM roas"
        ).fetchall()
        return [RouteOriginAuthorization(**dict(r)) for r in rows]

    # ── Read ──────────────────────────────────────────────────────────────── #

    def covering_roas(self, prefix: str) -> list[RouteOriginAuthorization]:
        """
        Return all ROAs whose prefix covers (or equals) the queried prefix.

        A ROA at 10.10.0.0/16 covers 10.10.1.0/24 because /24 is a subnet of /16.
        This is the first step of the RFC 6483 validation algorithm.

        Args:
            prefix: CIDR string to look up.

        Returns:
            List of matching ROAs, most-specific first.

        Edge cases handled:
          - IPv6 prefixes: lab ROAs are IPv4-only; mixed-family subnet_of()
            raises TypeError. We guard explicitly and return empty list.
          - Malformed prefix string: ip_network() raises ValueError; caller
            (ROVEngine.validate) already catches all exceptions.
        """
        queried_net = ipaddress.ip_network(prefix, strict=True)
        results: list[RouteOriginAuthorization] = []

        for roa in self.all_roas():
            roa_net = roa.network
            # Guard: subnet_of raises TypeError on mixed IPv4/IPv6 families
            if queried_net.version != roa_net.version:
                continue
            # 'subnet_of' returns True if queried_net ⊆ roa_net
            if queried_net.subnet_of(roa_net) or queried_net == roa_net:
                results.append(roa)

        # Sort most-specific (longest prefix) first — mirrors BGP selection
        results.sort(key=lambda r: r.network.prefixlen, reverse=True)
        return results

    def close(self) -> None:
        self._conn.close()


# --------------------------------------------------------------------------- #
# ROV Engine
# --------------------------------------------------------------------------- #

class ROVEngine:
    """
    Route Origin Validation engine implementing RFC 6483 §2 algorithm.

    Validation algorithm (verbatim from RFC 6483):
      1. If the BGP speaker has no ROA covering the announced prefix → NotFound
      2. Among covering ROAs:
         a. If any ROA matches (origin AS + prefix length ≤ maxLength) → Valid
         b. Otherwise → Invalid

    Key insight: a single Valid ROA is sufficient to mark a route Valid.
    A route is Invalid only when covering ROAs exist but NONE of them match.

    This asymmetry is important for the RPKI evasion demonstration:
    if a ROA for 10.10.0.0/16 has maxLength=/24, then an attacker announcing
    10.10.1.0/24 from a *different AS* is correctly marked Invalid.
    BUT if the ROA erroneously has maxLength=/24 AND the attacker happens to
    use the victim's ASN (path stuffing), ROV cannot detect it.
    """

    def __init__(self, roa_db: ROADatabase):
        self._db = roa_db
        logger.info("ROV engine initialised")

    def validate(self, update: BGPUpdate) -> tuple[ROVResult, str]:
        """
        Validate a BGP UPDATE against the ROA database.

        Args:
            update: Validated BGPUpdate model.

        Returns:
            Tuple of (ROVResult enum, human-readable reason string).

        Security note:
            This function must never raise — a crash here would leave a hijack
            undetected. All exceptions are caught and returned as NOT_FOUND with
            a logged error.
        """
        try:
            return self._validate_inner(update)
        except Exception as exc:                           # noqa: BLE001
            logger.error("ROV engine exception for prefix %s: %s",
                         update.prefix, exc, exc_info=True)
            return ROVResult.NOT_FOUND, f"Internal error during ROV: {exc}"

    def _validate_inner(self, update: BGPUpdate) -> tuple[ROVResult, str]:
        covering = self._db.covering_roas(update.prefix)

        # ── Step 1: No covering ROA → NotFound ─────────────────────────────
        if not covering:
            msg = (
                f"No ROA covers {update.prefix}. "
                f"RPKI provides no protection for this prefix."
            )
            logger.debug("[ROV] NOT_FOUND — %s", msg)
            return ROVResult.NOT_FOUND, msg

        announced_prefixlen = update.network.prefixlen
        invalid_reasons: list[str] = []

        # ── Step 2: Check each covering ROA for a Valid match ───────────────
        for roa in covering:
            origin_match = (update.origin_as == roa.origin_as)
            length_ok    = (announced_prefixlen <= roa.max_length)

            if origin_match and length_ok:
                msg = (
                    f"{update.prefix} from AS{update.origin_as} matches ROA "
                    f"[{roa.prefix}, AS{roa.origin_as}, maxLen=/{roa.max_length}]."
                )
                logger.debug("[ROV] VALID — %s", msg)
                return ROVResult.VALID, msg

            # Collect reasons this ROA did NOT match (for Invalid explanation)
            if not origin_match:
                invalid_reasons.append(
                    f"ROA [{roa.prefix}] authorises AS{roa.origin_as}, "
                    f"not AS{update.origin_as}"
                )
            if not length_ok:
                invalid_reasons.append(
                    f"ROA [{roa.prefix}] maxLength=/{roa.max_length} "
                    f"exceeded by announced /{announced_prefixlen}"
                )

        # ── Step 3: Covering ROAs exist but none matched → Invalid ──────────
        reason_str = "; ".join(invalid_reasons)
        msg = f"RPKI INVALID for {update.prefix} from AS{update.origin_as}: {reason_str}"
        logger.warning("[ROV] INVALID — %s", msg)
        return ROVResult.INVALID, msg

    def batch_validate(
        self, updates: list[BGPUpdate]
    ) -> list[tuple[BGPUpdate, ROVResult, str]]:
        """
        Validate a list of BGP updates.  Useful for replay analysis.

        Returns:
            List of (update, rov_result, reason) tuples in the same order.
        """
        return [(u, *self.validate(u)) for u in updates]


# --------------------------------------------------------------------------- #
# Lab ROA Fixture
# --------------------------------------------------------------------------- #

LAB_ROAS: list[dict] = [
    # Victim AS10 owns 10.10.0.0/16; ROA maxLength=/16 (tight — correct config)
    {"prefix": "10.10.0.0/16", "origin_as": 10, "max_length": 16},

    # Legitimate AS20
    {"prefix": "10.20.0.0/16", "origin_as": 20, "max_length": 24},

    # Regional ISPs
    {"prefix": "172.16.2.0/24", "origin_as": 2,  "max_length": 24},
    {"prefix": "172.16.3.0/24", "origin_as": 3,  "max_length": 24},
]


def build_lab_roa_database(db_path: str = ":memory:") -> ROADatabase:
    """
    Factory: create and populate an ROA database for the lab topology.

    Args:
        db_path: SQLite path. Default is in-memory (useful for tests).

    Returns:
        Populated ROADatabase instance ready for ROV queries.
    """
    db = ROADatabase(db_path)
    for entry in LAB_ROAS:
        roa = RouteOriginAuthorization(**entry)
        db.insert_roa(roa)
    logger.info("Lab ROA database ready with %d ROAs", len(LAB_ROAS))
    return db