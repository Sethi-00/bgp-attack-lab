"""
src/monitor/models.py
─────────────────────
Pydantic data models for all BGP entities used across the lab.
Using Pydantic ensures strict validation at data-entry points so
bad data never enters the detection pipeline silently.
"""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Optional, Union
from pydantic import BaseModel, field_validator, model_validator


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

class ROVResult(str, Enum):
    """Route Origin Validation outcome per RFC 6483 §2."""
    VALID     = "valid"
    INVALID   = "invalid"
    NOT_FOUND = "not_found"


class AttackScenario(str, Enum):
    """Enumeration of the three attack types implemented in the lab."""
    EXACT_PREFIX      = "exact_prefix"
    SUBPREFIX         = "subprefix"
    PATH_MANIPULATION = "path_manipulation"


class EventType(str, Enum):
    """BGP UPDATE event classification."""
    ANNOUNCE  = "announce"
    WITHDRAW  = "withdraw"
    KEEPALIVE = "keepalive"


# --------------------------------------------------------------------------- #
# BGP Entities
# --------------------------------------------------------------------------- #

class BGPUpdate(BaseModel):
    """
    Represents a single parsed BGP UPDATE message received by the monitor.
    All fields are validated on construction.
    """
    prefix:           str                  # CIDR notation, e.g. "10.10.0.0/16"
    origin_as:        int                  # Rightmost AS in AS_PATH (route originator)
    as_path:          list[int]            # Full AS path, left = nearest peer
    announcing_router: str                 # IP of the router that sent this update
    timestamp:        float                # Unix epoch seconds
    event_type:       EventType = EventType.ANNOUNCE
    next_hop:         Optional[str] = None # BGP NEXT_HOP attribute

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, v: str) -> str:
        """Reject malformed CIDR prefixes before they reach detection logic."""
        try:
            ipaddress.ip_network(v, strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid IP prefix '{v}': {exc}") from exc
        return v

    @field_validator("announcing_router")
    @classmethod
    def validate_announcing_router(cls, v: str) -> str:
        """Announcing router must be a valid IP address."""
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid announcing_router IP '{v}': {exc}") from exc
        return v

    @field_validator("next_hop")
    @classmethod
    def validate_next_hop(cls, v: Optional[str]) -> Optional[str]:
        """NEXT_HOP must be a valid IP address when provided."""
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid next_hop IP '{v}': {exc}") from exc
        return v

    @field_validator("origin_as")
    @classmethod
    def validate_asn(cls, v: int) -> int:
        """ASNs must be 1–4294967295 per RFC 4271 / RFC 6793."""
        if not (1 <= v <= 4_294_967_295):
            raise ValueError(f"ASN {v} is outside the valid range 1–4294967295")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: float) -> float:
        """Timestamp must be a non-negative Unix epoch value."""
        if v < 0:
            raise ValueError(f"timestamp {v} must be >= 0 (Unix epoch)")
        return v

    @field_validator("as_path")
    @classmethod
    def validate_as_path(cls, v: list[int]) -> list[int]:
        """AS_PATH must contain at least one entry with no consecutive duplicates."""
        if not v:
            raise ValueError("AS_PATH must contain at least one ASN")
        # Check for consecutive identical ASNs (AS path loops)
        for i in range(1, len(v)):
            if v[i] == v[i-1]:
                raise ValueError(f"AS_PATH contains consecutive identical ASNs at positions {i-1} and {i}: {v[i]}")
        return v

    @model_validator(mode="after")
    def origin_as_must_match_path_tail(self) -> BGPUpdate:
        """
        The origin AS (rightmost in path) must equal the last element of as_path.
        This is a basic sanity check — the BGP spec defines ORIGIN differently,
        but for our purposes origin_as is always the route originator.
        """
        if self.origin_as != self.as_path[-1]:
            raise ValueError(
                f"origin_as ({self.origin_as}) must match the last element "
                f"of as_path ({self.as_path[-1]})"
            )
        return self

    @property
    def network(self) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        """Return parsed network object for prefix comparisons.
        Supports both IPv4 and IPv6 prefixes.
        """
        return ipaddress.ip_network(self.prefix, strict=True)


class RouteOriginAuthorization(BaseModel):
    """
    A simulated RPKI Route Origin Authorization (ROA).
    In production this would be a signed X.509 object; here it is a trusted
    database entry sufficient for demonstrating ROV logic per RFC 6483.
    """
    prefix:     str   # The IP prefix covered by this ROA
    origin_as:  int   # The AS authorized to announce this prefix
    max_length: int   # Maximum prefix length considered valid under this ROA

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid ROA prefix '{v}': {exc}") from exc
        return v

    @field_validator("origin_as")
    @classmethod
    def validate_origin_as(cls, v: int) -> int:
        """ROA origin ASN must be in valid range 1–4294967295."""
        if not (1 <= v <= 4_294_967_295):
            raise ValueError(f"ROA origin_as {v} outside valid range 1–4294967295")
        return v

    @field_validator("max_length")
    @classmethod
    def validate_max_length(cls, v: int, info) -> int:
        prefix = info.data.get("prefix") if info and hasattr(info, "data") else None
        net = ipaddress.ip_network(prefix, strict=True) if prefix is not None else None
        max_allowed = 128 if net and net.version == 6 else 32
        if not (0 <= v <= max_allowed):
            family = "IPv6" if net and net.version == 6 else "IPv4"
            raise ValueError(
                f"max_length {v} must be 0–{max_allowed} for {family} prefixes"
            )
        return v

    @model_validator(mode="after")
    def max_length_must_not_be_shorter_than_prefix(self) -> RouteOriginAuthorization:
        """maxLength must be >= the prefix length it covers."""
        net = ipaddress.ip_network(self.prefix, strict=True)
        if self.max_length < net.prefixlen:
            raise ValueError(
                f"max_length ({self.max_length}) cannot be shorter than "
                f"the ROA prefix length ({net.prefixlen})"
            )
        return self

    @property
    def network(self) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        """Return parsed network object. Supports IPv4 and IPv6."""
        return ipaddress.ip_network(self.prefix, strict=True)


class DetectionEvent(BaseModel):
    """
    A detection alert produced by the BGP Monitor for one BGP UPDATE.
    Stored to the database and surfaced in real-time logs.
    """
    update:           BGPUpdate
    is_anomaly:       bool
    anomaly_reason:   Optional[str]
    rov_result:       ROVResult
    rov_reason:       str
    detection_latency_s: Optional[float] = None  # Seconds since attack start (if known)


class ExperimentResult(BaseModel):
    """Aggregated metrics for one complete attack scenario run."""
    scenario:                   AttackScenario
    attack_start_time:          float
    first_anomaly_detection_s:  Optional[float]  # None if anomaly detection missed it
    first_rov_invalid_s:        Optional[float]  # None if RPKI missed it
    propagation_scope_pct:      float            # % ASes routing to attacker
    false_positives_in_window:  int
    recovery_time_s:            Optional[float]
    rpki_evaded:                bool             # True if RPKI returned Valid for attack