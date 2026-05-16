"""
src/topology/builder.py
────────────────────────
Mininet Topology Builder — Ubuntu 24.04 / FRR compatible
──────────────────────────────────────────────────────────
Key fixes for Ubuntu 24.04 + FRR installed via apt:

  1. Stop system FRR service before starting (watchfrr blocks standalone daemons)
  2. Use full binary paths /usr/lib/frr/bgpd and /usr/lib/frr/zebra
  3. Pass --vty_socket to every vtysh call so it connects to the RIGHT daemon
     (not the system-wide one that is stopped)
  4. Create per-AS /var/run/frr/asN/ runtime directories with correct ownership
  5. Use /run/frr/ socket paths which FRR expects on modern Ubuntu
  6. Active convergence polling instead of fixed sleep

Run as root:
    sudo python3 src/topology/builder.py
"""

from __future__ import annotations

import argparse
import atexit
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    from mininet.net import Mininet
    from mininet.node import Node
    from mininet.link import TCLink
    from mininet.log import setLogLevel, info, error
    from mininet.cli import CLI
    from mininet.clean import cleanup
except ImportError:
    print("ERROR: Mininet not found.")
    print("       Run: sudo apt install mininet")
    sys.exit(1)

if os.geteuid() != 0:
    print("ERROR: Must run as root: sudo python3 src/topology/builder.py")
    sys.exit(1)

# ── Paths ─────────────────────────────────────────────────────────────────── #
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FRR_CONF  = REPO_ROOT / "config" / "frr"
LOG_BASE  = Path("/tmp/frr-logs")
RUN_BASE  = Path("/tmp/frr-run")   # per-AS runtime dirs (sockets, PIDs)

# FRR binary paths on Ubuntu 24.04 (installed via apt frr package)
FRR_BIN   = Path("/usr/lib/frr")
ZEBRA_BIN = FRR_BIN / "zebra"
BGPD_BIN  = FRR_BIN / "bgpd"
VTYSH_BIN = Path("/usr/bin/vtysh")


def _stop_system_frr() -> None:
    """
    Stop the system-wide FRR service before starting per-namespace daemons.

    The Ubuntu FRR package runs a system bgpd via watchfrr. If it is still
    running, standalone bgpd instances inside Mininet namespaces cannot bind
    their sockets, and vtysh connects to the system daemon instead.

    We restart it when the topology exits via atexit.
    """
    info("[FRR] Stopping system FRR service (will restart on exit)...\n")
    subprocess.run(["systemctl", "stop", "frr"], capture_output=True)
    time.sleep(1)
    # Verify stopped
    result = subprocess.run(["systemctl", "is-active", "frr"],
                            capture_output=True, text=True)
    if result.stdout.strip() == "active":
        error("[FRR] WARNING: Could not stop system FRR. BGP sessions may conflict.\n")
    else:
        info("[FRR] System FRR stopped.\n")


def _restart_system_frr() -> None:
    """Restart system FRR on exit so the machine is left in a clean state."""
    info("[FRR] Restarting system FRR service...\n")
    subprocess.run(["systemctl", "start", "frr"], capture_output=True)


# --------------------------------------------------------------------------- #
# FRR Router Node
# --------------------------------------------------------------------------- #

class FRRRouter(Node):
    """
    Mininet node running FRRouting inside its own Linux network namespace.

    Ubuntu 24.04 FRR-specific behaviour:
      - Daemons are at /usr/lib/frr/{zebra,bgpd}
      - Each AS gets its own runtime dir under /tmp/frr-run/asN/
        containing PID files and VTY sockets
      - vtysh must be called with -N <rundir> to connect to the right instance
      - FRR daemons must run as root (no frr user) inside Mininet namespaces
    """

    def __init__(self, name: str, asn: int, **params):
        super().__init__(name, **params)
        self.asn      = asn
        self.log_dir  = LOG_BASE / f"as{asn}"
        self.run_dir  = RUN_BASE / f"as{asn}"    # sockets + PIDs live here
        self.conf_dir = FRR_CONF / f"as{asn}"

    def config(self, **params) -> None:
        super().config(**params)

        # ── Kernel settings ────────────────────────────────────────────────
        self.cmd("sysctl -w net.ipv4.ip_forward=1        > /dev/null 2>&1")
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null 2>&1")
        self.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 > /dev/null 2>&1")

        # ── Create runtime directories owned by frr:frr ───────────────────
        # FRR daemons drop to user 'frr' immediately on start.
        # Directories created by root must be chowned so bgpd can write
        # its PID file and VTY socket. Without this bgpd exits immediately
        # with "Permission denied" on the PID lock file.
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.cmd(f"mkdir -p {self.log_dir} {self.run_dir}")
        self.cmd(f"chown -R frr:frr {self.log_dir} {self.run_dir} 2>/dev/null || true")
        self.cmd(f"chmod 755 {self.log_dir} {self.run_dir}")

        # ── Validate configs ───────────────────────────────────────────────
        bgpd_conf  = self.conf_dir / "bgpd.conf"
        zebra_conf = self.conf_dir / "zebra.conf"
        for conf in (bgpd_conf, zebra_conf):
            if not conf.exists():
                error(f"[FRR] Config not found: {conf}\n")
                return
        if not ZEBRA_BIN.exists():
            error(f"[FRR] Zebra binary not found at {ZEBRA_BIN}\n")
            error("[FRR] Install with: sudo apt install frr\n")
            return
        if not BGPD_BIN.exists():
            error(f"[FRR] bgpd binary not found at {BGPD_BIN}\n")
            return

        # ── Start zebra ────────────────────────────────────────────────────
        # -f  config file
        # -i  PID file
        # -z  zebra API socket (used by bgpd to talk to zebra)
        # --vty_socket  VTY socket for vtysh
        # -l  log file
        zebra_cmd = (
            f"{ZEBRA_BIN} "
            f"-f {zebra_conf} "
            f"-i {self.run_dir}/zebra.pid "
            f"-z {self.run_dir}/zserv.api "
            f"--vty_socket {self.run_dir}/zebra.vty "
            f"-l {self.log_dir}/zebra.log "
            f"--log-level debug "
            f"-d "
            f"2>{self.log_dir}/zebra-stderr.log"
        )
        self.cmd(zebra_cmd + " &")
        time.sleep(1)   # zebra must be up before bgpd connects to its socket

        # ── Start bgpd ─────────────────────────────────────────────────────
        # -z  zebra API socket (must match what zebra is listening on)
        bgpd_cmd = (
            f"{BGPD_BIN} "
            f"-f {bgpd_conf} "
            f"-i {self.run_dir}/bgpd.pid "
            f"-z {self.run_dir}/zserv.api "
            f"--vty_socket {self.run_dir}/bgpd.vty "
            f"-l {self.log_dir}/bgpd.log "
            f"--log-level debug "
            f"-d "
            f"2>{self.log_dir}/bgpd-stderr.log"
        )
        self.cmd(bgpd_cmd + " &")
        time.sleep(0.5)

        info(f"[FRR] AS{self.asn} daemons launched\n")

    def terminate(self) -> None:
        """Kill per-AS FRR daemons cleanly on topology teardown."""
        for daemon in ("bgpd", "zebra"):
            pid_file = self.run_dir / f"{daemon}.pid"
            self.cmd(
                f"[ -f {pid_file} ] && "
                f"kill $(cat {pid_file}) 2>/dev/null; "
                f"true"
            )
        time.sleep(0.3)
        super().terminate()

    def vtysh(self, *commands: str) -> str:
        """
        Run vtysh connected to THIS router's bgpd (not the system one).

        Uses --vty_socket pointing to our per-AS VTY socket file.
        This is more reliable than -N because -N inserts a prefix into
        default paths (/var/run/frr/) which may not match our /tmp paths.
        """
        cmd_args = " ".join(f'-c "{c}"' for c in commands)
        vty_sock  = self.run_dir / "bgpd.vty"
        return self.cmd(
            f"{VTYSH_BIN} --vty_socket {vty_sock} {cmd_args} 2>/dev/null"
        )

    def bgp_summary(self) -> str:
        return self.vtysh("show bgp summary")

    def ip_route(self) -> str:
        return self.vtysh("show ip route bgp")

    def is_bgpd_running(self) -> bool:
        """Check if bgpd PID file exists and process is alive."""
        pid_file = self.run_dir / "bgpd.pid"
        result = self.cmd(
            f"[ -f {pid_file} ] && "
            f"kill -0 $(cat {pid_file}) 2>/dev/null && "
            f"echo alive || echo dead"
        )
        return "alive" in result


# --------------------------------------------------------------------------- #
# IP Address Plan
# --------------------------------------------------------------------------- #

LOOPBACKS: dict[str, str] = {
    "as1":  "1.1.1.1",
    "as2":  "2.2.2.2",
    "as3":  "3.3.3.3",
    "as10": "10.10.10.10",
    "as20": "20.20.20.20",
    "as99": "99.99.99.99",
}


# --------------------------------------------------------------------------- #
# Convergence helpers
# --------------------------------------------------------------------------- #

def _wait_for_daemons(routers: dict[str, FRRRouter], timeout_s: int = 30) -> None:
    """Poll until bgpd PID file exists for every router, or timeout."""
    info(f"[TOPOLOGY] Waiting up to {timeout_s}s for daemons to start...\n")
    deadline = time.time() + timeout_s
    pending  = set(routers.keys())

    while pending and time.time() < deadline:
        for name in list(pending):
            if routers[name].is_bgpd_running():
                pending.discard(name)
                info(f"  [+] AS{routers[name].asn} bgpd ready\n")
        if pending:
            time.sleep(2)

    if pending:
        error(f"[WARNING] bgpd not ready after {timeout_s}s for: {pending}\n")
        error("[WARNING] Check logs in /tmp/frr-logs/asX/bgpd-stderr.log\n")
    else:
        info("[TOPOLOGY] All bgpd daemons running.\n")


def _wait_for_bgp_convergence(
    routers: dict[str, FRRRouter],
    expected: dict[str, int],
    timeout_s: int = 120,
) -> None:
    """Poll BGP session state until expected established counts are met."""
    info(f"[TOPOLOGY] Waiting up to {timeout_s}s for BGP sessions...\n")
    deadline  = time.time() + timeout_s
    converged: set[str] = set()

    while time.time() < deadline:
        for name, exp_count in expected.items():
            if name in converged:
                continue
            try:
                summary = routers[name].bgp_summary()
                count   = summary.count("Established") if summary else 0
                if count >= exp_count:
                    converged.add(name)
                    info(f"  [✓] AS{routers[name].asn}: {count} session(s) Established\n")
            except Exception:
                pass
        if len(converged) >= len(expected):
            info("[TOPOLOGY] BGP fully converged.\n")
            return
        time.sleep(5)

    missing = set(expected.keys()) - converged
    error(f"[WARNING] Convergence timeout. Still waiting: {missing}\n")
    error("[WARNING] Sessions may still be forming. Try 'show bgp summary' in CLI.\n")


# --------------------------------------------------------------------------- #
# Topology Builder
# --------------------------------------------------------------------------- #

def build_topology(enable_monitor: bool = True) -> Mininet:
    """Build and start the full 6-AS BGP simulation topology."""
    setLogLevel("info")
    cleanup()

    # CRITICAL: Stop system FRR so our per-namespace daemons can bind sockets
    _stop_system_frr()
    atexit.register(_restart_system_frr)

    net = Mininet(link=TCLink)

    # ── Create AS router nodes ──────────────────────────────────────────────
    info("[TOPOLOGY] Creating AS router nodes...\n")
    routers: dict[str, FRRRouter] = {}
    for asn in (1, 2, 3, 10, 20, 99):
        name          = f"as{asn}"
        router        = net.addHost(name, cls=FRRRouter, asn=asn)
        routers[name] = router
        info(f"  + {name} (AS{asn})\n")

    monitor = None
    if enable_monitor:
        monitor = net.addHost("monitor")
        info("  + monitor\n")

    # ── Inter-AS links ──────────────────────────────────────────────────────
    info("[TOPOLOGY] Creating inter-AS links...\n")
    lc = dict(bw=100, delay="5ms", loss=0)
    net.addLink(routers["as1"],  routers["as2"],  intfName1="as1-as2",  intfName2="as2-as1",  **lc)
    net.addLink(routers["as1"],  routers["as3"],  intfName1="as1-as3",  intfName2="as3-as1",  **lc)
    net.addLink(routers["as2"],  routers["as10"], intfName1="as2-as10", intfName2="as10-as2", **lc)
    net.addLink(routers["as2"],  routers["as99"], intfName1="as2-as99", intfName2="as99-as2", **lc)
    net.addLink(routers["as3"],  routers["as20"], intfName1="as3-as20", intfName2="as20-as3", **lc)
    net.addLink(routers["as3"],  routers["as99"], intfName1="as3-as99", intfName2="as99-as3", **lc)
    if monitor:
        net.addLink(routers["as1"], monitor,
                    intfName1="as1-mon", intfName2="mon-as1",
                    bw=1000, delay="1ms")

    # ── Pre-create runtime dirs with correct frr ownership ──────────────────
    # Must happen BEFORE net.start() calls each node's config() method,
    # which starts the daemons. FRR drops to user 'frr' immediately and
    # needs write access to these directories from the first moment.
    info("[TOPOLOGY] Creating FRR runtime directories...\n")
    import subprocess as _sp
    for asn in (1, 2, 3, 10, 20, 99):
        run_d = RUN_BASE / f"as{asn}"
        log_d = LOG_BASE / f"as{asn}"
        run_d.mkdir(parents=True, exist_ok=True)
        log_d.mkdir(parents=True, exist_ok=True)
        _sp.run(["chown", "-R", "frr:frr", str(run_d), str(log_d)],
                capture_output=True)
        _sp.run(["chmod", "755", str(run_d), str(log_d)],
                capture_output=True)

    # ── Start network ───────────────────────────────────────────────────────
    info("[TOPOLOGY] Starting network...\n")
    net.start()

    # ── Assign IP addresses ─────────────────────────────────────────────────
    info("[TOPOLOGY] Assigning interface addresses...\n")
    _assign_addresses(net, routers, monitor)

    # ── Wait for daemons ────────────────────────────────────────────────────
    _wait_for_daemons(routers, timeout_s=30)

    # ── Wait for BGP convergence ────────────────────────────────────────────
    _wait_for_bgp_convergence(
        routers,
        expected={"as1": 2, "as2": 2, "as3": 2},
        timeout_s=120,
    )

    info("[TOPOLOGY] ✓ Topology ready.\n")
    return net, routers


def _assign_addresses(
    net: Mininet,
    routers: dict[str, FRRRouter],
    monitor,
) -> None:
    """Assign point-to-point and loopback IP addresses."""

    def set_ip(node_name: str, intf: str, ip: str, prefix: int = 30) -> None:
        node = net.get(node_name)
        node.cmd(f"ip addr flush dev {intf} 2>/dev/null")
        node.cmd(f"ip addr add {ip}/{prefix} dev {intf}")
        node.cmd(f"ip link set {intf} up")

    set_ip("as1",  "as1-as2",  "10.0.12.1")
    set_ip("as2",  "as2-as1",  "10.0.12.2")
    set_ip("as1",  "as1-as3",  "10.0.13.1")
    set_ip("as3",  "as3-as1",  "10.0.13.3")
    set_ip("as2",  "as2-as10", "10.0.210.2")
    set_ip("as10", "as10-as2", "10.0.210.10")
    set_ip("as2",  "as2-as99", "10.0.299.2")
    set_ip("as99", "as99-as2", "10.0.299.99")
    set_ip("as3",  "as3-as20", "10.0.320.3")
    set_ip("as20", "as20-as3", "10.0.320.20")
    set_ip("as3",  "as3-as99", "10.0.399.3")
    set_ip("as99", "as99-as3", "10.0.399.99")

    if monitor:
        set_ip("as1", "as1-mon", "10.0.1.1")
        monitor.cmd("ip addr flush dev mon-as1 2>/dev/null")
        monitor.cmd("ip addr add 10.0.1.100/30 dev mon-as1")
        monitor.cmd("ip link set mon-as1 up")

    # Loopbacks
    for node_name, lo_ip in LOOPBACKS.items():
        node = net.get(node_name)
        node.cmd(f"ip addr add {lo_ip}/32 dev lo 2>/dev/null")
        node.cmd("ip link set lo up")


# --------------------------------------------------------------------------- #
# Entry Point
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(description="BGP Hijack Lab Topology")
    parser.add_argument("--no-cli",     action="store_true")
    parser.add_argument("--no-monitor", action="store_true")
    args = parser.parse_args()

    LOG_BASE.mkdir(parents=True, exist_ok=True)
    RUN_BASE.mkdir(parents=True, exist_ok=True)

    net, routers = build_topology(enable_monitor=not args.no_monitor)
    atexit.register(net.stop)

    if not args.no_cli:
        info("\n[TOPOLOGY] Mininet CLI ready. Useful commands:\n")
        info("  as1 vtysh -N /tmp/frr-run/as1 -c 'show bgp summary'\n")
        info("  as10 vtysh -N /tmp/frr-run/as10 -c 'show ip route bgp'\n")
        info("  as1 ping 10.0.12.2   (test link to AS2)\n")
        info("  exit                 (stop topology)\n\n")
        CLI(net)

    net.stop()


if __name__ == "__main__":
    main()