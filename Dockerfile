# =============================================================================
# BGP Hijack Lab — Dockerfile
# Ubuntu 22.04 base with Mininet, FRRouting, and Python toolchain.
# Build: docker build -t bgp-lab .
# Run:   docker run --privileged -it bgp-lab
# NOTE:  --privileged is required for Mininet network namespaces.
# =============================================================================

FROM ubuntu:22.04

LABEL maintainer="BGP Hijack Lab — Network Security Course"
LABEL description="Isolated BGP hijacking simulation environment"

# Prevent interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# --------------------------------------------------------------------------- #
# System dependencies
# --------------------------------------------------------------------------- #
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    git curl wget \
    iproute2 iputils-ping net-tools tcpdump \
    # Mininet dependencies
    mininet \
    openvswitch-switch \
    # FRRouting
    gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------------------- #
# Install FRRouting (stable release)
# --------------------------------------------------------------------------- #
RUN curl -s https://deb.frrouting.org/frr/keys.gpg \
    | tee /usr/share/keyrings/frrouting.gpg > /dev/null && \
    echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] \
    https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable" \
    | tee /etc/apt/sources.list.d/frr.list && \
    apt-get update && apt-get install -y frr frr-pythontools && \
    rm -rf /var/lib/apt/lists/*

# Enable BGP daemon in FRR
RUN sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons && \
    sed -i 's/zebra=no/zebra=yes/' /etc/frr/daemons

# --------------------------------------------------------------------------- #
# Python application
# --------------------------------------------------------------------------- #
WORKDIR /lab

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory for SQLite database
RUN mkdir -p /lab/data /lab/reports

# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #
# Override with: docker run --privileged -it bgp-lab /bin/bash
CMD ["bash", "-c", "service openvswitch-switch start && exec bash"]