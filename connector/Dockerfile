FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    iproute2 \
    iptables \
    jq \
    openresolv \
    procps \
    python3 \
    wireguard-go \
    wireguard-tools \
    awscli \
  && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY ws_udp_tunnel_client.py /usr/local/bin/ws_udp_tunnel_client.py
RUN chmod +x /entrypoint.sh
RUN chmod +x /usr/local/bin/ws_udp_tunnel_client.py

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
