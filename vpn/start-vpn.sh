#!/bin/bash
set -e

# Export DNS info to shared volume whenever resolv.conf changes.
# The WireGuard container reads from wireguard/config/vpn-dns and vpn-domains.
export_dns() {
    # Skip if we already redirected to dnsmasq (prevents inotifywait loop)
    grep -q '^nameserver 127.0.0.1$' /etc/resolv.conf 2>/dev/null && return

    mkdir -p /config/wireguard/config
    grep '^nameserver' /etc/resolv.conf \
        | awk '{print $2}' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
        > /config/wireguard/config/vpn-dns
    grep '^search\|^domain' /etc/resolv.conf \
        | awk '{for(i=2;i<=NF;i++) print $i}' \
        | grep -v '^$' | sort -u \
        > /config/wireguard/config/vpn-domains

    # Point all containers in this netns at dnsmasq
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
}

(
    # Wait for the file to exist before watching it
    until [ -f /etc/resolv.conf ]; do sleep 1; done
    while inotifywait -e close_write /etc/resolv.conf 2>/dev/null; do
        export_dns
    done
) &

# Without this, forwarded packets from WireGuard clients exit tun0 with a
# Docker-internal source IP (10.99.0.20) that the corporate VPN server can't
# route back to. MASQUERADE rewrites the src to the VPN-assigned tun0 IP so
# responses return correctly. The rule can be set before tun0 exists — Linux
# applies it once the interface appears.
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
iptables -t nat -A POSTROUTING -d 10.99.0.10 -p tcp --dport 1080 -j MASQUERADE
iptables -t nat -A POSTROUTING -d 10.99.0.10 -p tcp --dport 8118 -j MASQUERADE
ip route add 192.168.0.0/24 via 10.99.0.1

exec openconnect \
    --cookie=$OPENCONNECT_AUTH_COOKIE \
    --servercert=$OPENCONNECT_AUTH_SERVERCERT \
    --server $OPENCONNECT_AUTH_SERVER \
    --dtls-ciphers=ALL \
    --reconnect-timeout 60 \
    --dtls-local-port=0 \
    --force-dpd=30
