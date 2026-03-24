#!/bin/bash
set -e

echo "WireGuard: Starting setup..."

# Generate server keys if needed — client keys are generated client-side
if [ ! -f /config/server_private.key ]; then
    wg genkey | tee /config/server_private.key | wg pubkey > /config/server_public.key
    chmod 600 /config/server_private.key
fi

SERVER_PRIVATE_KEY=$(cat /config/server_private.key)

# Build wg0.conf with all registered peers
# Peers are stored in /config/clients/*.peer as "PUBKEY IP" lines
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.99.1.1/24
ListenPort = 51820
EOF

PEER_COUNT=0
for f in /config/clients/*.peer; do
    [ -f "$f" ] || continue
    PUBKEY=$(awk '{print $1}' "$f")
    IP=$(awk '{print $2}' "$f")
    cat >> /etc/wireguard/wg0.conf <<EOF

[Peer]
PublicKey = $PUBKEY
AllowedIPs = $IP/32
PersistentKeepalive = 25
EOF
    PEER_COUNT=$((PEER_COUNT + 1))
done

if [ "$PEER_COUNT" -eq 0 ]; then
    echo "WireGuard: no clients registered yet — run ./setup-wireguard-client.sh <name>"
else
    echo "WireGuard: loaded $PEER_COUNT peer(s)"
fi
chmod 600 /etc/wireguard/wg0.conf

wg-quick up wg0
sleep 2

# Route all WireGuard client traffic through the VPN container
ip route add default via $VPN_CONTAINER_IP dev eth0 table 100
ip rule add from 10.99.1.0/24 table 100

# NAT traffic from WireGuard clients out through the VPN container
iptables -t nat -A POSTROUTING -s 10.99.1.0/24 -o eth0 -j MASQUERADE

# Wait for the VPN container to connect and write its DNS info
echo "WireGuard: waiting for VPN DNS info..."
for i in {1..30}; do
    [ -s /config/vpn-dns ] && break
    sleep 2
done

if [ ! -s /config/vpn-dns ]; then
    echo "WireGuard: VPN DNS not available, falling back to 8.8.8.8"
    VPN_DNS=8.8.8.8
    CORP_DOMAINS=""
else
    VPN_DNS=$(head -1 /config/vpn-dns)
    CORP_DOMAINS=$(cat /config/vpn-domains 2>/dev/null || true)
fi

# Split DNS: corp domains -> VPN DNS, everything else -> 8.8.8.8
DNS_ARGS=""
if [ -n "$CORP_DOMAINS" ]; then
    for domain in $CORP_DOMAINS; do
        DNS_ARGS="$DNS_ARGS --server=/${domain}/${VPN_DNS}"
    done
    echo "WireGuard: split DNS — corp domains via $VPN_DNS, rest via 8.8.8.8"
else
    echo "WireGuard: no corp domains found, forwarding all to VPN DNS ($VPN_DNS)"
    DNS_ARGS="--server=$VPN_DNS"
fi

dnsmasq \
    --no-daemon \
    --listen-address=10.99.1.1 \
    --bind-interfaces \
    --no-hosts \
    --no-resolv \
    --cache-size=1000 \
    $DNS_ARGS \
    --server=8.8.8.8 \
    --log-queries &

echo "WireGuard: ready"
wg show

tail -f /dev/null
