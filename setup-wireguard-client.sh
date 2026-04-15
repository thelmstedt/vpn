#!/usr/bin/env bash
# Run on the server. Generates a client config and registers the peer.
# Usage: ./setup-wireguard-client.sh <name>
#   e.g. ./setup-wireguard-client.sh laptop
#        ./setup-wireguard-client.sh phone
set -e

NAME=${1:?Usage: $0 <client-name>}
CLIENTS_DIR=wireguard/config/clients

if ! docker compose ps wireguard | grep -q "Up"; then
    echo "ERROR: wireguard container is not running — run 'docker compose up -d' first"
    exit 1
fi

for i in {1..30}; do
    [ -f wireguard/config/server_public.key ] && break
    sleep 1
done
[ -f wireguard/config/server_public.key ] || { echo "ERROR: server_public.key not found after 30s"; exit 1; }

if [ -f "$CLIENTS_DIR/$NAME.conf" ]; then
    echo "ERROR: client '$NAME' already exists — delete $CLIENTS_DIR/$NAME.conf to re-register"
    exit 1
fi

# Find next available IP by scanning existing client files
NEXT_IP=2
for f in "$CLIENTS_DIR"/*.conf; do
    [ -f "$f" ] || continue
    LAST=$(awk '/^Address/{print $3}' "$f" | awk -F'[./]' '{print $4}')
    [ -n "$LAST" ] && [ "$LAST" -ge "$NEXT_IP" ] && NEXT_IP=$((LAST + 1))
done
CLIENT_IP="10.99.1.$NEXT_IP"

SERVER_PUBLIC_KEY=$(cat wireguard/config/server_public.key)
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

# Best-guess at server's LAN IP — adjust Endpoint in the generated config if wrong
SERVER_IP=$(ip route get 192.168.0.1 2>/dev/null | awk 'NR==1{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')
SERVER_IP=${SERVER_IP:-"<server-ip>"}

# Register peer with running server
docker compose exec wireguard \
    wg set wg0 peer "$CLIENT_PUBLIC_KEY" allowed-ips "$CLIENT_IP/32" persistent-keepalive 25

# Save peer info so start-wireguard.sh can restore it after container restarts
echo "$CLIENT_PUBLIC_KEY $CLIENT_IP" > "$CLIENTS_DIR/$NAME.peer"

# Save full client config (private key is in here — treat this file as a secret)
cat > "$CLIENTS_DIR/$NAME.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/32
DNS = 10.99.0.10
MTU = 1280
# Prevents a routing loop when this client runs on the same host as the
# Docker stack. Harmless no-op on remote machines (rule never matches).
PostUp = ip rule add from 10.99.0.0/24 table main priority 100
PreDown = ip rule del from 10.99.0.0/24 table main priority 100


[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

echo ""
echo "Client '$NAME' registered at $CLIENT_IP"
echo "Config: $CLIENTS_DIR/$NAME.conf"
echo ""
echo "Copy to client and install:"
echo "  scp $CLIENTS_DIR/$NAME.conf user@client:/etc/wireguard/wg0.conf"
echo "  sudo wg-quick up wg0"
