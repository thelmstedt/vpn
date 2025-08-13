#!/bin/bash
# wait for openconnect to populate resolv.conf
while [ ! -s /etc/resolv.conf ] || grep -q "127.0.0.1" /etc/resolv.conf; do
    echo "DNS: waiting for vpn resolv.conf..."
    sleep 2
done

# test which dns servers work
GOOD_NS=""
for ns in $(grep '^nameserver' /etc/resolv.conf | awk '{print $2}'); do
    if nslookup -timeout=1 google.com $ns &>/dev/null; then
        GOOD_NS="$GOOD_NS --server=$ns"
        echo "DNS: using $ns"
    else
        echo "DNS: skipping broken $ns"
    fi
done

if [ -z "$GOOD_NS" ]; then
    echo "DNS: no working servers found, using all"
    GOOD_NS=$(grep '^nameserver' /etc/resolv.conf | awk '{print "--server="$2}' | tr '\n' ' ')
fi

echo "DNS: starting dnsmasq with: $GOOD_NS"
exec dnsmasq \
    --no-daemon \
    --listen-address=127.0.0.53 \
    --bind-interfaces \
    --no-hosts \
    --no-resolv \
    --cache-size=1000 \
    $GOOD_NS