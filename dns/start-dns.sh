#!/bin/bash
set -e

VPN_DNS_FILE=/config/vpn-dns

until [ -s "$VPN_DNS_FILE" ]; do
    echo "DNS: waiting for vpn-dns..."
    sleep 2
done

write_conf() {
    awk '{print "server=" $1}' "$VPN_DNS_FILE" > /etc/dnsmasq-vpn.conf
}

write_conf

dnsmasq \
    --no-daemon \
    --no-hosts \
    --no-resolv \
    --cache-size=10000 \
    --min-cache-ttl=300 \
    --dns-forward-max=300 \
    --log-queries=extra \
    --log-facility=- \
    --servers-file=/etc/dnsmasq-vpn.conf &
DNSMASQ_PID=$!

(
    while inotifywait -e close_write "$VPN_DNS_FILE" 2>/dev/null; do
        write_conf
        kill -HUP $DNSMASQ_PID 2>/dev/null || true
        echo "DNS: reloaded upstream servers"
    done
) &

echo "DNS: ready"
wait $DNSMASQ_PID
