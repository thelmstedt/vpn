#!/bin/bash

LOG_FILE="/var/log/heartbeat.log"
INTERVAL=45
TARGET="http://httpbin.org/ip"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "heartbeat started, target: $TARGET, interval: ${INTERVAL}s"

while true; do
    start_time=$(date +%s)
    if response=$(curl -s --max-time 5 "$TARGET"); then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        log "heartbeat ok (${duration}s): $response"
    else
        log "heartbeat FAILED: $response"
    fi
    sleep "$INTERVAL"
done