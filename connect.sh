#!/usr/bin/env bash

MODE="direct"
if  [ "$1" = "proxied" ]; then
    MODE="proxied"
fi
echo "starting in $MODE mode..."


# fetch auth cookie/cert
# note it has to be run separately, cause it writes config.env which docker-compose reads for vpn
#docker compose up auth


# run in the selected mode
if [ "$MODE" = "direct" ]; then
    . ./config.env
    sudo openconnect --cookie=$OPENCONNECT_AUTH_COOKIE --servercert=$OPENCONNECT_AUTH_SERVERCERT --server $OPENCONNECT_AUTH_SERVER
else
    docker compose up vpn proxy heartbeat -d
    docker compose logs vpn proxy heartbeat -f
fi
