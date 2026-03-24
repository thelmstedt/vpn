#!/usr/bin/env bash
set -e
set -x

. auth.env

cd auth
uv run playwright install &> /dev/null
uv run openconnect_auth.py --user "$CLV_USERNAME" --server "$CLV_SERVER"  --password "$CLV_PASSWORD" --output-config config.env --debug