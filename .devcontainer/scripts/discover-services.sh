#!/bin/bash
# ============================================================================
# Discover Services — Trigger service discovery on a monitored host
# Runs inside the Checkmk container as the site user and uses the cmk CLI:
# it loads the plugins fresh on every run and needs neither the REST API nor
# the site's background job scheduler.
# ============================================================================

set -euo pipefail

TARGET_HOST="${1:-almalinux-host}"

echo "Discovering services on '${TARGET_HOST}'..."
# -II: rediscover all services (accept new, remove vanished)
cmk -II "${TARGET_HOST}"

echo "Activating changes..."
cmk -O

echo "Service discovery complete for '${TARGET_HOST}'."
