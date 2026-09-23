#!/bin/bash
# ============================================================================
# AlmaLinux Agent Entrypoint
# Downloads and installs the CheckMK agent, deploys the keystore plugin,
# creates a test keystore, registers with the CheckMK server, and starts
# the agent daemon.
# ============================================================================

set -euo pipefail

CMK_SERVER="${CMK_SERVER:-checkmk-server}"
CMK_SITE="${CMK_SITE:-cmk}"
CMK_USER="${CMK_USER:-cmkadmin}"
CMK_PASSWORD="${CMK_PASSWORD:-cmk}"
AGENT_HOSTNAME="${AGENT_HOSTNAME:-almalinux-host}"
WORKSPACE="${WORKSPACE:-/workspace}"

readonly API_URL="http://${CMK_SERVER}:5000/${CMK_SITE}/check_mk/api/1.0"

echo "============================================================================"
echo "AlmaLinux — CheckMK Agent Setup"
echo "============================================================================"

# --- Wait for CheckMK server to become ready ---
echo "Waiting for CheckMK server at ${CMK_SERVER}..."
MAX_ATTEMPTS=60
ATTEMPT=0
until curl -sf -o /dev/null \
    "${API_URL}/version" \
    -H "Authorization: Bearer ${CMK_USER} ${CMK_PASSWORD}"; do
    ATTEMPT=$((ATTEMPT + 1))
    if (( ATTEMPT >= MAX_ATTEMPTS )); then
        echo "ERROR: CheckMK server not ready after $((MAX_ATTEMPTS * 5))s"
        exec tail -f /dev/null
    fi
    sleep 5
done
echo "CheckMK server is ready."

# --- Download and install the CheckMK agent ---
if ! rpm -q check-mk-agent >/dev/null 2>&1; then
    echo "Downloading CheckMK agent RPM..."
    AGENTS_PAGE="http://${CMK_SERVER}:5000/${CMK_SITE}/check_mk/agents/"
    RPM_NAME=$(curl -sf --max-time 60 "${AGENTS_PAGE}" \
        | grep -oP 'check-mk-agent-[0-9][^"]*\.noarch\.rpm' \
        | head -n1) || true

    if [[ -z "${RPM_NAME:-}" ]]; then
        echo "ERROR: Could not find agent RPM on CheckMK server"
        exec tail -f /dev/null
    fi

    curl -sf --max-time 300 -o /tmp/check-mk-agent.rpm "${AGENTS_PAGE}${RPM_NAME}"
    echo "Installing CheckMK agent (${RPM_NAME})..."
    rpm -ivh --nodeps /tmp/check-mk-agent.rpm || true
    rm -f /tmp/check-mk-agent.rpm
else
    echo "CheckMK agent already installed."
fi

# --- Deploy the keystore agent plugin via symlink ---
PLUGIN_SRC="${WORKSPACE}/agents/plugins/keystore"
PLUGIN_DST="/usr/lib/check_mk_agent/plugins/keystore"

if [[ -f "${PLUGIN_SRC}" ]]; then
    echo "Deploying keystore agent plugin (symlink)..."
    ln -sf "${PLUGIN_SRC}" "${PLUGIN_DST}"
    chmod +x "${PLUGIN_DST}" 2>/dev/null || true
else
    echo "WARNING: Agent plugin not found at ${PLUGIN_SRC}"
fi

# --- Create a test Java keystore for demonstration ---
TEST_KEYSTORE_DIR="/opt/test-keystores"
mkdir -p "${TEST_KEYSTORE_DIR}"

if command -v keytool >/dev/null 2>&1; then
    echo "Creating test Java keystores..."

    # JKS keystore with a cert expiring in 365 days
    keytool -genkeypair -alias server-cert \
        -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "${TEST_KEYSTORE_DIR}/server.jks" \
        -storepass changeit \
        -dname "CN=server.example.com, O=Test, C=US" \
        -noprompt 2>/dev/null || true

    # Add a second cert expiring in 30 days (triggers warning)
    keytool -genkeypair -alias expiring-cert \
        -keyalg RSA -keysize 2048 -validity 30 \
        -keystore "${TEST_KEYSTORE_DIR}/server.jks" \
        -storepass changeit \
        -dname "CN=expiring.example.com, O=Test, C=US" \
        -noprompt 2>/dev/null || true

    # PKCS12 keystore with a cert expiring in 180 days
    keytool -genkeypair -alias app-cert \
        -keyalg RSA -keysize 2048 -validity 180 \
        -storetype PKCS12 \
        -keystore "${TEST_KEYSTORE_DIR}/app.p12" \
        -storepass secretpass \
        -dname "CN=app.example.com, O=Test, C=US" \
        -noprompt 2>/dev/null || true

    echo "Test keystores created in ${TEST_KEYSTORE_DIR}"
else
    echo "WARNING: keytool not found — skipping test keystore creation"
fi

# --- Create keystore plugin configuration ---
MK_CONFDIR="/etc/check_mk"
mkdir -p "${MK_CONFDIR}"

if [[ -d "${TEST_KEYSTORE_DIR}" ]]; then
    echo "Creating keystore plugin configuration..."
    cat > "${MK_CONFDIR}/keystore.cfg" << ENTRYEOF
# Test keystore configuration for devcontainer
[${TEST_KEYSTORE_DIR}/server.jks]
password=changeit
aliases=ALL

[${TEST_KEYSTORE_DIR}/app.p12]
password=secretpass
aliases=ALL
ENTRYEOF
    echo "Plugin config created at ${MK_CONFDIR}/keystore.cfg"
fi

# --- Create the host in CheckMK via REST API ---
echo "Creating host '${AGENT_HOSTNAME}' in CheckMK..."
OWN_IP=$(hostname -i 2>/dev/null | awk '{print $1}')

HTTP_CODE=$(curl -sf -o /tmp/api_resp.json -w "%{http_code}" \
    -X POST "${API_URL}/domain-types/host_config/collections/all" \
    -H "Authorization: Bearer ${CMK_USER} ${CMK_PASSWORD}" \
    -H "Content-Type: application/json" \
    -d "{
        \"host_name\": \"${AGENT_HOSTNAME}\",
        \"folder\": \"/\",
        \"attributes\": {\"ipaddress\": \"${OWN_IP}\"}
    }" 2>/dev/null) || HTTP_CODE="000"

case "${HTTP_CODE}" in
    200|201) echo "Host created successfully." ;;
    400)     echo "Host may already exist (HTTP 400), continuing." ;;
    *)       echo "WARNING: Host creation returned HTTP ${HTTP_CODE}"
             cat /tmp/api_resp.json 2>/dev/null || true ;;
esac

# --- Activate pending changes ---
echo "Activating changes..."
sleep 3
curl -sf -o /dev/null \
    -X POST "${API_URL}/domain-types/activation_run/actions/activate-changes/invoke" \
    -H "Authorization: Bearer ${CMK_USER} ${CMK_PASSWORD}" \
    -H "Content-Type: application/json" \
    -H "If-Match: *" \
    -d "{\"force_foreign_changes\": true, \"sites\": [\"${CMK_SITE}\"]}" \
    || echo "WARNING: Change activation may have failed"

sleep 5

# --- Register the agent controller with the CheckMK server ---
echo "Registering agent controller with CheckMK server..."
if command -v cmk-agent-ctl >/dev/null 2>&1; then
    # No systemd in the container: serve the agent socket that the
    # check-mk-agent.socket unit would provide (one agent run per connection)
    socat UNIX-LISTEN:/run/check-mk-agent.socket,fork,unlink-early,user=cmk-agent,mode=0240 \
        EXEC:/usr/bin/check_mk_agent &
    sleep 1

    cmk-agent-ctl register \
        --hostname "${AGENT_HOSTNAME}" \
        --server "${CMK_SERVER}:8000" \
        --site "${CMK_SITE}" \
        --user "${CMK_USER}" \
        --password "${CMK_PASSWORD}" \
        --trust-cert \
        2>&1 || echo "WARNING: Agent controller registration may have failed"

    echo "Starting agent controller daemon..."
    cmk-agent-ctl daemon &
else
    echo "WARNING: cmk-agent-ctl not found — using legacy agent mode"
    # Fallback: start xinetd for legacy agent pull
    if command -v xinetd >/dev/null 2>&1; then
        xinetd -stayalive &
    fi
fi

echo "============================================================================"
echo "AlmaLinux agent setup complete."
echo "  Host: ${AGENT_HOSTNAME}  IP: ${OWN_IP}"
echo "============================================================================"

# Keep container running
exec tail -f /dev/null
