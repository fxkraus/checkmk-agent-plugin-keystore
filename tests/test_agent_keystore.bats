#!/usr/bin/env bats
# BATS tests for the Java Keystore certificate monitor agent plugin.
#
# Prerequisites:
#   - Install BATS: https://github.com/bats-core/bats-core
#   - On RHEL: dnf install bats
#   - On Debian/Ubuntu: apt install bats
#
# Run with:
#   bats tests/test_agent_keystore.bats

setup() {
    # Create a temporary directory for test artifacts
    TEST_TEMP_DIR="$(mktemp -d)"

    # Set up mock MK_CONFDIR
    export MK_CONFDIR="${TEST_TEMP_DIR}/mk_confdir"
    mkdir -p "${MK_CONFDIR}"

    # Path to the agent plugin
    AGENT_PLUGIN="${BATS_TEST_DIRNAME}/../agents/plugins/keystore"
}

# Skip keytool-based tests locally when Java is missing, but fail in CI so
# they can never be skipped silently there.
require_keytool() {
    if command -v keytool &>/dev/null; then
        return 0
    fi
    if [[ -n "${CI:-}" ]]; then
        echo "keytool is required in CI" >&2
        return 1
    fi
    skip "keytool not available"
}

# Fake keytool that records its arguments and the KS_PASS environment
# variable, then fails so the plugin emits an ERROR line.
make_recording_keytool() {
    local fake="${TEST_TEMP_DIR}/fake-keytool"
    cat > "$fake" << BATSEOF
#!/bin/bash
printf '%s\n' "\$@" > "${TEST_TEMP_DIR}/argv"
printf '%s' "\${KS_PASS:-}" > "${TEST_TEMP_DIR}/env"
exit 1
BATSEOF
    chmod +x "$fake"
    echo "$fake"
}

teardown() {
    # Clean up temporary directory
    rm -rf "${TEST_TEMP_DIR}"
}

# =============================================================================
# Basic functionality tests
# =============================================================================

@test "Agent plugin is executable" {
    [ -x "${AGENT_PLUGIN}" ]
}

@test "Agent plugin starts with shebang" {
    head -1 "${AGENT_PLUGIN}" | grep -q '^#!/bin/bash'
}

@test "Agent plugin exits silently without config file" {
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "Agent plugin exits silently without MK_CONFDIR" {
    unset MK_CONFDIR
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# =============================================================================
# Config parsing tests
# =============================================================================

@test "Agent plugin outputs section header with empty config" {
    touch "${MK_CONFDIR}/keystore.cfg"
    # Empty config should still produce section header
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q '<<<keystore:sep(124)>>>'
}

@test "Agent plugin skips comment and blank lines in config" {
    cat > "${MK_CONFDIR}/keystore.cfg" << 'BATSEOF'
# This is a comment

# Another comment
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    # Should only have the section header, no errors
    line_count=$(echo "$output" | wc -l)
    [ "$line_count" -eq 1 ]
}

@test "Agent plugin reports error for nonexistent keystore" {
    cat > "${MK_CONFDIR}/keystore.cfg" << 'BATSEOF'
[/nonexistent/keystore.jks]
password=changeit
aliases=ALL
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q 'ERROR|/nonexistent/keystore.jks|Keystore file not found'
}

@test "Agent plugin reports error for missing keytool" {
    # Create a fake keystore file
    touch "${TEST_TEMP_DIR}/test.jks"
    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${TEST_TEMP_DIR}/test.jks]
password=changeit
keytool=/nonexistent/keytool
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "ERROR|${TEST_TEMP_DIR}/test.jks|keytool not found"
}

# =============================================================================
# Keystore monitoring tests (require Java keytool)
# =============================================================================

@test "Agent plugin reads a JKS keystore" {
    require_keytool

    # Create a test JKS keystore with a self-signed certificate
    local ks_path="${TEST_TEMP_DIR}/test.jks"
    keytool -genkeypair \
        -alias testcert \
        -keyalg RSA \
        -keysize 2048 \
        -validity 365 \
        -keystore "$ks_path" \
        -storepass changeit \
        -dname "CN=Test Certificate, O=Test, C=US" \
        -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
aliases=ALL
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q '<<<keystore:sep(124)>>>'
    # Should have a line with the alias and days remaining
    echo "$output" | grep -q "testcert"
}

@test "Agent plugin reads a PKCS12 keystore" {
    require_keytool

    # Create a test PKCS12 keystore
    local ks_path="${TEST_TEMP_DIR}/test.p12"
    keytool -genkeypair \
        -alias p12cert \
        -keyalg RSA \
        -keysize 2048 \
        -validity 365 \
        -storetype PKCS12 \
        -keystore "$ks_path" \
        -storepass changeit \
        -dname "CN=PKCS12 Test, O=Test, C=US" \
        -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
aliases=ALL
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "p12cert"
}

@test "Agent plugin filters by specific aliases" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/multi.jks"
    # Create keystore with two certificates
    keytool -genkeypair -alias cert1 -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=Cert One" -noprompt 2>/dev/null
    keytool -genkeypair -alias cert2 -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=Cert Two" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
aliases=cert1
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "|cert1|"
    # cert2 must not be reported
    [[ "$output" != *"|cert2|"* ]]
}

@test "Agent plugin matches aliases case-insensitively" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/case.jks"
    # JKS stores aliases lowercased
    keytool -genkeypair -alias MyServerCert -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=Case" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
aliases=MyServerCert
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -qi "^${ks_path}|myservercert|"
    [[ "$output" != *"ERROR"* ]]
}

@test "Agent plugin reports configured aliases missing from the keystore" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/missing.jks"
    keytool -genkeypair -alias present -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=Present" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
aliases=present,Gone
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "^${ks_path}|present|"
    echo "$output" | grep -qx "ERROR|${ks_path}|Alias 'Gone' not found in keystore"
}

@test "Agent plugin parses expiry dates regardless of the host time zone" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/tz.jks"
    keytool -genkeypair -alias tzcert -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=TZ" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
BATSEOF
    # A non-UTC host zone with abbreviations unknown to GNU date outside that zone
    export TZ=Australia/Sydney
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "^${ks_path}|tzcert|"
    [[ "$output" != *"ERROR"* ]]
}

@test "Agent plugin runs keytool in UTC" {
    local fake_keytool="${TEST_TEMP_DIR}/tz-keytool"
    printf '#!/bin/bash\nprintf %%s "$TZ" > "%s/tz"\nexit 1\n' "${TEST_TEMP_DIR}" > "$fake_keytool"
    chmod +x "$fake_keytool"
    touch "${TEST_TEMP_DIR}/any.jks"

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${TEST_TEMP_DIR}/any.jks]
password=changeit
keytool=${fake_keytool}
BATSEOF
    export TZ=Australia/Sydney
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/tz")" = "UTC" ]
}

@test "Agent plugin accepts alias lists with whitespace" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/ws.jks"
    local alias
    for alias in cert1 cert2 cert3; do
        keytool -genkeypair -alias "$alias" -keyalg RSA -keysize 2048 -validity 365 \
            -keystore "$ks_path" -storepass changeit \
            -dname "CN=${alias}" -noprompt 2>/dev/null
    done

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
aliases= cert1 , cert3
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "|cert1|"
    echo "$output" | grep -q "|cert3|"
    [[ "$output" != *"|cert2|"* ]]
}

@test "Agent plugin reports correct days remaining" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/days.jks"
    keytool -genkeypair -alias dayscert -keyalg RSA -keysize 2048 -validity 100 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=Days Test" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]

    # Extract days remaining (4th pipe-separated field after header)
    local days_line
    days_line=$(echo "$output" | grep "dayscert" | head -1)
    local days_remaining
    days_remaining=$(echo "$days_line" | cut -d'|' -f4)

    # Should be between 98 and 100 (allowing for execution time)
    [ "$days_remaining" -ge 98 ]
    [ "$days_remaining" -le 100 ]
}

@test "Agent plugin handles wrong password gracefully" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/badpw.jks"
    keytool -genkeypair -alias cert -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass correctpassword \
        -dname "CN=Bad PW Test" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=wrongpassword
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "ERROR|${ks_path}|keytool failed"
}

@test "Agent plugin handles multiple keystores" {
    require_keytool

    local ks1="${TEST_TEMP_DIR}/first.jks"
    local ks2="${TEST_TEMP_DIR}/second.p12"

    keytool -genkeypair -alias first -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks1" -storepass password1 \
        -dname "CN=First" -noprompt 2>/dev/null
    keytool -genkeypair -alias second -keyalg RSA -keysize 2048 -validity 365 \
        -storetype PKCS12 -keystore "$ks2" -storepass password2 \
        -dname "CN=Second" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks1}]
password=password1

[${ks2}]
password=password2
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "first"
    echo "$output" | grep -q "second"
}

@test "Agent plugin does not pass the password on the keytool command line" {
    local fake_keytool
    fake_keytool=$(make_recording_keytool)
    touch "${TEST_TEMP_DIR}/any.jks"

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${TEST_TEMP_DIR}/any.jks]
password=topsecret
keytool=${fake_keytool}
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    run grep -q "topsecret" "${TEST_TEMP_DIR}/argv"
    [ "$status" -ne 0 ]
    grep -qx -- "-storepass:env" "${TEST_TEMP_DIR}/argv"
    [ "$(cat "${TEST_TEMP_DIR}/env")" = "topsecret" ]
}

@test "Agent plugin passes passwords with special characters unchanged" {
    local fake_keytool
    fake_keytool=$(make_recording_keytool)
    touch "${TEST_TEMP_DIR}/any.jks"

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${TEST_TEMP_DIR}/any.jks]
password=p@ss w=rd;\$HOME*'"
keytool=${fake_keytool}
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/env")" = "p@ss w=rd;\$HOME*'\"" ]
}

@test "Agent plugin passes storetype to keytool" {
    local fake_keytool
    fake_keytool=$(make_recording_keytool)
    touch "${TEST_TEMP_DIR}/any.p12"

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${TEST_TEMP_DIR}/any.p12]
password=changeit
keytool=${fake_keytool}
storetype=PKCS12
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    grep -qx -- "-storetype" "${TEST_TEMP_DIR}/argv"
    grep -qx -- "PKCS12" "${TEST_TEMP_DIR}/argv"
}

@test "Agent plugin omits storetype when not configured" {
    local fake_keytool
    fake_keytool=$(make_recording_keytool)
    touch "${TEST_TEMP_DIR}/any.jks"

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${TEST_TEMP_DIR}/any.jks]
password=changeit
keytool=${fake_keytool}
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    run grep -qx -- "-storetype" "${TEST_TEMP_DIR}/argv"
    [ "$status" -ne 0 ]
}

@test "Agent plugin reports keytool failure with first output line" {
    local fake_keytool="${TEST_TEMP_DIR}/failing-keytool"
    printf '#!/bin/bash\necho "keytool error: boom"\necho "second line"\nexit 1\n' > "$fake_keytool"
    chmod +x "$fake_keytool"
    touch "${TEST_TEMP_DIR}/any.jks"

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${TEST_TEMP_DIR}/any.jks]
password=changeit
keytool=${fake_keytool}
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    [ "${lines[1]}" = "ERROR|${TEST_TEMP_DIR}/any.jks|keytool failed (rc=1): keytool error: boom" ]
    [[ "$output" != *"second line"* ]]
}

@test "Agent plugin reports expired certificates with negative days" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/expired.jks"
    keytool -genkeypair -alias oldcert -keyalg RSA -keysize 2048 \
        -startdate -20d -validity 10 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=Expired" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    local days
    days=$(echo "$output" | grep "|oldcert|" | cut -d'|' -f4)
    [ "$days" -le -9 ]
    [ "$days" -ge -11 ]
}

@test "Agent plugin handles CRLF line endings and missing trailing newline" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/crlf.jks"
    keytool -genkeypair -alias crlfcert -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=CRLF" -noprompt 2>/dev/null

    printf '[%s]\r\npassword=changeit\r\naliases=ALL' "$ks_path" > "${MK_CONFDIR}/keystore.cfg"
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "^${ks_path}|crlfcert|"
}

# =============================================================================
# Output format tests
# =============================================================================

@test "Output lines are pipe-separated with 5 fields" {
    require_keytool

    local ks_path="${TEST_TEMP_DIR}/format.jks"
    keytool -genkeypair -alias fmtcert -keyalg RSA -keysize 2048 -validity 365 \
        -keystore "$ks_path" -storepass changeit \
        -dname "CN=Format Test" -noprompt 2>/dev/null

    cat > "${MK_CONFDIR}/keystore.cfg" << BATSEOF
[${ks_path}]
password=changeit
BATSEOF
    run bash "${AGENT_PLUGIN}"
    [ "$status" -eq 0 ]

    local data_line
    data_line=$(echo "$output" | grep "fmtcert")
    # Count pipe separators (should be 4, giving 5 fields)
    local pipe_count
    pipe_count=$(echo "$data_line" | tr -cd '|' | wc -c)
    [ "$pipe_count" -eq 4 ]
}

# =============================================================================
# ShellCheck compliance
# =============================================================================

@test "Agent plugin passes shellcheck" {
    if ! command -v shellcheck &>/dev/null; then
        skip "shellcheck not installed"
    fi

    run shellcheck -x "${AGENT_PLUGIN}"
    echo "$output"
    [ "$status" -eq 0 ]
}
