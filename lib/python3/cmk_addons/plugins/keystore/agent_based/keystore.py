"""Checkmk 2.4 agent-based check plugin for Java Keystore certificate expiry.

Monitors certificate validity in Java keystores (JKS and PKCS12).
Creates one service per configured keystore and checks all monitored
certificates against warning and critical day thresholds.

Example agent output:

    <<<keystore:sep(124)>>>
    /opt/app/keystore.jks|myalias|1750000000|104|CN=example.com
    /opt/app/keystore.jks|ca|1780000000|450|CN=Example CA
    ERROR|/opt/app/bad.p12|keytool failed (rc=1): Keystore was tampered with
"""
#
# Copyright 2026 Felix Kraus (https://github.com/fxkraus)
# Licensed under the MIT License, see LICENSE

import math
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import NamedTuple

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    Metric,
    Result,
    Service,
    State,
    render,
)


class CertificateInfo(NamedTuple):
    """Parsed certificate information from the agent plugin."""

    keystore_path: str
    alias: str
    expiry_epoch: int
    days_remaining: int
    subject: str


class KeystoreSection(NamedTuple):
    """Parsed section data from the keystore agent plugin."""

    certificates: list[CertificateInfo]
    errors: list[tuple[str, str]]  # (keystore_path, error_message)


# ---------------------------------------------------------------------------
# Parse function
# ---------------------------------------------------------------------------


def parse_keystore(string_table: Sequence[Sequence[str]]) -> KeystoreSection:
    """Parse the ``<<<keystore:sep(124)>>>`` agent section."""
    certificates: list[CertificateInfo] = []
    errors: list[tuple[str, str]] = []

    for row in string_table:
        if not row:
            continue

        if row[0] == "ERROR":
            path = row[1] if len(row) > 1 else ""
            msg = row[2] if len(row) > 2 else "Unknown error"
            errors.append((path, msg))
            continue

        if len(row) < 4:
            continue

        try:
            cert = CertificateInfo(
                keystore_path=row[0],
                alias=row[1],
                expiry_epoch=int(row[2]),
                days_remaining=int(row[3]),
                subject=row[4] if len(row) > 4 else "",
            )
            certificates.append(cert)
        except (ValueError, IndexError):
            continue

    return KeystoreSection(certificates=certificates, errors=errors)


# ---------------------------------------------------------------------------
# Agent section registration
# ---------------------------------------------------------------------------

agent_section_keystore = AgentSection(
    name="keystore",
    parse_function=parse_keystore,
)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_keystore(section: KeystoreSection):
    """Discover one service per keystore path (from certificates or errors)."""
    seen_paths: set[str] = set()

    for cert in section.certificates:
        if cert.keystore_path not in seen_paths:
            seen_paths.add(cert.keystore_path)
            yield Service(item=cert.keystore_path)

    for path, _msg in section.errors:
        if path and path not in seen_paths:
            seen_paths.add(path)
            yield Service(item=path)


# ---------------------------------------------------------------------------
# Check function
# ---------------------------------------------------------------------------

_EXPIRED = "expired"
_CRITICAL = "critical"
_EXPIRING = "expiring soon"
_OK = "ok"


def _classify(days_remaining: int, warn_days: int, crit_days: int) -> tuple[State, str]:
    """Map remaining days to a state and a summary category."""
    if days_remaining < 0:
        return State.CRIT, _EXPIRED
    if days_remaining <= crit_days:
        return State.CRIT, _CRITICAL
    if days_remaining <= warn_days:
        return State.WARN, _EXPIRING
    return State.OK, _OK


def check_keystore(item: str, params: Mapping[str, object], section: KeystoreSection) -> CheckResult:
    """Evaluate certificate expiry in a keystore against configurable thresholds."""
    warn_days = int(params.get("warn_days", 30))
    crit_days = int(params.get("crit_days", 14))

    # Errors may affect single aliases only, so the certificates are still evaluated
    errors = [msg for path, msg in section.errors if path == item]
    for msg in errors:
        yield Result(state=State.CRIT, summary=f"Keystore error: {msg}")

    # Gather certificates for this keystore
    certs = [c for c in section.certificates if c.keystore_path == item]

    if not certs:
        if not errors:
            yield Result(state=State.UNKNOWN, summary="No certificate data available")
        return

    # Computed at check time: with an async plugin interval the agent's own value may be stale
    now = time.time()
    dated = sorted(((math.floor((cert.expiry_epoch - now) / 86400), cert) for cert in certs), key=lambda d: d[0])

    counts: Counter[str] = Counter()
    worst_days = dated[0][0]

    for days, cert in dated:
        state, category = _classify(days, warn_days, crit_days)
        counts[category] += 1

        text = f"EXPIRED {abs(days)}d ago: {cert.alias}" if category == _EXPIRED else f"{days}d remaining: {cert.alias}"
        if cert.subject:
            text += f" ({cert.subject})"
        text += f", expires {render.datetime(cert.expiry_epoch)}"
        yield Result(state=state, notice=text)

    # Overall summary names the most severe category present
    total = len(certs)
    summary = f"{total} certificate(s), all OK (nearest expiry: {worst_days}d)"
    for category in (_EXPIRED, _CRITICAL, _EXPIRING):
        if counts[category]:
            summary = f"{total} certificate(s), {counts[category]} {category}"
            break
    yield Result(state=State.OK, summary=summary)

    # Metrics
    yield Metric(name="days_remaining", value=worst_days)
    yield Metric(name="cert_count", value=total)


# ---------------------------------------------------------------------------
# Check plugin registration
# ---------------------------------------------------------------------------

check_plugin_keystore = CheckPlugin(
    name="keystore",
    service_name="Keystore %s",
    discovery_function=discover_keystore,
    check_function=check_keystore,
    check_default_parameters={
        "warn_days": 30,
        "crit_days": 14,
    },
    check_ruleset_name="keystore",
)
