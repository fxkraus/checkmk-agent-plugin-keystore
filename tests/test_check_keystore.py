"""Unit tests for the Java Keystore certificate monitor check plugin."""

from collections.abc import Mapping, Sequence

import pytest

try:
    from cmk.agent_based.v2 import Metric, Result, State
    from cmk_addons.plugins.keystore.agent_based import keystore as keystore_module
    from cmk_addons.plugins.keystore.agent_based.keystore import (
        CertificateInfo,
        KeystoreSection,
        agent_section_keystore,
        check_keystore,
        check_plugin_keystore,
        discover_keystore,
        parse_keystore,
    )
except ImportError:
    pytest.skip("Checkmk libraries not available", allow_module_level=True)


ITEM = "/opt/ks.jks"
NOW = 1750000000.0


@pytest.fixture(autouse=True)
def _fixed_now(monkeypatch):
    monkeypatch.setattr(keystore_module.time, "time", lambda: NOW)


@pytest.fixture
def default_params() -> Mapping[str, object]:
    return {"warn_days": 30, "crit_days": 14}


def _cert(days: float, alias: str = "cert", path: str = ITEM, subject: str = "", agent_days: int | None = None) -> CertificateInfo:
    """Certificate expiring ``days`` after NOW; ``agent_days`` is the (possibly stale) agent value."""
    return CertificateInfo(path, alias, int(NOW + days * 86400), int(days) if agent_days is None else agent_days, subject)


def _run(
    certs: Sequence[CertificateInfo],
    params: Mapping[str, object],
    item: str = ITEM,
    errors: Sequence[tuple[str, str]] = (),
) -> list:
    section = KeystoreSection(certificates=list(certs), errors=list(errors))
    return list(check_keystore(item, params, section))


def _worst_state(results: Sequence) -> State:
    return State.worst(*(r.state for r in results if isinstance(r, Result)))


def _metrics(results: Sequence) -> dict[str, float]:
    return {r.name: r.value for r in results if isinstance(r, Metric)}


def _summary(results: Sequence) -> str:
    """Overall summary line (non-OK per-certificate notices are promoted to summaries too)."""
    return next(r.summary for r in results if isinstance(r, Result) and "certificate(s)" in r.summary)


def _cert_details(results: Sequence) -> list[str]:
    return [r.details for r in results if isinstance(r, Result) and "certificate(s)" not in r.summary]


# =============================================================================
# Parse
# =============================================================================


class TestParseKeystore:
    def test_empty_output(self):
        result = parse_keystore([])
        assert result == KeystoreSection(certificates=[], errors=[])

    def test_error_line(self):
        result = parse_keystore([["ERROR", "/path/to/ks.jks", "Keystore file not found"]])
        assert result.errors == [("/path/to/ks.jks", "Keystore file not found")]
        assert result.certificates == []

    def test_error_line_with_missing_fields(self):
        result = parse_keystore([["ERROR"]])
        assert result.errors == [("", "Unknown error")]

    def test_certificate_line(self):
        result = parse_keystore([["/opt/app/keystore.jks", "myalias", "1750000000", "104", "CN=example.com"]])
        assert result.certificates == [CertificateInfo("/opt/app/keystore.jks", "myalias", 1750000000, 104, "CN=example.com")]

    def test_multiple_certificates_keep_order(self):
        result = parse_keystore(
            [
                ["/opt/ks.jks", "alias1", "1750000000", "104", "CN=one"],
                ["/opt/ks.jks", "alias2", "1760000000", "220", "CN=two"],
                ["/opt/other.p12", "cert", "1770000000", "335", "CN=three"],
            ]
        )
        assert [c.alias for c in result.certificates] == ["alias1", "alias2", "cert"]

    def test_mixed_certs_and_errors(self):
        result = parse_keystore(
            [
                ["/opt/good.jks", "cert", "1750000000", "104", "CN=good"],
                ["ERROR", "/opt/bad.jks", "keytool failed"],
            ]
        )
        assert len(result.certificates) == 1
        assert result.errors == [("/opt/bad.jks", "keytool failed")]

    def test_missing_subject_defaults_to_empty(self):
        result = parse_keystore([["/opt/ks.jks", "alias1", "1750000000", "104"]])
        assert result.certificates[0].subject == ""

    @pytest.mark.parametrize(
        "row",
        [
            ["/opt/ks.jks", "alias1", "notanumber", "104", "CN=test"],
            ["/opt/ks.jks", "alias1", "1750000000", "abc", "CN=test"],
            ["/opt/ks.jks", "alias1"],
            [],
        ],
    )
    def test_malformed_rows_are_skipped(self, row):
        assert parse_keystore([row]) == KeystoreSection(certificates=[], errors=[])

    def test_negative_days(self):
        result = parse_keystore([["/opt/ks.jks", "expired", "1600000000", "-200", "CN=expired"]])
        assert result.certificates[0].days_remaining == -200


# =============================================================================
# Discovery
# =============================================================================


class TestDiscoverKeystore:
    def test_one_service_per_keystore(self):
        section = KeystoreSection(
            certificates=[_cert(100, "a1"), _cert(200, "a2"), _cert(300, "c", path="/opt/other.p12")],
            errors=[],
        )
        assert [s.item for s in discover_keystore(section)] == [ITEM, "/opt/other.p12"]

    def test_error_keystores_get_a_service(self):
        section = KeystoreSection(certificates=[], errors=[("/opt/bad.jks", "keytool failed")])
        assert [s.item for s in discover_keystore(section)] == ["/opt/bad.jks"]

    def test_no_duplicate_for_error_and_cert(self):
        section = KeystoreSection(certificates=[_cert(100)], errors=[(ITEM, "some warning")])
        assert [s.item for s in discover_keystore(section)] == [ITEM]

    def test_error_without_path_is_ignored(self):
        section = KeystoreSection(certificates=[], errors=[("", "Unknown error")])
        assert list(discover_keystore(section)) == []

    def test_empty_section(self):
        assert list(discover_keystore(KeystoreSection(certificates=[], errors=[]))) == []


# =============================================================================
# Check
# =============================================================================


class TestCheckKeystore:
    def test_error_is_crit(self, default_params):
        results = _run([], default_params, errors=[(ITEM, "keytool failed: wrong password")])
        assert results == [Result(state=State.CRIT, summary="Keystore error: keytool failed: wrong password")]

    def test_alias_error_does_not_hide_other_certificates(self, default_params):
        results = _run([_cert(200, "ok"), _cert(5, "crit")], default_params, errors=[(ITEM, "Alias 'gone' not found in keystore")])
        assert Result(state=State.CRIT, summary="Keystore error: Alias 'gone' not found in keystore") in results
        assert _summary(results) == "2 certificate(s), 1 critical"
        assert _metrics(results) == {"days_remaining": 5, "cert_count": 2}

    def test_multiple_errors_are_all_reported(self, default_params):
        results = _run([], default_params, errors=[(ITEM, "one"), (ITEM, "two")])
        assert results == [
            Result(state=State.CRIT, summary="Keystore error: one"),
            Result(state=State.CRIT, summary="Keystore error: two"),
        ]

    def test_error_of_other_keystore_is_ignored(self, default_params):
        results = _run([_cert(200)], default_params, errors=[("/opt/other.jks", "boom")])
        assert _worst_state(results) == State.OK

    def test_no_data_is_unknown(self, default_params):
        results = _run([], default_params)
        assert results == [Result(state=State.UNKNOWN, summary="No certificate data available")]

    def test_all_ok(self, default_params):
        results = _run([_cert(200, "c1"), _cert(300, "c2")], default_params)
        assert _worst_state(results) == State.OK
        assert _summary(results) == "2 certificate(s), all OK (nearest expiry: 200d)"

    @pytest.mark.parametrize(
        ("days", "expected"),
        [
            (31, State.OK),
            (30, State.WARN),  # warn threshold is inclusive
            (15, State.WARN),
            (14, State.CRIT),  # crit threshold is inclusive
            (0, State.CRIT),
            (-1, State.CRIT),
        ],
    )
    def test_threshold_boundaries(self, default_params, days, expected):
        assert _worst_state(_run([_cert(days)], default_params)) == expected

    def test_warning_summary(self, default_params):
        assert _summary(_run([_cert(20)], default_params)) == "1 certificate(s), 1 expiring soon"

    def test_critical_summary(self, default_params):
        assert _summary(_run([_cert(10)], default_params)) == "1 certificate(s), 1 critical"

    def test_expired_summary_and_notice(self, default_params):
        results = _run([_cert(-100, "old")], default_params)
        assert _summary(results) == "1 certificate(s), 1 expired"
        assert _cert_details(results)[0].startswith("EXPIRED 100d ago: old")

    def test_worst_state_wins(self, default_params):
        results = _run([_cert(200, "ok"), _cert(20, "warn"), _cert(5, "crit")], default_params)
        assert _worst_state(results) == State.CRIT
        assert _summary(results) == "3 certificate(s), 1 critical"

    def test_notices_sorted_by_remaining_days_with_subject(self, default_params):
        results = _run([_cert(200, "late", subject="CN=late"), _cert(100, "early", subject="CN=early")], default_params)
        details = _cert_details(results)
        assert details[0].startswith("100d remaining: early (CN=early)")
        assert details[1].startswith("200d remaining: late (CN=late)")

    def test_days_are_computed_at_check_time(self, default_params):
        # Cached agent output claims 40 days, but the certificate expires in 10
        results = _run([_cert(10, agent_days=40)], default_params)
        assert _worst_state(results) == State.CRIT
        assert _metrics(results)["days_remaining"] == 10

    def test_recently_expired_is_reported_as_expired(self, default_params):
        results = _run([_cert(-20 / 24, "old")], default_params)
        assert _summary(results) == "1 certificate(s), 1 expired"
        assert _cert_details(results)[0].startswith("EXPIRED 1d ago: old")

    def test_custom_thresholds(self):
        results = _run([_cert(70)], {"warn_days": 90, "crit_days": 60})
        assert _worst_state(results) == State.WARN

    def test_missing_params_fall_back_to_defaults(self):
        assert _worst_state(_run([_cert(30)], {})) == State.WARN
        assert _worst_state(_run([_cert(14)], {})) == State.CRIT

    def test_metrics(self, default_params):
        results = _run([_cert(100, "c1"), _cert(200, "c2")], default_params)
        assert _metrics(results) == {"days_remaining": 100, "cert_count": 2}

    def test_only_own_keystore_is_evaluated(self, default_params):
        results = _run([_cert(100, "c1"), _cert(5, "c2", path="/opt/other.jks")], default_params)
        assert _metrics(results) == {"days_remaining": 100, "cert_count": 1}
        assert _worst_state(results) == State.OK


# =============================================================================
# Registration
# =============================================================================


class TestRegistration:
    def test_section_name_matches_agent_header(self):
        assert agent_section_keystore.name == "keystore"

    def test_default_parameters(self):
        assert check_plugin_keystore.check_default_parameters == {"warn_days": 30, "crit_days": 14}

    def test_ruleset_name_matches_rule_spec(self):
        from cmk_addons.plugins.keystore.rulesets.ruleset_keystore_check_parameters import rule_spec_keystore

        assert check_plugin_keystore.check_ruleset_name == rule_spec_keystore.name

    def test_emitted_metrics_are_defined_in_graphing(self, default_params):
        from cmk_addons.plugins.keystore.graphing import graphing_keystore

        defined = {graphing_keystore.metric_days_remaining.name, graphing_keystore.metric_cert_count.name}
        assert set(_metrics(_run([_cert(100)], default_params))) <= defined

    def test_bakery_ruleset_loads(self):
        from cmk_addons.plugins.keystore.rulesets.ruleset_keystore_bakery import rule_spec_keystore_bakery

        assert rule_spec_keystore_bakery.name == "keystore"
