"""Unit tests for the Java Keystore Agent Bakery plugin."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

bakery_pkg = pytest.importorskip("cmk.base.cee.plugins.bakery", reason="Checkmk bakery API not available")
password_store = pytest.importorskip("cmk.utils.password_store")

from cmk.base.cee.plugins.bakery.bakery_api.v1 import OS, Plugin, PluginConfig  # noqa: E402

BAKERY_FILE = Path(__file__).resolve().parents[1] / "lib/check_mk/base/cee/plugins/bakery/keystore.py"


@pytest.fixture(scope="module")
def bakery() -> ModuleType:
    name = f"{bakery_pkg.__name__}.keystore"
    spec = importlib.util.spec_from_file_location(name, BAKERY_FILE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _explicit(password: str) -> tuple:
    return ("cmk_postprocessed", "explicit_password", ("uuid-1234", password))


def _stored(store_id: str) -> tuple:
    return ("cmk_postprocessed", "stored_password", (store_id, ""))


# =============================================================================
# Password resolution
# =============================================================================


class TestResolvePassword:
    def test_plain_string(self, bakery):
        assert bakery._resolve_password("secret") == "secret"

    def test_explicit_password(self, bakery):
        assert bakery._resolve_password(_explicit("s3cr=t")) == "s3cr=t"

    def test_stored_password(self, bakery, monkeypatch):
        monkeypatch.setattr(password_store, "lookup_for_bakery", lambda pw_id: {"ks_pw": "from-store"}[pw_id])
        assert bakery._resolve_password(_stored("ks_pw")) == "from-store"

    def test_missing_stored_password_yields_empty(self, bakery, monkeypatch):
        def _missing(pw_id: str) -> str:
            raise ValueError(f"Password '{pw_id}' not found")

        monkeypatch.setattr(password_store, "lookup_for_bakery", _missing)
        assert bakery._resolve_password(_stored("unknown")) == ""


# =============================================================================
# keystore.cfg generation
# =============================================================================


class TestBuildConfigLines:
    def test_full_entry(self, bakery):
        conf = {
            "keytool": "/opt/java/bin/keytool",
            "keystores": [
                {
                    "path": "/opt/app/server.jks",
                    "password": _explicit("changeit"),
                    "aliases": ("specific", ["web", "api"]),
                    "storetype": ("pkcs12", None),
                },
            ],
        }
        body = [line for line in bakery._build_config_lines(conf) if not line.startswith("#")]
        assert body == [
            "",
            "[/opt/app/server.jks]",
            "password=changeit",
            "aliases=web,api",
            "keytool=/opt/java/bin/keytool",
            "storetype=PKCS12",
            "",
        ]

    def test_defaults(self, bakery):
        conf = {"keystores": [{"path": "/opt/ks.jks", "password": _explicit("pw")}]}
        lines = bakery._build_config_lines(conf)
        assert "aliases=ALL" in lines
        assert "keytool=/usr/bin/keytool" in lines
        assert not any(line.startswith("storetype=") for line in lines)

    def test_per_keystore_keytool_overrides_global(self, bakery):
        conf = {
            "keytool": "/global/keytool",
            "keystores": [{"path": "/opt/ks.jks", "password": "pw", "keytool": "/local/keytool"}],
        }
        assert "keytool=/local/keytool" in bakery._build_config_lines(conf)

    def test_empty_global_keytool_falls_back_to_default(self, bakery):
        conf = {"keytool": "", "keystores": [{"path": "/opt/ks.jks", "password": "pw"}]}
        assert "keytool=/usr/bin/keytool" in bakery._build_config_lines(conf)

    def test_empty_keytool_override_falls_back_to_global(self, bakery):
        conf = {
            "keytool": "/global/keytool",
            "keystores": [{"path": "/opt/ks.jks", "password": "pw", "keytool": " "}],
        }
        assert "keytool=/global/keytool" in bakery._build_config_lines(conf)

    def test_entries_without_path_are_skipped(self, bakery):
        conf = {"keystores": [{"path": "", "password": "pw"}, {"password": "pw"}]}
        assert not any(line.startswith("[") for line in bakery._build_config_lines(conf))

    def test_multiple_keystores(self, bakery):
        conf = {
            "keystores": [
                {"path": "/opt/a.jks", "password": "a"},
                {"path": "/opt/b.p12", "password": "b"},
            ]
        }
        headers = [line for line in bakery._build_config_lines(conf) if line.startswith("[")]
        assert headers == ["[/opt/a.jks]", "[/opt/b.p12]"]


# =============================================================================
# Files yielded to the bakery
# =============================================================================


CONF_KEYSTORES = {"keystores": [{"path": "/opt/ks.jks", "password": _explicit("pw")}]}


class TestGetKeystoreFiles:
    def test_no_config(self, bakery):
        assert list(bakery.get_keystore_files(None)) == []

    @pytest.mark.parametrize("deploy", [("nodeploy", None), "nodeploy"])
    def test_nodeploy_deploys_nothing(self, bakery, deploy):
        # keystore.cfg holds cleartext passwords and must not be deployed either
        assert list(bakery.get_keystore_files({**CONF_KEYSTORES, "deploy": deploy})) == []

    def test_interval_deployment(self, bakery):
        files = list(bakery.get_keystore_files({**CONF_KEYSTORES, "deploy": ("interval", 3600)}))
        config, plugin = files
        assert isinstance(config, PluginConfig)
        assert config.target == Path("keystore.cfg")
        assert config.base_os == OS.LINUX
        assert "password=pw" in config.lines
        assert plugin == Plugin(base_os=OS.LINUX, source=Path("keystore"), interval=3600)

    def test_deployment_without_interval(self, bakery):
        files = list(bakery.get_keystore_files({**CONF_KEYSTORES, "deploy": ("interval", None)}))
        assert files[-1] == Plugin(base_os=OS.LINUX, source=Path("keystore"))
