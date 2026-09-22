# Checkmk Agent Plugin — Java Keystore Certificate Expiry

A [Checkmk](https://checkmk.com) extension package (MKP) that monitors
certificate expiry in Java keystores (JKS and PKCS12).

> **Checkmk ≥ 2.4.0** is required.
> This plugin uses the **Agent Based API v2**, **Rulesets API v1**,
> **Bakery API v1**, and **Graphing API v1**.

---

## Features

- **JKS and PKCS12** — monitors certificates in both Java KeyStore and
  PKCS12 format keystores.
- **Configurable thresholds** — set warning and critical levels in days
  before certificate expiry via the Checkmk Web UI.
- **Alias filtering** — monitor all certificates in a keystore (default)
  or only specific aliases. Aliases match case-insensitively; a configured
  alias missing from the keystore turns the service CRITICAL.
- **Multiple keystores** — monitor any number of keystores per host.
- **Custom keytool path** — specify the path to the `keytool` binary if
  it is not at `/usr/bin/keytool`.
- **Keystore password** — configure the keystore password through the
  Checkmk Web UI (explicit or from the password store). It is deployed to
  the agent host in `keystore.cfg` and passed to `keytool` via environment
  variable, never on the command line (see [SECURITY.md](SECURITY.md)).
- **Pure bash agent plugin** — the code running on monitored hosts uses
  only bash and `keytool`, minimising dependencies.
- **WATO rules** — fully configurable via the Checkmk GUI.
- **Agent Bakery** — deploy the agent plugin and its configuration
  automatically, with an optional async execution interval.
- **Graphing** — metric for nearest certificate expiry with a graph
  definition.

---

## Installation

### From a release MKP

1. Download the latest `.mkp` file from the
   [Releases](../../releases)
   page.
2. Upload and install via **Setup → Maintenance → Extension packages** in the
   Checkmk GUI, or with the CLI:

   ```bash
   mkp install keystore-<version>.mkp
   ```

### Manual (development)

Copy the file tree under `lib/` into
`~/local/lib/` of your Checkmk site and the `agents/` tree into
`~/local/share/check_mk/agents/`.

---

## Configuration

### Check Parameters

**Setup → Services → Service monitoring rules → Java Keystore Certificate Expiry**

| Parameter | Description | Default |
|---|---|---|
| Warning threshold | Days before expiry to trigger WARNING | 30 |
| Critical threshold | Days before expiry to trigger CRITICAL | 14 |

Thresholds apply to all certificates in all keystores matched by the rule.
You can use the item condition to target specific keystore paths.

### Agent Bakery

**Setup → Agents → Windows, Linux, Solaris, AIX → Agent rules → Java Keystore certificate monitor plugin**

| Parameter | Description | Default |
|---|---|---|
| Deployment options | Deploy with interval / do not deploy | Deploy with 1 h interval |
| Path to keytool | Global default keytool binary path (empty = default) | `/usr/bin/keytool` |
| Keystores | List of keystores to monitor | *(empty)* |

Each keystore entry has:

| Parameter | Description |
|---|---|
| Keystore file path | Absolute path on the monitored host |
| Keystore password | Password to access the keystore |
| Aliases to monitor | All (default) or a specific list of alias names |
| keytool path override | Override the global keytool path for this keystore (empty = global default) |
| Keystore type | Auto-detect (default), JKS, or PKCS12 |

### Agent-side configuration (manual)

If not using the Agent Bakery, create `/etc/check_mk/keystore.cfg` on the
monitored host:

```ini
# One section per keystore
[/opt/app/server.jks]
password=changeit
aliases=ALL
keytool=/usr/bin/keytool
storetype=JKS

[/opt/app/client.p12]
password=secret
aliases=myalias,otheralias
keytool=/usr/bin/keytool
```

Section header: keystore file path in square brackets.

The file contains cleartext passwords — restrict it to root:

```bash
chown root:root /etc/check_mk/keystore.cfg
chmod 600 /etc/check_mk/keystore.cfg
```

| Key | Description | Default |
|---|---|---|
| `password` | Keystore password | *(required)* |
| `aliases` | Comma-separated alias list (case-insensitive) or `ALL` | `ALL` |
| `keytool` | Path to keytool binary | `/usr/bin/keytool` |
| `storetype` | `JKS`, `PKCS12`, or omit for auto-detection | auto |

---

## Agent Output Format

The agent plugin produces a `<<<keystore>>>` section with pipe-separated
fields:

```text
<<<keystore:sep(124)>>>
/opt/app/server.jks|server-cert|1780000000|365|CN=server.example.com
/opt/app/server.jks|ca-cert|1810000000|712|CN=Example CA
ERROR|/opt/app/bad.p12|keytool failed (rc=1): Keystore was tampered with
```

| Field | Description |
|---|---|
| 1 | Keystore path (or `ERROR` for error lines) |
| 2 | Certificate alias (or keystore path for errors) |
| 3 | Expiry Unix timestamp (or error message) |
| 4 | Days remaining until expiry at plugin run time (informational) |
| 5 | Certificate subject (Owner/DN) |

The check computes the remaining days from the expiry timestamp at check
time, so cached output of an async plugin interval does not delay alerts.
Error lines for single aliases (e.g. an alias not found) are reported as
CRITICAL alongside the results of the other certificates in the keystore.

---

## File Layout

```text
agents/
  plugins/
    keystore                     # Bash agent plugin (deployed to monitored hosts)
lib/check_mk/base/cee/plugins/bakery/
    keystore.py                  # Bakery plugin (Agent Bakery deployment)
lib/python3/
  cmk_addons/plugins/keystore/
    agent_based/
      keystore.py                # Server-side check plugin (Agent Based API v2)
    checkman/
      keystore                   # Checkmk manual page
    graphing/
      graphing_keystore.py       # Metric & graph definitions (Graphing API v1)
    rulesets/
      ruleset_keystore_bakery.py           # WATO ruleset: bakery configuration
      ruleset_keystore_check_parameters.py # WATO ruleset: check thresholds
.pre-commit-config.yaml          # Linters + secret scan (local and CI)
.hadolint.yaml                   # Dockerfile lint configuration
.github/workflows/
  ci.yml                         # Lint, secret scan, tests and MKP build
  release.yml                    # Build and publish the MKP on version tags
  dependabot-auto-merge.yml      # Auto-merge minor/patch Dependabot PRs
build/
  build-entrypoint.sh            # Packages the MKP inside the container
  build-modify-extension.py      # Injects git version into the manifest
  Dockerfile                     # Build container definition
.devcontainer/
  docker-compose.yml             # Multi-container dev environment
  checkmk/Dockerfile             # CheckMK 2.4 Cloud dev container
  almalinux/Dockerfile           # AlmaLinux 9 monitored test host (with Java)
  almalinux/entrypoint.sh        # Agent install + keystore setup automation
  scripts/post-create.sh         # Symlinks plugin into CMK site
  scripts/deploy-plugin.sh       # Redeploy plugin + reload CMK
  scripts/discover-services.sh   # Trigger service discovery via REST API
tests/
  test_check_keystore.py         # Check plugin tests (pytest)
  test_bakery_keystore.py        # Bakery plugin tests (pytest)
  test_agent_keystore.bats       # Agent plugin tests (BATS)
  run-pytest.sh                  # Runs pytest with the Checkmk interpreter
```

---

## Building from Source

The build runs inside a Checkmk container to ensure the correct `mkp`
tooling is available. Both **Docker** and **Podman** are supported.

### Using Podman (recommended)

```bash
podman build --format docker -t checkmk-keystore-build -f build/Dockerfile .
podman run --rm -v "$PWD:/source:Z" checkmk-keystore-build
```

> **Note:** The `:Z` suffix is required on SELinux-enabled systems (RHEL,
> Fedora) to relabel the volume for container access.

### Using Docker

```bash
docker build -t checkmk-keystore-build -f build/Dockerfile .
docker run --rm -v "$PWD:/source" checkmk-keystore-build
```

### Build Output

The resulting `keystore-<version>.mkp` file is written to the repository root.

A version number is derived automatically:

- If the current commit is tagged (e.g. `v1.2.3`), the tag is used.
- Otherwise a numeric version is generated from the commit hash.

> [!WARNING]
> **The git tag (and therefore `CMK_VERSION`) must be a valid Checkmk
> version string** such as `1.2.3`, `2.4.0p1`, or `2.4.0i1`.
> Non-standard suffixes like `-alpha`, `-beta`, or `-rc1` will cause the
> Checkmk server to crash when parsing `parse_check_mk_version()`, so the
> build rejects them.
>
> **Good:** `v0.1.0`, `v0.1.0p1`, `v1.0.0`
> **Bad:** `v0.1.0-alpha`, `v1.0.0-beta2`

---

## Development

### DevContainer (Recommended)

The project includes a full devcontainer setup with two containers on a
shared Docker network:

| Container | Image | Purpose |
|---|---|---|
| `checkmk-keystore-checkmk` | CheckMK 2.4 Cloud | CheckMK server + dev environment |
| `checkmk-keystore-almalinux` | AlmaLinux 9 + Java 17 | Monitored test host with test keystores |

**Quick start:**

1. Open the repository in VS Code.
2. When prompted, click **Reopen in Container** (or run
   `Dev Containers: Reopen in Container` from the command palette).
3. Both containers build and start automatically. The AlmaLinux host
   registers itself with the CheckMK server, installs the agent,
   creates test keystores, and deploys the keystore plugin.
4. Enable the [pre-commit hooks](#pre-commit-hooks) once per clone
   (`pre-commit` is preinstalled in the devcontainer):

   ```bash
   pre-commit install
   pre-commit run --all-files   # optional: check the whole tree once
   ```

   The hooks run the linters and the gitleaks secret scan on every commit.
   If you also commit from the host, `pre-commit` must be installed there
   too (see below); otherwise the hook refuses the commit.

**Credentials:**

- **Web UI:** `http://localhost:5000/cmk/`
- **Login:** `cmkadmin` / `cmk` (local development only; ports are bound to `127.0.0.1`)

**Test keystores created in the AlmaLinux container:**

| Path | Type | Contents |
|---|---|---|
| `/opt/test-keystores/server.jks` | JKS | `server-cert` (365d), `expiring-cert` (30d) |
| `/opt/test-keystores/app.p12` | PKCS12 | `app-cert` (180d) |

Inside the devcontainer, use `make deploy-plugin`, `make discover`, or
`make redeploy` to push server-side changes and rediscover services.

> **Note:** The devcontainer and build image use the
> `checkmk/check-mk-cloud` Docker image, a commercial Checkmk edition.
> Review the [Checkmk licensing terms](https://checkmk.com/pricing) before use.

### Prerequisites (local development without devcontainer)

Install development tools:

```bash
# RHEL/Fedora
dnf install bats java-17-openjdk-headless

# Debian/Ubuntu
apt install bats default-jdk-headless

# Linters and secret scanning are managed by pre-commit (see below)
uv tool install pre-commit   # or: pipx install pre-commit
```

Then enable the hooks in your clone before the first commit:

```bash
pre-commit install
```

### Pre-commit Hooks

All linters and the secret scan are defined in `.pre-commit-config.yaml`.
CI runs exactly the same hooks, so a clean local run means a clean CI run.

| Hook | Checks |
|---|---|
| gitleaks, detect-private-key | secrets and private keys in staged changes |
| ruff (check + format) | Python lint and formatting |
| mypy | type checks for the build script |
| shellcheck | shell scripts, including the agent plugin |
| hadolint | Dockerfiles (`.hadolint.yaml`) |
| actionlint | GitHub Actions workflows |
| pre-commit-hooks | YAML/TOML/JSON syntax, large files, merge conflicts, whitespace, shebangs |

Enable the hooks once per clone, so every commit is checked before it is
created and commits containing secrets are blocked:

```bash
pre-commit install
```

Run all hooks against the whole repository:

```bash
make lint            # = pre-commit run --all-files
make secrets         # full git history scan with gitleaks (Docker)
```

### Makefile Targets

```bash
make lint         # Run all pre-commit hooks (linters + secret scan)
make secrets      # Scan the full git history for secrets
make format       # Auto-format Python code
make test         # Run all tests
make build        # Build the MKP package
make clean        # Remove build artifacts
```

### Testing

**Shell Tests (BATS):**

Requires `bats` and a Java `keytool`. Keytool-based tests are skipped locally
when Java is missing, but fail in CI (`CI` environment variable set).

```bash
bats tests/test_agent_keystore.bats
```

**Python Unit Tests:**

The check and bakery plugins need the Checkmk libraries. Run them inside the
Checkmk build image (no local Checkmk required):

```bash
make test-python-docker
```

Inside the devcontainer or a Checkmk site, `pytest tests/` works directly.

### CI/CD

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push to `main`, pull requests | pre-commit lint, gitleaks secret scan, BATS, pytest against Checkmk 2.4 and 2.5, MKP build |
| `release.yml` | tag `vX.Y.Z` (optionally `pN`, `iN`, `bN` suffix) | builds the MKP and publishes a GitHub release (`iN`/`bN` as pre-release) |
| `dependabot-auto-merge.yml` | Dependabot pull requests | enables auto-merge for minor/patch updates |

Every commit on `main` produces an MKP, attached to the CI run as the
artifact `keystore-mkp-<commit-sha>` (kept 90 days, version `0.0.<n>`
derived from the commit hash). Tagged releases get a proper version.

Dependabot minor and patch updates are merged automatically once all
required checks pass. This needs two repository settings:

1. **Settings → General → Allow auto-merge** enabled.
2. A branch ruleset on `main` requiring the status checks `lint`, `secrets`,
   `bats`, `pytest (Checkmk 2.4)`, `pytest (Checkmk 2.5)` and `mkp`.

The pytest jobs use the `2.4.0-latest` / `2.5.0-latest` images, so the
matrix needs no version maintenance. The MKP itself is built once with the
pinned image in `build/Dockerfile` (an MKP only bundles the plugin files and
is not version-specific).

---

## Requirements

### Monitored Hosts

- **Java** — a JRE or JDK installation that provides the `keytool` binary
  (Java 8+).
- **Bash** — the agent plugin is a pure bash script.
- **CheckMK Agent** — the standard Checkmk agent must be installed.

### Checkmk Server

- **Checkmk 2.4 or 2.5** (tested in CI). Agent Bakery support needs a
  commercial edition (2.4: Enterprise, Cloud, MSP; 2.5: Pro, Ultimate,
  Ultimate MT); Raw / Community works with manual plugin deployment.

---

## License

[MIT](LICENSE)
