#!/bin/bash
# Run the pytest suite with the Checkmk Python interpreter and libraries.
# Intended to run inside the Checkmk image (see `make test-python-docker`).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="/omd/versions/default/bin/python3"
DEPS_DIR="$(mktemp -d)"

# Same pytest version as the devcontainer (kept current by Dependabot)
PYTEST_PIN="$(grep -E '^pytest==' "${REPO_DIR}/.devcontainer/requirements.txt")"
"${PYTHON}" -m pip install --quiet --disable-pip-version-check --target "${DEPS_DIR}" "${PYTEST_PIN}"

# Fail loudly instead of letting the test modules skip themselves
"${PYTHON}" -c "import cmk.agent_based.v2, cmk.base.cee.plugins.bakery.bakery_api.v1"

cd "${REPO_DIR}"
PYTHONPATH="${DEPS_DIR}:${REPO_DIR}/lib/python3" \
    "${PYTHON}" -m pytest -p no:cacheprovider "$@" tests/
