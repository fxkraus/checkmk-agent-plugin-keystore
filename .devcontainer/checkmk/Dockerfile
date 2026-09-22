# Literal tags (no ARG) so Dependabot can detect and bump them
FROM ghcr.io/astral-sh/uv:0.12.17 AS uv

FROM docker.io/checkmk/check-mk-cloud:2.4.0p37

RUN /docker-entrypoint.sh /bin/true

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
       gcc vim sudo less curl git jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN echo "cmk ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/cmk \
    && chmod 440 /etc/sudoers.d/cmk

# Dev dependencies from uv.lock (with hashes), installed into the site's Python
COPY pyproject.toml uv.lock /tmp/deps/
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv export --project /tmp/deps --frozen --only-group dev --no-emit-project \
       --output-file /tmp/requirements.txt \
    && PATH="/omd/sites/cmk/bin:${PATH}" \
       OMD_ROOT="/omd/sites/cmk" \
       /omd/sites/cmk/bin/pip3 install -r /tmp/requirements.txt

COPY .devcontainer/checkmk/startup.sh /startup.sh
RUN chmod +x /startup.sh

ENTRYPOINT ["/startup.sh"]
CMD ["sleep", "infinity"]
