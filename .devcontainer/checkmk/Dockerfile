# Literal tag (no ARG) so Dependabot can detect and bump it
FROM docker.io/checkmk/check-mk-cloud:2.4.0p21

RUN /docker-entrypoint.sh /bin/true

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
       gcc vim sudo less curl git jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN echo "cmk ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/cmk \
    && chmod 440 /etc/sudoers.d/cmk

COPY .devcontainer/requirements.txt /tmp/requirements.txt
RUN PATH="/omd/sites/cmk/bin:${PATH}" \
    OMD_ROOT="/omd/sites/cmk" \
    /omd/sites/cmk/bin/pip3 install -r /tmp/requirements.txt

COPY .devcontainer/checkmk/startup.sh /startup.sh
RUN chmod +x /startup.sh

ENTRYPOINT ["/startup.sh"]
CMD ["sleep", "infinity"]
