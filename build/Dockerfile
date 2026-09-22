# Literal tag (no ARG) so Dependabot can detect and bump it
FROM docker.io/checkmk/check-mk-cloud:2.4.0p37

# Initialize the CheckMK site at build time so it is cached in the image layer.
# This avoids the ~25 s penalty of running /docker-entrypoint.sh on every container start.
RUN /docker-entrypoint.sh /bin/true

COPY build/build-entrypoint.sh /build-entrypoint.sh
COPY build/build-modify-extension.py /build-modify-extension.py

RUN chmod +x /build-entrypoint.sh /build-modify-extension.py

ENTRYPOINT ["/build-entrypoint.sh"]
