FROM debian:bookworm-slim@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b AS runtime

LABEL org.opencontainers.image.title="SASTSIMI pinned CodeQL runner"
LABEL org.opencontainers.image.version="2.27.0"
LABEL io.sastsimi.codeql.bundle.sha256="8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305"
LABEL io.sastsimi.codeql.bundle.size="686083106"

# The host builder verifies the exact local archive before Docker receives the
# context. The image verifies it again in the same stage that extracts it, so
# BuildKit cannot prune away the verification step.
COPY --chown=0:0 codeql-bundle-linux64.tar.gz /tmp/
COPY --chmod=0555 sastsimi-codeql /usr/local/bin/sastsimi-codeql

RUN set -eu; \
    printf '%s  %s\n' \
        '8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305' \
        '/tmp/codeql-bundle-linux64.tar.gz' \
        | sha256sum --check --strict -; \
    tar -xzf /tmp/codeql-bundle-linux64.tar.gz -C /opt; \
    rm -f /tmp/codeql-bundle-linux64.tar.gz; \
    test -x /opt/codeql/codeql; \
    mkdir -p /work/database /work/output; \
    printf '%s\n' 'sastsimi:x:65532:' >> /etc/group; \
    printf '%s\n' 'sastsimi:x:65532:65532:SASTSIMI CodeQL:/nonexistent:/usr/sbin/nologin' >> /etc/passwd; \
    chmod 0555 /usr/local/bin/sastsimi-codeql

ENV LC_ALL=C
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sastsimi-codeql"]
