# syntax=docker/dockerfile:1
# Qualification-only rebuild: retain PostgreSQL 17/data layout and the upstream
# gosu 1.19 implementation, with an explicitly identified Nex.os dependency overlay.
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS gosu-build
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOSUMDB=sum.golang.org
WORKDIR /src/gosu

# Upstream 1.19 tag resolves to this commit. Pin the archive bytes as well as
# the revision; a changed source or failed CA/checksum verification fails closed.
RUN --mount=type=secret,id=proxy_ca,required=true,mode=0444 \
    set -eu; \
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
      --cacert /run/secrets/proxy_ca \
      https://codeload.github.com/tianon/gosu/tar.gz/6456aaa0f3c854d199d0f037f068eb97515b7513 \
      -o /tmp/gosu.tar.gz; \
    echo '33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b  /tmp/gosu.tar.gz' | sha256sum --check --strict; \
    tar --extract --gzip --file=/tmp/gosu.tar.gz --strip-components=1; \
    rm /tmp/gosu.tar.gz; \
    grep -Fx 'const Version = "1.19"' version.go

# Verify the original upstream module inputs before applying the authored frozen
# overlay. The Go source remains unchanged; this is not an upstream release.
COPY deploy/qualification/gosu/ /nex/gosu-overlay/
COPY scripts/apply-gosu-overlay.sh /nex/apply-gosu-overlay.sh
# Go's checksum database remains enabled. Never resolve floating module versions,
# strip build metadata, or retain this session's proxy CA in a layer.
RUN --mount=type=secret,id=proxy_ca,required=true,mode=0444 \
    set -eu; \
    export SSL_CERT_FILE=/run/secrets/proxy_ca; \
    sh /nex/apply-gosu-overlay.sh /nex/gosu-overlay; \
    go mod download all; \
    go mod verify; \
    cmp go.mod /nex/gosu-overlay/go.mod; \
    cmp go.sum /nex/gosu-overlay/go.sum; \
    mkdir -p /out; \
    go build -mod=readonly -buildvcs=false -trimpath -ldflags='-w' -o /out/gosu .; \
    go version -m /out/gosu > /out/gosu-build.txt; \
    grep -F 'go1.27.3' /out/gosu-build.txt; \
    /out/gosu --version; \
    /out/gosu nobody true; \
    printf '%s\n' \
      'upstream=https://github.com/tianon/gosu' \
      'version=1.19' \
      'revision=6456aaa0f3c854d199d0f037f068eb97515b7513' \
      'archive-sha256=33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b' \
      'dependency-profile=Nex.os downstream overlay; upstream Go source unchanged' \
      >> /out/gosu-build.txt; \
    sha256sum go.mod go.sum >> /out/gosu-build.txt; \
    cp /nex/gosu-overlay/upstream-inputs.json /out/gosu-dependency-overlay.json

FROM postgres:17.11-trixie@sha256:31ba9c94a03ada9988f2bb493a22a75eef3a185884533e5cdbcd498ea835b08f
LABEL org.nex.qualification.postgres.base="postgres:17.11-trixie@sha256:31ba9c94a03ada9988f2bb493a22a75eef3a185884533e5cdbcd498ea835b08f" \
      org.nex.qualification.gosu.revision="6456aaa0f3c854d199d0f037f068eb97515b7513" \
      org.nex.qualification.gosu.source-sha256="33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b" \
      org.nex.qualification.gosu.compiler="go1.27.3" \
      org.nex.qualification.gosu.dependency-profile="nex-downstream-overlay-1" \
      org.nex.qualification.openssl.version="3.5.7-1~deb13u3"

# Keep the distribution's signed Debian sources/keyring. Limit this transaction
# to that existing source file: the unrelated PGDG repository need not be reached.
# APT still verifies repository signatures, expiry and downloaded package hashes.
RUN --mount=type=secret,id=proxy_ca,required=true,mode=0444 \
    set -eu; \
    test -f /etc/apt/sources.list.d/debian.sources; \
    mkdir -p /tmp/nex-debian-sources; \
    cp /etc/apt/sources.list.d/debian.sources /tmp/nex-debian-sources/debian.sources; \
    sed -i 's|http://deb.debian.org/|https://deb.debian.org/|g' /tmp/nex-debian-sources/debian.sources; \
    apt-get -o Dir::Etc::sourcelist=/dev/null \
      -o Dir::Etc::sourceparts=/tmp/nex-debian-sources \
      -o Acquire::https::CaInfo=/run/secrets/proxy_ca update; \
    DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist=/dev/null \
      -o Dir::Etc::sourceparts=/tmp/nex-debian-sources \
      -o Acquire::https::CaInfo=/run/secrets/proxy_ca \
      install --yes --only-upgrade --no-remove --no-install-recommends \
      libssl3t64=3.5.7-1~deb13u3 openssl=3.5.7-1~deb13u3 tzdata=2026e-0+deb13u1 libsqlite3-0=3.46.1-7+deb13u2 zlib1g=1:1.3.dfsg+really1.3.1-1+b1 libxml2=2.12.7+dfsg+really2.9.14-2.1+deb13u3; \
    test "$(dpkg-query -W -f='${Version}' libssl3t64)" = '3.5.7-1~deb13u3'; \
    test "$(dpkg-query -W -f='${Version}' openssl)" = '3.5.7-1~deb13u3'; \
    test "$(dpkg-query -W -f='${Version}' tzdata)" = '2026e-0+deb13u1'; \
    test "$(dpkg-query -W -f='${Version}' libsqlite3-0)" = '3.46.1-7+deb13u2'; \
    test "$(dpkg-query -W -f='${Version}' zlib1g)" = '1:1.3.dfsg+really1.3.1-1+b1'; \
    test "$(dpkg-query -W -f='${Version}' libxml2)" = '2.12.7+dfsg+really2.9.14-2.1+deb13u3'; \
    rm -rf /var/lib/apt/lists/* /tmp/nex-debian-sources

COPY --from=gosu-build --chmod=0755 /out/gosu /usr/local/bin/gosu
COPY --from=gosu-build --chmod=0444 /out/gosu-build.txt /usr/local/share/nex/gosu-build.txt
COPY --from=gosu-build --chmod=0444 /out/gosu-dependency-overlay.json /usr/local/share/nex/gosu-dependency-overlay.json
RUN set -eu; \
    test "$PG_MAJOR" = 17; \
    test "$PGDATA" = /var/lib/postgresql/data; \
    gosu --version; \
    gosu nobody true; \
    gosu postgres sh -c 'test "$(id -u)" = 999 && test "$(id -g)" = 999'; \
    postgres --version
# The upstream ENTRYPOINT, CMD, UID transition, volume and stop signal are inherited.
