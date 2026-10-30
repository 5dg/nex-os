# syntax=docker/dockerfile:1
FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY apps/workspace/package.json apps/workspace/package-lock.json ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca; fi; \
    npm ci --strict-ssl=true
COPY apps/workspace/ ./
RUN npm run build
FROM node:24.19.0-trixie-slim@sha256:ab3eebe934147fee049b5eb83c570f68c849a13c930bdfa482de99fcdfa3b3de
# ldconfig's auxiliary scan cache stores build inode/ctime/device identities.
# The loader uses /etc/ld.so.cache; retain that cache and all package metadata.
RUN --mount=type=secret,id=proxy_ca,required=true,mode=0444 \
    sed -i 's|URIs: http://deb.debian.org|URIs: https://deb.debian.org|' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::https::CaInfo=/run/secrets/proxy_ca update \
    && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CaInfo=/run/secrets/proxy_ca install -y --no-install-recommends --only-upgrade --no-remove \
       perl-base=5.40.1-6+deb13u1 libpcre2-8-0=10.46-1~deb13u3 liblzma5=5.8.1-1+deb13u2 tzdata=2026e-0+deb13u1 libssl3t64=3.5.7-1~deb13u3 libsqlite3-0=3.46.1-7+deb13u2 zlib1g=1:1.3.dfsg+really1.3.1-1+b1 \
    && test "$(dpkg-query -W -f='${Version}' liblzma5)" = '5.8.1-1+deb13u2' \
    && test "$(dpkg-query -W -f='${Version}' tzdata)" = '2026e-0+deb13u1' \
    && test "$(dpkg-query -W -f='${Version}' perl-base)" = '5.40.1-6+deb13u1' \
    && test "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" = '10.46-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' libssl3t64)" = '3.5.7-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' libsqlite3-0)" = '3.46.1-7+deb13u2' \
    && test "$(dpkg-query -W -f='${Version}' zlib1g)" = '1:1.3.dfsg+really1.3.1-1+b1' \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb \
       /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
       /opt/yarn-v1.22.22 /usr/local/bin/npm /usr/local/bin/npx \
       /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && rm -f /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log /var/cache/ldconfig/aux-cache \
    && test -s /etc/ld.so.cache
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
USER node
CMD ["node", "server.js"]
