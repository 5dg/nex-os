# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test tooling only. E owns builds/runs; this is not an application runtime.
FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df
WORKDIR /fixture
COPY --chmod=0444 apps/workspace/tests/browser/package.json apps/workspace/tests/browser/package-lock.json apps/workspace/tests/browser/entry.mjs ./
RUN --mount=type=secret,id=proxy_ca,required=true,mode=0444 \
    set -eu; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::https::CaInfo=/run/secrets/proxy_ca update; \
    apt-get -o Acquire::https::CaInfo=/run/secrets/proxy_ca install --yes --no-install-recommends \
      chromium=156.0.8078.47-1~deb12u1 \
      chromium-common=156.0.8078.47-1~deb12u1 \
      chromium-sandbox=156.0.8078.47-1~deb12u1 \
      libnss3=2:3.87.1-1+deb12u4 \
      libnss3-tools=2:3.87.1-1+deb12u4; \
    NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca npm ci --ignore-scripts --strict-ssl=true --cache=/tmp/nex-browser-npm-cache; \
    node /fixture/entry.mjs --build-inventory; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /tmp/nex-browser-npm-cache
USER node
ENTRYPOINT ["node", "/fixture/entry.mjs"]
