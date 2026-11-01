# Diagnostic only: Node 24.22.2 differs from the app's pinned 24.19.0 engine.
FROM node@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY apps/workspace/package.json apps/workspace/package-lock.json ./
RUN --mount=type=secret,id=proxy_ca,required=true \
    test "$(node --version)" = 'v24.22.2' \
    && NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca npm ci --ignore-scripts --strict-ssl=true \
    && node -e "require('@next/swc-linux-x64-musl'); require('@img/sharp-linuxmusl-x64/sharp.node')"
COPY apps/workspace/ ./
RUN npm run typecheck && npm test && npm run build
FROM node@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
USER node
CMD ["node", "server.js"]
