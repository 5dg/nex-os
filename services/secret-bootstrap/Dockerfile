# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY services/secret-bootstrap ./services/secret-bootstrap
RUN --mount=type=secret,id=proxy_ca,required=true \
    SSL_CERT_FILE=/run/secrets/proxy_ca CGO_ENABLED=0 \
    go build -trimpath -ldflags=-buildid= -o /out/secret-bootstrap ./services/secret-bootstrap

FROM scratch
COPY --from=build --chmod=0555 /out/secret-bootstrap /secret-bootstrap
USER 0:0
ENTRYPOINT ["/secret-bootstrap"]
