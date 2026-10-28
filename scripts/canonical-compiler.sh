#!/bin/sh
# Runs only inside a digest-pinned compiler with /src read-only and fresh outputs.
set -eu
case "$1" in
go)
 go version | grep -F 'go1.27.3'
 export GOCACHE=/work/go-cache GOPATH=/work/gopath GOTMPDIR=/work/tmp
 mkdir -p "$GOCACHE" "$GOPATH" "$GOTMPDIR"
 go mod download
 go mod verify
 for item in control:services/control/cmd/control dev-issuer:services/control/cmd/dev-issuer model:services/model/cmd/model executor:services/tool-executor/cmd/executor worker:services/worker evidence:services/evidence qualification-edge:scripts/qualification-edge qualification-policy-edge:scripts/qualification-policy-edge qualification-pki:tests/qualification/cmd/pki qualification-issuer:tests/qualification/cmd/oidc-issuer qualification-receiver-readiness:tests/qualification/cmd/receiver-readiness; do
  name=$(printf '%s' "$item" | cut -d: -f1); package=$(printf '%s' "$item" | cut -d: -f2)
  go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w' -o "/out/$name" "./$package"
 done
 go version > /out/go-version.txt
 go env GOOS GOARCH CGO_ENABLED > /out/go-target.txt
 sha256sum /usr/local/go/bin/go > /out/go-compiler.sha256
 mkdir -p /package/trust
 cp /etc/ssl/certs/ca-certificates.crt /package/trust/ca-certificates.crt
 sha256sum /package/trust/ca-certificates.crt > /out/runtime-trust-bundle.sha256
 ;;
rust)
 rustc --version | grep -F 'rustc 1.99.1'
 export CARGO_TARGET_DIR=/work/target CARGO_HOME=/work/cargo CARGO_INCREMENTAL=0
 export RUSTFLAGS='--remap-path-prefix=/src=/nex/source --remap-path-prefix=/work=/nex/build'
 cargo build --locked --release -j 2 --manifest-path services/guard-kernel/Cargo.toml
 install -m0555 /work/target/release/nex-guard-kernel /out/guard-kernel
 rustc -Vv > /out/rustc-version.txt
 rustc --print target-libdir > /out/rust-target.txt
 sha256sum "$(rustup which rustc)" > /out/rustc-compiler.sha256
 ldd --version > /out/rust-libc.txt
 ldd /out/guard-kernel > /out/guard-linked-libraries.txt
 ;;
node)
 node --version | grep -Fx 'v24.19.0'
 export NPM_CONFIG_CACHE=/work/npm-cache XDG_CACHE_HOME=/work/node-cache
 mkdir -p "$NPM_CONFIG_CACHE" "$XDG_CACHE_HOME"
 cd /work/workspace
 npm ci --strict-ssl=true
 npm run build
 mkdir -p /package/workspace
 cp -a .next/standalone /package/workspace/standalone
 cp -a .next/static /package/workspace/static
 node /src/scripts/prepare-workspace-runtime.mjs /package/workspace/standalone /src/apps/workspace /out/workspace-packaging.json
 node --version > /out/node-version.txt
 npm --version > /out/npm-version.txt
 sha256sum /usr/local/bin/node > /out/node-compiler.sha256
 ;;
gosu)
 mkdir -p /work/gosu
 cd /work/gosu
 curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
  --cacert /run/ca.crt https://codeload.github.com/tianon/gosu/tar.gz/6456aaa0f3c854d199d0f037f068eb97515b7513 -o source.tar.gz
 echo '33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b  source.tar.gz' | sha256sum --check --strict
 tar -xzf source.tar.gz --strip-components=1
 rm source.tar.gz
 grep -Fx 'const Version = "1.19"' version.go
 sh /src/scripts/apply-gosu-overlay.sh /src/deploy/qualification/gosu
 export GOCACHE=/work/gosu-go-cache GOPATH=/work/gosu-gopath GOTMPDIR=/work/tmp
 mkdir -p "$GOCACHE" "$GOPATH" "$GOTMPDIR" /package/postgres/usr/local/bin /package/postgres/usr/local/share/nex
 go mod download all
 go mod verify
 cmp go.mod /src/deploy/qualification/gosu/go.mod
 cmp go.sum /src/deploy/qualification/gosu/go.sum
 go build -mod=readonly -buildvcs=false -trimpath -ldflags='-w' -o /package/postgres/usr/local/bin/gosu .
 go version -m /package/postgres/usr/local/bin/gosu > /package/postgres/usr/local/share/nex/gosu-build.txt
 grep -F 'go1.27.3' /package/postgres/usr/local/share/nex/gosu-build.txt
 printf '%s\n' 'revision=6456aaa0f3c854d199d0f037f068eb97515b7513' 'archive-sha256=33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b' >> /package/postgres/usr/local/share/nex/gosu-build.txt
 printf '%s\n' 'dependency-profile=Nex.os downstream overlay; upstream Go source unchanged' >> /package/postgres/usr/local/share/nex/gosu-build.txt
 sha256sum go.mod go.sum >> /package/postgres/usr/local/share/nex/gosu-build.txt
 cp /src/deploy/qualification/gosu/upstream-inputs.json /package/postgres/usr/local/share/nex/gosu-dependency-overlay.json
 chmod 0755 /package/postgres/usr/local/bin/gosu
 chmod 0444 /package/postgres/usr/local/share/nex/gosu-build.txt
 chmod 0444 /package/postgres/usr/local/share/nex/gosu-dependency-overlay.json
 ;;
*) echo 'Unknown compiler role' >&2;exit 2;;
esac
