#!/bin/sh
# Runs inside the pinned Go compiler as part of the canonical build.
set -eu
go version | grep -F 'go1.27.3'
export GOTOOLCHAIN=local CGO_ENABLED=0
export GOCACHE=/work/opa-go-cache GOPATH=/work/opa-gopath GOTMPDIR=/work/tmp
[ -d /out ] && [ ! -L /out ] || exit 2
for task_output in opa opa-build.txt opa-source-inventory.txt opa-bundle-tests.txt opa-topdown-tests.txt opa-private-key-tests.txt opa-rest-tests.txt opa-jwe-tests.txt; do
 [ ! -e "/out/$task_output" ] && [ ! -L "/out/$task_output" ] || { echo 'OPA output already exists; retain it and use a fresh build.' >&2; exit 2; }
done
[ ! -e /work/opa-source.tar.gz ] && [ ! -L /work/opa-source.tar.gz ] || exit 2
[ -d /package ] && [ ! -L /package ] || exit 2
[ ! -e /package/opa ] && [ ! -L /package/opa ] || { echo 'OPA inventory output already exists; retain it and use a fresh build.' >&2; exit 2; }
mkdir /package/opa
mkdir -p "$GOCACHE" "$GOPATH" "$GOTMPDIR"
mkdir /work/opa-source
cd /work/opa-source
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
 --cacert /run/ca.crt https://codeload.github.com/open-policy-agent/opa/tar.gz/d4c8d0c8812290c3e3715ca4cf958f75283f6ec4 -o /work/opa-source.tar.gz
echo '4455609bdf200db7531f9c93600047d242dfa1a3cec7f0e048532fe9e36b6133  /work/opa-source.tar.gz' | sha256sum --check --strict
tar -xzf /work/opa-source.tar.gz --strip-components=1
sh /src/scripts/apply-opa-overlay.sh /src/deploy/qualification/opa
# Go caches and outputs live outside this tree. Capture every source file's
# bytes and the tree's paths, types, modes, ownership, sizes and link targets.
opa_inventory() {
 task_snapshot="$1"
 LC_ALL=C find . -type f -exec sha256sum --zero -- {} + > "/work/opa-files-$task_snapshot.unsorted"
 LC_ALL=C sort -z "/work/opa-files-$task_snapshot.unsorted" > "/work/opa-files-$task_snapshot"
 LC_ALL=C find . -printf '%y %m %U %G %s %p %l\0' > "/work/opa-tree-$task_snapshot.unsorted"
 LC_ALL=C sort -z "/work/opa-tree-$task_snapshot.unsorted" > "/work/opa-tree-$task_snapshot"
}
opa_inventory before
go mod download all
go mod verify
cmp go.mod /src/deploy/qualification/opa/go.mod
cmp go.sum /src/deploy/qualification/opa/go.sum

bundle_tests='TestGenerateSignedToken|TestGenerateSignedTokenWithClaims|TestVerifyBundleSignature|TestVerifyJWTSignature|TestNexRejectSignedMalformedHeader|TestNexRejectUnsupportedCriticalHeaders|TestNexBundleAlgorithmRoundTrip'
go test -p=1 -mod=readonly -count=1 -v -run "^($bundle_tests)$" ./v1/bundle > /out/opa-bundle-tests.txt
for task_test in TestGenerateSignedToken TestGenerateSignedTokenWithClaims TestVerifyBundleSignature TestVerifyJWTSignature TestNexRejectSignedMalformedHeader TestNexRejectUnsupportedCriticalHeaders TestNexBundleAlgorithmRoundTrip; do
 grep -F -- "--- PASS: $task_test (" /out/opa-bundle-tests.txt >/dev/null
done
! grep -E '^[[:space:]]*--- SKIP:' /out/opa-bundle-tests.txt
topdown_tests='TestTopDownJWTEncodeSignES256|TestTopDownJWTEncodeSignES512|TestTopdownJWTUnknownAlgTypesDiscardedFromJWKS|TestTopdownJWTVerifyOnlyVerifiesUsingApplicableKeys|TestTopdownJWTDecodeVerifyIgnoresKeysOfUnknownAlgInJWKS|TestBuiltinJWTDecodeVerify'
go test -p=1 -mod=readonly -count=1 -v -run "^($topdown_tests)$" ./v1/topdown > /out/opa-topdown-tests.txt
for task_test in TestTopDownJWTEncodeSignES256 TestTopDownJWTEncodeSignES512 TestTopdownJWTUnknownAlgTypesDiscardedFromJWKS TestTopdownJWTVerifyOnlyVerifiesUsingApplicableKeys TestTopdownJWTDecodeVerifyIgnoresKeysOfUnknownAlgInJWKS TestBuiltinJWTDecodeVerify; do
 grep -F -- "--- PASS: $task_test (" /out/opa-topdown-tests.txt >/dev/null
done
! grep -E '^[[:space:]]*--- SKIP:' /out/opa-topdown-tests.txt
# Exercise the modified JWK import through both upstream Rego versions.
go test -p=1 -mod=readonly -count=1 -v -run '^TestRego$/^(v0|v1)$/^cryptox509parsersaprivatekey$/^(valid|invalid)$' ./v1/topdown > /out/opa-private-key-tests.txt
for task_version in v0 v1; do
 for task_case in valid invalid; do
  grep -F -- "--- PASS: TestRego/$task_version/cryptox509parsersaprivatekey/$task_case (" /out/opa-private-key-tests.txt >/dev/null
 done
done
! grep -E '^[[:space:]]*--- SKIP:' /out/opa-private-key-tests.txt
# These upstream tests use local test servers to verify real signed client assertions.
rest_tests='TestOauth2JwtBearerGrantType|TestOauth2JwtBearerGrantTypePKCS8EncodedPrivateKey|TestOauth2JwtBearerGrantTypeEllipticCurveAlgorithm|TestOauth2ClientCredentialsJwtAuthentication'
go test -p=1 -mod=readonly -count=1 -v -run "^($rest_tests)$" ./v1/plugins/rest > /out/opa-rest-tests.txt
for task_test in TestOauth2JwtBearerGrantType TestOauth2JwtBearerGrantTypePKCS8EncodedPrivateKey TestOauth2JwtBearerGrantTypeEllipticCurveAlgorithm TestOauth2ClientCredentialsJwtAuthentication; do
 grep -F -- "--- PASS: $task_test (" /out/opa-rest-tests.txt >/dev/null
done
! grep -E '^[[:space:]]*--- SKIP:' /out/opa-rest-tests.txt
go test -p=1 -mod=readonly -count=1 -v -run '^(TestKeyDecryptPBES2|TestKeyDecryptPBES2RFC7517Vector)$' github.com/lestrrat-go/jwx/v4/jwe/jwebb > /out/opa-jwe-tests.txt
for task_test in TestKeyDecryptPBES2 TestKeyDecryptPBES2RFC7517Vector; do
 grep -F -- "--- PASS: $task_test (" /out/opa-jwe-tests.txt >/dev/null
done
! grep -E '^[[:space:]]*--- SKIP:' /out/opa-jwe-tests.txt
cmp go.mod /src/deploy/qualification/opa/go.mod
cmp go.sum /src/deploy/qualification/opa/go.sum
go build -p=1 -mod=readonly -buildmode=exe -tags=opa_wasm -trimpath -buildvcs=false -o /out/opa .
cmp go.mod /src/deploy/qualification/opa/go.mod
cmp go.sum /src/deploy/qualification/opa/go.sum
opa_inventory after
cmp /work/opa-files-before /work/opa-files-after
cmp /work/opa-tree-before /work/opa-tree-after
cp /work/opa-files-before /package/opa/source-files.bin
cp /work/opa-tree-before /package/opa/source-tree.bin
cmp /work/opa-files-before /package/opa/source-files.bin
cmp /work/opa-tree-before /package/opa/source-tree.bin
sha256sum /package/opa/source-files.bin /package/opa/source-tree.bin > /out/opa-source-inventory.txt
go version -m /out/opa > /out/opa-build.txt
printf '%s\n' 'upstream-revision=d4c8d0c8812290c3e3715ca4cf958f75283f6ec4' 'upstream-archive-sha256=4455609bdf200db7531f9c93600047d242dfa1a3cec7f0e048532fe9e36b6133' 'profile=Nex OS downstream OPA overlay' >> /out/opa-build.txt
sha256sum go.mod go.sum >> /out/opa-build.txt
for task_output in opa opa-build.txt opa-source-inventory.txt opa-bundle-tests.txt opa-topdown-tests.txt opa-private-key-tests.txt opa-rest-tests.txt opa-jwe-tests.txt; do
 [ -f "/out/$task_output" ] && [ ! -L "/out/$task_output" ] && [ -s "/out/$task_output" ] || exit 2
done
