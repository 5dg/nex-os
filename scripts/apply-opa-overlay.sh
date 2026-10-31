#!/bin/sh
# Apply the reviewed downstream overlay only to the separately verified OPA source.
set -eu
[ "$#" = 1 ] || { echo 'Usage: apply-opa-overlay.sh /absolute/overlay-directory' >&2; exit 2; }
task_overlay="$1"
case "$task_overlay" in /*) ;; *) exit 2;; esac
for task_file in go.mod go.sum LICENSE; do
 [ -f "$task_file" ] && [ ! -L "$task_file" ] || exit 2
done
for task_file in go.mod go.sum LICENSE opa-v4.patch crit.patch nex_v4_algorithms_test.go; do
 [ -f "$task_overlay/$task_file" ] && [ ! -L "$task_overlay/$task_file" ] || exit 2
done
sha256sum --check --strict <<'SUMS'
38e3c2ba97215a1f28cc67933c52c376d3deabe8a13bda3b7f20d98c36907f2f  go.mod
77629297a1b141d6ea9ec6d99b3af212e5781b9a0feb45bdefaba0c167d91499  go.sum
c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08  LICENSE
SUMS
(
 cd "$task_overlay"
 sha256sum --check --strict <<'SUMS'
ea139726d226264f14b7420ca2233d3619713756a70a7cd079cb4d59839d6970  opa-v4.patch
afecfab3bdfc680a7d8823e691a33d4c35c9c287a1af9aa952e7b839e42da545  crit.patch
1a2a68216edfaae7cb59e5434af3bcbcf20af857658802d31ad7bc7eca11b2e9  go.mod
f2480d3512817e67932bcfe564819f7305d25e297a401793f675fa18babdabed  go.sum
b20829bfc193a6c143860237d957951f7a5949bff9f9202ecdb06b1a53b4ab14  nex_v4_algorithms_test.go
c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08  LICENSE
SUMS
)
[ ! -e v1/bundle/nex_v4_algorithms_test.go ] && [ ! -L v1/bundle/nex_v4_algorithms_test.go ] || exit 2
git apply --check "$task_overlay/opa-v4.patch"
git apply "$task_overlay/opa-v4.patch"
git apply --check "$task_overlay/crit.patch"
git apply "$task_overlay/crit.patch"
cmp go.mod "$task_overlay/go.mod"
cmp go.sum "$task_overlay/go.sum"
cp "$task_overlay/nex_v4_algorithms_test.go" v1/bundle/nex_v4_algorithms_test.go
