#!/bin/sh
# Apply only the reviewed dependency overlay to the checksum-pinned upstream tree.
# No upstream Go source changes or claim that this is an upstream gosu release.
set -eu
[ "$#" = 1 ] || { echo 'Usage: apply-gosu-overlay.sh /absolute/overlay-directory' >&2; exit 2; }
task_overlay="$1"
case "$task_overlay" in /*) ;; *) exit 2;; esac
for task_file in go.mod go.sum; do
 [ -f "$task_file" ] && [ ! -L "$task_file" ] || exit 2
done
for task_file in go.mod go.sum upstream-inputs.json; do
 [ -f "$task_overlay/$task_file" ] && [ ! -L "$task_overlay/$task_file" ] || exit 2
done
sha256sum --check --strict <<'SUMS'
0475f1708db81d718b633faf2d9dd64695037eabdc8562125060607bcb01b2ba  go.mod
2a8f3fb6adb84839bbb9999f12f1416fb86c184135aaa1c2e489b35203c08346  go.sum
SUMS
(
 cd "$task_overlay"
 sha256sum --check --strict <<'SUMS'
9fbb62db2a67741040e7c132836c501d74625ae751ac6659abbc9505abf11f6d  go.mod
5f3a4dcbabbf663822ed2f1cdad2f3fae988f27878c440c3e04dbc996e8608e6  go.sum
31a306f7e83deda67213fae3795f29afe07d2875e4c197cb99bfbfd385b9303f  upstream-inputs.json
SUMS
)
cp "$task_overlay/go.mod" go.mod
cp "$task_overlay/go.sum" go.sum
