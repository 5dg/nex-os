# Downstream OPA candidate

This overlay modifies OPA v1.22.0 from commit
`d4c8d0c8812290c3e3715ca4cf958f75283f6ec4`. The upstream codeload archive
SHA-256 is `4455609bdf200db7531f9c93600047d242dfa1a3cec7f0e048532fe9e36b6133`.
The upstream Apache 2.0 license is retained here. This is a Nex OS downstream
modification, not an official OPA release.

The first patch updates JOSE dependencies and adapts OPA's JOSE callers; the
second adds fail-closed critical-header handling. The standalone algorithm test
covers all supported configured signing algorithms. The lock files are the
expected result of applying the patches, not a replacement for Go module
checksum verification. Apply the overlay only after independently verifying the
complete upstream archive; the overlay script also checks its inputs and locks.

These files alone do not qualify a release. The rebuilt runtime image, its OS
packages, exact image identity, full vulnerability gates and integration tests
must all pass the existing canonical qualification pipeline.
The work-in-progress canonical pipeline invokes `scripts/canonical-opa.sh` and
reconstructs its OPA image using the verified upstream base layer and the compiled
downstream executable. No canonical build, full image scan or qualification has
yet passed for this integration.
