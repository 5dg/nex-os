# Alpha 0.4 candidate build and evidence contract

Status: interface 1, lead-approved direction; I and the lead must approve measured resource
admission and concrete non-overlapping IPAM before execution. This contract does not claim that its builds,
comparisons or qualification checks have run. Preserve the Alpha 0.3 evidence.

## Candidate boundary

I captures a reviewed, coherent commit published by H after the applicable J cleanup. Capture
records the full revision, commit timestamp, an archive digest and a sorted
relative-path-to-SHA256 input map. The input map includes authored application,
test, policy, migration, contract, lock, deployment, tool and CI inputs; it excludes
Git internals and generated dependencies, binaries, state, PKI and evidence.
Symlinks that escape the captured tree and unlisted build inputs are rejected.

The extracted tree has an explicit `.nex-source.json` metadata companion with the revision, source epoch and
input-map digest. All build and inventory tools accept that explicit metadata and
verify actual bytes; they do not require `.git`. Revision text alone is not a
source-integrity check. The companion itself is excluded from its own input map;
the outside capture record hashes the complete archive including the companion.
Missing or mismatched metadata prevents a canonical build.
The physical compilation tree must contain exactly the admitted files and their
ancestor directories, plus the noncompiled metadata companion. Capture rejects
excluded tracked archive files; verification also rejects later ignored-looking
injections. Generated-location exclusions are exact paths, not nested names such
as Cargo's authored `src/bin`.
A diagnostic tree may report an unknown revision, but cannot become a canonical
candidate. Capture metadata ownership stays with I; source editors resume immediately
after capture. Every later authored change requires a new candidate.

## Canonical and diagnostic build paths

Canonical builds use the existing digest-pinned Linux amd64 Go, Rust and Node
compiler images and digest-pinned runtime bases. A pinned compiler container may
mount the immutable source read-only and write into fresh, run-specific `/tmp`
target/cache/output directories. This is an actual container compilation, not a
claim that an older multistage Dockerfile ran. This approach avoids copying Cargo
targets into VFS image layers. A fresh staging copy is permitted for Node's
writable dependency/build directory; its authored input bytes must match the
immutable source before compilation. No pre-existing host `bin`, `.next`,
`node_modules`, target directory or compiler cache is an input.

Go uses the pinned compiler, `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, `-mod=readonly`
and `-trimpath`. Rust uses the pinned installed toolchain, `--locked --release`,
nonincremental compilation and a constant in-container source/output path. Record
the actual compiler/version/digest, target, flags, libc and linked-library
requirements. The Rust compiler ABI must be compatible with the selected runtime;
verify the resulting executable in that runtime. Node uses the pinned compiler
image and frozen lock, with normal TLS/package verification. Canonical frontend
builds provide the verified input-map digest as build-only
`NEX_SOURCE_INPUT_SHA256`, which A's deterministic Next build-ID hook consumes.
Normal developer builds may omit it. A owns the small
workspace configuration hook. No build identifier grants runtime authority.
Framework-generated private randomness must be measured and reported; never use a
public source hash as an encryption/signing key to force byte equality.

The current pinned Next 16.4.3 application declares no Server Actions, preview,
draft mode or on-demand revalidation. Canonical packaging runs
`scripts/prepare-workspace-runtime.mjs` against the actual standalone payload and
the admitted authored app source. It requires empty node/edge action maps,
exactly empty per-route action maps, known mirrored manifest formats and no
unexpected occurrences of generated credentials. It rejects new authored uses of
the excluded framework features and unsupported layouts/versions before mutation.
It removes unused action encryption material and replaces preview credentials
with the explicit disabled marker `{"previewModeId":false}`. Omitting the marker,
using null, or using a public string is unsafe: pinned framework paths compare
Node undefined, Web null and wire strings against this value. Boolean false
matches none and cannot enable draft mode. The same image payload bytes, including
the transformed manifests, remain subject to full reproducibility comparison;
no file or field is excluded. The preparation report retains before/after hashes
and authored-input identities, never credential values. Introducing those
features requires a new reviewed key/runtime contract rather than silently
retaining or deriving a shared secret.

Build outputs are freshly exported, hashed and mapped to source paths. Runtime
packaging receives only those verified outputs and the declared runtime files.
The coordinator PKI and evidence CLIs are part of this closure: canonical `init`
executes the exported, manifest-bound static tools. It must not fall back to a
stale host `bin/evidence` or require a host Go/Rust compiler to create those tools.
Generate short-lived fixture PKI after compilation, not before a long build.

The host development path remains explicitly diagnostic, with its host compiler,
ABI and output identities recorded. A diagnostic output cannot satisfy a canonical
gate or silently replace a missing canonical artifact. Existing active development
behavior and historical artifacts remain supported.

Thin runtime images use the official BuildKit v0.34.1 Linux amd64 exporter,
`moby/buildkit:v0.34.1@sha256:b651bf250c2805569f1db385ad1ea8fb73737dfc851de305f274ca02690fa93f`,
with the existing pinned Dockerfile frontend. Each image has a fresh, exclusively
owned builder container and cache volume. The trusted build daemon requires its
standard privileged container; its only mount is that cache, its network and
PID/IPC namespaces are private, and CPU/memory are bounded. All insecure
entitlements and CDI are disabled. It has no application state, Docker socket,
home or custody mounts. Public proxy trust is copied and hash-verified before
startup, while normal proxy and TLS validation remain enabled.

Buildx connects over the inspected local Docker container's stdio endpoint with
an explicit default context; redirected endpoint/context/TLS selectors are
cleared while registry configuration is preserved. Record the actual Buildx
version/plugin hash, exact BuildKit image, daemon arguments, public configuration
hash and ownership checks. The second build requires the same client identity.
An automatic driver that adds host-network entitlements is outside this path.

The exporter writes a fresh untagged Docker archive with explicit timestamp
rewriting, gzip compression and Docker media types. Verify its configuration and
layer identities, load it, and verify the resulting immutable image before
preparing the retained archive. Diagnostic tags are applied separately. The
unchanged pinned OPA image uses an exact-ID Docker save. Exporter provenance
options do not replace the required hosted candidate-origin attestation.

The PostgreSQL gosu executable retains upstream 1.19 source revision
`6456aaa0f3c854d199d0f037f068eb97515b7513` and its verified archive. The reviewed
`deploy/qualification/gosu/` dependency overlay updates only frozen Go module
inputs. The build verifies original upstream module hashes, overlay hashes and
checksum-database results before compiling read-only module inputs. Both build
paths identify this as a Nex.os downstream dependency overlay, retain upstream
revision/archive identity and package overlay metadata with the executable.
Source inventories include its separate dependency graph and all overlay input
hashes. No unchanged-upstream-release or clean-scan claim follows from the
overlay; actual uid/gid/group/exec behavior, PostgreSQL operation and image scans
remain required.

## Resource admission and execution ownership

I alone starts Docker/Compose processes, builds images, allocates ports and changes
shared database/PKI state. H alone publishes Git. D, E, F and G supply reviewed
build/security/verification commands; they do not run competing stacks or builds.

Default admission budgets are one image build at a time, at most two Cargo jobs,
at least 8 GiB free on the Docker-data filesystem and 6 GiB on the temporary-output
filesystem before a cold canonical build, and 2 GiB reserved headroom during
execution. I records the actual driver, capacity/free bytes, available memory,
estimated peak for the selected strategy and observed peak. A documented measured
strategy can replace the conservative cold-build estimates only after lead
review; it cannot waive the reserve or reuse stale outputs. The pinned-container
bind-output strategy is preferred for this VFS environment. Stop further build
admission if the reserve cannot be maintained. Do not reset volumes, delete
receipts/keys, manually edit Docker storage, or claim success after ENOSPC.

Only checksum-verified download caches may be shared between reproducibility
builds. Compilation targets, Go build caches and Node output trees are distinct
and initially empty. No automatic image/data pruning is part of qualification;
I inventories and the lead explicitly reviews any removal of reproducible unused cache.
The resource-plan interface may whitelist exact pinned Go/Rust compiler image
IDs for phase-boundary removal, bound to the captured source and Docker driver.
Go and gosu compile consecutively; exported public trust avoids repulling Go for
scratch runtime packaging. Each boundary verifies fresh exported bytes/metadata
before deleting only that build's compile scratch. A whitelisted image is removed
normally only after checking no container references it; no force or broad prune
is allowed. Rust's Cargo home, unpacked sources and target are fresh per build.
The Node base shared with browser/runtime remains retained. I/root must approve
separate first/second-build peak forecasts; a source flag cannot approve itself.
Proxy/CA material remains ephemeral and credentials are never recorded in the
manifest. Retain normal TLS, checksum, module and package-signature validation.

Go's downloaded modules may contain read-only directories. Scratch removal may
restore owner directory access only inside the verified original, same-owner
build scratch inode, without following links or changing file modes/hardlinked
targets. Preserve exported bytes and failed attempts. Retention excludes only the
exact build work/package roots before walking; links or unreadable/nonregular
entries in retained trees remain errors rather than silently omitted evidence.

### Measured second-build admission

The lead approved the following fixed policy on 2026-10-28, before either final
build. It permits unattended execution without an unreviewed resource waiver.
An absolute, regular, outside-capture policy record binds the source-input hash,
Docker driver, versioned formula and explicit lead review reference. Build one
records its exact policy bytes/hash before executing. Build two verifies that
binding against the completed candidate-bound first manifest and requires complete
initial, sampled minimum and final free-space measurements for both filesystems.

For each filesystem, observed first-build peak addition is initial free space
minus its minimum observed free space. The approved second-build estimated peak
addition is `max(8 GiB, observed first peak addition + 2 GiB safety margin)`.
Minimum free space is that estimate plus the unchanged **2 GiB reserve**. Samples
include command start/end and one-second observations. Missing, inconsistent or
substituted measurements/policy fail admission. Record the first-manifest and
policy hashes and exact derivation. Existing explicit resource plans may raise
these floors or carry separately reviewed exact compiler evictions; they cannot
lower them. Fresh second output/cache trees and all source-integrity checks remain
mandatory.

The local coordinator supplies the reviewed source-bound external policy. The
trusted-main CI job may emit the same reviewed fixed policy after source capture.
Neither the policy nor its local review label is a cryptographic attestation or a
new runtime authority. Changed formula constants, incomplete measurements or an
insufficient actual reserve require a new reviewed decision rather than automatic
approval by a source flag. This contract does not claim either build has run.
Build two may inherit only the first plan's exact reviewed per-image packaging
forecasts and compiler-eviction whitelist. Verify and record the completed first
manifest hash, original plan hash, source and driver binding. This inheritance
does not copy whole-build admission floors: the measured second-build formula
remains mandatory, and an explicit second plan may only raise those floors.
Compiler container names, CIDs and ownership labels include run/build/role and a
fresh nonce. Timeout/interruption stops only the exactly inspected owned compiler
and verifies it stopped before further admission or scratch disposal. Unknown
BuildKit cancellation state remains a reconciliation blocker after packaging
failure; killing the Docker client alone is not proof that daemon work ended.

Packaging also has a declared per-image peak addition and an admission floor
equal to that peak plus the unchanged 2 GiB reserve. Samples cover the builder,
cache, export, loaded image and retained archive. Stop on a forecast or reserve
violation. Before advancing, successful packaging normally removes only the
exact inspected owned builder, unused cache volume and remote client profile;
retained image/archive/proof/log bytes remain. Failure stops the owned daemon
independently of resource admission and preserves its cache for reconciliation.
Whole-build first/second admission still includes retained outputs, both archive
sets and bundle growth; a per-image floor does not replace those bounds.

### Post-build resource admission

The lead approved these additional phase bounds on 2026-10-28 before final
capture. Before supplemental browser packaging or qualification startup, require
6 GiB forecast addition plus the unchanged 2 GiB reserve on the actual candidate
output and Docker-data filesystems. Group paths sharing a device rather than
double-counting their capacity. The separate host temporary filesystem must also
retain 2 GiB free. The 6 GiB forecast conservatively covers the measured 5.3 GiB
diagnostic runtime pair; it is not permission to delete earlier state.

Every bundle attempt, including failed-pipeline retention, calculates its output
bound from the exact sealed file allowlist and release manifest, including actual
tar/PAX headers, payload/record padding and conservative gzip expansion overhead.
Require that bound plus 2 GiB reserve on the output filesystem and 2 GiB remaining
on the host temporary filesystem. Record source/run/build bindings, observed
paths/devices/free bytes, forecast and decision outside captured source. A denied
attempt preserves logs, seal and admission evidence and creates no archive.
The bundle-admission sidecar remains outside its own sealed subject to avoid a
circular self-hash. Actual resource shortage blocks the phase; it does not allow
automatic cleanup, a smaller forecast, or an ENOSPC success claim.

## Isolated run identity and lifecycle

A new run ID is twelve lowercase hexadecimal characters generated by I. Primary
project names are `nex-alpha04-<run-id>` and restore names append `-restore`. Every candidate
has separate private source/output/evidence/state directories and separate primary
and restore project/volume names derived from that run ID. Scripts validate the
fixed qualification namespace and inspected ownership labels. They do not accept
arbitrary forwarding destinations or overwrite existing run state. Existing
`nex-local`, `nex-qualification` and `nex-qualification-restore` data remains intact.

The same fixed loopback test ports can be reused only after I stops the previous
qualification ingress/writer set and its owned relays. New relays preserve native
TLS and map only the inspected service/project endpoints. There is one active
writer set for a copied custody domain. Restore creates a new empty volume and
state directory, preserving the original stopped set. Existing-run refusal is not
resolved by deleting prior state. Compose stop grace periods will use the
B/C-approved admission/drain/cleanup deadlines; D will not retain a conflicting
hard-coded five-second stop budget. The approved shared HTTP drain is 70 seconds
and Compose stop grace is 75 seconds; shutdown tests remain G's responsibility.

If default Docker address pools cannot hold both new networks, I selects and
records an inspected non-overlapping private IPAM block. Generated primary and
restore overrides allocate distinct subnets within it; existing backend networks
are not shared. No CIDR is selected silently and no live network is removed to
make room.

## Manifest and reproducibility claims

The versioned candidate manifest records:

- Candidate/run ID; revision, source epoch, archive and input-map digests.
- Canonical/diagnostic mode; pinned compiler/runtime image identities, actual
  compiler and target/ABI data, allowed build flags and exact commands.
- Exported binary/tool hashes; image configuration IDs, available registry
  digests, rootfs layer identities and normalized filesystem payload digests.
- Every qualification command and its start/end/status/exit code, tested image
  identities, result-file hashes and lifecycle checkpoint references.
- Source and complete OS-inclusive SBOM hashes; scanner/tool/database identities,
  raw report hashes, failed/blocked checks and the explicit release decision.

The build record is unsigned engineering evidence unless a separately verified
attestation mechanism signs it. Local tags are convenient selectors, not immutable
promotion identities. Retained output excludes runtime secrets, PKI private keys,
session handles, receipt contents and private database dumps; public checkpoint
hashes and verification results may reference private local backup evidence.

Run two independent builds of the same captured source. Targets are declared
before comparison: exported native binaries and frontend/runtime filesystem
payloads must be byte-identical, including permissions and symlink targets.
The filesystem record includes opaque PAX security metadata (xattrs, capabilities,
ACLs and flags), excluding only explicitly declared timestamp fields and standard
PAX fields already bound by typed path/content/ownership data. Hardlinks bind an
existing regular inode at their header position. Later pathname replacement leaves
older aliases on their original inode; the final identity includes stable surviving
alias groups. Forward, nonregular, metadata-mutating and ambiguous traversal cases
remain unsupported and fail closed. Synthetic tests and actual vendor-layer
qualification must both pass before making a complete runtime payload claim.
Compare OCI configuration/layer/manifest bytes separately. BuildKit creation times,
history timestamps and compression may differ; record those exact differences as
OCI-metadata nonreproducibility, never as a matching OCI digest. Do not normalize
changed executable, library, package metadata, frontend payload or source bytes
away. A binary/rootfs mismatch fails the reproducibility gate even when functional
tests pass. Unexpected OCI differences remain failed or unresolved; a report must
state which target passed, rather than calling the whole image reproducible.

The archive producer may set only outer regular/directory tar-header mtimes to
the source epoch and recompute their dependent header checksums. It preserves
every payload byte, member order, padding and non-time metadata, including all
inner image configuration/layer bytes and opaque PAX security fields. Unsupported
outer types, sparse entries or time overrides fail closed. Retain raw and emitted
archive hashes, exact changed header offsets/times, member hashes and immutable
image binding. Comparison independently verifies the emitted archive against that
proof and rederives its full merged payload. Report raw-export equality separately
from exact emitted-archive equality. No comparison-time byte normalization or
executable/library/security-metadata exclusion is permitted.

Runtime package installation may omit glibc's inode/ctime auxiliary
`/var/cache/ldconfig/aux-cache` after installation while requiring a nonempty
active `/etc/ld.so.cache`. Preserve libraries, active loader data and package
inventory. This producer choice remains subject to full payload comparison,
runtime acceptance and image scans.

## Qualification, retention and release decision

Qualify the captured images from fresh run state using the complete ordered
verifier: browser/API, PostgreSQL trust/roles, current-authority mutations,
receiver proofs, coordinated PKI rotation and quiescent restore. Shared mutations
and lifecycle transitions are serial. F/G independently check manifest/image/test
binding and supplies negative tests for stale tools, changed inputs and mismatched
images. A combined wrapper is passed only after that wrapper actually executes.

The fixed-UID browser fixture receives a validated, bounded single current public
CA through a fresh attempt-private mode0444 projection. The original PKI and all
private-key permissions remain unchanged. Bind-mount only that public copy
read-only, retain its exact hash and require each browser engine's trust hash to
match it. Cross-UID readability is required even when the coordinator creates
private state under umask077. This input projection does not relax TLS validation.

The required `packaged-shutdown` gate is distinct from native `shutdown` checks.
It exercises actual candidate containers under admitted model/export work before
DOM/rotation/restore, verifies direct authenticated admission closure and existing
drain budgets, restarts the same containers/images, and checks real protected
results, receipts and one signed authorization/completion after replay. Candidate
execution, sealing and independent retained-artifact verification all require
this gate. A compiled harness or diagnostic host-image run cannot qualify the
canonical images.

The required `history-pagination` native gate runs the captured-source Go handler
against the isolated private PostgreSQL/OPA fixtures with race detection. It
checks real signed oversized histories, stable visibility, cursor scope/current
revocation and append ordering. This is source/native evidence; actual packaged
history and workspace behavior are independently exercised by the DOM gate.
The suite, seal and retained-artifact consumer all require its recorded result.

Persist non-secret candidate records, raw findings, SBOMs and test outputs together
with checksums and source/image identities; retain failed attempts separately.
Hosted CI/artifact publication is claimed only after a recorded run succeeds and
the retained artifact can be retrieved and verified. Local `/tmp` logs alone do
not satisfy durable release evidence. H publishes reviewed source checkpoints to
`main` throughout; source publication does not waive release eligibility gates.

Canonical hosted execution may be selected by manual dispatch or an explicit
`[qualify-candidate]` marker in the pushed head commit. Both canonical and origin
jobs first require exact repository/ref literals in an inline shell guard before
checkout or artifact download. This supplements GitHub's case-insensitive
expression selection; case-variant refs must fail admission. Routine checkpoint
pushes remain unmarked. Marker selection never changes qualification, scan,
provenance or retention requirements.

Scans retain every configured severity and warning. Missing advisory feeds,
unavailable CI, unsupported reproducibility, unresolved findings and unsigned
records remain distinguishable blockers. No automatic suppression or risk waiver
is introduced. Live AWS, customer IdP, CUI, approved production cryptography and
formal assessment remain deferred.
