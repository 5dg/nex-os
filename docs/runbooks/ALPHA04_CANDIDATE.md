# Alpha 0.4 canonical candidate execution

This is the active Alpha 0.4 delivery path. Alpha 0.5 remains a future proposal.
Only E runs these commands or starts shared Docker/DB/PKI processes. Root reviews
the coherent source and resource/network admission first. Preserve earlier
projects, database volumes, keys, receipts, backups and failed candidate attempts.

## Capture and execute

After independent tests, F's applicable cleanup and publication, capture a clean
reviewed `main`. The new destination must not exist. Use `/tmp` on a filesystem
with the reviewed capacity; the default compiler admission requires 8 GiB free
on the Docker filesystem, 6 GiB free on the output filesystem and a 2 GiB reserve.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/candidate.py capture --output /tmp/nex-alpha04-candidate-NEW
# Prepare the reviewed external policy described below before this invocation.
export NEX_CANONICAL_SECOND_ADMISSION_POLICY=/tmp/nex-alpha04-admission-NEW.json
bash /tmp/nex-alpha04-candidate-NEW/source/scripts/candidate-pipeline.sh /tmp/nex-alpha04-candidate-NEW/candidate.json 10.231.0.0/20
```

Before the first build, create that new regular policy file outside the captured
source with mode `0600`. Bind `source_input_sha256` to
`candidate.json` → `source.inputs.sha256`, and `docker_driver` to the actual local
Docker driver's reported value. The reviewed policy has exactly these fields;
replace the two identity placeholders and the source revision in the approval
record with the observed candidate values:

```json
{
  "schema_version": 1,
  "kind": "measured-second-build-v1",
  "source_input_sha256": "CAPTURED_SOURCE_INPUT_SHA256",
  "docker_driver": "OBSERVED_LOCAL_DOCKER_DRIVER",
  "minimum_estimated_peak_additional_bytes": 8589934592,
  "safety_margin_bytes": 2147483648,
  "reserve_bytes": 2147483648,
  "approval": {
    "authority": "root",
    "decision": "approved",
    "record": "docs/architecture/ALPHA04_RELEASE_CONTRACT.md#measured-second-build-admission; root review 2026-10-28; trusted main FULL_SOURCE_REVISION"
  }
}
```

The root-reviewed [resource contract](../architecture/ALPHA04_RELEASE_CONTRACT.md#measured-second-build-admission)
fixes these budgets. The first build retains the policy hash and measurements;
the second requires the larger of 8 GiB or the first measured peak addition plus
2 GiB, then adds the unchanged 2 GiB reserve. Missing, mismatched or changed
policies block admission. The trusted-main workflow creates this file after
capture, checks the captured revision against `GITHUB_SHA`, observes the local
Docker driver and exports its path through `GITHUB_ENV`. It never invents a lower
budget after a failed build or overwrites an existing policy file.

The `/20` is an explicit proposal, not a standing allocation. The runner must
recheck Docker subnets and host routes immediately before creating its distinct
primary/restore `/28` links. A collision blocks execution; choose another reviewed
pool rather than removing old networks. Existing fixed loopback ingress ports
require E to stop the prior ingress/writer set while preserving its state.

Two fresh pinned-container builds export compiler metadata, binaries and all
coordinator helpers. The driver records the exact pinned Dockerfile frontend
invocation. It compares native bytes, merged runtime metadata/content/inodes and
OCI/configuration/layer/archive bytes separately. Unsupported extraction semantics
fail closed. No public build hash is used as a framework encryption key.

Fresh synthetic PKI is generated after builds. Native binary parity/shutdown
checks and native Chromium DOM, revocation and polling checks precede PKI rotation
and quiescent restore. The browser fixture is supplemental tooling, separate from
the six runtime images, with its own actual engine/package identities. Runtime
ABI and packaged-image checks remain required alongside native binary tests.

The pipeline source is under implementation and must pass independent review
before E executes it. Missing native fixture wiring, unavailable feeds, failed
tests, unsupported reproduction or absent remote evidence remain explicit blockers.
An unfinished or failed build can still produce a blocked bundle with no invented
tested-image identity. Failed attempts are retained; do not resume into the same
candidate output paths.

## Hosted origin and durable retrieval

The trusted-main `Alpha integrity checks` workflow has two explicit entry points:
manual dispatch on `main` with `canonical_candidate: true`, or a normal push to
`5dg/nex-os` `main` whose head commit message contains `[qualify-candidate]`.
The dedicated publisher selects that marker only for the final reviewed,
candidate-ready checkpoint (for example, `[qualify-candidate] Qualify synthetic
release candidate`). Keep routine checkpoint commits unmarked. The marker is
examined as event data, never executed as shell text. PR events, different fork
repositories, other branches/tags, unmarked pushes and dispatches with the input
disabled are excluded by the job selection condition. GitHub string comparisons
are case-insensitive, so a case-variant ref such as `refs/heads/Main` can select a
job. Both jobs therefore begin with an inline, case-sensitive Bash guard requiring
exactly `5dg/nex-os` and `refs/heads/main`, before checkout or artifact download.
A rejected guard also disables the producer's always-on artifact steps. A marked commit message does not
authorize a PR run, and an earlier marked commit in a push does not opt in an
unmarked head commit.

This opt-in push path provides the same captured-source pipeline when an Actions
dispatch client is unavailable. It does not change network policy, token
permissions, source checks or release gates. Its producer retains the non-secret bundle
for 30 days even when the release gate is blocked, provided storage admission
permits bundle creation. The separate `alpha04-candidate-execution-metadata`
artifact retains only `candidate.json`, `release-manifest.json`, `pipeline.log`,
`reproducibility.json`, top-level and `evidence/` admission JSON records,
`builds/*/manifest.json`, the named `evidence/dom-browser-*.log` and
`evidence/qualification-*.log` gate outputs, and
`evidence/browser-*/{dom,operator,revocation}/browser-results.json` (three explicit
paths in the workflow). These browser results contain assertion statuses, engine
identity, counts, timings and fixed failure codes. They exclude browser profiles,
Chromium logs, cookies, tokens, receipts and private fixture state. Preserve their
exact bytes and check available hashes against the candidate and release manifest;
they provide diagnostics when the full subject exceeds a download client's limit.
Four exact additional paths retain `builds/one/workspace-payload.json`,
`builds/two/workspace-payload.json`, `builds/one/postgres-payload.json` and
`builds/two/postgres-payload.json`. These sealed public maps contain runtime path,
type, ownership, mode, content-hash and link metadata; they contain no image or
application data bytes. Compare their exact hashes against the sealed manifest
before using them to locate cross-host differences. No other payload-map glob,
image archive, private directory or source worktree is included.
Before upload, the same explicit allowlist must pass a size check: at most
1,024 regular files, no symlink files or ancestors, relative names at most 512
UTF-8 bytes, and at most 24 MiB total file bytes. A conservative ZIP header
allowance must also keep the total below 30 MiB. Upload stores the files without
compression, leaving margin below the materializer's declared 32 MiB limit.
If that check fails, this diagnostic upload is blocked; it does not trim evidence
or claim successful retrieval. The full signed subject and its gates are unchanged.
The workspace explicitly sets Next `experimental.cpus` to `2`, matching the
admitted compiler CPU quota. Next 16.4.3 otherwise derives this serialized build
input from the host CPU count. The configuration regression loads the actual
pinned framework under two simulated host CPU counts and compares the complete
serialized configuration, with security headers and build-identity checks intact.
This corrects a demonstrated input difference; fresh build comparison is still
required and the earlier `4f27015` cross-host images are not declared equivalent.
Five additional explicit paths retain `evidence/browser-*/fixture-inputs.json`,
`evidence/browser-*/fixture-trust-input.json`, and each of the `dom`, `operator`
and `revocation` directories' `browser-engine.json`. These contain the immutable
fixture identity and input hashes, public CA hash and source/projected file modes,
and public engine inventories. Check that all three engine CA hashes match the
projected public root record. The certificate bytes, private keys and browser
profiles are excluded from this small metadata artifact.
The artifact also retains exactly `startup-result.json`, `browser-engine.json`
and `browser-image-id` under `evidence/browser-dependency-preflight/`.
It runs after successful trusted-main admission even if a later step fails, and
also retains admission records when a valid subject exists. It excludes private
state, keys, backups, binaries and source worktrees. These diagnostic records are
outside the signed subject; they establish neither attestation nor release
approval. If bundle creation is refused, they preserve the reason without
inventing a subject or weakening storage admission.

Before either cold compilation, the trusted-main job builds the pinned browser
fixture from the captured source and runs `scripts/browser-dependency-preflight.sh`
with a 45-second startup limit, no network, a public
CA and private temporary storage. A failure stops compilation and retains the
small sanitized startup result. A successful check passes the immutable fixture
image ID to the later pipeline, which checks its captured helper inputs during
browser qualification. This dependency check does not exercise Nex OS, replace
the DOM gate, or establish release readiness; no automatic sandbox fallback is attempted.

The script defaults to the native sandbox. Hosted diagnostic run
[`40786456380`](https://github.com/5dg/nex-os/actions/runs/40786456380), at source
`89ac2a65f995459964ee200fac15d73ce6a81b9a`, retained a native
`BROWSER_SANDBOX_UNAVAILABLE` failure after 637 ms with verified fixture inputs.
Based on that measured failure, root approved the explicit hosted synthetic
fixture exception `--sandbox-mode disabled-fixture-only --sandbox-approval
https://github.com/5dg/nex-os/actions/runs/40786456380`. The workflow validates
successful status, exact approval reference, mode and image identity before
exporting that same fixture ID and `NEX_BROWSER_FIXTURE_NO_SANDBOX=1` to the
later browser gate. The isolated fixture retains its read-only filesystem,
private temporary storage and restricted networks. Native TLS validation and
all DOM assertions remain required; this exception does not apply to application
images or production operation.

A separate scoped job downloads
the retained subject, compares its SHA256 to the producer output, and uses the
commit-pinned official provenance action. An attestation proves origin, not
qualification, compliance or release approval.

After successful attestation, the origin job retains the official action's signed
bundle as the separate `alpha04-candidate-origin` artifact for 30 days. The
`alpha04-candidate-subject` archive remains unchanged. A failed attestation or a
missing bundle cannot publish the origin artifact.

When connected GitHub artifact tools are available, list artifacts for the exact
completed run and download both named artifacts. Retain each ZIP and compare its
SHA256 with GitHub's artifact metadata before bounded inspection. Check their run,
repository, main branch and source revision bindings. The subject ZIP contains
`candidate-bundle.tar.gz`; its SHA256 must match the producer output. The separate
origin ZIP contains the official action's signed bundle. Do not treat the ZIP
checksum, artifact name or an unsigned manifest as signature verification.

With those verified local files, the existing verifier accepts the signed bundle
without fetching the attestation through the GitHub API:

```bash
python3 -B scripts/verify-provenance.py --subject /absolute/candidate-bundle.tar.gz --subject-sha256 BUNDLE_SHA256 --source-revision FULL_COMMIT --attestation-bundle /absolute/signed-origin-bundle.json --output /tmp/nex-alpha04-origin-NEW.json
```

Install the checksum-pinned verifier first using `scripts/install-gh-attestation.sh`.
The verifier also needs a writable cache for its authenticated TUF metadata. If
the environment's default cache is read-only, set `XDG_CACHE_HOME` to an isolated
writable directory outside the captured source. This does not replace the
official trust roots or remove their network requirement. A denied TUF fetch or
failed signature verification remains blocked even when all downloaded byte
hashes match; retain the failed receipt and raw error.
The same repository, workflow, source, issuer and hosted-runner constraints apply;
required trusted-root material must also be available. A missing dependency or
failed cryptographic check remains blocked. This separate origin receipt does not
replace completed-run validation, required local gates or the full retained
candidate consumer below, which still requires its own supported API access.

After that hosted run has actually completed, independently retrieve the exact
artifact and verify its origin. Use its actual run/artifact identifiers, expected
source revision and bundle SHA256 from the producer's output. Configure the
GitHub `actions:read` identity securely as `GH_TOKEN` or `GITHUB_TOKEN`; never put
it in a command argument or committed configuration.

```bash
./scripts/install-gh-attestation.sh
python3 -B scripts/verify-retained-candidate.py --run-id RUN_ID --artifact-id ARTIFACT_ID --source-revision FULL_COMMIT --subject-sha256 BUNDLE_SHA256 --output /tmp/nex-alpha04-remote-receipt-NEW
```

The consumer requires completed trusted-main workflow/source metadata, the exact
unexpired artifact producer, the GitHub-retained archive SHA256 and expected bundle
SHA256. It invokes the checksum-pinned `gh` verifier with repository, workflow,
source commit, main ref and GitHub issuer constraints, denying self-hosted runners.
Redirects never forward the GitHub bearer credential to artifact storage.
The streaming download and subject extraction each preserve a 2 GiB filesystem
reserve. Subject interpretation starts only after successful strict origin
verification, and the decompressed first-manifest stream has a 5 MiB cap.
The consumer then checks every signed manifest-listed regular member in sorted
order, hashing its bytes without filesystem extraction. Duplicate manifest
fields, noncanonical paths, missing/extra members, links, sparse members, digest
mismatches, oversized metadata and nonzero trailing data fail closed. The
consumer admits at most 4,096 members, 16 GiB per member and 32 GiB of total
decompressed bundle stream. This verifies manifest-to-member bytes; independent
image configuration, layer and merged-filesystem rederivation remains a separate
claim.

For an independent GitHub-hosted consumer, dispatch the **Verify retained
candidate** workflow on `main` after the producer run has completed. Supply the
exact producer run ID, subject artifact ID, producer source commit and subject
SHA256. The workflow retrieves the full artifact directly from GitHub and uses
the same pinned verifier, default trust roots and source/workflow/issuer rules.
It retains a bounded `alpha04-retained-verification-<run-id>` summary containing
validated identities, gate statuses, inner-member count/bytes and map digest,
manifest digest and the verified-statements hash; raw API
metadata, errors and verified statements are not uploaded. Retrieve and review
that summary and the workflow result. A failed producer or failed release gate
still fails the verification workflow even when origin and retention pass.
Workflow code and receipts alone do not establish that this path has run.

An explicitly reviewed normal push to `main` may also start this independent
workflow. Include `[verify-retained]` exactly once in the commit message and
include each of these exact single-line fields once, replacing the placeholders
with the completed producer's numeric IDs and lowercase full hashes:

```text
[verify-retained]

producer_run_id=RUN_ID
artifact_id=ARTIFACT_ID
source_revision=FULL_COMMIT
subject_sha256=BUNDLE_SHA256
```

The workflow parses those fields as data, validates them before use and still
independently verifies the completed producer's metadata and origin. Unmarked
pushes do not invoke the retained consumer.

The completed-run receipt is outside the attested subject, avoiding a circular
claim that an unfinished bundle contains its own future CI success. It separately
records hosted outcome, durable retrieval and verified origin. A failed hosted
run may have valid retained origin evidence while remaining failed. No local
zero exit, unsigned manifest, source push or mock verifier can stand in for these
remote facts. Current source does not establish that hosted CI, attestation or
independent retrieval has executed successfully.

## Scanner compatibility

The Go source scanner is the official `golang.org/x/vuln` release `v1.9.0`,
whose `x/tools v0.52.0` supports the pinned Go 1.27.3 compiler. The installer
checks its module and `go.mod` checksums against the official public SumDB values.
It does not modify application dependencies. Version `v1.1.4` crashed during
hosted SSA analysis and must not be used as evidence of a completed source scan.

To reproduce the scanner regression with the installed binary:

```bash
python3 -B scripts/check-govulncheck.py --binary "$NEX_TOOLS_DIR/bin/govulncheck" --output /tmp/nex-scanner-compatibility-NEW
```

This uses a synthetic local advisory database and Go 1.27 promoted-field literals.
The real scanner runs through the release-audit coordinator; unrelated scanners
and inventory are isolated test stubs. A reachable imported vulnerable symbol
must produce a multi-frame call trace and block that test audit. Uncalled and
fixed-version controls must remain distinct. These results verify scanner and
parser compatibility only; they do not establish project vulnerability clearance.

Govulncheck JSON mode exits zero even when it reports reachable vulnerabilities.
The release gate therefore requires a valid completed full source/symbol stream
and blocks reported reachable symbols. Module and package findings remain in raw
output and recorded counts. Scanner errors, unsupported modes, malformed or
incomplete output all block the gate. Live advisory scans and all exact runtime
image scans remain required without suppressions or weaker scan-level fallbacks.

All candidate content is synthetic. Live GovCloud/Bedrock, customer identity,
approved production cryptography, CUI and formal assessments remain deferred.
