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
for 30 days even when the release gate is blocked. A separate scoped job downloads
the retained subject, compares its SHA256 to the producer output, and uses the
commit-pinned official provenance action. An attestation proves origin, not
qualification, compliance or release approval.

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

The completed-run receipt is outside the attested subject, avoiding a circular
claim that an unfinished bundle contains its own future CI success. It separately
records hosted outcome, durable retrieval and verified origin. A failed hosted
run may have valid retained origin evidence while remaining failed. No local
zero exit, unsigned manifest, source push or mock verifier can stand in for these
remote facts. Current source does not establish that hosted CI, attestation or
independent retrieval has executed successfully.

All candidate content is synthetic. Live GovCloud/Bedrock, customer identity,
approved production cryptography, CUI and formal assessments remain deferred.
