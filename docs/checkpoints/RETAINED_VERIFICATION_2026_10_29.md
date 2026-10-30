# Independent retained-candidate verification — 29 October 2026

An independent GitHub-hosted consumer retrieved the complete historical candidate subject and verified its origin with the pinned verifier and default trust policy. The historical candidate's vulnerability gate and hosted CI failed, so its qualification remains blocked and this is not release approval.

The reviewed consumer implementation was published at `0d9720449b355f91b04ecb22a11b0a525b014817`. Its separate [verification run 40997021473](https://github.com/5dg/nex-os/actions/runs/40997021473), job `123872396926`, ran on trusted `main` after the producer completed. The trusted-main/input guard and pinned verifier installation passed. The consumer fetched the full subject, checked its GitHub artifact ZIP digest and subject digest, and completed strict origin verification. It used `gh` attestation verifier `2.103.3`, binary SHA256 `b768184570b12536be4ac1528893f6340d1c6a7b40b56ad45bca9cd0e87ad34d`, with the required repository, workflow, source revision, main ref, GitHub issuer and hosted-runner constraints. Default trust roots remained in force.

The verified producer binding was:

- Producer run: `40798668756`; source revision: `16edb6a68ca2a91770239c7220acb670d2d080d1`.
- Subject artifact: `12865776887`; GitHub ZIP SHA256: `09933136ffc90753261abb568de9f32fe9183d6a363945595359908c33d5e638`.
- Candidate bundle subject SHA256: `3884c61f6feb44a88d4461108246108580e80dc878ece82cbe86d434100f33d3`.

The consumer recorded `durable_retention: passed` and `origin_verification: passed` for this retrieval and signature check. Its bounded public receipt artifact `12951363587` has ZIP SHA256 `c3d322b4e31c6cdba4644e734f301130e45ce61c2ba64efccc3d36b790553eb4`, independently matched against GitHub artifact metadata, the upload log and the downloaded ZIP. Its `summary.json` SHA256 is `92cec1ff371f75a6d2a64f2a8e44ac69145632dbd96e3f93cfcbe1057e1f0b9a`; the hash of the verified statements is `a246fdad17061fc673816589973edc14e23ca374b544177cb93e7131bf045146`.

The receipt also records `hosted_ci: failed`, `vulnerability-scans: failed`, `synthetic_qualification_gate: blocked` and `release_approval: false`. The verification step returns failure for that blocked producer after recording its independent origin and retrieval results; the final enforcement step makes the consumer job fail accordingly. GitHub reports the continued verification step's conclusion as success because `continue-on-error` is enabled, so use the receipt's `verification_step: failure` and final job conclusion when interpreting the result.

The full subject and raw verified statements were processed in the independent hosted job. The locally retrieved receipt contains the verified-statement hash, not the raw statements or full subject. The consumer verifies the complete subject bytes and signature and reads the signed first release manifest; it does **not** independently rederive every inner artifact or image member from that bundle. Thirty-day GitHub artifact retention is not proof of indefinite retention. This historical synthetic-candidate verification does not establish production readiness or qualify later source changes.

The [28 October decision](ALPHA04_RELEASE_DECISION_2026_10_28.md) describes the earlier evidence and limitations at that time. This checkpoint records the later successful independent hosted retrieval and origin verification without changing that historical report.
