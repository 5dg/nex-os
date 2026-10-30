# Historical export decryption access

`production_export_history_access` is empty by default and requires an explicit
current `production_export_access` destination. Each selected same-account and
same-region KMS key/bucket-key-mode pair grants only `kms:Decrypt` through
regional S3 with that pair's exact bucket or approved object-prefix encryption
context. It grants no KMS data-key generation, S3 write, list or delete access.
The existing current-route policy separately controls conditional writes and
versioned reads. Duplicate pairs and the already-authorized current pair are
rejected; the same key with a different historical bucket-key mode is allowed.

This is only the IAM precursor for explicitly reviewed historical retrieval.
The tested S3 adapter records the original write-key ARN in new receipts,
accepts only a bounded approved current/historical key set, and requires an
explicit trusted legacy-key mapping for old receipts without a key. It remains
unwired to the production server and profile. The mapping must be supported
by trustworthy custody records; IAM access by itself neither configures the
adapter nor proves the retained objects or receipts can be recovered safely.

Inventory each retained version's actual KMS key and bucket-key mode before
selecting these pairs. With bucket keys the KMS context is bucket-wide, so the
S3 object permission remains the independent prefix boundary. KMS bucket-key
caching can delay the effect of a KMS policy change; stop admission and verify
revocation and reconciliation across effective S3/bucket/endpoint policies.
Keep old keys and backing material available as long as authorized evidence
requires them, or perform an independently reviewed migration.

The module checks the combined sizes of the two export inline policies it
manages. Other inline policies on the same task role share IAM's role quota and
must be inventoried in the target account. Key policies, bucket policies,
regional endpoints and all effective role permissions require live review.
Applying this policy changes IAM permissions but does not activate any task or
service. Mocked Terraform results are not production IAM or recovery evidence.
