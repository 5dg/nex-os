# Managed export task access

`production_export_access` is null by default. An explicit configuration adds
an inline policy only to the existing `tool-executor` task role for one approved
same-account S3 bucket, slash-terminated prefix and customer-managed KMS key.
It grants the bucket versioning check, prefix-scoped object write and versioned
object read, plus the key operations needed for SSE-KMS through regional S3.
It grants no list, delete, unrelated bucket, model invocation or general KMS
permissions. Writes must specify the exact approved KMS key and `aws:kms`.
The current adapter sends `If-None-Match: *`, and this allow statement requires
that header. Other attached policies could independently grant broader write
access. Enforce and independently test the required conditional-write, retention
and deletion protections across the selected bucket policy, all effective role
permissions and the operational boundary before activation.

The `s3_bucket_key_enabled` value must match the bucket's effective setting.
When enabled, S3 uses the bucket ARN as the KMS encryption context; when
disabled, the policy restricts that context to the approved object prefix.
With a bucket key, the S3 object permission is the prefix boundary: the KMS
context is bucket-wide and is not an independent per-prefix control. Confirm
the key policy, bucket owner, versioning, object retention/deletion controls,
bucket and endpoint policies, regional access, effective role policies and
actual encryption context in the selected account before use.
Existing object versions retain their original encryption context and can have
per-object bucket-key overrides. Inventory and test the actual bucket-key mode
and KMS key for every retained version, including after re-encryption or key
rotation. A default-setting change can make historical versions unreadable
under a single-context policy. The current adapter requires every returned KMS
key ARN to equal its single configured ARN. Granting access to an old key alone
does not make old-key versions readable after changing that configured ARN.
Keep the old configured key ARN, or implement and independently review an
adapter/receipt key-binding migration before changing it. KMS backing-key
rotation under the same ARN also requires retained key material and tested
historical reads. Mixed bucket-key modes under one key need a separately
reviewed context policy or a verified migration before the current narrow
single-context policy changes. Stop admission and reconcile where required.
S3 bucket-key caching can skip subsequent KMS policy
re-evaluation, so immediate revocation must not rely on a KMS policy change
alone. Restrict effective S3/bucket/endpoint permissions, stop admission and
independently test the actual revocation and reconciliation behavior.
Other inline policies on the executor role also consume its IAM role policy
quota; review the combined effective policies and size in the target account.

This policy creates no bucket, keys, task or ECS service. It does not activate
the export adapter, provision its application credentials, or establish fenced
receipt durability. In particular, asynchronous database failover or rollback
can lose a previously acknowledged started receipt; do not activate exports
until the reviewed RPO-zero or admission-stop-and-reconciliation contract is
implemented and independently verified. Mocked policy tests are not live IAM,
S3, KMS, storage, failover or production-acceptance evidence.
