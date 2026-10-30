# RDS capacity alarms

`production_database_alarms` is optional and defaults to null. When configured
with `production_database`, it creates alarms for RDS CPU utilization,
free storage and freeable memory. The operator selects an SNS topic in the
approved account and region, whether actions are enabled, all three thresholds,
the period and the evaluation and datapoint counts. Storage and memory
thresholds are in bytes. Select these values from the chosen database class,
storage size, workload, recovery objectives and approved budget. The module does
not provision a topic or subscription, perform a restore, or establish on-call
delivery. Each alarm incurs charges.

CPU uses the period average and breaches at or above its threshold. Free storage
and memory use the period minimum and breach at or below their thresholds.
Missing metrics are treated as breaching. CloudWatch alarm state changes also
reach EventBridge even with alarm actions disabled. Review existing event rules
and destination access, KMS key policy, SNS topic policy, subscriptions and
on-call routing in the target account. Verify delivery and the behavior of each
metric and state transition there. Enabling actions after an alarm has entered
ALARM does not guarantee a retroactive notification.

These capacity signals are not a readiness check or a substitute for database
connection and application probes, transaction and replication monitoring,
tested backups, restore and failover exercises, or independent evidence custody.
An alarm on missing data does not identify its cause. Mock tests verify the
configuration only; no RDS or notification behavior has been verified in AWS.
