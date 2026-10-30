# ECS service utilization alarms

`production_service_alarms` defaults to null and creates no alarms. To opt in,
select existing service scaffolds, an existing standard SNS topic ARN in the
approved account and region, CPU and memory percentage thresholds per service,
period, evaluation count, datapoint count and an explicit action-enabled state.
The policy creates no topic, subscription, task, autoscaling rule or service.
Both the ALARM and OK transitions use the chosen SNS topic when actions are
enabled. Test its topic policy, CloudWatch publishing, subscriptions, encryption,
recipient access and on-call delivery in the actual account; the ARN alone does
not establish them. Metrics and alarm names contain service identifiers, so
review the destination and operator access before enabling notifications.
Disabling alarm actions does not suppress CloudWatch state-change events sent to
EventBridge; existing event rules may trigger separate actions. Review and test
those rules independently in the target account.

Alarms use the AWS/ECS service average CPU and memory utilization and breach
when the average is greater than or equal to the selected threshold. They also
consider missing data breaching. A scaffold has configured desired count zero; it emits
no utilization metric until tasks run, so its alarms will transition to ALARM
and may notify if actions are enabled. Keep actions disabled until the target
service and on-call routing are ready, then deliberately test both transitions
and missed data. Enabling actions while an alarm is already in ALARM does not
guarantee a retroactive notification; verify actual delivery with a deliberate
state transition or separately approved notification test. Creating the alarms incurs charges; select periods and counts
against the approved budget and operational objectives.

CPU and memory are capacity signals, not application health or evidence that a
request is safely executable. They do not prove readiness, mTLS, durable
custody, successful deployment, rollback, lossless recovery or security. ECS
service metrics are aggregated over running tasks and can mask individual task
failure. Establish independently authenticated readiness and external checks,
service-specific error and latency signals, deployment and database alarms,
runbooks, backup/restore and failover tests before activation. Verify metric
availability, resolution, dimensions, alarm behavior, notifications and
permissions in the selected AWS region. Mocked tests are configuration evidence
only. Investigate missing data as potentially stopped tasks, permissions,
publishing or metric-delivery failure; do not infer the cause from the alarm.
