# Private service network foundations

`production_service_network` creates an explicit network identity for each
selected service and paired TCP ingress/egress rules for each reviewed directed
connection. Its null default creates nothing. Connections require a source,
destination and port; the module invents no application ports or routes.

Attach only the matching service security group to a task. Database clients
require their separate, explicitly authorized database-client group. AWS
endpoint access requires the separately reviewed workload endpoint group and
verified regional endpoint inventory. Rules from every group attached to a task
are additive, so review their combined effect and test allowed and denied
connections in the actual environment. This graph does not configure ingress
from an ALB, external identity providers, DNS or internet access.

Security groups do not establish mutual TLS or service identity. Configure and
independently verify workload certificates, trust, authorization and rotation
before deploying services. This module does not create task definitions or
services and does not establish production readiness.
