#!/usr/bin/env sh
set -eu
# The fixture key stays private on the host; copy it into a PostgreSQL-owned
# ephemeral directory rather than making it world readable for container UID999.
install -d -m0700 -o postgres -g postgres /run/pg-tls
install -m0600 -o postgres -g postgres /run/secrets/postgres_tls_key /run/pg-tls/server.key
install -m0644 -o postgres -g postgres /run/secrets/postgres_tls_cert /run/pg-tls/server.crt
exec /usr/local/bin/docker-entrypoint.sh postgres \
 -c ssl=on -c ssl_cert_file=/run/pg-tls/server.crt -c ssl_key_file=/run/pg-tls/server.key \
 -c ssl_min_protocol_version=TLSv1.3 -c ssl_max_protocol_version=TLSv1.3 -c hba_file=/etc/nex/pg_hba.conf
