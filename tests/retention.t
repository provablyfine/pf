Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

A new tenant keeps a year of records, and purging is on
  $ pfa -c config.json tenant get -i 1 | tail -1
  .* 365 +365 +True (re)

A period outside the allowed range is refused
  $ pfa -c config.json tenant update -i 1 --audit-retention-days 7
  .* (re)
  [2]
  $ pfa -c config.json tenant update -i 1 --activity-retention-days 366
  .* (re)
  [2]

Changing the periods and the purge flag is recorded in the audit log
  $ pfa -c config.json tenant update -i 1 --audit-retention-days 90 --activity-retention-days 30 --disable-purge
  $ pfa -c config.json tenant get -i 1 | tail -1
  .* 90 +30 +False (re)
  $ pfa -c config.json audit-log list --all --format json | jq -c '.entries[] | select(.type == "tenant-update") | .details.changes'
  {"audit_retention_days":{"old":365,"new":90},"activity_retention_days":{"old":365,"new":30},"retention_purge_enabled":{"old":true,"new":false}}

An update that changes nothing writes no entry
  $ pfa -c config.json tenant update -i 1 --audit-retention-days 90
  $ pfa -c config.json audit-log list --all --format json | jq '[.entries[] | select(.type == "tenant-update")] | length'
  1

The owner of a tenant changes its periods. The identity id of the owner means nothing there
  $ pfa -c config.json tenant create --name acme --display-name "Acme Corp"
  .* (re)
  .* (re)
  .* (re)
  $ ssh-keygen -t ed25519 -f acme-account -N "" > /dev/null
  $ ACME_UUID=$(pfa -c config.json tenant get -i 2 | awk 'NR==3{print $2}')
  $ pfa -c acme.json initialize http://127.0.0.1:$API_PORT/pf/t/$ACME_UUID/directory --key acme-account
  $ ssh-keygen -t ed25519 -f acme-session -N "" > /dev/null
  $ pfa -c acme.json login --session-key acme-session
  $ pfa -c config.json tenant update -i 2 --audit-retention-days 30
  $ pfa -c acme.json audit-log list --all --format json | jq -c '.entries[] | select(.type == "tenant-update") | {by_identity_id, by_identity_name, by_tenant_id, by_tenant_name, changes: .details.changes}'
  {"by_identity_id":null,"by_identity_name":"root","by_tenant_id":1,"by_tenant_name":"root","changes":{"audit_retention_days":{"old":365,"new":30}}}

The entry can be found by the tenant of its author
  $ pfa -c acme.json audit-log list --all --by-tenant 1 --format json | jq '[.entries[].type] | index("tenant-update") != null'
  true
  $ pfa -c acme.json audit-log list --all --by-tenant 7 --format json | jq '.entries | length'
  0

The owner has an entry of its own, which says which tenant was changed
  $ pfa -c config.json audit-log list --all --format json | jq -c '.entries[] | select(.type == "tenant-update" and .details.tenant_id == 2) | {by_tenant_id, tenant_name: .details.tenant_name}'
  {"by_tenant_id":null,"tenant_name":"Acme Corp"}

Renaming a tenant is recorded in its own log and in the log of the owner
  $ pfa -c config.json tenant update -i 2 --display-name "Acme Inc"
  $ pfa -c acme.json audit-log list --all --format json | jq -c '.entries[] | select(.type == "tenant-update" and .details.changes.display_name != null) | {by_tenant_name, changes: .details.changes}'
  {"by_tenant_name":"root","changes":{"display_name":{"old":"Acme Corp","new":"Acme Inc"}}}
  $ pfa -c config.json audit-log list --all --format json | jq -c '.entries[] | select(.type == "tenant-update" and .details.changes.display_name != null) | {tenant_id: .details.tenant_id, tenant_name: .details.tenant_name, changes: .details.changes}'
  {"tenant_id":2,"tenant_name":"Acme Corp","changes":{"display_name":{"old":"Acme Corp","new":"Acme Inc"}}}

Disabling a tenant is recorded in the log of the owner
  $ pfa -c config.json tenant update -i 2 --disable
  $ pfa -c config.json audit-log list --all --format json | jq -c '.entries[] | select(.type == "tenant-update") | .details.changes.is_enabled | values'
  {"old":true,"new":false}
