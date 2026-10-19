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
  $ pfa -c config.json audit-log list --all --format json | jq -c '.entries[] | select(.type == "retention-set") | .details.changes'
  {"audit_retention_days":{"old":365,"new":90},"activity_retention_days":{"old":365,"new":30},"retention_purge_enabled":{"old":true,"new":false}}

An update that changes nothing writes no entry
  $ pfa -c config.json tenant update -i 1 --audit-retention-days 90
  $ pfa -c config.json audit-log list --all --format json | jq '[.entries[] | select(.type == "retention-set")] | length'
  1
