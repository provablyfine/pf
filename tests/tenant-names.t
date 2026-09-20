Tenant names do not have to be unique, so that a name cannot be probed by creating a tenant.

Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create two tenants with the same name
  $ pfa -c config.json tenant create --name acme --display-name "First"
  .* (re)
  .* (re)
  .* (re)
  $ pfa -c config.json tenant create --name acme --display-name "Second"
  .* (re)
  .* (re)
  .* (re)

Both exist, and they have different UUIDs
  $ pfa -c config.json tenant list -q
  1
  2
  3
  $ pfa -c config.json tenant list -f json | jq -r '.[].uuid' | sort -u | wc -l | tr -d ' '
  3
