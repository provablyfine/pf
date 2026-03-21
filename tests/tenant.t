Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing tenants (only root)
  $ pfa -c config.json tenant list -q
  1

Create a child tenant
  $ pfa -c config.json tenant create --name acme --display-name "Acme Corp"
  .* (re)
  .* (re)
  .* (re)

Verify the child tenant appears in the list
  $ pfa -c config.json tenant list -q
  1
  2

  $ TENANT_ID=$(pfa -c config.json tenant list -q | tail -1)

Get the child tenant
  $ pfa -c config.json tenant get -i $TENANT_ID
  .* (re)
  .* (re)
  .* acme.*Acme Corp.* (re)

Update the child tenant's display name
  $ pfa -c config.json tenant update -i $TENANT_ID --display-name "Acme Corporation"

Verify the display name was updated
  $ pfa -c config.json tenant get -i $TENANT_ID
  .* (re)
  .* (re)
  .* acme.*Acme Corporation.* (re)

Disable the child tenant
  $ pfa -c config.json tenant update -i $TENANT_ID --disable

Delete (soft-delete) the child tenant
  $ pfa -c config.json tenant delete -i $TENANT_ID

The tenant is deleted (is_enabled=False, is_deleted=True) and still visible in the management list
  $ pfa -c config.json tenant list -q
  1
  2

Get a non-existing tenant
  $ pfa -c config.json tenant get -i 999
  Tenant 999 not found
  [2]
