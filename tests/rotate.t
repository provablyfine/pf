Initialize server, login, and create the tenant's first identity
  $ bash $TESTDIR/fixture.sh
  .* (re)
  $ ROOT_DB=$(python3 -c "
  > import json
  > import sqlalchemy
  > import provablyfine.api.db as db
  > import provablyfine.api.registry_db as registry_db
  > config = json.load(open('$API_CONFIG'))
  > url = db.derive_tenant_url(config['tenant_registry_url'], registry_db.ROOT_TENANT_UUID)
  > print(sqlalchemy.make_url(url).database)
  > ")

The OIDC signing key already exists right after initialize: current + staged in the database
  $ sqlite3 $ROOT_DB "SELECT count(*) FROM oidc_key"
  2

The current key is already visible to a real client via the public JWKS endpoint
  $ curl -s "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/oidc/.well-known/jwks.json" | jq -r '.keys | length'
  1

Rotating immediately after initialize is a no-op: still two keys, nothing new
  $ pf-api-rotate -c $API_CONFIG
  $ sqlite3 $ROOT_DB "SELECT count(*) FROM oidc_key"
  2

Age both keys well past the point where the staged one is due to become current. This is a
one-shot database edit rather than a real sleep, so the test does not race a fixed wait against
however long `pfa`/`curl`/`pf-api-rotate` subprocess startup happens to take on a loaded machine.
  $ sqlite3 $ROOT_DB "UPDATE oidc_key SET valid_after = valid_after - 590, valid_before = valid_before - 590"
  $ pf-api-rotate -c $API_CONFIG
  $ sqlite3 $ROOT_DB "SELECT count(*) FROM oidc_key"
  3
