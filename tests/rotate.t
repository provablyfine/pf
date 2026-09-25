Initialize server, login, and create the tenant's first identity
  $ bash $TESTDIR/fixture.sh
  .* (re)
  $ ROOT_DB=$(dirname $API_CONFIG)/root.db

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

Once the staged key is due to become current, rotate creates a fresh staged key
  $ sleep 28
  $ pf-api-rotate -c $API_CONFIG
  $ sqlite3 $ROOT_DB "SELECT count(*) FROM oidc_key"
  3
