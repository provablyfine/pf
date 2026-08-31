Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a boundary
  $ pfa -c config.json boundary create -n test-boundary
  $ BOUNDARY_ID=$(pfa -c config.json boundary list -n test-boundary -q)
  $ pfa -c config.json boundary read -i $BOUNDARY_ID | head -3
  id           .* (re)
  name         test-boundary
  description

Attempt to create another boundary with the same name should fail
  $ pfa -c config.json boundary create -n test-boundary
  .* (re)
  [2]
