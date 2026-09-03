Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a role (gets id=2)
  $ pfa -c config.json role create -n test

Trigger a ValidationError by sending a boundary grant with the required
'permission.create' field removed. The client validates the grant before sending
to the API.
  $ pfa -c config.json grant boundary -f json | jq 'del(.permission.create)' | pfa -c config.json role grant -i 2 -a
  Request invalid. Field required: boundary.permission.create
  [2]
