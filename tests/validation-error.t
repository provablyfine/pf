Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a role (gets id=2)
  $ pfa -c config.json role create -n test

Trigger a RequestValidationError by sending a boundary grant with the required
'permission.create' field removed. The API must return 400 with a problem
document describing the missing field.
  $ pfa -c config.json grant boundary -f json | jq 'del(.permission.create)' | pfa -c config.json role grant -i 2 -a
  Request invalid. Field required: body.grant_list.0.boundary.permission.create
  [2]
