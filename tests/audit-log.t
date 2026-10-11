Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .

List audit log with table format shows signing-key-create events
  $ pfa -c config.json audit-log list | grep signing-key-create | wc -l
  .* (re)

Create a tag to generate an audit event
  $ TAG_ID=$(pfa -c config.json tag create -n env -v prod)

Verify tag-create event exists in audit log
  $ pfa -c config.json audit-log list --object-type tag | grep -q tag-create && echo "OK"
  OK

List audit log with JSON format
  $ pfa -c config.json audit-log list --format json | grep -q "tag-create" && echo "OK"
  OK

Create an identity
  $ pfa -c config.json identity create -n test-user
  [0-9]+ (re)

Verify identity-create event exists
  $ pfa -c config.json audit-log list --object-type identity | grep -q identity-create && echo "OK"
  OK

List audit log with quiet format (IDs only)
  $ pfa -c config.json audit-log list --quiet | wc -l
  .* (re)

Count tag events
  $ pfa -c config.json audit-log list --object-type tag --quiet | wc -l
  .* (re)

Create more tags
  $ pfa -c config.json tag create -n region -v us
  [0-9]+ (re)
  $ pfa -c config.json tag create -n region -v eu
  [0-9]+ (re)

Delete first tag
  $ pfa -c config.json tag delete -i $TAG_ID

Verify tag-delete event exists
  $ pfa -c config.json audit-log list --object-type tag | grep -q tag-delete && echo "OK"
  OK

Deleting a role and a boundary leaves an audit event
  $ BOUNDARY_ID=$(pfa -c config.json boundary create -n audit-b)
  $ ROLE_ID=$(pfa -c config.json role create -n audit-r)
  $ pfa -c config.json boundary delete -i $BOUNDARY_ID
  $ pfa -c config.json role delete -i $ROLE_ID
  $ pfa -c config.json audit-log list --object-type boundary | grep -q boundary-delete && echo "OK"
  OK
  $ pfa -c config.json audit-log list --object-type role | grep -q role-delete && echo "OK"
  OK
