Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .

List audit log with table format shows signing-key-create events
  $ pfa -c config.json audit-log list | grep signing-key-create | wc -l
  .* (re)

List the object types and actions that the server knows
  $ pfa -c config.json audit-log types | grep -E "^(role|tag) " | cut -c1-30
  role .* (re)
  tag .* (re)

A wrong action is refused with the list of valid ones
  $ pfa -c config.json audit-log list --action nope 2>&1 | grep -c "create"
  1

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

List the objects that had a name, and the ids to ask for
  $ pfa -c config.json audit-log objects --object tag:nothing
  $ pfa -c config.json role create -n ops > /dev/null
  $ pfa -c config.json audit-log objects --object role:ops | tail -n 1 | cut -d' ' -f1
  role

Following needs a name
  $ pfa -c config.json audit-log list --object-id role:1 --follow 2>&1 | grep -c "needs --object"
  1

The json format carries the cursor, so a script can continue
  $ pfa -c config.json audit-log list --limit 2 --format json > page1.json
  $ python3 -c "import json; d = json.load(open('page1.json')); print(len(d['entries']), d['is_last'], bool(d['next_cursor']))"
  2 False True
  $ CURSOR=$(python3 -c "import json; print(json.load(open('page1.json'))['next_cursor'])")
  $ pfa -c config.json audit-log list --limit 2 --cursor $CURSOR --format json > page2.json
  $ python3 -c "import json; a = json.load(open('page1.json')); b = json.load(open('page2.json')); print(a['entries'][-1]['id'] > b['entries'][0]['id'])"
  True

Reading every page ends on the last one
  $ pfa -c config.json audit-log list --all --format json > all.json
  $ python3 -c "import json; d = json.load(open('all.json')); print(d['is_last'], len(d['entries']) > 2)"
  True True

The objects listing has the same shape
  $ pfa -c config.json audit-log objects --object role:ops --format json | python3 -c "import json, sys; d = json.load(sys.stdin); print(len(d['objects']), d['is_last'])"
  1 True

Reading every page can start from a cursor and use a page size
  $ pfa -c config.json audit-log list --all --limit 2 --cursor $CURSOR --format json > rest.json
  $ python3 -c "import json; a = json.load(open('page2.json')); r = json.load(open('rest.json')); print(r['is_last'], r['entries'][:2] == a['entries'], len(r['entries']) > 2)"
  True True True
