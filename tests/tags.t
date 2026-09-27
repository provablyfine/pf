Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing tags (there are none)
  $ pfa -c config.json tag list

Create a new tag
  $ pfa -c config.json tag create -n env -v prod

List existing tags (there is one now)
  $ pfa -c config.json tag list
    id  name    value
  ----  ------  -------
     1  env     prod


Create an existing tag
  $ pfa -c config.json tag create -n env -v prod
  Tag already exists
  [2]

Create more tags
  $ pfa -c config.json tag create -n env -v preprod
  $ pfa -c config.json tag create -n env -v dev
  $ pfa -c config.json tag create -n region -v us-east
  $ pfa -c config.json tag create -n region -v eu-west
  $ pfa -c config.json tag create -n region -v eu-east

List existing tags (sorted by increasing id)
  $ pfa -c config.json tag list -s id
    id  name    value
  ----  ------  -------
     1  env     prod
     2  env     preprod
     3  env     dev
     4  region  us-east
     5  region  eu-west
     6  region  eu-east

List existing tags (sorted by name/value pair lexicographically)
  $ pfa -c config.json tag list -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod
     6  region  eu-east
     5  region  eu-west
     4  region  us-east

List only env tags
  $ pfa -c config.json tag list -n env -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod

Find a specific tag
  $ pfa -c config.json tag list -n env -v preprod -q
  2

Find a specific tag that does not exist
  $ pfa -c config.json tag list -n env -v hello -q

Delete a tag
  $ pfa -c config.json tag delete -i $(pfa -c config.json tag list -n env -v preprod -q)

Check that the tag is gone
  $ pfa -c config.json tag list -n env -v preprod -q

Delete a tag that does not exist
  $ pfa -c config.json tag delete -i 15
  Tag does not exist
  [2]

Delete all tags (check ids are never reused)
  $ for tag_id in $(pfa -c config.json tag list -q); do pfa -c config.json tag delete -i $tag_id; done
  $ pfa -c config.json tag list -n env -v dev
  $ pfa -c config.json tag create -n env -v dev
  $ pfa -c config.json tag list -n env -v dev
    id  name    value
  ----  ------  -------
     7  env     dev

A tag that is neither tagged nor ACL-referenced can be deleted (already covered above)

A tag that is only identity-tagged (no ACL reference) can be deleted, and the tagging goes with it
  $ pfa -c config.json tag create -n team -v ops
  $ pfa -c config.json identity create -n carol -t team=ops
  $ CAROL_ID=$(pfa -c config.json identity list -n carol -q)
  $ pfa -c config.json identity read -i $CAROL_ID -f json | jq -c '.tags'
  [{"name":"team","value":"ops"}]
  $ pfa -c config.json tag delete -i $(pfa -c config.json tag list -n team -v ops -q)
  $ pfa -c config.json identity read -i $CAROL_ID -f json | jq -c '.tags'
  []

A tag that is only ACL-referenced (no identity tagged) can be deleted, and the reference goes with it
  $ pfa -c config.json tag create -n quarantine -v "true"
  $ pfa -c config.json boundary create -n quarantine-guard -d "Blocks SSH for anyone quarantined"
  $ GUARD_ID=$(pfa -c config.json boundary list -n quarantine-guard -q)
  $ pfa -c config.json grant ssh --tag quarantine=true --username-all --capability-all | pfa -c config.json boundary denied -i $GUARD_ID --add
  $ pfa -c config.json boundary read -i $GUARD_ID -f json | jq '.denied_list | length'
  1
  $ pfa -c config.json tag delete -i $(pfa -c config.json tag list -n quarantine -v true -q)
  $ pfa -c config.json boundary read -i $GUARD_ID -f json | jq '.denied_list | length'
  0

A tag that is both identity-tagged and ACL-referenced refuses deletion; untagging and retrying then succeeds
  $ pfa -c config.json tag create -n quarantine -v "true"
  $ pfa -c config.json grant ssh --tag quarantine=true --username-all --capability-all | pfa -c config.json boundary denied -i $GUARD_ID --add
  $ pfa -c config.json identity create -n dave -t quarantine=true
  $ DAVE_ID=$(pfa -c config.json identity list -n dave -q)
  $ QUARANTINE_ID=$(pfa -c config.json tag list -n quarantine -v true -q)
  $ pfa -c config.json tag delete -i $QUARANTINE_ID
  Tag is still in use
  [2]
  $ pfa -c config.json identity tag -i $DAVE_ID -d quarantine=true
  $ pfa -c config.json tag delete -i $QUARANTINE_ID
  $ pfa -c config.json boundary read -i $GUARD_ID -f json | jq '.denied_list | length'
  0

Deleting a tag narrows a bastion's tag list when other tags remain on it
  $ pfa -c config.json tag create -n site -v hq
  $ pfa -c config.json tag create -n rack -v a1
  $ SITE_ID=$(pfa -c config.json tag list -n site -v hq -q)
  $ RACK_ID=$(pfa -c config.json tag list -n rack -v a1 -q)
  $ pfa -c config.json bastion create --url https://multi-tag.example.com -t $SITE_ID $RACK_ID
  $ MULTI_BASTION_ID=$(pfa -c config.json bastion list -q | tail -1)
  $ pfa -c config.json tag delete -i $SITE_ID
  $ pfa -c config.json bastion read -i $MULTI_BASTION_ID -f json | jq -c '.tag_list'
  [{"name":"rack","value":"a1"}]

Deleting a tag that is a bastion's only tag strips it, leaving the bastion unrestricted (tag_id_list gates visibility, not access)
  $ pfa -c config.json tag create -n site -v remote
  $ SITE2_ID=$(pfa -c config.json tag list -n site -v remote -q)
  $ pfa -c config.json bastion create --url https://sole-tag.example.com -t $SITE2_ID
  $ SOLE_BASTION_ID=$(pfa -c config.json bastion list -q | tail -1)
  $ pfa -c config.json tag delete -i $SITE2_ID
  $ pfa -c config.json bastion read -i $SOLE_BASTION_ID -f json | jq -c '.tag_list'
  null
  $ pfa -c config.json bastion list -q | wc -l | tr -d ' '
  2
