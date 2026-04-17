Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing boundaries (there is one)
  $ pfa -c config.json boundary list
    id  name    description
  ----  ------  -------------------------------------------
     1  root    The Root boundary is not a boundary at all.

JSON output
  $ pfa -c config.json boundary list -f json
  [
    {
      "id": 1,
      "name": "root",
      "description": "The Root boundary is not a boundary at all.",
      "ceiling_list": null,
      "denied_list": []
    }
  ]

Display details about the boundary
  $ pfa -c config.json boundary read -i 1
  id           1
  name         root
  description  The Root boundary is not a boundary at all.
  ceiling      *

Search for the root boundary explicitely
  $ pfa -c config.json boundary list -n root -q
  1

Try to delete it (we cannot)
  $ pfa -c config.json boundary delete -i $(pfa -c config.json boundary list -n root -q)
  Boundary is still in use
  [2]

Update name and description
  $ pfa -c config.json boundary update -i 1 -d hello -n hello
  $ pfa -c config.json boundary read -i 1
  id           1
  name         hello
  description  hello
  ceiling      *
  $ cat <<EOF >identity-crud.yaml
  > type: identity
  > filter:
  >   name: null
  >   tag_list: null
  >   boundary_list: null
  > permission:
  >   create:
  >     allowed: true
  >     allowed_tag_list: null
  >     required_boundary_list: null
  >   read: true
  >   update:
  >     name: true
  >   delete: true
  >   add_tag_list: null
  >   del_tag_list: null
  >   invite_list: null
  > EOF
  $ cat ./identity-crud.yaml | pfa -c config.json boundary denied -i 1 --add
  Not allowed to update denied list on boundary that applies to self
  [2]
  $ cat ./identity-crud.yaml | pfa -c config.json boundary ceiling -i 1 -a
  Not allowed to update ceiling list on boundary that applies to self
  [2]

Create a new boundary
  $ pfa -c config.json boundary create -n non-admin -d "Most users are not admins and they should get a boundary that derives from this"

Make sure important permissions are denied from these users
  $ BOUNDARY_ID=$(pfa -c config.json boundary list -n non-admin -q)
  $ pfa -c config.json grant role --create |pfa -c config.json boundary denied -i $BOUNDARY_ID --add
  $ pfa -c config.json grant role --update grant_list | pfa -c config.json boundary denied -i $BOUNDARY_ID --add
  $ pfa -c config.json grant tag -crd | pfa -c config.json boundary denied -i $BOUNDARY_ID --add
  $ pfa -c config.json grant boundary -crd --update denied_list | pfa -c config.json boundary denied -i $BOUNDARY_ID --add 

Check that boundary has been created
  $ pfa -c config.json boundary read -i $BOUNDARY_ID
  id           2
  name         non-admin
  description  Most users are not admins and they should get a boundary that derives from this
  ceiling      *
  denied       type:       role
               filter:     *
               permission: create
  denied       type:       role
               filter:     *
               permission: update.grant_list
  denied       type:       tag
               filter:     *
               permission: create read delete
  denied       type:       boundary
               filter:     *
               permission: create read update.denied_list delete

We can remove and add permissions from the boundary denied list
  $ pfa -c config.json boundary read -i $BOUNDARY_ID -f json | jq '.denied_list[0]' | pfa -c config.json boundary denied -i $BOUNDARY_ID --del 
  $ pfa -c config.json boundary read -i 2
  id           2
  name         non-admin
  description  Most users are not admins and they should get a boundary that derives from this
  ceiling      *
  denied       type:       role
               filter:     *
               permission: update.grant_list
  denied       type:       tag
               filter:     *
               permission: create read delete
  denied       type:       boundary
               filter:     *
               permission: create read update.denied_list delete
  $ pfa -c config.json grant role --create | pfa -c config.json boundary denied -i $BOUNDARY_ID --add
  $ pfa -c config.json boundary read -i 2
  id           2
  name         non-admin
  description  Most users are not admins and they should get a boundary that derives from this
  ceiling      *
  denied       type:       role
               filter:     *
               permission: update.grant_list
  denied       type:       tag
               filter:     *
               permission: create read delete
  denied       type:       boundary
               filter:     *
               permission: create read update.denied_list delete
  denied       type:       role
               filter:     *
               permission: create

  $ pfa -c config.json grant role --read | pfa -c config.json boundary denied -i $BOUNDARY_ID --del

We can also edit the boundary ceiling list
  $ pfa -c config.json grant role --update | pfa -c config.json boundary ceiling -i $BOUNDARY_ID --set
