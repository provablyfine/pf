Initialize server and login
  $ bash $TESTDIR/fixture.sh

List existing tags (there are none)
  $ idbctl admin tag list

Create a new tag
  $ idbctl admin tag create -n env -v prod

List existing tags (there is one now)
  $ idbctl admin tag list
    id  name    value
  ----  ------  -------
     1  env     prod


Create an existing tag
  $ idbctl admin tag create -n env -v prod
  Unable to create tag: Tag already exists
  [2]

Create more tags
  $ idbctl admin tag create -n env -v preprod
  $ idbctl admin tag create -n env -v dev
  $ idbctl admin tag create -n region -v us-east
  $ idbctl admin tag create -n region -v eu-west
  $ idbctl admin tag create -n region -v eu-east

List existing tags (sorted by increasing id)
  $ idbctl admin tag list -s id
    id  name    value
  ----  ------  -------
     1  env     prod
     2  env     preprod
     3  env     dev
     4  region  us-east
     5  region  eu-west
     6  region  eu-east

List existing tags (sorted by name/value pair lexicographically)
  $ idbctl admin tag list -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod
     6  region  eu-east
     5  region  eu-west
     4  region  us-east

List only env tags
  $ idbctl admin tag list -n env -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod

Find a specific tag
  $ idbctl admin tag list -n env -v preprod -q
  2

Find a specific tag that does not exist
  $ idbctl admin tag list -n env -v hello -q

Delete a tag
  $ idbctl admin tag delete -i $(idbctl admin tag list -n env -v preprod -q)

Check that the tag is gone
  $ idbctl admin tag list -n env -v preprod -q

Delete a tag that does not exist
  $ idbctl admin tag delete -i 15
  Unable to delete tag: Tag does not exist
  [2]

Delete all tags (check ids are never reused)
  $ for tag_id in $(idbctl admin tag list -q); do idbctl admin tag delete -i $tag_id; done
  $ idbctl admin tag list -n env -v dev
  $ idbctl admin tag create -n env -v dev
  $ idbctl admin tag list -n env -v dev
    id  name    value
  ----  ------  -------
     7  env     dev
