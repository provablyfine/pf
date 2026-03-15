Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing tags (there are none)
  $ pf admin tag list

Create a new tag
  $ pf admin tag create -n env -v prod

List existing tags (there is one now)
  $ pf admin tag list
    id  name    value
  ----  ------  -------
     1  env     prod


Create an existing tag
  $ pf admin tag create -n env -v prod
  Tag already exists
  [2]

Create more tags
  $ pf admin tag create -n env -v preprod
  $ pf admin tag create -n env -v dev
  $ pf admin tag create -n region -v us-east
  $ pf admin tag create -n region -v eu-west
  $ pf admin tag create -n region -v eu-east

List existing tags (sorted by increasing id)
  $ pf admin tag list -s id
    id  name    value
  ----  ------  -------
     1  env     prod
     2  env     preprod
     3  env     dev
     4  region  us-east
     5  region  eu-west
     6  region  eu-east

List existing tags (sorted by name/value pair lexicographically)
  $ pf admin tag list -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod
     6  region  eu-east
     5  region  eu-west
     4  region  us-east

List only env tags
  $ pf admin tag list -n env -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod

Find a specific tag
  $ pf admin tag list -n env -v preprod -q
  2

Find a specific tag that does not exist
  $ pf admin tag list -n env -v hello -q

Delete a tag
  $ pf admin tag delete -i $(pf admin tag list -n env -v preprod -q)

Check that the tag is gone
  $ pf admin tag list -n env -v preprod -q

Delete a tag that does not exist
  $ pf admin tag delete -i 15
  Unable to delete tag. Tag does not exist
  [2]

Delete all tags (check ids are never reused)
  $ for tag_id in $(pf admin tag list -q); do pf admin tag delete -i $tag_id; done
  $ pf admin tag list -n env -v dev
  $ pf admin tag create -n env -v dev
  $ pf admin tag list -n env -v dev
    id  name    value
  ----  ------  -------
     7  env     dev
