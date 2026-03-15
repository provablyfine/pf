Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing tags (there are none)
  $ pfa tag list

Create a new tag
  $ pfa tag create -n env -v prod

List existing tags (there is one now)
  $ pfa tag list
    id  name    value
  ----  ------  -------
     1  env     prod


Create an existing tag
  $ pfa tag create -n env -v prod
  Tag already exists
  [2]

Create more tags
  $ pfa tag create -n env -v preprod
  $ pfa tag create -n env -v dev
  $ pfa tag create -n region -v us-east
  $ pfa tag create -n region -v eu-west
  $ pfa tag create -n region -v eu-east

List existing tags (sorted by increasing id)
  $ pfa tag list -s id
    id  name    value
  ----  ------  -------
     1  env     prod
     2  env     preprod
     3  env     dev
     4  region  us-east
     5  region  eu-west
     6  region  eu-east

List existing tags (sorted by name/value pair lexicographically)
  $ pfa tag list -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod
     6  region  eu-east
     5  region  eu-west
     4  region  us-east

List only env tags
  $ pfa tag list -n env -s name
    id  name    value
  ----  ------  -------
     3  env     dev
     2  env     preprod
     1  env     prod

Find a specific tag
  $ pfa tag list -n env -v preprod -q
  2

Find a specific tag that does not exist
  $ pfa tag list -n env -v hello -q

Delete a tag
  $ pfa tag delete -i $(pfa tag list -n env -v preprod -q)

Check that the tag is gone
  $ pfa tag list -n env -v preprod -q

Delete a tag that does not exist
  $ pfa tag delete -i 15
  Unable to delete tag. Tag does not exist
  [2]

Delete all tags (check ids are never reused)
  $ for tag_id in $(pfa tag list -q); do pfa tag delete -i $tag_id; done
  $ pfa tag list -n env -v dev
  $ pfa tag create -n env -v dev
  $ pfa tag list -n env -v dev
    id  name    value
  ----  ------  -------
     7  env     dev
