Initialize server and login
  $ bash $TESTDIR/fixture.sh

List existing boundaries (there is one)
  $ idbctl admin boundary list
    id  name    description
  ----  ------  -------------------------------------------
     1  root    The Root boundary is not a boundary at all.

JSON output
  $ idbctl admin boundary list -f json
  [
    {
      "id": 1,
      "name": "root",
      "description": "The Root boundary is not a boundary at all.",
      "ceiling_list": [],
      "denied_list": []
    }
  ]

Display details about the boundary
  $ idbctl admin boundary read -i 1
  id           1
  name         root
  description  The Root boundary is not a boundary at all.

Search for the root boundary explicitely
  $ idbctl admin boundary list -n root -q
  1

Try to delete it (we cannot)
  $ idbctl admin boundary delete -i $(idbctl admin boundary list -n root -q)
  Unable to delete boundary: Unable to delete boundary: it is still in use
  [2]

Try to update it (we cannot)
  $ idbctl admin boundary update -i 1 -d hello -n hello
  Unable to update boundary: Not allowed to update boundary that applies to self.
  [2]
