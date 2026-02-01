Initialize server and login
  $ bash $TESTDIR/fixture.sh

List existing identities (there is one)
  $ idbctl admin identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
  $ idbctl admin identity delete -i 1
  Unable to delete identity. You cannot delete yourself
  [2]
  $ idbctl admin identity update -i 1 -n hello
  Unable to update identity. Not allowed to update self.
  [2]

Create a boundary to be able to create an identity with it
  $ idbctl admin boundary create -n boundary1

Create tags to be able to tag and untag indentity
  $ idbctl admin tag create -n env -v dev
  $ idbctl admin tag create -n env -v preprod
  $ idbctl admin tag create -n env -v prod

Create a new identity to be able to update and delete it
  $ idbctl admin identity create -n user2 -b boundary1 -t env=dev
  $ USER2_ID=$(idbctl admin identity list -n user2 -q)
  $ idbctl admin identity update -i $USER2_ID -n hello
  $ idbctl admin identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
     2  hello         1              2
  $ idbctl admin identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=dev
  boundary  root
  boundary  boundary1
  $ idbctl admin identity invite -i $USER2_ID --manual
  [A-Za-z0-9_-]+ (re)

We can add and remove tags from identities
  $ idbctl admin identity tag -i $USER2_ID -a env=prod -d env=dev
  $ idbctl admin identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=prod
  boundary  root
  boundary  boundary1
  $ idbctl admin identity tag -i $USER2_ID -a env=prod
  [2]


And yes, we can delete an identity
  $ idbctl admin identity delete -i $USER2_ID
