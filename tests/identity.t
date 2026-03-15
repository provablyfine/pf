Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing identities (there is one)
  $ pf admin identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
  $ pf admin identity delete -i 1
  You cannot delete yourself
  [2]
  $ pf admin identity update -i 1 -n hello
  Unable to update identity. Not allowed to update self.
  [2]

Create a boundary to be able to create an identity with it
  $ pf admin boundary create -n boundary1

Create tags to be able to tag and untag indentity
  $ pf admin tag create -n env -v dev
  $ pf admin tag create -n env -v preprod
  $ pf admin tag create -n env -v prod

Create a new identity to be able to update and delete it
  $ pf admin identity create -n user2 -b boundary1 -t env=dev
  $ USER2_ID=$(pf admin identity list -n user2 -q)
  $ pf admin identity update -i $USER2_ID -n hello
  $ pf admin identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
     2  hello         1              2
  $ pf admin identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=dev
  boundary  root
  boundary  boundary1
  $ pf admin identity invite -i $USER2_ID --manual
  [A-Za-z0-9_-]+ (re)

We can add and remove tags from identities
  $ pf admin identity tag -i $USER2_ID -a env=prod -d env=dev
  $ pf admin identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=prod
  boundary  root
  boundary  boundary1
  $ pf admin identity tag -i $USER2_ID -a env=prod

And yes, we can delete an identity
  $ pf admin identity delete -i $USER2_ID
