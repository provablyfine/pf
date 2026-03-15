Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing identities (there is one)
  $ pfa identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
  $ pfa identity delete -i 1
  You cannot delete yourself
  [2]
  $ pfa identity update -i 1 -n hello
  Unable to update identity. Not allowed to update self.
  [2]

Create a boundary to be able to create an identity with it
  $ pfa boundary create -n boundary1

Create tags to be able to tag and untag indentity
  $ pfa tag create -n env -v dev
  $ pfa tag create -n env -v preprod
  $ pfa tag create -n env -v prod

Create a new identity to be able to update and delete it
  $ pfa identity create -n user2 -b boundary1 -t env=dev
  $ USER2_ID=$(pfa identity list -n user2 -q)
  $ pfa identity update -i $USER2_ID -n hello
  $ pfa identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
     2  hello         1              2
  $ pfa identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=dev
  boundary  root
  boundary  boundary1
  $ pfa identity invite -i $USER2_ID --manual
  [A-Za-z0-9_-]+ (re)

We can add and remove tags from identities
  $ pfa identity tag -i $USER2_ID -a env=prod -d env=dev
  $ pfa identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=prod
  boundary  root
  boundary  boundary1
  $ pfa identity tag -i $USER2_ID -a env=prod

And yes, we can delete an identity
  $ pfa identity delete -i $USER2_ID
