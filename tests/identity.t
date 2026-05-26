Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing identities (there is one)
  $ pfa -c config.json identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
  $ pfa -c config.json identity delete -i 1
  You cannot delete yourself
  [2]
  $ pfa -c config.json identity update -i 1 -n hello
  Not allowed to update self
  [2]

Create a boundary to be able to create an identity with it
  $ pfa -c config.json boundary create -n boundary1

Create tags to be able to tag and untag identity
  $ pfa -c config.json tag create -n env -v dev
  $ pfa -c config.json tag create -n env -v preprod
  $ pfa -c config.json tag create -n env -v prod

Create a new identity to be able to update and delete it
  $ pfa -c config.json identity create -n user2 -b boundary1 -t env=dev
  $ USER2_ID=$(pfa -c config.json identity list -n user2 -q)
  $ pfa -c config.json identity update -i $USER2_ID -n hello
  $ pfa -c config.json identity list
    id  name      ntags    nboundaries
  ----  ------  -------  -------------
     1  root          0              1
     2  hello         1              2
  $ pfa -c config.json identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=dev
  boundary  root
  boundary  boundary1
  $ pfa -c config.json identity invite -i $USER2_ID --manual
  https?://.+ (re)

We can add and remove tags from identities
  $ pfa -c config.json identity tag -i $USER2_ID -a env=prod -d env=dev
  $ pfa -c config.json identity read -i $USER2_ID
  id        2
  name      hello
  tag       env=prod
  boundary  root
  boundary  boundary1
  $ pfa -c config.json identity tag -i $USER2_ID -a env=prod

And yes, we can delete an identity
  $ pfa -c config.json identity delete -i $USER2_ID
