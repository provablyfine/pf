Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)
  $ ROOT_ID=$(pfa -c config.json identity list -n root -q)

Create role
  $ pfa -c config.json role create -n role
  $ ROLE_ID=$(pfa -c config.json role list -n role -q)

Create identity user1
  $ pfa -c config.json identity create -n user1
  $ USER1_ID=$(pfa -c config.json identity list -n user1 -q)
  $ INVITATION=$(pfa -c config.json identity invite -i $USER1_ID --manual)

Add identity to role
  $ pfa -c config.json role member -i $ROLE_ID -a user1

New user accepts invitation and logs in
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ pf -c user1.json config --directory $DIRECTORY_URL
  $ ssh-keygen -t ed25519 -f user1 -N "" > /dev/null
  $ pf -c user1.json accept --invitation=$INVITATION --key user1
  $ ssh-keygen -t ed25519 -f user1-session -N "" > /dev/null
  $ pf -c user1.json login --session-key user1-session

Create a tag for testing
  $ pfa -c config.json tag create -n env -v dev


Check that permission "--read" is actually enforcing access control
  $ pfa -c user1.json tag list -q
  $ pfa -c config.json grant tag --read | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c user1.json tag list -q
  1
  $ pfa -c config.json role read -i $ROLE_ID -f json | jq '.grant_list[-1]' | pfa -c config.json role grant -i $ROLE_ID --del

Check that permission "--read --name-value env=dev" is actually enforcing access control
  $ pfa -c user1.json tag list -q
  $ pfa -c config.json grant tag --read --name-value env=dev | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c user1.json tag list -q
  1
  $ pfa -c config.json role read -i $ROLE_ID -f json | jq '.grant_list[-1]' | pfa -c config.json role grant -i $ROLE_ID --del



Check that permission "--create" is actually enforcing access control
  $ pfa -c user1.json tag create -n env -v prod
  Not allowed to create tag
  [2]
  $ pfa -c config.json grant tag --create | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c user1.json tag create -n env -v prod
  $ pfa -c config.json role read -i $ROLE_ID -f json | jq '.grant_list[-1]' | pfa -c config.json role grant -i $ROLE_ID --del
  $ TAG_ID=$(pfa -c config.json tag list -n env -v prod -q)
  $ pfa -c config.json tag delete -i $TAG_ID



Check that permission "--delete" is actually enforcing access control
  $ pfa -c config.json tag create -n env -v prod
  $ TAG_ID=$(pfa -c config.json tag list -n env -v prod -q)
  $ pfa -c user1.json tag delete -i $TAG_ID
  Not allowed to delete tag
  [2]
  $ pfa -c config.json grant tag --delete | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c user1.json tag delete -i $TAG_ID
  $ pfa -c config.json role read -i $ROLE_ID -f json | jq '.grant_list[-1]' | pfa -c config.json role grant -i $ROLE_ID --del



Check that permission "--delete --name-value env=prod" is actually enforcing access control
  $ pfa -c config.json tag create -n env -v prod
  $ TAG_ID=$(pfa -c config.json tag list -n env -v prod -q)
  $ pfa -c user1.json tag delete -i $TAG_ID
  Not allowed to delete tag
  [2]
  $ pfa -c config.json grant tag --delete --name-value env=prod | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c user1.json tag delete -i $TAG_ID
  $ pfa -c config.json role read -i $ROLE_ID
  id           2
  name         role
  description
  member       user1
  grant        type:       invalid
               filter:     !
               permission: !
  $ pfa -c config.json role read -i $ROLE_ID -f json | jq '.grant_list[-1]' | pfa -c config.json role grant -i $ROLE_ID --del
