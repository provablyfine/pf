# Create Boundary
pfa -c config.json boundary create -n boundary >/dev/null

# Create tag
PERSON_ID=$(pfa -c config.json tag create -n id -v person)
DEVICE_ID=$(pfa -c config.json tag create -n id -v device)

# Create role
ROLE_ID=$(pfa -c config.json role create -n role)

# Create identity user1 and add to role before inviting
USER1_ID=$(pfa -c config.json identity create -n user1)
pfa -c config.json role member -i $ROLE_ID -a user1
INVITATION=$(pfa -c config.json identity invite -i $USER1_ID --manual)
echo $INVITATION

# Create identity user2
USER2_ID=$(pfa -c config.json identity create -n user2)

# New user accepts invitation and logs in
ssh-keygen -t ed25519 -f user1 -N "" > /dev/null
pf -c user1.json accept --invitation=$INVITATION --key user1
ssh-keygen -t ed25519 -f user1-session -N "" > /dev/null
pf -c user1.json login --session-key user1-session
