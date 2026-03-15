# Create Boundary
pfa boundary create -n boundary

# Create tag
pfa tag create -n id -v person
pfa tag create -n id -v device
PERSON_ID=$(pfa tag list -n id -v person -q)
DEVICE_ID=$(pfa tag list -n id -v device -q)

# Create role
pfa role create -n role
ROLE_ID=$(pfa role list -n role -q)

# Create identity user1
pfa identity create -n user1
USER1_ID=$(pfa identity list -n user1 -q)
INVITATION=$(pfa identity invite -i $USER1_ID --manual)
echo $INVITATION

# Create identity user2
pfa identity create -n user2
USER2_ID=$(pfa identity list -n user2 -q)

# Add identity to role
pfa role member -i $ROLE_ID -a user1

# New user accepts invitation and logs in
DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/directory
pf -c user1.json config --directory $DIRECTORY_URL
ssh-keygen -t ed25519 -f user1 -N "" > /dev/null
pf -c user1.json accept --invitation=$INVITATION --key user1
ssh-keygen -t ed25519 -f user1-session -N "" > /dev/null
pf -c user1.json login --session-key user1-session
