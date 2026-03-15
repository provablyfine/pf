# Create Boundary
pf admin boundary create -n boundary

# Create tag
pf admin tag create -n id -v person
pf admin tag create -n id -v device
PERSON_ID=$(pf admin tag list -n id -v person -q)
DEVICE_ID=$(pf admin tag list -n id -v device -q)

# Create role
pf admin role create -n role
ROLE_ID=$(pf admin role list -n role -q)

# Create identity user1
pf admin identity create -n user1
USER1_ID=$(pf admin identity list -n user1 -q)
INVITATION=$(pf admin identity invite -i $USER1_ID --manual)
echo $INVITATION

# Create identity user2
pf admin identity create -n user2
USER2_ID=$(pf admin identity list -n user2 -q)

# Add identity to role
pf admin role member -i $ROLE_ID -a user1

# New user accepts invitation and logs in
DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/directory
pf -c user1.json config --directory $DIRECTORY_URL
ssh-keygen -t ed25519 -f user1 -N "" > /dev/null
pf -c user1.json accept --invitation=$INVITATION --key user1
ssh-keygen -t ed25519 -f user1-session -N "" > /dev/null
pf -c user1.json login --session-key user1-session
