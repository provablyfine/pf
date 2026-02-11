#!/bin/bash
set -m

# First, start the signer service
SIGNER_CONFIG=$(mktemp --suffix .yaml)
SIGNER_LOG=$(mktemp --suffix .log)
SIGNER_PORT_FILE=/tmp/$(xxd -l 16 -p /dev/random).portfile
SIGNER_KEK_FILE=$(mktemp --suffix .key)
dd if=/dev/random of=$SIGNER_KEK_FILE count=1 bs=32 2>/dev/null
cat > $SIGNER_CONFIG <<EOF
debug: true
log_level: DEBUG
kek_filename: $SIGNER_KEK_FILE
#debug_sql: true
EOF
PYTHONUNBUFFERED=1 idb-signer -c $SIGNER_CONFIG --port-file $SIGNER_PORT_FILE >$SIGNER_LOG 2>&1 &
SIGNER_PID=$!
trap 'kill -TERM -${SIGNER_PID} 2>/dev/null' EXIT

while [ ! -s "$SIGNER_PORT_FILE" ]; do
  sleep 0.1
done
SIGNER_PORT=$(cat $SIGNER_PORT_FILE)
SIGNER_URL=http://127.0.0.1:$SIGNER_PORT
until curl -f -s $SIGNER_URL/host/ca > /dev/null; do
  sleep 0.1
done

# Second, start the api service
API_CONFIG=$(mktemp --suffix .yaml)
API_DB=$(mktemp --suffix .db)
API_LOG=$(mktemp --suffix .log)
API_PORT_FILE=/tmp/$(xxd -l 16 -p /dev/random).portfile
API_KEK_FILE=$(mktemp --suffix .key)
dd if=/dev/random of=$API_KEK_FILE count=1 bs=32 2>/dev/null
cat > $API_CONFIG <<EOF
database_url: sqlite:///$API_DB
debug: true
log_level: DEBUG
kek_filename: $API_KEK_FILE
signer_url: $SIGNER_URL
#debug_sql: true
EOF


PYTHONUNBUFFERED=1 idb -c $API_CONFIG --port-file $API_PORT_FILE >$API_LOG 2>&1 &
API_PID=$!
trap 'kill -TERM -${API_PID} -${SIGNER_PID} 2>/dev/null' EXIT

while [ ! -s "$API_PORT_FILE" ]; do
  sleep 0.1
done
API_PORT=$(cat $API_PORT_FILE)
until curl -f -s 127.0.0.1:$API_PORT/idb/directory > /dev/null; do
  sleep 0.1
done

# Run the test
API_PORT=$API_PORT cram $1
EXIT_CODE=$?

# Cleanup
kill $API_PID
kill $SIGNER_PID
if test $EXIT_CODE -ne 0; then
  echo "API logs: $API_LOG";
  echo "API database: $API_DB";
  echo "API config: $API_CONFIG";
  echo "API port file: $API_PORT_FILE";
  echo "API kek file: $API_KEK_FILE";
  echo "Signer logs: $API_LOG";
  echo "Signer config: $API_CONFIG";
  echo "Signer port file: $API_PORT_FILE";
  echo "Signer kek file: $API_KEK_FILE";
else
  rm -f $API_LOG 2>/dev/null
  rm -f $API_DB 2>/dev/null
  rm -f $API_CONFIG 2>/dev/null
  rm -f $API_PORT_FILE 2>/dev/null
  rm -f $API_KEK_FILE 2>/dev/null
  rm -f $SIGNER_LOG 2>/dev/null
  rm -f $SIGNER_CONFIG 2>/dev/null
  rm -f $SIGNER_PORT_FILE 2>/dev/null
  rm -f $SIGNER_KEK_FILE 2>/dev/null
fi
exit $EXIT_CODE
