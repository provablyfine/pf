#!/bin/bash
set -m

# Prepare configuration
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
#debug_sql: true
EOF

# Start api service
PYTHONUNBUFFERED=1 idb -c $API_CONFIG --port-file $API_PORT_FILE >$API_LOG 2>&1 &
API_PID=$!
trap 'kill -TERM -${API_PID} 2>/dev/null' EXIT

# wait until api service is ready
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
if test $EXIT_CODE -ne 0; then
  echo "API logs: $API_LOG";
  echo "API database: $API_DB";
  echo "API config: $API_CONFIG";
  echo "API port file: $API_PORT_FILE";
  echo "API kek file: $API_KEK_FILE";
else
  rm -f $API_LOG 2>/dev/null
  rm -f $API_DB 2>/dev/null
  rm -f $API_CONFIG 2>/dev/null
  rm -f $API_PORT_FILE 2>/dev/null
  rm -f $API_KEK_FILE 2>/dev/null
fi
exit $EXIT_CODE
