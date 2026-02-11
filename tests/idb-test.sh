#!/bin/bash
set -m

SERVER_CONFIG=$(mktemp --suffix .yaml)
SERVER_DB=$(mktemp --suffix .db)
SERVER_LOG=$(mktemp --suffix .log)
SERVER_PORT_FILE=/tmp/$(xxd -l 16 -p /dev/random).portfile
SERVER_KEK_FILE=$(mktemp --suffix .key)
dd if=/dev/random of=$SERVER_KEK_FILE count=1 bs=32 2>/dev/null
cat > $SERVER_CONFIG <<EOF
database_url: sqlite:///$SERVER_DB
debug: true
log_level: DEBUG
kek_filename: $SERVER_KEK_FILE
#debug_sql: true
EOF


PYTHONUNBUFFERED=1 idb -c $SERVER_CONFIG --port-file $SERVER_PORT_FILE >$SERVER_LOG 2>&1 &
SERVER_PID=$!
trap 'kill -TERM -${SERVER_PID} 2>/dev/null' EXIT

while [ ! -s "$SERVER_PORT_FILE" ]; do
  sleep 0.1
done
SERVER_PORT=$(cat $SERVER_PORT_FILE)
until curl -f -s 127.0.0.1:$SERVER_PORT/idb/directory > /dev/null; do
  sleep 0.1
done

SERVER_PORT=$SERVER_PORT cram $1
EXIT_CODE=$?

kill $SERVER_PID
if test $EXIT_CODE -ne 0; then
  echo "Server logs: $SERVER_LOG";
  echo "Server database: $SERVER_DB";
  echo "Server config: $SERVER_CONFIG";
  echo "Server port file: $SERVER_PORT_FILE";
  echo "Server kek file: $SERVER_KEK_FILE";
else
  rm -f $SERVER_LOG 2>/dev/null
  rm -f $SERVER_DB 2>/dev/null
  rm -f $SERVER_CONFIG 2>/dev/null
  rm -f $SERVER_PORT_FILE 2>/dev/null
  rm -f $SERVER_KEK_FILE 2>/dev/null
fi
exit $EXIT_CODE
