#!/bin/bash
set -m

SERVER_CONFIG=$(mktemp --suffix .yaml)
SERVER_DB=$(mktemp --suffix .db)
SERVER_LOG=$(mktemp --suffix .log)
echo "database_url: sqlite:///$SERVER_DB" > $SERVER_CONFIG
idb -c $SERVER_CONFIG >$SERVER_LOG 2>&1 & 
SERVER_PID=$!
trap 'kill -TERM -${SERVER_PID} 2>/dev/null' EXIT

until curl -s 127.0.0.1:8000/idb/directory > /dev/null; do
  sleep 0.1
done

cram $1
EXIT_CODE=$?

kill $SERVER_PID
if test $EXIT_CODE -ne 0; then
  echo "Server logs: $SERVER_LOG";
  echo "Server database: $SERVER_DB";
  echo "Server config: $SERVER_CONFIG";
fi
exit $EXIT_CODE
