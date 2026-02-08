#!/bin/bash
set -m

SSH_AGENT_CONFIG=$(mktemp)
ssh-agent -s > $SSH_AGENT_CONFIG
source $SSH_AGENT_CONFIG

trap 'kill -TERM -${SSH_AGENT_PID} 2>/dev/null' EXIT

cram $1
EXIT_CODE=$?

kill $SSH_AGENT_PID
exit $EXIT_CODE
