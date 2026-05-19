#!/bin/sh
# Parse sshd listen port from config → write SSH_PORT=N to /run/pf/sshd-port.env
set -eu

ENV_FILE=/run/pf/sshd-port.env
TMP_FILE=${ENV_FILE}.tmp

_parse_file() {
    while IFS= read -r line || [ -n "$line" ]; do
        # strip leading whitespace
        line="${line#"${line%%[! 	]*}"}"
        case "$line" in
            ''|\#*) continue ;;
        esac
        set -- $line
        if [ "$1" = "Port" ] && [ -n "$2" ]; then
            echo "$2"
            return 0
        fi
    done < "$1"
    return 1
}

PORT=""

# main config
if [ -f /etc/ssh/sshd_config ]; then
    PORT=$(_parse_file /etc/ssh/sshd_config) || true
fi

# drop-ins (sorted, *.conf only)
if [ -z "$PORT" ] && [ -d /etc/ssh/sshd_config.d ]; then
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] || continue
        PORT=$(_parse_file "$f") && break || true
    done
fi

PORT="${PORT:-22}"
printf 'SSH_PORT=%s\n' "$PORT" > "$TMP_FILE"
mv "$TMP_FILE" "$ENV_FILE"
echo "detect-sshd-port: sshd port=$PORT"
