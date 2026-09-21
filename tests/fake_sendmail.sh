#!/bin/sh
# A stand-in for sendmail: keeps the message in $FAKE_SENDMAIL_OUT, and fails if $FAKE_SENDMAIL_FAIL is set.
if [ -n "$FAKE_SENDMAIL_FAIL" ]; then
    echo "boom" >&2
    exit 1
fi
cat > "$FAKE_SENDMAIL_OUT"
