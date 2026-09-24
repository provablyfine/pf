#!/bin/sh
# A stand-in for sendmail: keeps the message in $FAKE_SENDMAIL_OUT, and fails if $FAKE_SENDMAIL_FAIL is set.
# $FAKE_SENDMAIL_DELAY_SECONDS, if set, sleeps first: it stands in for a slow outbound call.
if [ -n "$FAKE_SENDMAIL_DELAY_SECONDS" ]; then
    sleep "$FAKE_SENDMAIL_DELAY_SECONDS"
fi
if [ -n "$FAKE_SENDMAIL_FAIL" ]; then
    echo "boom" >&2
    exit 1
fi
cat > "$FAKE_SENDMAIL_OUT"
