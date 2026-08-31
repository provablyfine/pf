Trigger the generic exception handler
  $ RESPONSE=$(curl -s http://127.0.0.1:$API_PORT/debug/trigger-error)
  $ echo $RESPONSE | jq '{type, title, status}'
  {
    "type": "about:blank",
    "title": "Internal Server Error",
    "status": 500
  }

Fetch method, path and backtrace from the instance URL
  $ curl -s $(echo $RESPONSE | jq -r '.instance') | jq '{method, path}'
  {
    "method": "GET",
    "path": "/debug/trigger-error"
  }
  $ curl -s $(echo $RESPONSE | jq -r '.instance') | jq -r '.backtrace'
  Traceback (most recent call last):
    .* (re)
    .*raise RuntimeError\("Triggered for testing"\).* (re)
  RuntimeError: Triggered for testing

The server log holds the same exception, trimmed to application frames by
log_filter.AppFormatter.  uvicorn logs it after the response is sent, so wait
for it to show up first.
  $ for i in $(seq 50); do grep -q "Exception in ASGI application" $API_LOG && break; sleep 0.1; done
  $ grep -c 'File "' $API_LOG
  2
  $ grep -c site-packages $API_LOG
  0
  [1]
