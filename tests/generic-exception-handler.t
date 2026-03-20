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
