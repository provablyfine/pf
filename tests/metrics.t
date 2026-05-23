Metrics endpoint returns prometheus text format
  $ curl -s -o /dev/null http://127.0.0.1:$API_PORT/debug/trigger-error
  $ curl -s http://127.0.0.1:$API_PORT/metrics | grep 'http_requests_total{' | head -1
  http_requests_total{.*} [0-9.]+ (re)
  $ curl -s http://127.0.0.1:$API_PORT/metrics | grep 'http_request_duration_seconds_count{' | head -1
  http_request_duration_seconds_count{.*} [0-9.]+ (re)

Metrics endpoint itself is tracked
  $ curl -s http://127.0.0.1:$API_PORT/metrics > /dev/null
  $ curl -s http://127.0.0.1:$API_PORT/metrics | grep 'http_requests_total.*path="/metrics"'
  http_requests_total{.*path="/metrics".*} [0-9.]+ (re)
