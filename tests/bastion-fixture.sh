start_echo_server() {
    socat -d -d TCP-LISTEN:0,reuseaddr,fork EXEC:/bin/cat > echo-server.log 2>&1 &
    echo $! > echo-server.pid
    while ! grep -q "listening on" echo-server.log 2>/dev/null; do sleep 0.05; done
    grep "listening on" echo-server.log | grep -oE '[0-9]+$' | tail -1
}
