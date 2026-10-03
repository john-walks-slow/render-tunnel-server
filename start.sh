#!/bin/sh
# Renders frps.toml from env, then runs frps + public gateway.
: "${FRP_TOKEN:?FRP_TOKEN env required}"
cat > /app/frps.toml <<EOF
bindPort = 18080
vhostHTTPPort = 18080
auth.token = "$FRP_TOKEN"
transport.tcpMux = true
transport.maxPoolCount = 5
log.level = "info"
EOF
/opt/frp/frps -c /app/frps.toml &
exec python3 /app/tunnel-gateway.py
