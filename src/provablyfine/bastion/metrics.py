import prometheus_client

BYTES_FORWARDED = prometheus_client.Counter(
    "bastion_bytes_forwarded_total",
    "Bytes forwarded through tunnels",
    ["direction"],
)

CONNECTIONS_ACTIVE = prometheus_client.Gauge(
    "bastion_connections_active",
    "Currently active connections",
    ["connection_type"],
)

CONNECTIONS_TOTAL = prometheus_client.Counter(
    "bastion_connections_total",
    "Total connections opened since process start",
    ["connection_type"],
)
