# quic-frp

A fast, lightweight reverse proxy built on QUIC protocol for exposing local services behind NAT or firewall to the internet. Similar to [rathole](https://github.com/rapiz1/rathole) but uses QUIC for the tunnel transport.

## Features

- **QUIC Transport**: Multiplexed streams over a single UDP connection with built-in encryption
- **NAT Traversal**: Client initiates connection, allowing services behind NAT/firewall to be exposed
- **Authentication**: Token-based and TLS certificate-based client authentication
- **Hot Reload**: Client configuration can be modified at runtime - services are automatically registered/unregistered
- **Connection Multiplexing**: All TCP connections share a single QUIC connection, reducing overhead
- **Auto-Reconnect**: Client automatically reconnects with exponential backoff on connection loss
- **Zero-Copy Design**: Efficient data forwarding using shared references and lock-free data structures
- **Graceful Cleanup**: Proper resource cleanup when connections drop or services are unregistered

## Architecture

```
                    Internet
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│                  Public Server                       │
│                                                      │
│   TCP:80 ───┐                                        │
│   TCP:443 ──┼──► QUIC Endpoint (UDP:4433)            │
│   TCP:8080 ─┘         │                              │
└───────────────────────│──────────────────────────────┘
                        │ QUIC Connection
                        │ (multiplexed streams)
                    [NAT/Firewall]
                        │
┌───────────────────────│──────────────────────────────┐
│                  Client (behind NAT)                 │
│                       │                              │
│              QUIC Client ◄──┘                        │
│                   │                                  │
│     ┌─────────────┼─────────────┐                    │
│     ▼             ▼             ▼                    │
│  127.0.0.1:80  127.0.0.1:443  192.168.1.10:8080      │
│  (web server)  (https)        (internal API)         │
└──────────────────────────────────────────────────────┘
```

### Protocol Design

- **Control Plane**: Long-lived bidirectional QUIC stream for service registration/unregistration
- **Data Plane**: New QUIC stream opened for each proxied TCP connection
- **Framing**: 4-byte length prefix + bitcode payload for control messages, 2-byte port header for data streams

## Installation

### From Source

```bash
git clone https://github.com/vjyanand/quic-frp.git
cd quic-frp
cargo build --release
```

## Usage

### Server Setup (Public VPS)

#### Basic Configuration

1. Create `server.toml`:

```toml
[server]
listen_addr = "0.0.0.0:4433"
```

2. Run the server:

```bash
RUST_LOG=info ./quic-frp -c server.toml
```

The server will:
- Listen on UDP port 4433 for QUIC connections from clients
- Dynamically open TCP ports as clients register services

#### With Token Authentication

1. Create `server.toml`:

```toml
[server]
listen_addr = "0.0.0.0:4433"
token = "your-secret-token-here"
```

2. Run the server:

```bash
RUST_LOG=info ./quic-frp -c server.toml
```

#### With Custom TLS Certificates

1. Create `server.toml`:

```toml
[server]
listen_addr = "0.0.0.0:4433"
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
token = "your-secret-token-here"  # Optional but recommended
```

2. Run the server:

```bash
RUST_LOG=info ./quic-frp -c server.toml
```

### Client Setup (Behind NAT)

#### Basic Configuration

1. Create `client.toml`:

```toml
[client]
remote_addr = "your-server.com:4433"
prefer_ipv6 = false
retry_interval = 5

[[client.services]]
service_name = "web"
local_addr = "127.0.0.1:8080"
remote_port = 80

[[client.services]]
service_name = "ssh"
local_addr = "127.0.0.1:22"
remote_port = 2222

[[client.services]]
service_name = "api"
local_addr = "192.168.1.100:3000"
remote_port = 3000
```

2. Run the client:

```bash
RUST_LOG=info ./quic-frp -c client.toml
```

#### With Token Authentication

1. Create `client.toml`:

```toml
[client]
remote_addr = "your-server.com:4433"
token = "your-secret-token-here"
prefer_ipv6 = false
retry_interval = 5

[[client.services]]
service_name = "web"
local_addr = "127.0.0.1:8080"
remote_port = 80
compression = true
```

2. Run the client:

```bash
RUST_LOG=info ./quic-frp -c client.toml
```

#### With TLS Client Certificate

1. Create `client.toml`:

```toml
[client]
remote_addr = "your-server.com:4433"
prefer_ipv6 = false
retry_interval = 5

[client.tls]
cert = "/path/to/client-cert.pem"
key = "/path/to/client-key.pem"

[[client.services]]
service_name = "web"
local_addr = "127.0.0.1:8080"
remote_port = 80
```

2. Run the client:

```bash
RUST_LOG=info ./quic-frp -c client.toml
```

The client will:
- Connect to the server over QUIC
- Authenticate using the configured token or certificate
- Register all configured services
- Forward incoming connections to local services

### Hot Reload

Modify `client.toml` while the client is running. Changes are automatically detected:

- **Add service**: New TCP listener opens on server
- **Remove service**: TCP listener closes on server
- **Modify local_addr**: Future connections route to new address

## Configuration Reference

### Server Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listen_addr` | String | Yes | UDP address to listen on (e.g., `"0.0.0.0:4433"`) |
| `token` | String | No | Shared secret token for client authentication |
| `cert` | String | No | Path to TLS certificate file (PEM format) |
| `key` | String | No | Path to TLS private key file (PEM format) |

### Client Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `remote_addr` | String | Yes | - | Server address (`"host:port"`) |
| `token` | String | No | - | Authentication token (must match server) |
| `prefer_ipv6` | Boolean | No | `false` | Prefer IPv6 when resolving server address |
| `retry_interval` | Integer | No | `5` | Initial retry interval in seconds |
| `services` | Array | Yes | - | List of services to expose |
| `tls` | Object | No | - | TLS client certificate configuration |
| `compression` | Boolean | No | `false` | compress traffic / data plane |

### TLS Client Certificate Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cert` | String | Yes | Path to client certificate file (PEM format) |
| `key` | String | Yes | Path to client private key file (PEM format) |

### Service Definition

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service_name` | String | Yes | Human-readable name for logging |
| `local_addr` | String | Yes | Local service address (`"host:port"`) |
| `remote_port` | Integer | Yes | Public port on server |
| `prefer_ipv6` | Boolean | No | Override global IPv6 preference for this service |

## Logging

Control log verbosity with `RUST_LOG` environment variable:

```bash
# Minimal logging
RUST_LOG=warn ./quic-frp -c (client|server).toml

# Standard logging
RUST_LOG=info ./quic-frp -c (client|server).toml

# Debug logging
RUST_LOG=debug ./quic-frp -c (client|server).toml

# Trace logging (very verbose)
RUST_LOG=trace ./quic-frp -c (client|server).toml
```

## Security Considerations

- **TLS**: QUIC provides built-in TLS 1.3 encryption for all traffic
- **Authentication**: Use token-based or certificate-based authentication to prevent unauthorized clients
- **Self-Signed Certificates**: Server generates self-signed certificates by default. For production, use proper certificates via the `cert` and `key` options
- **Token Security**: Choose a strong, random token and keep it secret. Tokens are transmitted securely over the QUIC connection
- **Firewall**: Only expose necessary ports on the server (UDP port for QUIC, TCP ports for services)
- **Network Trust**: Even with authentication, ensure your server is properly secured and monitored

### Generating TLS Certificates

For production use with custom certificates:

```bash
# Generate a self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Generate client certificate (for mutual TLS)
openssl req -x509 -newkey rsa:4096 -keyout client-key.pem -out client-cert.pem -days 365 -nodes
```

For production, obtain certificates from a trusted Certificate Authority (CA) like Let's Encrypt.

## Performance

- **Multiplexing**: Single QUIC connection handles all services and connections
- **Keep-Alive**: 5-second keep-alive prevents connection drops
- **Lock-Free**: Uses `DashMap` for concurrent service registry access
- **Zero-Copy**: Efficient stream forwarding without unnecessary allocations
- **Async Runtime**: Built on Tokio for high-performance async I/O

## Work in Progress

> ⚠️ **This project is under active development. The following features are planned or in progress:**

### Planned Features
- [ ] **Connection Pooling**: Reuse QUIC streams for better performance
- [ ] **Metrics/Monitoring**: Prometheus metrics endpoint

## Comparison with Alternatives

| Feature | quic-frp | rathole | frp |
|---------|------------|---------|-----|
| Transport | QUIC | TCP/TLS | TCP/KCP/QUIC |
| Multiplexing | Native | Manual | Manual |
| Hot Reload | ✓ | ✓ | ✓ |
| Token Auth | ✓ | ✓ | ✓ |
| TLS Cert Auth | ✓ | ✗ | ✗ |
| HTTP Features | ✗ | ✗ | ✓ |
| Complexity | Low | Low | High |

## Troubleshooting

### Authentication Failed

- Ensure the `token` matches exactly on both client and server
- If using client certificates, verify the cert and key paths are correct
- Check that certificate files are readable by the process

### Connection Refused

- Ensure server is running and UDP port 4433 is open
- Check firewall rules on both server and client
- Verify the server address is correct in client config

### Service Not Accessible

- Verify local service is running on configured `local_addr`
- Check server logs for TCP listener binding errors
- Ensure `remote_port` is not already in use on server
- Confirm authentication is successful (check logs)

### Frequent Reconnections

- Increase `retry_interval` in client config
- Check network stability
- Review server logs for connection errors
- Verify authentication credentials are correct

### Certificate Errors

- Ensure certificate and key files are in PEM format
- Check file permissions on certificate/key files
- Verify certificate hasn't expired
- For client certificates, ensure they're properly signed

## Dependencies

- [tokio](https://github.com/tokio-rs/tokio) - Async runtime
- [quinn](https://github.com/quinn-rs/quinn) - QUIC implementation in Rust
- [dashmap](https://github.com/xacrimon/dashmap) - Lock-free concurrent hashmap
- [bitcode](https://github.com/SoftbearStudios/bitcode) - Binary serialization
- [notify](https://github.com/notify-rs/notify) - File system watcher for hot reload
- [rustls](https://github.com/rustls/rustls) - Modern TLS library

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
