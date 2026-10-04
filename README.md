# quic-frp

A lightweight reverse proxy that exposes TCP services behind NAT or a firewall through a public server, using QUIC as the tunnel transport. Similar to [rathole](https://github.com/rapiz1/rathole) / [frp](https://github.com/fatedier/frp), but every proxied connection is a stream on one multiplexed QUIC connection.

## Features

- **QUIC transport**: one UDP connection carries all services and TCP connections, with TLS 1.3 built in
- **NAT traversal**: the client dials out, so services behind NAT/firewalls can be exposed
- **Token authentication**: checked after the TLS handshake, never sent in cleartext
- **Hot reload**: edit the client config while it runs; services are added, removed or updated live
- **Auto-reconnect**: exponential backoff; a reconnecting client reclaims its ports from its stale connection
- **Optional compression**: per-service snappy compression, skipped automatically for incompressible data
- **IPv4 and IPv6** for both the tunnel and the public ports

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

## Installation

Requires the Rust toolchain pinned in `rust-toolchain`.

```bash
git clone https://github.com/vjyanand/quic-frp.git
cd quic-frp
cargo build --release
```

The same binary runs as server or client, depending on whether the config file has a `[server]` or `[client]` section:

```bash
./quic-frp server.toml
./quic-frp client.toml
```

## Quick Start

**Server** (public host), `server.toml`:

```toml
[server]
listen_addr = "0.0.0.0:4433"
token = "change-me-to-a-long-random-string"
```

**Client** (behind NAT), `client.toml`:

```toml
[client]
remote_addr = "your-server.example.com:4433"
token = "change-me-to-a-long-random-string"

# The server above uses a self-signed certificate, see "TLS" below.
[client.tls]
mode = "skip_verification"

[[client.services]]
name = "web"
local_addr = "127.0.0.1:8080"
remote_port = 80

[[client.services]]
name = "ssh"
local_addr = "127.0.0.1:22"
remote_port = 2222
```

Connections to `your-server.example.com:80` now reach `127.0.0.1:8080` on the client machine, and port `2222` reaches its SSH server.

Open UDP `4433` and each `remote_port` (TCP) in the server's firewall.

## TLS

Without `cert`/`key`, the server generates a fresh self-signed certificate (for `localhost`) at every start. Clients cannot verify it, so pick one of:

| Server | Client `[client.tls]` | Notes |
|--------|-----------------------|-------|
| `cert` + `key` from a public CA (e.g. Let's Encrypt) | `mode = "system_root"` (default) | Recommended. The certificate must match the host in `remote_addr`, or set `server_name`. |
| `cert` + `key`, your own CA or self-signed | `mode = "trust_cert"`, `cert_path = "/path/to/ca-or-cert.pem"` | Pin the certificate the server uses. |
| No `cert`/`key` | `mode = "skip_verification"` | Encrypted but unauthenticated: vulnerable to man-in-the-middle. Rely on the token and use it for testing only. |

Generate a self-signed certificate for `trust_cert`:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=your-server.example.com" \
  -addext "subjectAltName=DNS:your-server.example.com"
```

## Configuration Reference

### `[server]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listen_addr` | String | Yes | UDP address for QUIC, e.g. `"0.0.0.0:4433"` or `"[::]:4433"` |
| `token` | String | No | Shared secret clients must present. Without it, any client may register ports. |
| `cert` | Path | No | Certificate chain (PEM). Needs `key`. |
| `key` | Path | No | Private key (PEM). Needs `cert`. |

### `[client]`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `remote_addr` | String | Yes | | Server address, `"host:port"` |
| `token` | String | No | | Must match the server's `token` |
| `server_name` | String | No | host of `remote_addr` | Name the server certificate is verified against |
| `prefer_ipv6` | Bool | No | `false` | Use an IPv6 address when `remote_addr` resolves to both |
| `retry_interval` | Integer | No | `5` | First reconnect delay in seconds; doubles per failure up to 30s |
| `tls` | Table | No | `system_root` | See [TLS](#tls) |
| `services` | Array | Yes | | Services to expose, see below |

### `[[client.services]]`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | String | Yes | | Label used in logs and acknowledgements |
| `local_addr` | String | Yes | | Address the client forwards to, `"host:port"` |
| `remote_port` | Integer | Yes | | Public TCP port opened on the server |
| `compression` | Bool | No | `false` | Snappy-compress this service's traffic in the tunnel. Helps for text-heavy plain protocols; useless for TLS/SSH or already-compressed data. |
| `prefer_ipv6` | Bool | No | `false` | Server listens on `[::]` instead of `0.0.0.0` for this port |

## Hot Reload

The client watches its config file. On change:

- **Service added**: registered and its port opened on the server
- **Service removed**: unregistered and its port closed
- **`local_addr` changed**: new connections go to the new address; open ones are untouched
- **`compression`, `prefer_ipv6` or `name` changed**: the service is re-registered, which closes connections open on that port

Connection settings (`remote_addr`, `token`, `tls`, …) need a client restart.

## Reconnects and Port Ownership

Each client process picks a random session id and sends it (with the token) when it connects. If the connection drops and the same process reconnects, even from a different IP, it takes its ports back from the stale connection immediately.

A *different* process asking for a port that is still held, for example a restarted client while its old connection has not yet timed out (about 10s), is refused. The client retries refused registrations every 5 seconds, so the service comes back on its own. Two clients configured with the same `remote_port` do not steal from each other: the second keeps logging a conflict.

## Logging

The default level is `info`. Override it with `RUST_LOG`:

```bash
RUST_LOG=debug ./quic-frp client.toml
RUST_LOG=warn,quic_frp=info ./quic-frp server.toml
```

## Protocol

Not compatible across protocol revisions. Client and server must be built from the same revision (enforced through ALPN `quic-proxy-<major>-r<revision>`).

- **Control stream**: opened by the client. Frames are a 2-byte big-endian length followed by a [bitcode](https://github.com/SoftbearStudios/bitcode) payload (max 65535 bytes). The first frame is `ClientHello { token, session_id }`, then `RegisterService` / `DeregisterService` requests, each answered by an acknowledgement.
- **Data streams**: one per public TCP connection, opened by the server. A 3-byte header (port, compression flag) is followed by the raw bytes or, with compression, by frames `[kind: u8][len: u32][payload]` where each frame carries at most 64 KiB of original data, snappy-compressed or raw if it would not shrink.

## Security Notes

- Use a long random `token`: it is the only thing stopping anyone from opening ports on your server.
- Prefer a CA-signed or pinned certificate over `skip_verification`, which allows a man-in-the-middle to capture the token.
- Only `remote_port`s registered by clients are opened, but they listen on all interfaces. Firewall the server accordingly.

## Development

```bash
cargo test                                         # unit + loopback end-to-end tests
cargo test --release bench_throughput -- --ignored --nocapture   # tunnel throughput benchmark
cargo build --release --features hotpath           # build with hotpath profiling
```

Source layout:

| Path | Purpose |
|------|---------|
| `src/main.rs`, `src/cli.rs`, `src/config.rs` | Entry point, CLI, config file parsing |
| `src/client/` | `transport` (resolve + connect), `session` (control stream, registration retries), `reload` (hot reload), `streams` (data streams to local services), `tls` (server verification), `backoff` |
| `src/server/` | `connection` (auth, control), `registry` (port ownership), `listener` (public TCP ports), `transport` (QUIC/UDP setup), `tls` (server certificate) |
| `src/shared/` | `protocol` (messages, framing, ALPN), `proxy` (TCP ⇄ QUIC forwarding, compression), `tls` (PEM loading) |
| `src/e2e_tests.rs` | End-to-end tests running server and client over loopback |

## Troubleshooting

**Client keeps reconnecting with `unauthorized`**: the `token` differs between client and server.

**`invalid peer certificate` / `UnknownIssuer`**: the client cannot verify the server certificate. See [TLS](#tls); for a self-signed server use `trust_cert` or `skip_verification`.

**`registration failed … port N conflict`**: another client (or an older connection of this one that has not timed out yet) owns the port. Wait for the retry, or change `remote_port`.

**`registration failed … failed to bind`**: the port is in use by another program on the server, or is privileged (< 1024) and the server lacks permission.

**Port open but connections close immediately**: the client cannot reach `local_addr`. Check the service is running and `RUST_LOG=debug` client logs.

## License

MIT License - see [LICENSE](LICENSE) for details.
