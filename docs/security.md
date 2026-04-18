# Security Model and CA Trust

Outgate is a local TLS MITM proxy. It decrypts HTTPS traffic so policy can inspect it before it leaves the machine.

## How it works

When a client connects to Outgate and sends a `CONNECT` request, Outgate:

1. Replies `200 OK` and upgrades the connection.
2. Mints a leaf TLS certificate for the target hostname, signed by the Outgate CA.
3. Presents that certificate to the client.
4. The client accepts it only if it trusts the Outgate CA.
5. Policy runs against the decrypted request; if it returns a `Response`, Outgate forwards it upstream.

For plain HTTP (non-CONNECT), Outgate reads the request directly and runs policy before forwarding.

## The CA bundle

Outgate generates a private root CA on first run and writes it to `cert/outgate-root-ca.pem` (or `/data/outgate-root-ca.pem` in Docker). This file contains **both the public CA certificate and the private signing key**. It is written with `0600` permissions on Unix.

Treat this file as authorization infrastructure. Anyone with the private key can sign certificates for any hostname and MITM any TLS connection from a client that trusts the CA.

- Do not commit it to version control. The default path is in `.gitignore`.
- Do not install it as a long-lived system-wide trusted root.
- Keep it scoped to the machines and accounts you control.
- Rotate it by deleting the file and restarting; Outgate will generate a new one.

## Downloading the public CA

The public CA certificate (without the private key) is available at:

```
GET http://127.0.0.1:9191/_outgate/ca.pem
```

This endpoint always returns the public cert only, never the private key. Membrane uses this endpoint to fetch and install the CA automatically for child processes.

To configure a client manually:

```bash
curl -o outgate-ca.pem http://127.0.0.1:9191/_outgate/ca.pem
```

Then point your HTTP client at the proxy and trust that PEM file. The startup log also prints a temp file path for the public cert.

## Scope

Outgate intercepts HTTP/1.1 only. Current limitations:

- No HTTP/2 or HTTP/3.
- No WebSocket pass-through.
- No upstream proxy chaining.
- No certificate caching; leaf certs are minted per `CONNECT`.
- JavaScript policy workers start fresh for each request.

Large streaming responses pass through the streaming path. Policy code that calls `.text()` or `.arrayBuffer()` buffers the full body in memory.

## Who to run this for

Run Outgate only for processes and accounts you control. Do not use it to intercept traffic from other users, other machines, or accounts you are not authorised to monitor.

The typical use case is wrapping AI agents running locally: the agent is launched through Membrane, which sets the proxy and CA trust variables automatically. The agent never holds real credentials and cannot bypass the policy.
