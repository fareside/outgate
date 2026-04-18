# Security Model And Transport Scope

Outgate decrypts traffic from clients that trust its generated CA certificate so
policy can authorize requests before they leave the machine.

Run it only for machines, clients, and accounts you control.

Do not install the generated CA as a long-lived system-wide trusted root unless
you are comfortable with every process on the machine trusting certificates that
can be minted by the private key in `cert/outgate-root-ca.pem`.

That file is a private CA bundle: it contains both the public CA certificate and
the private signing key. It is written with `0600` permissions on Unix-like
systems, and the default private bundle path is ignored by git. Treat that key
as authorization infrastructure: keep it scoped, private, and short-lived.

## Local Admin Endpoints

These endpoints are served by the proxy itself before forwarding:

```text
GET /_outgate/healthz
GET /_outgate/ca.pem
```

They are useful for health checks and for downloading the generated public CA
certificate from a client configured to use the proxy. `/_outgate/ca.pem` never
returns the private signing key.

## Plain HTTP Flow

1. A client sends a proxy-form request, for example `GET http://example.com/`.
2. Outgate runs JavaScript policy if configured.
3. The policy returns a `Response`, usually from `fetch(request, { redirect: "manual" })`.
4. Outgate sends that response back to the client. Any non-`Response` denies.

## HTTPS Flow

1. A client sends `CONNECT example.com:443 HTTP/1.1`.
2. Outgate replies `200 OK`, upgrades the connection, and starts a TLS server
   session on that same socket.
3. Outgate mints a leaf certificate for `example.com`, signed by the local
   Outgate CA.
4. The client accepts that leaf certificate only if it trusts the Outgate CA.
5. The browser sends ordinary HTTP/1.1 inside the TLS stream.
6. Outgate rewrites origin-form requests like `/path` to absolute upstream URIs
   like `https://example.com/path`.
7. Outgate runs policy and returns its `Response`, or denies when there is none.

## Runtime Scope

Outgate currently enforces HTTP/TLS request policy with this transport scope:

- HTTP/1.1 only.
- TLS ALPN advertises only `http/1.1`.
- Rust-only proxy mode streams request bodies into `reqwest`.
- Rust-only proxy mode streams upstream response bodies back to the client.
- JavaScript policy mode exposes request bodies as Web streams.
- JavaScript policy mode streams returned `Response.body` chunks back through a
  Hyper channel.
- Policy code can still choose to buffer by calling full-body helpers such as
  `.text()` or `.arrayBuffer()`.
- No WebSocket or raw tunnel pass-through mode.
- No certificate cache; leaf certificates are minted per `CONNECT`.
- No upstream proxy chaining.
- No HTTP/2 support.
- JavaScript interception starts a fresh Deno worker for each request.

Use this scope when choosing what traffic to route through Outgate. Very large
downloads and streaming APIs can pass through the streaming path, but policy
code that reads full bodies will buffer those bodies inside JavaScript.

## Troubleshooting

If HTTPS requests fail with certificate errors, the client does not trust the
Outgate CA used by the running proxy. Download the public cert from
`http://127.0.0.1:9191/_outgate/ca.pem`, or use the public certificate temp path
printed at startup, then configure the client to trust that public PEM.

If plain HTTP requests fail with `HTTP request missing Host header`, the client
is not sending a valid HTTP/1.1 request for proxy forwarding.

If large streaming responses hang or memory usage grows, check whether policy
code is calling full-body helpers before returning a response.
