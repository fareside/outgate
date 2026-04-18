# Development And Architecture

## Local Development

Start the proxy:

```bash
cargo run
```

Run a command through the authorization boundary:

```bash
cargo run -p outgate-membrane -- http://127.0.0.1:9191 -- curl https://example.com
```

By default Outgate listens on `127.0.0.1:9191` and stores the generated CA in
`cert/outgate-root-ca.pem`. Startup also writes a public-only CA certificate copy
to a temp file and logs that path.

## Docker Image

Build the Outgate proxy image:

```bash
docker build -t outgate:local .
```

Run Outgate with persistent CA storage:

```bash
docker run --rm \
  --name outgate \
  -p 9191:9191 \
  -v outgate-data:/data \
  outgate:local
```

The image binds Outgate to `0.0.0.0:9191` and stores the private CA bundle at
`/data/outgate-root-ca.pem`. Keep `/data` persistent for clients that should
continue trusting the same Outgate CA across restarts.

Run the built-in GitHub action policy:

```bash
docker run --rm \
  --name outgate \
  -p 9191:9191 \
  -v outgate-data:/data \
  -e GITHUB_TOKEN \
  -e INTERCEPT=/usr/local/share/outgate/examples/github_safe_agent.mjs \
  outgate:local
```

Run a policy mounted from your working tree:

```bash
docker run --rm \
  --name outgate \
  -p 9191:9191 \
  -v outgate-data:/data \
  -v "$PWD/examples:/policies:ro" \
  -e GITHUB_TOKEN \
  -e INTERCEPT=/policies/github_safe_agent.mjs \
  outgate:local
```

## CLI

```text
outgate [OPTIONS]
```

```text
--host <HOST>                  Bind host, default 127.0.0.1, env HOST
--port <PORT>                  Bind port, default 9191, env PORT
--certificate <CERTIFICATE>   Private CA PEM bundle, default cert/outgate-root-ca.pem, env CERTIFICATE
--intercept <INTERCEPT>       JavaScript module file or directory, env INTERCEPT
```

## Architecture

The crate is split by runtime responsibility:

```text
src/main.rs        Entrypoint, tracing, server startup
src/cli.rs         Clap option definitions and defaults
src/ca.rs          Private root CA bundle persistence and leaf cert minting
src/proxy.rs       Hyper listener, CONNECT handling, forwarding
src/interceptor.rs Deno worker setup and JavaScript response mapping
src/body.rs        Hyper response body helpers
src/kv.rs          In-memory policy KV store
crates/membrane    Membrane command boundary crate
Dockerfile         Outgate proxy image
```

The structure mirrors the useful parts of the original executor crate while
leaving out Pinkey-specific state, token authorization, and admin behavior.
