# Docker Reference

## Quick start

```bash
docker run --rm \
  -p 9191:9191 \
  -v outgate-data:/data \
  ghcr.io/ukstv/outgate:latest
```

The proxy listens on `0.0.0.0:9191` inside the container. Mount a named volume at `/data` to persist the CA bundle across restarts — clients that already trust the CA will keep working.

## With a policy

```bash
docker run --rm \
  -p 9191:9191 \
  -v outgate-data:/data \
  -e GITHUB_TOKEN \
  -e INTERCEPT=/policies/github.mjs \
  -v $(pwd)/policies:/policies:ro \
  ghcr.io/ukstv/outgate:latest
```

`INTERCEPT` accepts a path to a single `.js`/`.mjs`/`.ts`/`.tsx` file or a directory of policy files. See [Writing Policies](policies.md) for how to write one.

## With a policy directory

```bash
docker run --rm \
  -p 9191:9191 \
  -v outgate-data:/data \
  -e GITHUB_TOKEN \
  -e LINEAR_TOKEN \
  -e INTERCEPT=/policies \
  -v $(pwd)/policies:/policies:ro \
  ghcr.io/ukstv/outgate:latest
```

Each file in `/policies` becomes a named policy. The proxy username selects which one runs:

```bash
curl --proxy http://github:x@127.0.0.1:9191 https://api.github.com/user
curl --proxy http://linear:x@127.0.0.1:9191 https://api.linear.app/graphql
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address inside the container |
| `PORT` | `9191` | Bind port |
| `CERTIFICATE` | `/data/outgate-root-ca.pem` | Private CA bundle path |
| `INTERCEPT` | _(none)_ | Policy file or directory |

Any additional variables are available to policy as `env.*`.

## Volumes

| Path | Purpose |
|---|---|
| `/data` | CA bundle persistence |
| `/policies` | Policy files (mount read-only with `:ro`) |

## Launching an agent through Docker

Run Outgate in one terminal, then use Membrane in another to launch the agent:

```bash
# terminal 1
docker run --rm -p 9191:9191 -v outgate-data:/data \
  -e GITHUB_TOKEN -e INTERCEPT=/policies/github.mjs \
  -v $(pwd)/policies:/policies:ro \
  ghcr.io/ukstv/outgate:latest

# terminal 2
npx outgate http://127.0.0.1:9191 -- claude
```

Membrane fetches the CA from `/_outgate/ca.pem`, writes it to a temp file, and injects the proxy and CA trust variables into the child process. The agent needs no configuration changes.

## Building locally

```bash
docker build -t outgate:local .

docker run --rm \
  -p 9191:9191 \
  -v outgate-data:/data \
  outgate:local
```
