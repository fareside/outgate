# Launching Agents with outgate

`outgate` js package runs any command inside Outgate's action boundary. It sets the proxy and CA trust variables so the child process routes all HTTP traffic through Outgate automatically.

```bash
npx outgate http://127.0.0.1:9191 -- claude
npx outgate http://127.0.0.1:9191 -- codex
npx outgate http://127.0.0.1:9191 -- node agent.js
npx outgate http://127.0.0.1:9191 -- curl https://example.com
```

The agent needs no changes.

## Per-agent policies with `--agent-id`

When Outgate is configured with a policy directory and an `agents.json` or `agents.yaml` manifest, each agent gets its own named policy. Pass `--agent-id` to select which policy applies:

```bash
npx outgate --agent-id github http://127.0.0.1:9191 -- claude
npx outgate --agent-id linear http://127.0.0.1:9191 -- node agent.js
```

The agent ID is sent as the proxy auth username. Outgate looks it up in the manifest and runs the matching policy for every request that process makes. The password is ignored — use any non-empty value if configuring the proxy directly.

See [Writing policies](policies.md) for how to configure the manifest.

## What outgate injects

Downloads `/_outgate/ca.pem` into a private temp file for the duration of the child process, then sets:

```text
http_proxy, https_proxy, HTTP_PROXY, HTTPS_PROXY
all_proxy, ALL_PROXY, NODE_USE_ENV_PROXY
NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE, SSL_CERT_FILE
```

## Manual curl setup

Plain HTTP through the proxy:

```bash
curl --proxy http://127.0.0.1:9191 http://example.com
```

HTTPS through the proxy:

```bash
curl http://127.0.0.1:9191/_outgate/ca.pem -o /tmp/outgate-ca.pem
curl \
  --proxy http://127.0.0.1:9191 \
  --cacert /tmp/outgate-ca.pem \
  https://example.com
```

With a request body:

```bash
curl http://127.0.0.1:9191/_outgate/ca.pem -o /tmp/outgate-ca.pem
curl \
  --proxy http://127.0.0.1:9191 \
  --cacert /tmp/outgate-ca.pem \
  -H 'content-type: application/json' \
  -d '{"hello":"outgate"}' \
  https://httpbin.org/post
```
