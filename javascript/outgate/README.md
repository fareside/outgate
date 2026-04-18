# outgate

Launch any agent or command through an [Outgate](https://github.com/ukstv/outgate) proxy. All outbound HTTP runs through your JavaScript policy — credential injection, action boundaries, audit logging.

```bash
npx outgate http://outgate-proxy.host -- claude
npx outgate http://outgate-proxy.host -- codex
npx outgate http://outgate-proxy.host -- node agent.js
npx outgate http://outgate-proxy.host -- curl https://example.com
```

Downloads the proxy CA certificate, injects proxy and trust variables, starts the command. The agent needs no changes.

Use `--agent-id` to select a named policy from the server's `agents.json` manifest:

```bash
npx outgate --agent-id github-triage http://outgate-proxy.host -- claude
npx outgate --agent-id linear-wizard http://outgate-proxy.host -- node agent.js
```

## Injected variables

```text
http_proxy, https_proxy, HTTP_PROXY, HTTPS_PROXY
all_proxy, ALL_PROXY, NODE_USE_ENV_PROXY
NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE, SSL_CERT_FILE
```

## Library

```ts
import { runMembrane } from "outgate";

const code = await runMembrane({
  proxyUrl: "http://127.0.0.1:9191",
  agentId: "github-triage",        // optional: selects a named policy
  command: ["node", "agent.js"]
});

process.exit(code);
```

## Development

```bash
npm install
npm test
```
