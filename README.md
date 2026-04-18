# Outgate

**Programmable action boundary for AI agents.**

Your agent can open a GitHub issue. It cannot delete a repo. That's not a setting — that's policy. Every action an agent takes on the internet runs through JavaScript you control. What isn't explicitly allowed is blocked.

The agent never touches real credentials. Destructive actions never reach the upstream service. Works with any agent, any framework, any cloud — no code changes required.

---

## What you get

**Agents that can't go rogue.**
Define exactly what each agent is allowed to do — which services, which operations, which payloads. Anything outside that boundary is blocked before it leaves your machine.

**Credentials that stay yours.**
Your API keys, tokens, and secrets live in Outgate. The agent never sees them. They're injected only into requests that pass policy — and only at the moment they're needed.

**Full visibility into what agents actually did.**
Every outbound call runs through policy code you control. Log what matters, in whatever format your team needs. No black boxes.

**A yes from your security team.**
Agents with unconstrained API access are a hard sell internally. Outgate gives you the controls that make deployment possible: explicit action boundaries, credential isolation, audit trail.

---

## How it works

```bash
npx outgate http://your-outgate-instance -- claude
npx outgate http://your-outgate-instance -- node agent.js
```

The agent runs normally. Outgate intercepts every outbound call. Your policy — a short JavaScript function — sees each request and decides what happens.

```js
export default async function intercept(request, env, ctx) {
  const url = new URL(request.url);

  if (url.hostname !== "api.github.com") return deny();
  if (request.method === "DELETE") return deny();

  // Inject real token — agent never sees it
  const headers = new Headers(request.headers);
  headers.set("authorization", `Bearer ${env.GITHUB_TOKEN}`);
  return fetch(request, { headers, redirect: "manual" });
}
```

Policy is JavaScript. It can read the request body, call a secrets manager, check a rate limit, log to your audit system — anything.

---

## Docs

- [Writing policies](docs/policies.md)
- [Launching agents with outgate](docs/outgate.md)
- [Per-agent policies](docs/outgate.md#per-agent-policies-with---agent-id)
- [Security model](docs/security.md)
- [Docker reference](docs/docker.md)
- [Building from source](docs/development.md)

---

## License

Not yet assigned.
