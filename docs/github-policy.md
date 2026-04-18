# GitHub Safe-Agent Policy

The included GitHub policy lets an agent open issues and comment on pull
requests while blocking repo deletion, secret changes, deploy-key edits, and
unknown outbound hosts.

Start Outgate with the GitHub action policy:

```bash
GITHUB_TOKEN=ghp_example cargo run -- --intercept examples/github_safe_agent.mjs
```

Then run an agent or command through Membrane:

```bash
cargo run -p outgate-membrane -- http://127.0.0.1:9191 -- curl \
  https://api.github.com/repos/octocat/Hello-World
```

Allowed action, with the token injected by Outgate rather than exposed to the
client process:

```bash
cargo run -p outgate-membrane -- http://127.0.0.1:9191 -- curl \
  -X POST \
  -H 'content-type: application/json' \
  -d '{"title":"Agent-created issue","body":"Created through Outgate policy."}' \
  https://api.github.com/repos/OWNER/REPO/issues
```

Blocked destructive action:

```bash
cargo run -p outgate-membrane -- http://127.0.0.1:9191 -- curl \
  -X DELETE \
  https://api.github.com/repos/OWNER/REPO
```

The example policy logs one JSON audit line per decision:

```json
{
  "outgate": "github_safe_agent",
  "requestId": "7d4a5d5e-3d4a-4a61-9a9d-b4cc0ff30b7d",
  "method": "DELETE",
  "host": "api.github.com",
  "path": "/repos/OWNER/REPO",
  "decision": "block",
  "reason": "destructive GitHub deletes are blocked"
}
```

This is the core Outgate shape for GitHub:

```text
Agent has no GitHub token
Membrane launches the agent with Outgate proxy and CA trust
Agent sends an HTTP request through Outgate
Outgate evaluates method, host, path, body, and context
Outgate injects the real credential only if policy allows the action
Outgate returns a clear deny response before dangerous requests leave
```
