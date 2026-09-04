# Samples — copy-paste setup

Runnable starting points, so you don't hand-assemble config from prose.

| File | For | What it is |
|------|-----|------------|
| `mcp-config-human.jsonc` | Route A (person) | Paste-ready `buzz` MCP block, wire-sign mode. |
| `mcp-config-agent.jsonc` | Route B (agent) | The block `buzz agent add` writes for an agent's own identity. |
| `env.example`            | Route A | Wire-mode env vars (no secrets). |
| `example-client.mjs`     | both | Minimal MCP-stdio client: `whoami → read → post → DM`. Read-only until you flip `DO_POST`/`DO_DM`. |

## Quick start (Route A, person)

```sh
# 1. install
curl -fsSL https://raw.githubusercontent.com/ola-krutrim/buzz-mcp/main/install.sh | bash
# 2. one-time email login (opens a browser)
BUZZ_EKAM_CLIENT_ID=clt_37501bdddf3c4e43a0ff buzz-mcp-login
# 3. paste mcp-config-human.jsonc into your MCP client, OR try the raw client:
node example-client.mjs
```

`example-client.mjs` should print your identity and the last few `#buzz-main` messages —
**green means it ran.** Flip `DO_POST` / `DO_DM` at the top to exercise writes.

> These samples target the **internal** deployment (`ola.buzz.ola.in`, Ekam). Point
> `BUZZ_RELAY_HTTP` / `BUZZ_EKAM_BASE` elsewhere for another deployment.
