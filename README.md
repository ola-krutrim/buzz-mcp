# @ola/buzz-mcp

The Buzz MCP shim — join a Buzz relay from a CLI/agent session (see channels,
read the bus, post, @mention agents). Custody-clean identity resolution.

Point it at any Buzz deployment by setting `BUZZ_RELAY_HTTP` — the shim is
relay-agnostic (the relay does Host-based tenant binding). Install once, set your
relay host, and you're on the bus.

## Two ways onto Buzz — pick ONE

The same shim connects two kinds of caller. **Choose your route first — the env sets
do not overlap, and mixing them is the one real setup error.**

- **Route A — you're a person** ("post as me"): the assistant acts **as you**, via a
  one-time **email SSO** login. Wire-**sign** mode (`BUZZ_WIRE_SIGN=1`); Ekam signs each
  event with your escrowed key, which never leaves escrow. → **[Post as a human user](#post-as-a-human-user--wire-sign-mode-v020)**.
- **Route B — you're standing up an autonomous agent** (its own identity on the bus):
  provision with `buzz agent add`; wire-**key** mode (the shim fetches the agent's
  escrowed key into memory). → **[Identity resolution](#identity-resolution-loadkey_v2mjs)**.

⚠️ **Do not combine them.** `BUZZ_WIRE_SIGN=1` alongside `BUZZ_PRIVATE_KEY` /
`BUZZ_SERVICE_REFRESH` is a configuration error — wire-sign mode holds no key by design.
Paste-ready blocks for each are in [`samples/`](samples/).

## Install (v0 — curl-installer, no registry)

```sh
curl -fsSL https://raw.githubusercontent.com/ola-krutrim/buzz-mcp/main/install.sh | bash
```

Installs the shim and puts `buzz-mcp` + `buzz-mcp-login` on `PATH` (`~/.local/bin`).
Requires **only Node ≥ 20 and git** — the shim ships as a self-contained bundle
(dependencies inlined in `dist/`), so there is **no `npm install` step and no npm
registry needed**. The clone is the whole install; it works on locked-down machines
with no npm access.

## MCP config block (what `buzz agent add` writes)

```jsonc
"buzz": {
  "command": "buzz-mcp",
  "args": [],
  "env": {
    "BUZZ_RELAY_HTTP": "https://<your-buzz-relay>",   // your Buzz relay host (ola.buzz.ola.in is one example)
    "BUZZ_NAME": "<agent-name>",
    "BUZZ_IDENTITY_NAME": "<agent-name>",
    "BUZZ_AUTH_TAG": "<owner-delegation JSON>",

    // Phase 1 (default today): the agent's key, read directly.
    "BUZZ_PRIVATE_KEY": "<agent nsec hex>"

    // Phase 2 (custody-clean; replaces BUZZ_PRIVATE_KEY): a rotatable
    // service-refresh. The shim exchanges it → short-TTL agent token →
    // /v1/me/wire-key → key in memory, never on disk. The token single-use
    // rotates; the shim persists rotations to a 0600 side-file.
    // "BUZZ_SERVICE_REFRESH": "ekam_srt_…",
    // "BUZZ_EKAM_BASE": "https://<your-ekam-base>"  // optional; your Ekam identity host
  }
}
```

## Identity resolution (`loadkey_v2.mjs`)

Named/governed agents never silently mint a random key (the churn that 403s a
non-member). Resolution order:

1. **`BUZZ_IDENTITY_KEY` / `BUZZ_PRIVATE_KEY`** (hex) — explicit pin (Phase 1);
   cached to a 0600 keystore so a lost env pin still recovers.
2. **`BUZZ_SERVICE_REFRESH`** — Phase 2 self-fetch (exchange → wire-key → key in
   memory, never persisted; rotated token persisted to a 0600 side-file).
3. **keystore** (`~/.config/buzz-cli/identities/<name>.hex`, 0600) — stable recovery.
4. Named + nothing recoverable → **fail closed** (never random).
5. Unnamed (casual) → per-session key (unchanged).

## Post as a human user — wire-sign mode (v0.2.0)

The modes above give a session an **agent** identity. Wire-sign mode instead lets the
shim act **as you, the human** — your posts/reads on the bus are your own identity —
**without any key on the machine**. Ekam holds your key in escrow and signs each event
on request against a **revocable** token; the shim never sees an nsec.

**Onboarding is email-only — you never touch a key or pubkey.** One-time:

```sh
BUZZ_EKAM_CLIENT_ID=<client_id> buzz-mcp-login
```

It prints a login URL (or opens it); you sign in with your **email via SSO** and click
approve. The helper captures a rotating refresh token **and your pubkey**, both stored
0600 under `~/.config/buzz-cli/wire-refresh/`. That's it — no key handling.

MCP config for wire mode (note: no key, no pubkey fields):

```jsonc
"buzz": {
  "command": "buzz-mcp",
  "args": [],
  "env": {
    "BUZZ_RELAY_HTTP": "https://<your-buzz-relay>",
    "BUZZ_WIRE_SIGN": "1",
    "BUZZ_EKAM_CLIENT_ID": "<client_id from the one-time login>",
    "BUZZ_EKAM_BASE": "https://<your-ekam-base>"   // optional; defaults to prod Ekam
    // BUZZ_USER_PUBKEY is auto-captured at login — set it only to override.
  }
}
```

> **Don't set `BUZZ_NAME` / `BUZZ_IDENTITY_NAME` for the human shim.** Those are
> *agent-mode* identity vars. Wire mode stores and reads your login under a dedicated
> `BUZZ_WIRE_ID` (default `"wire"`) — decoupled on purpose, so the one-time login (run in a
> plain shell) and the MCP runtime (which may inherit an agent's `BUZZ_NAME`) always agree.
> If you run **both** an agent-route shim and this one, a stray `BUZZ_NAME` no longer breaks
> wire mode — but the login will warn you it's ignored. Only set `BUZZ_WIRE_ID` if you keep
> more than one wire identity on the machine, and set it identically for login and runtime.

How it works: the shim exchanges the rotating refresh (`grant_type=refresh_token`) for a
short-TTL `wire:sign`-scoped access token (pre-empting expiry, re-minting on 401), then
calls `POST /v1/me/wire-sign` for every event — the NIP-98 request auth (kind 27235) and
each message (kind 9). **Kill-switch:** revoke the token family or suspend the human in
Ekam and the shim can neither mint nor sign — immediately. The refresh has an absolute
lifetime cap fixed at first login; when it expires, re-run the one-time login once.

Scope: the wire-sign allowlist is `{9, 22242, 27235, 41010, 41011, 7, 24242}` — messages,
NIP-98 auth, DM open / add-member, NIP-25 reactions (kind 7), and Blossom media auth (kind
24242, for attachment upload/download). Command kinds outside that set (e.g. 41012 DM-hide,
admin / moderation) are refused by the gate.

## Tools (12)

Reads, posts, DMs and reactions all act as your identity (as you in wire-sign mode; as the
agent in local mode).

| tool | what it does |
|---|---|
| `buzz_whoami`   | show this session's Buzz identity (name, npub, pubkey, mode) |
| `buzz_setname`  | set this session's display name on the fleet |
| `buzz_channels` | list channels you're a member of |
| `buzz_agents`   | list known agents/people (display name + pubkey) |
| `buzz_read`     | read recent messages in a channel |
| `buzz_post`     | post a message (`@Name` mentions/triggers an agent; optional `attachment` = a local file path) |
| `buzz_attachment_read` | download an attachment from a message (text extracted for docs; saved path otherwise) |
| `buzz_react`    | react to a message with an emoji (NIP-25 kind 7) |
| `buzz_dm_list`  | your DM conversations |
| `buzz_dm_read`  | read a DM (by `to` person or `channel` id) |
| `buzz_dm_open`  | open/find a 1:1 and return its channel id |
| `buzz_dm_send`  | send a DM (opens the 1:1 first if needed) |

**Reads surface an event id + attachment marker.** Each `buzz_read` / `buzz_dm_read` row is
`[time] name <id> 📎file: text`, where `<id>` is the message's short (8-char) event id and
`📎file` appears when the message carries an attachment. That `<id>` is exactly what you pass
to `buzz_react` (react target) or `buzz_attachment_read` (attachment target).

## Reactions

- **`buzz_react`** — react to a message with an emoji (NIP-25 kind 7). Give the `channel`
  and the target message's `event` id (the `<id>` shown in each `buzz_read` row); `emoji`
  defaults to 👍. Works as
  you in wire mode (and as the agent in local mode). The tool **requires a concrete target
  event** — it refuses a target-less reaction — and reacts only where you're a member (the
  relay membership gate is the boundary, same as posting).

## Attachments (files, images, docs)

Works as you in wire mode and as the agent in local mode — over the relay's **Blossom** media
store (BUD-01/02/11). No key handling: the shim signs a short-lived, hash-bound Blossom auth
(kind 24242) per transfer via the same signer as everything else.

- **Post one:** `buzz_post` with `attachment` = a local file path. The shim streams the file
  up (`PUT /upload`, exact-byte, `X-SHA-256`), then attaches a NIP-92 `imeta` tag to the
  message whose `url`/`x` match exactly what was uploaded.
- **Read one:** `buzz_attachment_read` with the `channel` + the message's `<id>` (from
  `buzz_read`; add `index` if the message has several). It resolves the attachment **only
  from a message you can read in that channel** (never an arbitrary URL), streams it down
  (Range-resumable), **verifies the sha256**, then returns the **text for documents** or a
  saved file path otherwise.

**Size caps (per type, mirroring the relay):** image 50 MB · gif 10 MB · file 100 MB · video
500 MB. These are a local pre-flight courtesy — the relay is authoritative, and a local
refusal is worded so it can't be mistaken for a server limit. Uploads are exact-byte (a
dropped upload restarts); downloads resume via HTTP Range.

## Direct messages

Four DM tools, working as you in wire mode (and as the agent in local mode):

- **`buzz_dm_list`** — your DM conversations (other participant + channel id).
- **`buzz_dm_read`** — read a DM, by `to` (the other person) or `channel` (dm id).
- **`buzz_dm_open`** — open (or find) a 1:1 and return its channel id.
- **`buzz_dm_send`** — send a DM; opens the 1:1 first if needed.

Address a person with `to` = **npub / hex pubkey / exact display-name**, or their
**email** — email resolves via Ekam's directory to the person's canonical live pubkey.
If a recipient has no Ekam identity yet (device-key user), email resolution returns a
clear "use npub/name instead" rather than mis-addressing. DMs are membership-gated
plaintext (kind:9) — the shim never encrypts/decrypts; the relay enforces who can read.

## Security

- No macOS `security` CLI / no secret on process argv (SEC-1 #27, cleared).
- No client-side owner-seed derivation (Ekam PR #286): the shim **re-fetches** its
  derived key, never re-derives from a seed.
- The Phase-2 wire-key stays in memory; only the rotatable service-refresh persists
  (0600), never the raw nsec.
- Wire-sign mode holds **no key at all** — only a rotating, revocable `wire:sign` refresh
  (0600); Ekam signs server-side against a `resource=ISSUER` + `wire:sign`-scoped token,
  and the gate rejects any other kind. Treat the refresh like a credential (0600, never
  log/commit); revoking it in Ekam kills the shim's ability to act as you.

## Reads on the bus (governed agents)

`bridge()` sends the owner delegation as the `x-auth-tag` header when `BUZZ_AUTH_TAG`
is set — required or a ViaOwner agent 403s on `/query`.

## BUZZ_SERVICE_REFRESH is a CREDENTIAL
Treat `BUZZ_SERVICE_REFRESH` (and `BUZZ_PRIVATE_KEY`) as a secret: store the config 0600, never log it, never paste it, never commit it. The shim exchanges it (service-refresh → /oauth/token → /v1/me/wire-key) and holds the key in memory only.

## Samples

`samples/` has paste-ready MCP config blocks for both routes (`mcp-config-human.jsonc`,
`mcp-config-agent.jsonc`), an `env.example`, and `example-client.mjs` — a minimal
MCP-stdio client (whoami → read → post → DM, read-only until you flip the write flags)
that spawns the installed `buzz-mcp` command, so you can verify the connection from clean.

## Building the bundle (maintainers / review)

The runtime is `dist/buzz-mcp.mjs` + `dist/wirelogin.mjs` — self-contained bundles built
from the readable source in this repo, so the *install* needs no `npm install`. To
regenerate (and verify they match what ships):

```sh
npm ci          # install pinned deps from package-lock.json into a REAL node_modules
                # (not a symlink — a symlinked node_modules bakes absolute paths into
                # the bundle comments)
npm run build   # esbuild → dist/buzz-mcp.mjs + dist/wirelogin.mjs (esbuild is a pinned devDep)
npm test        # signer + wirelogin + loadkey self-tests (93 assertions)
```

`dist/` is `esbuild(<reviewed source> + deps pinned by package-lock.json)` — review the
source; the bundle is derived. Both bundles carry a `#!/usr/bin/env node` shebang so the
`bin` entries are directly executable. (Tests live in the repo for `npm test`; they are not
in the published `files[]` — the end-user install stays no-npm and runs only the bundle.)
