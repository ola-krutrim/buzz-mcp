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
buzz-mcp-login
```

(The Ola OAuth client id is built in; set `BUZZ_EKAM_CLIENT_ID` only for a different Ekam deployment.)

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
    // "BUZZ_EKAM_CLIENT_ID": "<only for a non-Ola Ekam; the Ola client id is built in>",
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

Scope: the wire-sign allowlist is `{9, 22242, 27235, 41010, 41011, 7, 24242, 9000, 9001, 9005,
9007, 9002, 9021, 40003, 9022}` — messages, NIP-98 auth, DM open / add-member, NIP-25 reactions
(kind 7), Blossom media auth (kind 24242, for attachment upload/download), NIP-29 moderation
(9000 / 9001 / 9005) and channel lifecycle (9007 / 9002 / 9021), message edit (40003) and channel
leave (9022). 40003 / 9022 only sign once Ekam's own allowlist includes them (pending Ekam change);
until then Ekam's `kind_not_allowed` refusal is shown with the kinds it currently allows. Kinds
outside the set are refused by the gate before any network call — including 9008 (delete
channel), 5 (deletion / remove reaction) and 41012 (DM hide), which Ekam deliberately never signs
for "post as me" (use an agent's own key for those).

## Tools (48)

Reads, posts, DMs and reactions all act as your identity (as you in wire-sign mode; as the
agent in local mode).

| tool | what it does |
|---|---|
| `buzz_whoami`   | show this session's Buzz identity (name, npub, pubkey, mode) |
| `buzz_profile_set` | set your own profile (kind 0): `name` / `about` / `picture` (https only; `""` clears) — patch-style, other fields kept. Agent mode only (wire mode: kind 0 is refused until Ekam allows it) |
| `buzz_setname`  | **deprecated** alias of `buzz_profile_set { name }` |
| `buzz_channels` | list channels you're a member of; `scope: "open"` browses every open channel you could join (✓ = joined; private channels and DMs never listed) — names and descriptions escaped |
| `buzz_create_channel` | create a channel (NIP-29 kind 9007) — you become its owner; `visibility` **private (default)**/open, `type` stream/forum |
| `buzz_edit_channel` | edit a channel's metadata (NIP-29 kind 9002) — rename / visibility / description / ttl; patch-style, owner/admin only; private→open needs `confirm_make_public` |
| `buzz_join_channel` | join an open channel yourself (NIP-29 kind 9021) — idempotent; private needs an invite |
| `buzz_agents`   | list known agents/people (display name + pubkey) |
| `buzz_read`     | read recent messages in a channel |
| `buzz_search`   | search your channels and DMs (NIP-50). Filters: `from` (a person, fail-closed), `after` / `before` (`YYYY-MM-DD`, ISO time, epoch, or `24h` / `7d`), `in` = all / channels / dms, `channel`. `query` is optional when a filter is given |
| `buzz_channel_members` | list a channel's members (display name + owner/member role) |
| `buzz_post`     | post a message (`@Name` mentions/triggers an agent; optional `attachment` = a local file or folder path, known secret locations refused — see v0.2.31 changelog) |
| `buzz_edit_message` | edit one of your own messages (kind 40003) |
| `buzz_thread_read` | read a whole thread (root + replies) from any message in it |
| `buzz_attachment_read` | download an attachment from a message (text extracted for docs; saved path otherwise) |
| `buzz_react`    | react to a message with an emoji (NIP-25 kind 7) |
| `buzz_unreact`  | remove your reaction (kind 5) |
| `buzz_reactions` | list a message's reactions grouped by emoji |
| `buzz_channel_topic` | set/clear a channel's topic and purpose (kind 9002) |
| `buzz_leave_channel` | leave a channel (kind 9022) |
| `buzz_archive_channel` | archive / unarchive a channel (kind 9002 `archived`; archive needs `confirm: true`) |
| `buzz_delete_channel` | delete a channel (kind 9008; owner only; always `confirm: true`) |
| `buzz_profile` | look up a person's profile by npub / pubkey / email / exact name |
| `buzz_add_member` | add a person to a channel (NIP-29 kind 9000) — where your own role permits |
| `buzz_remove_member` | remove a person from a channel (NIP-29 kind 9001) — owner/admin only |
| `buzz_delete`   | delete a message in a channel (NIP-29 kind 9005) — owner/admin only |
| `buzz_dm_list`  | your DM conversations |
| `buzz_dm_read`  | read a DM (by `to` person or `channel` id) |
| `buzz_dm_open`  | open/find a 1:1 or group DM (`to` = one person or up to 8) and return its channel id |
| `buzz_dm_send`  | send a DM (opens the conversation first if needed) |
| `buzz_dm_add`   | add a person to a DM you're in (kind 41011; they see prior history — wire mode asks `confirm: true` once per session) |
| `buzz_dm_hide`  | hide a DM from your list (kind 41012) |
| `buzz_message_link` | make a `buzz://message?channel=…&id=…[&thread=…]` link to a message, or open one (strict parser; only channels/DMs you can read) |
| `buzz_activity` | your activity feed — mentions / needs-action / activity from the relay feed, or an @mention scan on older relays (labelled) |
| `buzz_files`    | list the files attached in a channel or DM (name, type, size, `<id>` + index for `buzz_attachment_read`); nothing is downloaded |
| `buzz_presence` | who is online / away / offline — relay-signed presence only (a status not signed by the relay's NIP-11 `self` key is ignored) |
| `buzz_emoji`    | list the workspace's custom emoji (`:shortcode:` → image URL; URLs shown, never fetched). `buzz_react` accepts `:shortcode:` |
| `buzz_unread`   | unread per channel / DM. Agent mode: **real counts** from your NIP-RS read state (kind 30078, NIP-44 encrypted to you; channel / thread / message frontiers; conversations with no read marker are counted within `hours` and labelled). Wire mode: a recent-messages heuristic, labelled |
| `buzz_mark_read` | mark a channel / DM read up to its newest message (or a given `event`), or `all: true` — NIP-RS, forward-only, synced with other Buzz clients. Agent mode only |
| `buzz_save` / `buzz_saved` | save / unsave a message (`remove: true`) and list saved items — NIP-51 bookmark list (kind 10003), private (NIP-44 to self) by default, `private: false` for a public entry. Save: agent mode only; list: read-only |
| `buzz_post_diff` | post a code diff (kind 40008, rendered with highlighting) with `repo` + `commit` (+ optional file, parent commit, branches, PR, language, description, truncated); `event` = thread reply. Diff ≤ 60 KB. Agent mode only for now |
| `buzz_status_set` / `buzz_status_clear` | set / clear your live status (NIP-38 kind 30315). Agent mode only — refused in wire mode until Ekam allows 30315 |

**`dry_run: true` on every write tool** (not `buzz_login`): the shim builds the event exactly as the
real call would — resolution, mentions, thread tags, attachment checks — then shows it and stops.
Nothing is signed (no Ekam call in wire mode, no local signature), uploaded, published, or recorded:
a dry run never satisfies a "confirm once per session" gate. Signatures and the `auth` attestation
are redacted from the preview. Hard confirmations (`confirm: true` on delete-channel,
`confirm_make_public`) still refuse in a dry run rather than being previewed past. Read tools refuse
`dry_run` as an unknown argument.

### Slack parity (v0.2.33)

| Slack | Buzz MCP | status |
|---|---|---|
| post / reply in thread / edit / delete | `buzz_post` / `buzz_reply` / `buzz_edit_message` / `buzz_delete` | ✅ (edit: wire mode needs Ekam to allow 40003) |
| reactions incl. custom emoji | `buzz_react` (`:shortcode:` → NIP-30 tag) / `buzz_unreact` / `buzz_reactions` / `buzz_emoji` | ✅ |
| DMs, group DMs | `buzz_dm_*` | ✅ |
| channel browse / join / leave | `buzz_channels scope:"open"` / `buzz_join_channel` / `buzz_leave_channel` | ✅ (leave: wire mode needs Ekam to allow 9022) |
| create / rename / topic / archive / delete channel | `buzz_create_channel` / `buzz_edit_channel` / `buzz_channel_topic` / `buzz_archive_channel` / `buzz_delete_channel` | ✅ (delete: local mode only) |
| members, add / remove | `buzz_channel_members` / `buzz_add_member` / `buzz_remove_member` | ✅ |
| search with `from:` / `before:` / `after:` / `in:` | `buzz_search` filters | ✅ |
| copy link to message | `buzz_message_link` | ✅ |
| Activity / mentions | `buzz_activity` | ✅ (relay feed; @mention fallback) |
| channel files | `buzz_files` | ✅ |
| presence | `buzz_presence` | ✅ read-only (setting your own status is the relay's job) |
| profiles / user lookup | `buzz_profile` / `buzz_agents` | ✅ |
| edit your profile (name, bio, avatar) | `buzz_profile_set` (`buzz_setname` = deprecated alias) | ✅ agent mode (wire mode needs Ekam to allow kind 0) |
| unread counts / mark as read | `buzz_unread` / `buzz_mark_read` | ✅ agent mode — NIP-RS read state, encrypted to you (wire mode: unread is a labelled heuristic; mark-read refused) |
| saved items | `buzz_save` / `buzz_saved` | ✅ NIP-51 kind 10003, private by default (save: agent mode; wire needs Ekam to allow 10003) |
| post a code snippet / diff | `buzz_post_diff` | ✅ kind 40008 (agent mode; wire needs Ekam to allow 40008) |
| set your status | `buzz_status_set` / `buzz_status_clear` | ✅ agent mode (wire needs Ekam to allow 30315) |
| delete your own message (as author) | — | ⏳ gated: needs the relay to accept an author-signed delete (relay SRE) |
| pins, reminders, scheduled send, polls/workflows, huddles | — | ❌ not in Buzz yet (needs relay support) |
| personal emoji list (kind 10030) | — | ⏳ deferred |

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

## Search & members

- **`buzz_search`** — full-text search recent messages (NIP-50). Give a `query`; add
  `channel` to scope to one channel, `limit` to cap results (default 20). Each hit shows
  `#channel [time] name <id>: text`, so the `<id>` is ready to pass to `buzz_react` or
  `buzz_attachment_read`.
- **`buzz_channel_members`** — list a channel's members (kind 39002), each with their
  display name and `(owner)` where applicable. Members without a published profile show a
  truncated pubkey.
- **`buzz_create_channel`** — create a channel (NIP-29 create-group, kind 9007). `name` is
  required (a leading `#` and surrounding whitespace are trimmed); `visibility` is `private`
  (invite-only — **the default, fail-closed**) or `open` (searchable, anyone self-joins); `type` is
  `stream` (default) or `forum`; optional `description` and `ttl` (idle-seconds before the channel is
  archived). `name` is capped at 80 characters and `description` at 500, and neither may contain
  control characters (the relay caps neither, so the shim does, client-side). **You become the
  channel's owner.** It does not add anyone — add members afterwards with `buzz_add_member`. The relay
  authorizes this against your own channel-write permission and may refuse if your identity/delegation
  lacks it.
- **`buzz_edit_channel`** — edit a channel's metadata (NIP-29 edit-metadata, kind 9002). Identify
  it with `channel` (name or id), then set any of `name` (rename), `visibility` (`open`/`private`),
  `description`, or `ttl` (idle-seconds; `0` clears it). **Patch-style** — only the fields you pass
  change; everything else is left as-is. Owner/admin only (relay-enforced). Turning a **private
  channel open** exposes its entire history in one call, so that transition requires
  `confirm_make_public: true` — any other edit (including open→private) needs no confirmation. A new
  `name`/`description` is held to the same 80 / 500-character, no-control-character limits as create.
- **`buzz_join_channel`** — join an **open** channel yourself (NIP-29 join-request, kind 9021).
  Idempotent: a no-op if you're already a member. `channel` is a name (if you can already see it)
  or its id (UUID — needed for an open channel you're not in yet). Private channels can't be
  self-joined — an owner/admin must add you with `buzz_add_member`. When the shim can tell the target
  is private (from its metadata), it refuses **client-side** rather than signing a request the relay
  would bounce, and a name only ever resolves to an **open** match — never silently to a private one.

## Moderation (add / remove members · delete messages)

These act **as you** (NIP-29 admin events, signed via Ekam wire-sign in wire mode; as the agent
in local mode). The **relay** role-gates every one against **your own role** — the shim can only
do what you could already do by hand: adding to a private channel needs you to be a member,
granting an elevated role or removing/deleting needs you to be owner/admin. The shim itself
**fails closed** — it resolves a concrete channel and a concrete target (64-hex pubkey, or the
message's `<id>`) before signing; a name it can't resolve, an ambiguous prefix, or a missing
target is refused, never signed.

- **`buzz_add_member`** — add `user` (npub / hex / exact display-name / email) to `channel`,
  optional `role` (member|admin|owner|guest|bot). ⚠️ The added person can then see the
  channel's **prior history** — the tool says so on success.
- **`buzz_remove_member`** — remove `user` from `channel`. Owner/admin only (relay-enforced).
- **`buzz_delete`** — delete the message identified by `channel` + `event` (the `<id>` from
  `buzz_read`). Owner/admin only (relay-enforced); the shim resolves the target within the named
  channel and refuses a cross-channel target.

## Connector reliability (v0.2.8)

Long-lived sessions are kept healthy automatically:

- **Wire token keep-alive.** The wire ("post as me") access token is refreshed ahead of expiry
  (~75% of its life) and all refreshes are **single-flight** — one in flight at a time. Ekam's
  refresh tokens are single-use/rotating, so a *concurrent* double-refresh would trip reuse
  detection and revoke the token family; single-flight + rotate-and-persist prevents that, so a
  session renews itself indefinitely and re-login is reserved for a genuine revoke.
- **Transport self-heal.** If Node's built-in fetch pool wedges on a long session (every read/post
  throwing while the connection looks up), the shim retries over a fresh socket and reroutes
  subsequent calls, so it recovers **without a restart**. `buzz_whoami` shows a `transport:` line;
  if it ever reports wedged, a full client restart (not just reconnect) clears it.

## Direct messages

Four DM tools, working as you in wire mode (and as the agent in local mode):

- **`buzz_dm_list`** — your DM conversations (other participant + channel id).
- **`buzz_dm_read`** — read a DM, by `to` (the other person) or `channel` (dm id).
- **`buzz_dm_open`** — open (or find) a 1:1 and return its channel id.
- **`buzz_dm_send`** — send a DM; opens the 1:1 first if needed.

Address a person with `to` = **npub / hex pubkey / exact display-name**, or their **email**.

- **By name**: resolved via the relay's `POST /profiles/search` (falling back to NIP-50 search on
  relays without it) and matched **only** against the profile's `name` and `display_name` — a hit
  that came back because of its bio / about / nip05 never resolves. Both sides are normalized
  (NFKC + case-fold, Bidi_Control and default-ignorable characters stripped) and compared by their
  Unicode TR39 **skeleton** (vendored `confusables.mjs`), so a Cyrillic / fullwidth / ligature /
  zero-width lookalike collides with the real name. Resolution is **fail-closed**: only an exact
  (NFC) match on exactly one person resolves — and, since v0.2.32-pre, a single match that differs
  only in letter case (`navendu` → `Navendu`; `CASE_ONLY_IS_AMBIGUOUS`, default `false`). Two or more
  matches (e.g. `Sam` and `SAM`), or a single match that is only a lookalike / confusable or carries
  hidden bidi / invisible characters, is refused with "use an npub". Identities on the relay's NIP-IA archived list (kind:13535 signed by the
  relay's NIP-11 `self` key) are never resolved and are hidden from `buzz_agents`.
- **By email**: **wire mode only**, via Ekam's directory to the person's canonical live pubkey. In
  agent mode email is **refused** (use an npub or display name): a profile's `nip05` is self-asserted,
  so trusting it would let anyone claim a colleague's address and receive their DMs/moderation.
  An email containing non-ASCII, invisible/bidi characters, or anything NFKC would change is
  refused **before** any Ekam / directory call.

DMs are membership-gated plaintext (kind:9) — the shim never encrypts/decrypts; the relay enforces who can read.

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
npm test        # signer + wirelogin + names + bridge + clientversion + loadkey suites (~500 assertions)
sha256sum -c dist/SHA256SUMS   # CI (.github/workflows/ci.yml) enforces this after a rebuild
```

`dist/` is `esbuild(<reviewed source> + deps pinned by package-lock.json)` — review the
source; the bundle is derived. Both bundles carry a `#!/usr/bin/env node` shebang so the
`bin` entries are directly executable. (Tests live in the repo for `npm test`; they are not
in the published `files[]` — the end-user install stays no-npm and runs only the bundle.)

## Changelog

### v0.2.33
- **Slack parity batch 2 (48 tools).** `buzz_profile_set`, `buzz_mark_read`, `buzz_save`, `buzz_saved`,
  `buzz_post_diff`; `buzz_unread` now gives real counts. See the parity table above.
- **NIP-44 v2, vendored (`nip44.mjs`).** Spec-strict (1–65535-byte plaintext; the non-spec
  >64 KiB extension in nostr-tools is refused), constant-time MAC check before decrypt, strict
  base64, message keys zeroed. Built only on `@noble/*` already in the lockfile (now pinned as exact
  devDependencies — no new packages). Tested against the official NIP-44 vectors
  (`vectors/nip44.vectors.json`, sha256-pinned) and cross-checked against nostr-tools. The local
  signer exposes encrypt/decrypt/derive **to self only** (the conversation key never leaves the
  closure and is zeroed on wipe); the wire signer has none.
- **Real unread + mark read (NIP-RS, kind 30078).** Agent mode only. Read-state blobs are
  NIP-44 encrypted to yourself; frontiers are message `created_at` (never the wall clock), forward
  only, max-merged across all your clients. The shim's slot and `client_id` are derived from your key
  (no state file); a different `client_id` at that slot is a conflict → refuses to publish. Only
  your own, signature-verified blobs are read. Wire mode: `buzz_mark_read` refuses (no encrypt-to-self
  at Ekam; 30078 is **not** added to the wire allowlist); `buzz_unread` keeps the heuristic, labelled.
- **`buzz_profile_set`** (kind 0: name / about / picture) with patch semantics: the newest own,
  signature-verified kind 0 is merged, so a picture or hand-written bio also survives the boot
  republish. `buzz_setname` stays as a deprecated alias. Refused in wire mode until Ekam allows kind 0.
- **Saved items (NIP-51 kind 10003).** Private by default (NIP-44 to self). If your existing list has
  private content this shim can't decrypt (e.g. legacy NIP-04), it refuses to rewrite it.
- **`buzz_post_diff` (kind 40008)** — tags mirror the relay validator / buzz-sdk builder (`repo`,
  `commit`, `file`, `parent-commit`, `branch`, `pr`, `l`, `description`, `truncated`); ≤ 61440 bytes;
  thread replies use root/reply markers.
- **Status in wire mode:** clear refusal (30315 isn't on Ekam's allowlist) + TODO; unchanged in agent mode.
- **Deferred:** self-delete as author (needs relay confirmation that an author-signed 9005 is
  accepted).
- New write tools get `dry_run` automatically.

### v0.2.32
- **Slack parity tools (43 total).** `buzz_message_link`, `buzz_activity`, `buzz_files`,
  `buzz_presence`, `buzz_emoji` (all read-only), plus `buzz_channels scope:"open"` and
  `buzz_search` filters `from` / `after` / `before` / `in`. See the parity table above.
- **`dry_run` on every write tool.** Intercepted at the signer: in a dry run only NIP-98 (kind
  27235) read auth is signed; any other event stops before signing and is previewed (signatures and
  `auth` redacted). Belt and braces: the bridge refuses `/events` and Blossom refuses uploads in a
  dry run, the confirm gate never records, and `buzz_setname` doesn't change the session name.
- **Fail-closed throughout.** `from` / presence `users` resolve with the same ambiguity rules as
  mentions; message links are parsed strictly (`buzz` scheme, `message` host, UUID channel,
  64-hex ids, no extra/duplicate params) and the event must carry the link's `h` tag; presence counts
  only events signed by the relay's NIP-11 `self` key; emoji URLs must be http(s), no credentials,
  and are never fetched; every echoed string is escaped.
- **Reactions escape the emoji** they echo back.

### v0.2.32-pre
- **"Post as me" edit and leave.** Kinds 40003 (`buzz_edit_message`) and 9022 (`buzz_leave_channel`)
  join the wire-sign allowlist, so in wire mode they now go to Ekam's `POST /v1/me/wire-sign`. They
  only succeed once Ekam ships the matching allowlist change (pending, security-reviewed Ekam PR).
  9008 / 5 / 41012 stay refused locally — Ekam refuses them by design — with a message saying so.
- **Clear Ekam refusals.** A `400 kind_not_allowed` from wire-sign becomes "Ekam (your signing
  service) doesn't sign kind N yet; it currently allows {…}. Ask the Ekam owner to add it, or use an
  agent's own key." The allowed set is parsed defensively from Ekam's `error_description`; no
  version pinning.
- **Case-only names resolve.** `CASE_ONLY_IS_AMBIGUOUS` is now `false`: a single match that differs
  only in letter case (e.g. `navendu` → `Navendu`) resolves. Lookalike / confusable matches, hidden
  bidi / invisible characters and multiple matches (e.g. `Sam` and `SAM`) are still refused.

### v0.2.31
- **New tools (Slack parity, 38 total).** `buzz_edit_message` (kind 40003, your own messages; reads
  show the newest edit by the same author, marked `(edited)`), `buzz_thread_read`,
  `buzz_channel_topic` (topic / purpose, kind 9002), `buzz_leave_channel` (9022),
  `buzz_archive_channel` (9002 `archived`), `buzz_delete_channel` (9008, always `confirm: true`),
  `buzz_profile` (by npub / hex / email / exact name), `buzz_unreact` (kind 5, one `e` = your reaction),
  `buzz_reactions`, `buzz_dm_add` (41011), `buzz_dm_hide` (41012). Group DMs: `buzz_dm_open` /
  `buzz_dm_send` take `to` as a string or an array of up to 8.
  In wire ("post as me") mode, kinds 40003 / 9022 / 9008 / 5 / 41012 are refused locally as
  *blocked on Ekam wire-sign allowlist* until Ekam adds them. (v0.2.32-pre: 40003 / 9022 now go to Ekam.)
- **Attachments.** Any file type, or a folder (its top-level regular files, ≤10; hidden files are skipped).
  A **denylist** (not an allowlist — any other file or folder is allowed) refuses known secret
  locations, checked on both the typed path and the realpath, case-insensitively, so a symlink,
  a symlinked parent folder or a hard link to a secret is refused too:
  the shim's own key store and wire tokens (`~/.config/buzz-cli/**` incl. `identities/*.hex` and
  `wire-refresh/*.tok`, plus the identity / token dirs the shim actually uses, resolved at runtime),
  `~/.buzz`, `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.docker`, `~/.kube`, `~/.azure`, `~/.password-store`,
  `~/.config/{gcloud,gh,ekam}`, keyrings and credential stores (`~/.local/share/keyrings`,
  `~/.local/share/kwalletd`, `~/.kde/share/apps/kwallet`, `~/Library/Keychains`, `~/.pki`,
  `AppData/…/Microsoft/{Credentials,Protect}` — also matched anywhere), and anywhere: `.netrc`,
  `.git-credentials`, `.npmrc`, `.pypirc`, `.pgpass`, `.credentials.json`, `kubeconfig`, `id_*`,
  `.env*`, `*.key`, `*.pem`, `*.hex`, `*.tok`, `*.authtag`, `*.keychain(-db)`, `*.keyring`, `*.kwl`,
  and shell / REPL history (`.bash_history`, `.zsh_history`, `.sh_history`, `fish_history`,
  `.histfile`, `.python_history`, `.node_repl_history`, `.psql_history`, `.mysql_history`, …,
  PowerShell `ConsoleHost_history.txt`, `~/.zsh_sessions`).
  Kernel pseudo-filesystems are never attachable: anything under `/proc` (e.g. `/proc/self/environ`,
  `/proc/<pid>/environ`, `/proc/self/fd/N`), `/sys` or `/dev` is refused — on the typed path, the
  realpath and every hop of a symlink chain (so a link that detours through `/proc/self/cwd` is
  refused too); on Windows, `\\.\` / `\\?\GLOBALROOT` device paths. Hard links are checked
  against every file in the secret directories at any depth (e.g.
  `~/.config/gcloud/legacy_credentials/<acct>/adc.json`); a hard-linked file is refused if that walk
  can't be completed.
  The upload re-opens the checked file with `O_NOFOLLOW` and re-checks its device/inode, so a swap
  after the check is refused. This is a best-effort denylist: a secret stored under an ordinary
  name elsewhere is **not** detected. The result shows the resolved path.
- **Downloads.** `buzz_attachment_read` streams to a private 0700 dir, writing 0600 files opened with
  `O_EXCL|O_NOFOLLOW`. It never overwrites and is size-capped (`BUZZ_DOWNLOAD_MAX_MB`, default 200).
- **Untrusted output.** Every tool that returns relay text (`buzz_read`, `buzz_dm_read`,
  `buzz_thread_read`, `buzz_search`, `buzz_profile`, `buzz_attachment_read`, `buzz_channels`) starts
  with an "untrusted data" note. Message text, names and channel descriptions are escaped: newlines,
  C0/DEL, the C1 controls U+0080–U+009F (NEL included), and every invisible character — `\p{Bidi_Control}`, `\p{Default_Ignorable_Code_Point}`,
  `\p{Cf}`, U+00AD, U+2061–2064 and the tag characters U+E0000–E007F — become visible `\u{..}`
  escapes (one shared definition with `names.mjs`; a single emoji variation selector is kept). Authors are shown as `name (pk8)`, with `⚠name-collision`
  when two people share a name, and the newest kind:0 wins. Inbound events are
  signature-verified (messages, edits, reactions, profiles): bad ones are dropped by default (`BUZZ_VERIFY_INBOUND=flag` keeps and flags them),
  and timestamps more than 5 minutes in the future are flagged.
  Error text is untrusted too: the catch-all `error: …` result (and the join / edit-verify / login
  error paths) is escaped the same way and capped at 1500 code points, so a relay error body or a
  hostile profile / channel name can't inject a raw newline, control or bidi character. (Labels that
  `names.mjs` already quoted show their backslashes doubled there, e.g. `\\u{202e}` — never raw.)
- **Write safety.** A per-session throttle (`BUZZ_WRITE_PER_MIN`, default 10, 0 = off) plus duplicate
  suppression for an identical message or reaction within 2 minutes. @mentions use the
  v0.2.30 fail-closed resolution: a name that two people share, or that only matches as a lookalike,
  tags nobody and is reported. Channel names are resolved the same way (duplicates are refused with
  the ids to pick from). In wire mode, the first 9001 / 9005 / 9002 / 41011 (DM add) of a session
  needs `confirm: true`.
- **MCP hygiene.** Tool annotations (`readOnlyHint` / `destructiveHint` / `idempotentHint` /
  `openWorldHint` / title), `additionalProperties: false`, and bounded `limit` / text arguments,
  validated at call time. Client cancellation (`extra.signal`), hard timeouts
  (`BUZZ_RELAYINFO_TIMEOUT_S`, `BUZZ_TRANSFER_TIMEOUT_S`) and progress notifications cover uploads and downloads.
- **Key hygiene.** Key env vars are removed from `process.env` after boot, child processes get a
  minimal env, and the local signer's key buffer is zeroed on exit. The browser opens without
  `cmd.exe` on Windows, and https only.
- **Repo.** `CODEOWNERS`, Dependabot (npm + actions), `SECURITY.md`, and a tag-triggered release
  workflow (sha256 + `actions/attest-build-provenance`). `install.sh` now installs the latest release
  tag by default and verifies sha256 before installing.

### v0.2.30
- **Lookalike-proof names.** Invisible-character handling uses Unicode properties
  (`\p{Bidi_Control}`, `\p{Default_Ignorable_Code_Point}`, soft hyphen) instead of a literal
  list — LRM / RLM / ALM, U+202A–202E, U+2066–2069, zero-widths, U+FEFF are now all covered.
  Channel names refuse them on create and edit; variation selectors are stripped (so `Pulse 💓`
  / `Pulse ❤️` still work). Names compare by NFKC + case-fold + TR39 skeleton
  (`names.mjs`, vendored `confusables.mjs` generated by `scripts/gen-confusables.mjs` from the
  pinned Unicode 16.0.0 `confusables.txt`, SHA-256 recorded; still zero runtime deps).
- **Fail closed.** A single skeleton-only / case-only hit is refused ("ambiguous / lookalike - use
  an npub"); `CASE_ONLY_IS_AMBIGUOUS` (default `true`; `false` since v0.2.32-pre) controls case-only matches. Non-ASCII,
  invisible or NFKC-unstable emails are refused before any Ekam/directory call.
- **Relay-aware resolution.** `POST /profiles/search` with NIP-50 fallback; only `name` /
  `display_name` ever match, exact first. NIP-IA archived identities (kind:13535 signed by the
  relay's NIP-11 `self`; fail open if absent) are excluded from DM resolution and `buzz_agents`.
- **Client identification.** kind:10100 carries `["client","buzz-mcp",<version>]`; kind:0 carries
  `client_version`.
- **Edit verification.** `buzz_edit_channel` re-reads kind:39000 and reports any mismatch
  (private / name / ttl / description) — or an unreadable read-back — as an error.
- **p-tag guard.** Every signed event's `p` tags must be 64 lowercase hex; mention p-tags from
  malformed profile pubkeys are dropped (and deduped).
- **@mentions fail closed** (fix after buzz_security's release review). `@name` is resolved with
  the same exact → case → lookalike tiers as a recipient name, over the 200-newest profiles **plus**
  a server-side profile search for each token. Two keys sharing a name (e.g. an old and a new
  `buzz_security`), a lookalike-only match, or an archived identity → **nobody is tagged**, and the
  post/reply result says which `@token` was not tagged and why. Typed `@tokens` match case-insensitively;
  `Pulse 💓` → `@pulse` and `bharatrouter·falcon` → `@bharatrouterfalcon` still work.
- **Channel names fail closed.** A channel given by name resolves only when exactly one channel
  matches (exact, or differing only in case). Two channels sharing a name (`general` / `General`) or a
  lookalike-only match are refused with the channel ids to pick from — never the first match.
  `buzz_join_channel` discovery uses the same rule.
- **Escaped labels; profile search fails closed** (buzz_security re-check). Every profile or
  channel name, channel id and typed query echoed in an error (ambiguous / lookalike / not found,
  including the `Available:` channel list, capped at 50 with "…and N more") is quoted with C0/C1,
  bidi, zero-width, tag and other invisible characters shown as `\u{..}` escapes and capped at 64
  code points. If `/profiles/search` fails (anything but 404/405) **and** the NIP-50 fallback also
  fails, the name is not resolved from the partial 200-newest list: DM recipients get "profile
  search for "x" failed … use an npub", and that `@mention` is not tagged (the post says why).
- `@modelcontextprotocol/sdk` → 1.32.1 (clears the SDK advisory); `npm audit fix` bumps the
  transitive zod 4.5.4 → 4.6.7 and fast-uri 3.1.7 → 3.1.9 (both bundled into dist), plus
  proxy-addr, body-parser, hono and ip-address (dev-only, not bundled): `npm audit` 6 → 0; new `names.test.mjs`,
  `loadkey.test.mjs`; `bridge.test.mjs` capture cases now FAIL instead of skip when nothing was
  captured; CI workflow with SHA-pinned actions and a reproducible-dist check (`dist/SHA256SUMS`).
