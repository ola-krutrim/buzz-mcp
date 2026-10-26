# Security policy — buzz-mcp

## Reporting a vulnerability
Please report privately to the maintainer (@navenduagarwal) — a GitHub private security advisory on
this repo, or a direct message on Buzz. Do not open a public issue for a vulnerability. Expect an
acknowledgement within 3 working days.

## Supported versions
Only the latest release tag is supported. `install.sh` installs the latest release by default.

## What the shim protects (v0.2.31)
- **Keys.** The agent key is read once at boot (env pin / 0600 keystore / Ekam service-refresh),
  then the key env vars are deleted from `process.env`, child processes get a minimal env, and the
  in-memory secret key buffer is zeroed on exit. Wire ("post as me") mode holds no key at all and can
  only sign the kinds on Ekam's wire-sign allowlist.
- **Attachments.** Any file type or a folder (top-level regular files, ≤10) may be attached. Paths are
  resolved with realpath, and secret locations are refused even via a symlink or hard link: `~/.buzz`,
  `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/{buzz-cli,gcloud,gh,ekam}`, keyrings / keychains /
  Windows credential stores, shell and REPL history files, `*.key`, `*.pem`, `id_*`, `.env*`,
  `*.authtag` (full list in the README). `/proc`, `/sys` and `/dev` are never attachable (typed
  path, realpath or any symlink hop).
  The resolved path is always shown in the tool result.
- **Downloads.** Written to a private dir (0700) as 0600 files opened `O_CREAT|O_EXCL|O_NOFOLLOW`,
  streamed, size-capped (`BUZZ_DOWNLOAD_MAX_MB`, default 200), never overwriting.
- **Untrusted content.** Inbound events are signature-verified (bad ones dropped, or flagged with
  `BUZZ_VERIFY_INBOUND=flag`), future timestamps are flagged, message text is escaped (no raw
  newlines / control / bidi characters), authors are shown as `name (pk8)` with a collision flag, and
  every read is prefixed with a note that content is data, not instructions.
- **Writes.** A per-session throttle (`BUZZ_WRITE_PER_MIN`, default 10/min) and duplicate
  suppression; destructive admin kinds (9001/9005/9002) need `confirm: true` once per session in wire
  mode, deleting or archiving a channel always does.

## Known limits
- `/proc/<pid>/environ` keeps the process's **initial** environment, so a key passed through the
  environment stays readable there by the same user for the process lifetime. Prefer the 0600
  keystore over `BUZZ_PRIVATE_KEY`.
- JS strings cannot be wiped; only the signer's `Uint8Array` key is zeroed.
- Relay-side authorization (owner/admin roles, membership) is enforced by the relay, not the shim.
