# buzz-mcp hosted mode ("Ola Buzz" connector) — `buzz-mcp --http`.
# Ships ONLY the reproducible bundle (dist/buzz-mcp.mjs, zero runtime deps; verify with dist/SHA256SUMS).
# Non-root, read-only-rootfs friendly, no secrets baked in: config + client secret come from env/Secrets.
# Nothing is built or installed in the image (no npm, no RUN build step): it copies the prebuilt, committed bundle.
# Build:  sha256sum -c dist/SHA256SUMS && docker build -t buzz-mcp-hosted:0.2.35 .
# Base pinned by digest (multi-arch index of node:20-alpine, resolved 2026-10-28). Bump deliberately.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
ENV NODE_ENV=production PORT=8080 BUZZ_HOSTED_HOST=0.0.0.0 HOME=/tmp
WORKDIR /app
COPY --chown=root:root dist/buzz-mcp.mjs dist/SHA256SUMS ./dist/
RUN cd /app && grep ' dist/buzz-mcp.mjs$' dist/SHA256SUMS | sha256sum -c - && chmod 0444 dist/buzz-mcp.mjs
# Built-in non-root user `node` (uid 1000).
USER 1000:1000
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["node", "/app/dist/buzz-mcp.mjs", "--http"]
