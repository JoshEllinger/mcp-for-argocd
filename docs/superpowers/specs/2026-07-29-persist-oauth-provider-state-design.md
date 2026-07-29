# Persist OAuth provider state across local server restarts

## Problem

`ArgocdOAuthProvider` (`src/auth/mcp-oauth-provider.ts`) is the OAuth 2.1 server
this fork exposes to MCP clients (Claude Code) in HTTP transport mode. It keeps
all OAuth state in plain in-memory `Map`s:

- `clients` — registered MCP client (Dynamic Client Registration) records
- `accessTokens` — opaque MCP access token → upstream ArgoCD ID/refresh token
- `refreshTokens` — opaque MCP refresh token → upstream ArgoCD refresh token
- `pendingAuths` / `completedAuths` — short-lived, mid-flow state

The lucidworks-claude-marketplace `mcp-argocd` plugin restarts this process
deliberately (`argocd-setup`, e.g. to pick up a fork update) and
incidentally (crash, machine sleep/wake). Any restart wipes all four maps.

Claude Code's own MCP client runs in a separate, longer-lived process. After a
restart of this server, it still holds the `client_id` (and possibly a still
class-"valid" opaque access token) it obtained before the restart, and keeps
presenting it. The server no longer recognizes that `client_id` at all, so the
OAuth `/authorize` or `/token` endpoint rejects it with `invalid_client` —
not a normal "please re-authenticate", but an error state a plain `/mcp`
re-login doesn't recover from, per the plugin's own README troubleshooting
section. The documented workaround is to notice this specific error and call
the server's `authenticate` tool directly to force a brand-new Dynamic Client
Registration.

## Goal

Restarting this server should not force reauthentication in the common case.
Specifically: after a restart, an MCP client that registered a client and/or
obtained tokens before the restart should be able to keep using them exactly
as if the server had never restarted — including the existing silent
upstream-token-refresh behavior in `verifyAccessToken`.

## Approach

Persist `clients`, `accessTokens`, and `refreshTokens` to disk, one JSON file
per ArgoCD environment (dev/prod each get their own `ArgocdOAuthProvider`
instance, keyed by `argocdServerUrl` — see `connectMultiEnvHttpTransport`).
Load on provider construction; write after every mutation.

This follows the existing persistence pattern in `src/auth/token-store.ts`
(used by the separate legacy stdio/header-auth path): a JSON file under
`~/.argocd-mcp/`, directory created with `0o700`, file written with `0o600`,
because the file contains live ArgoCD ID/refresh tokens.

`pendingAuths` and `completedAuths` are NOT persisted. They live for single-
digit minutes, are mid-flow state tied to a specific upstream PKCE verifier
and a browser redirect already in progress at the moment of restart — if the
server restarts mid-login, that specific login attempt is lost regardless of
persistence (the browser has already been sent a URL bound to the old
process's in-memory PKCE verifier). The user just retries the login, same as
today.

### Storage layout

New module `src/auth/oauth-provider-store.ts`, mirroring `token-store.ts`'s
shape and conventions:

```ts
interface OAuthProviderStoreData {
  version: number;
  servers: {
    [normalizedServerUrl: string]: {
      clients: Record<string, OAuthClientInformationFull>;
      accessTokens: Record<string, StoredToken>;
      refreshTokens: Record<string, StoredRefreshToken>;
    };
  };
}
```

- File path: `~/.argocd-mcp/oauth-provider-state.json` (same config dir as
  `auth.json`, respecting `XDG_CONFIG_HOME` the same way `token-store.ts`
  does).
- Keyed by normalized server URL (reuse the same `origin.toLowerCase()`
  normalization as `token-store.ts` — dev and prod URLs differ, so they
  naturally get separate top-level entries in one file; no need for one file
  per environment).
- `StoredToken` / `StoredRefreshToken` are the existing private interfaces in
  `mcp-oauth-provider.ts` — exported instead of kept private so the store
  module can reference them, but otherwise unchanged.

### `ArgocdOAuthProvider` changes

- Constructor kicks off an async load (`this.ready = this.loadPersisted()`)
  that populates `clients`/`accessTokens`/`refreshTokens` from disk if a
  matching `servers[normalizedUrl]` entry exists. Every public method that
  reads or writes those maps `await`s `this.ready` first (cheap after the
  first call — the promise is already settled).
- After each mutation site — `registerClient`, `exchangeAuthorizationCode`,
  `exchangeRefreshToken`, and the silent-refresh branch inside
  `verifyAccessToken` — call a `persist()` helper that writes the current
  `clients`/`accessTokens`/`refreshTokens` maps for this provider's
  `argocdServerUrl` back to the shared file (read-modify-write, so two
  providers — dev and prod — sharing one file don't clobber each other's
  entries).
- `cleanup()` (the existing 5-minute interval that evicts stale
  `pendingAuths`/`completedAuths`/expired `accessTokens`) also persists after
  it removes anything from `accessTokens`, so the on-disk file doesn't
  accumulate entries the in-memory cleanup already decided to drop.
- No change to the constructor's public signature or to `clientsStore`'s
  synchronous-looking interface shape beyond awaiting readiness internally —
  `OAuthRegisteredClientsStore.getClient`/`registerClient` are already
  allowed to return promises per the SDK's type.

### What this does and doesn't fix

- Fixes: restarting the local server (via `argocd-setup`, or any crash/
  respawn) no longer invalidates a client_id or token an already-running
  Claude Code session was using — no `invalid_client`, no forced re-login,
  for that cause.
- Does not change: a genuinely expired/revoked upstream ArgoCD refresh token
  still forces a real re-login (unchanged, existing behavior in
  `verifyAccessToken`). A restart that happens mid-authorization-flow (after
  `/authorize` redirected to Okta but before the callback lands) still loses
  that one in-flight attempt — the user just retries `/mcp`.

## Testing

Extend `src/auth/mcp-oauth-provider.test.ts` (and add
`src/auth/oauth-provider-store.test.ts` for the new module, mirroring the
existing `token-store.ts` test conventions if any exist — otherwise modeled
directly on `mcp-oauth-provider.test.ts`'s style):

- New module: round-trips clients/accessTokens/refreshTokens through
  save/load; two different server URLs don't clobber each other's entries in
  the shared file; missing file loads as empty state (same as
  `token-store.ts`'s `readStore`).
- `ArgocdOAuthProvider`: constructing a *second* provider instance against
  the same `argocdServerUrl` (simulating a restart) can retrieve a client
  registered by the first instance, and can successfully call
  `verifyAccessToken` with a token issued by the first instance. This is the
  actual regression test for the bug being fixed.
- Existing tests in `mcp-oauth-provider.test.ts` continue to pass unmodified
  (each test already constructs its own fresh provider against a unique-ish
  flow; persistence must not change behavior for a provider that has nothing
  persisted yet, i.e. the common today's-tests case is "empty store on
  disk").

## Out of scope

- No change to `token-store.ts` or the legacy stdio/header-auth path.
- No change to the lucidworks-claude-marketplace plugin itself (`setup.js`,
  `ensure-server-running.js`) — this fix lives entirely in this fork.
- No change to `pendingAuths`/`completedAuths` persistence, per above.
- Not addressing the upstream PR #86 merge status — this stays on the
  `pr-86-pkce-fix` branch like the fork's other fixes.
