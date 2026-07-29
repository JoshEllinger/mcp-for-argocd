import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { StoredToken, StoredRefreshToken } from './mcp-oauth-provider.js';

export interface ServerOAuthState {
  clients: Record<string, OAuthClientInformationFull>;
  accessTokens: Record<string, StoredToken>;
  refreshTokens: Record<string, StoredRefreshToken>;
}

interface OAuthProviderStoreData {
  version: number;
  servers: { [normalizedServerUrl: string]: ServerOAuthState };
}

/**
 * Same config dir (and XDG_CONFIG_HOME override) as token-store.ts's
 * auth.json, but a separate file -- this stores OAuth-proxy-path state
 * (Dynamic Client Registration clients + opaque MCP tokens), not the
 * legacy stdio/header-auth path's tokens.
 */
function getConfigDir(): string {
  const xdgConfigHome = process.env.XDG_CONFIG_HOME;
  if (xdgConfigHome) {
    return join(xdgConfigHome, 'argocd-mcp');
  }
  return join(homedir(), '.argocd-mcp');
}

function getStateFilePath(): string {
  return join(getConfigDir(), 'oauth-provider-state.json');
}

function normalizeServerUrl(serverUrl: string): string {
  const url = new URL(serverUrl);
  return url.origin.toLowerCase();
}

function emptyServerState(): ServerOAuthState {
  return { clients: {}, accessTokens: {}, refreshTokens: {} };
}

async function readStore(): Promise<OAuthProviderStoreData> {
  try {
    const content = await readFile(getStateFilePath(), 'utf-8');
    return JSON.parse(content) as OAuthProviderStoreData;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { version: 1, servers: {} };
    }
    throw err;
  }
}

async function writeStore(store: OAuthProviderStoreData): Promise<void> {
  const configDir = getConfigDir();
  const stateFile = getStateFilePath();

  await mkdir(configDir, { recursive: true, mode: 0o700 });
  await writeFile(stateFile, JSON.stringify(store, null, 2), 'utf-8');
  await chmod(stateFile, 0o600);
}

/**
 * Load the persisted OAuth state for one ArgoCD server. Always resolves --
 * a server with nothing persisted yet gets empty maps, not null/undefined,
 * so callers can populate their in-memory Maps directly from the result.
 */
export async function loadOAuthProviderState(serverUrl: string): Promise<ServerOAuthState> {
  const store = await readStore();
  const normalizedUrl = normalizeServerUrl(serverUrl);
  return store.servers[normalizedUrl] ?? emptyServerState();
}

/**
 * Persist one server's OAuth state. Read-modify-write against the shared
 * file so multiple environments (e.g. dev and prod, each its own
 * ArgocdOAuthProvider in the same http-multi process) don't clobber each
 * other's entries.
 */
export async function saveOAuthProviderState(serverUrl: string, state: ServerOAuthState): Promise<void> {
  const normalizedUrl = normalizeServerUrl(serverUrl);
  const store = await readStore();
  store.servers[normalizedUrl] = state;
  await writeStore(store);
}
