import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadOAuthProviderState, saveOAuthProviderState } from './oauth-provider-store.js';

describe('oauth-provider-store', () => {
  let tempDir: string;
  let originalXdgConfigHome: string | undefined;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'argocd-mcp-oauth-store-test-'));
    originalXdgConfigHome = process.env.XDG_CONFIG_HOME;
    process.env.XDG_CONFIG_HOME = tempDir;
  });

  afterEach(async () => {
    if (originalXdgConfigHome === undefined) {
      delete process.env.XDG_CONFIG_HOME;
    } else {
      process.env.XDG_CONFIG_HOME = originalXdgConfigHome;
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it('returns empty state for a server with nothing persisted yet', async () => {
    const state = await loadOAuthProviderState('https://argocd.dev.example.com');
    expect(state).toEqual({ clients: {}, accessTokens: {}, refreshTokens: {} });
  });

  it('round-trips saved state back through load', async () => {
    const state = {
      clients: {
        'client-1': { client_id: 'client-1', redirect_uris: ['http://localhost/cb'] } as any
      },
      accessTokens: {
        'token-1': {
          argocdIdToken: 'id-token',
          oidcConfig: {} as any,
          providerMetadata: {} as any,
          clientId: 'client-1',
          createdAt: 123
        }
      },
      refreshTokens: {
        'refresh-1': {
          upstreamRefreshToken: 'upstream-refresh',
          oidcConfig: {} as any,
          providerMetadata: {} as any,
          clientId: 'client-1'
        }
      }
    };

    await saveOAuthProviderState('https://argocd.dev.example.com', state);
    const loaded = await loadOAuthProviderState('https://argocd.dev.example.com');

    expect(loaded).toEqual(state);
  });

  it('keeps two different server URLs from clobbering each other', async () => {
    const devState = {
      clients: { 'dev-client': { client_id: 'dev-client', redirect_uris: [] } as any },
      accessTokens: {},
      refreshTokens: {}
    };
    const prodState = {
      clients: { 'prod-client': { client_id: 'prod-client', redirect_uris: [] } as any },
      accessTokens: {},
      refreshTokens: {}
    };

    await saveOAuthProviderState('https://argocd.dev.example.com', devState);
    await saveOAuthProviderState('https://argocd.prod.example.com', prodState);

    expect(await loadOAuthProviderState('https://argocd.dev.example.com')).toEqual(devState);
    expect(await loadOAuthProviderState('https://argocd.prod.example.com')).toEqual(prodState);
  });

  it('normalizes server URLs so trailing slashes/casing share one entry', async () => {
    const state = {
      clients: { c1: { client_id: 'c1', redirect_uris: [] } as any },
      accessTokens: {},
      refreshTokens: {}
    };
    await saveOAuthProviderState('https://ArgoCD.Example.com/', state);

    expect(await loadOAuthProviderState('https://argocd.example.com')).toEqual(state);
  });
});
