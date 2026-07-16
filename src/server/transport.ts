import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import express from 'express';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { logger } from '../logging/logging.js';
import { createServer } from './server.js';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { getDefaultServer, loadToken, isTokenExpired, saveToken } from '../auth/token-store.js';
import { createTokenRefreshProvider } from '../auth/token-refresh.js';
import { fetchOIDCProviderMetadata } from '../auth/settings.js';
import { refreshAccessToken } from '../auth/oauth.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { ArgocdOAuthProvider } from '../auth/mcp-oauth-provider.js';
import { startCallbackServer } from '../auth/mcp-oauth-callback.js';
import type { StoredAuth } from '../auth/types.js';

interface AuthConfig {
  baseUrl: string;
  apiToken: string;
  /** Whether this auth comes from SSO (stored token with refresh capability) */
  isSSOAuth: boolean;
}

/**
 * Attempt to refresh an expired token at startup.
 * Returns the new ID token if successful, null otherwise. ArgoCD's own
 * server validates the bearer credential as an OIDC RP: it checks the JWT's
 * `aud` claim against its configured client ID, which the spec only
 * guarantees for the ID token -- an access token's audience is
 * provider-defined (Okta's, for example, is the authorization server
 * itself) and ArgoCD rejects it with "invalid session: failed to verify the
 * token".
 */
async function tryRefreshExpiredToken(storedAuth: StoredAuth): Promise<string | null> {
  // First, try token refresh if we have a refresh token
  if (storedAuth.token.refreshToken) {
    try {
      logger.info(
        { serverUrl: storedAuth.serverUrl },
        'Token expired, attempting refresh at startup...'
      );

      // Try with stored OIDC config first
      let providerMetadata = await fetchOIDCProviderMetadata(storedAuth.oidcConfig);
      let oidcConfig = storedAuth.oidcConfig;

      try {
        const newToken = await refreshAccessToken(
          providerMetadata,
          oidcConfig,
          storedAuth.token.refreshToken
        );
        await saveToken(storedAuth.serverUrl, newToken, oidcConfig);
        logger.info({ serverUrl: storedAuth.serverUrl }, 'Token refreshed successfully at startup');
        if (!newToken.idToken) {
          logger.warn(
            { serverUrl: storedAuth.serverUrl },
            'Refresh response had no ID token; re-run `argocd-mcp login` to re-authenticate.'
          );
          return null;
        }
        return newToken.idToken;
      } catch {
        // If refresh fails, try re-fetching OIDC settings from server (config may have changed)
        logger.debug(
          { serverUrl: storedAuth.serverUrl },
          'Refresh with stored config failed, re-fetching OIDC settings...'
        );

        const { fetchOIDCSettings } = await import('../auth/settings.js');
        oidcConfig = await fetchOIDCSettings(storedAuth.serverUrl);
        providerMetadata = await fetchOIDCProviderMetadata(oidcConfig);

        const newToken = await refreshAccessToken(
          providerMetadata,
          oidcConfig,
          storedAuth.token.refreshToken
        );
        await saveToken(storedAuth.serverUrl, newToken, oidcConfig);
        logger.info(
          { serverUrl: storedAuth.serverUrl },
          'Token refreshed successfully with updated OIDC config'
        );
        if (!newToken.idToken) {
          logger.warn(
            { serverUrl: storedAuth.serverUrl },
            'Refresh response had no ID token; re-run `argocd-mcp login` to re-authenticate.'
          );
          return null;
        }
        return newToken.idToken;
      }
    } catch (error) {
      logger.warn(
        {
          serverUrl: storedAuth.serverUrl,
          error: error instanceof Error ? error.message : String(error)
        },
        'Token refresh failed'
      );
    }
  } else {
    logger.debug(
      { serverUrl: storedAuth.serverUrl },
      'No refresh token available'
    );
  }

  return null;
}

/**
 * Resolve authentication credentials from environment variables or stored tokens
 */
async function resolveAuth(options?: { serverUrl?: string }): Promise<AuthConfig | null> {
  // Priority 1: Environment variables
  const envBaseUrl = process.env.ARGOCD_BASE_URL || '';
  const envApiToken = process.env.ARGOCD_API_TOKEN || '';

  if (envBaseUrl && envApiToken) {
    logger.info('Using authentication from environment variables');
    return { baseUrl: envBaseUrl, apiToken: envApiToken, isSSOAuth: false };
  }

  // Priority 2: Stored token for specific server
  if (options?.serverUrl) {
    const storedAuth = await loadToken(options.serverUrl);
    if (storedAuth) {
      // ArgoCD validates the bearer credential's `aud` claim against its own
      // client ID, which is only guaranteed to match the ID token -- not the
      // access token (see tryRefreshExpiredToken above).
      let idToken = storedAuth.token.idToken;

      if (isTokenExpired(storedAuth.token)) {
        // Try to refresh the expired token
        const refreshedToken = await tryRefreshExpiredToken(storedAuth);
        if (refreshedToken) {
          idToken = refreshedToken;
        } else {
          logger.warn(
            { serverUrl: options.serverUrl },
            'Stored token is expired and refresh failed. Please run `argocd-mcp login` to re-authenticate.'
          );
          return null;
        }
      }

      if (!idToken) {
        logger.warn(
          { serverUrl: options.serverUrl },
          'Stored auth has no ID token. Please run `argocd-mcp login` to re-authenticate.'
        );
        return null;
      }

      logger.info({ serverUrl: options.serverUrl }, 'Using stored authentication token');
      return {
        baseUrl: storedAuth.serverUrl,
        apiToken: idToken,
        isSSOAuth: true
      };
    }
    logger.warn({ serverUrl: options.serverUrl }, 'No stored authentication found for server');
    return null;
  }

  // Priority 3: Default stored token (first stored server)
  const defaultAuth = await getDefaultServer();
  if (defaultAuth) {
    let idToken = defaultAuth.token.idToken;

    if (isTokenExpired(defaultAuth.token)) {
      // Try to refresh the expired token
      const refreshedToken = await tryRefreshExpiredToken(defaultAuth);
      if (refreshedToken) {
        idToken = refreshedToken;
      } else {
        logger.warn(
          { serverUrl: defaultAuth.serverUrl },
          'Stored token is expired and refresh failed. Please run `argocd-mcp login` to re-authenticate.'
        );
        return null;
      }
    }

    if (!idToken) {
      logger.warn(
        { serverUrl: defaultAuth.serverUrl },
        'Stored auth has no ID token. Please run `argocd-mcp login` to re-authenticate.'
      );
      return null;
    }

    logger.info({ serverUrl: defaultAuth.serverUrl }, 'Using default stored authentication token');
    return {
      baseUrl: defaultAuth.serverUrl,
      apiToken: idToken,
      isSSOAuth: true
    };
  }

  return null;
}

export const connectStdioTransport = async () => {
  const auth = await resolveAuth();

  // Start server even without auth - tools will report auth errors gracefully
  const tokenRefreshProvider = auth?.isSSOAuth
    ? createTokenRefreshProvider(auth.baseUrl)
    : undefined;

  const server = createServer({
    argocdBaseUrl: auth?.baseUrl ?? '',
    argocdApiToken: auth?.apiToken ?? '',
    tokenRefreshProvider,
    isAuthenticated: auth !== null
  });

  logger.info('Connecting to stdio transport');
  await server.connect(new StdioServerTransport());
};

export const connectSSETransport = (port: number) => {
  const app = express();
  const transports: { [sessionId: string]: SSEServerTransport } = {};

  app.get('/sse', async (req, res) => {
    const server = createServer({
      argocdBaseUrl: (req.headers['x-argocd-base-url'] as string) || '',
      argocdApiToken: (req.headers['x-argocd-api-token'] as string) || ''
    });

    const transport = new SSEServerTransport('/messages', res);
    transports[transport.sessionId] = transport;
    res.on('close', () => {
      delete transports[transport.sessionId];
    });
    await server.connect(transport);
  });

  app.post('/messages', async (req, res) => {
    const sessionId = req.query.sessionId as string;
    const transport = transports[sessionId];
    if (transport) {
      await transport.handlePostMessage(req, res);
    } else {
      res.status(400).send(`No transport found for sessionId: ${sessionId}`);
    }
  });

  logger.info(`Connecting to SSE transport on port: ${port}`);
  app.listen(port);
};

/**
 * Wire OAuth 2.1 routes (/.well-known/oauth-authorization-server, /authorize,
 * /token, /register) and a bearer-authed /mcp POST handler onto `app` for one
 * ArgoCD environment's provider. Shared between the single-environment
 * connectHttpTransport and connectMultiEnvHttpTransport so N environments
 * (each its own port, its own provider, its own set of these routes) don't
 * duplicate this wiring -- only the callback listener (see
 * connectMultiEnvHttpTransport) is actually shared across them.
 */
function installOAuthMcpRoutes(
  app: express.Express,
  provider: ArgocdOAuthProvider,
  mcpBaseUrl: string,
  httpTransports: { [sessionId: string]: StreamableHTTPServerTransport }
): void {
  app.use(mcpAuthRouter({
    provider,
    issuerUrl: new URL(mcpBaseUrl),
    baseUrl: new URL(mcpBaseUrl),
  }));

  const bearerAuth = requireBearerAuth({ verifier: provider });

  app.post('/mcp', bearerAuth, async (req, res) => {
    const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    if (sessionIdFromHeader && httpTransports[sessionIdFromHeader]) {
      transport = httpTransports[sessionIdFromHeader];
    } else if (!sessionIdFromHeader && isInitializeRequest(req.body)) {
      // Extract ArgoCD credentials from the verified OAuth token
      const argocdToken = req.auth?.extra?.argocdToken as string;
      const argocdBaseUrl = req.auth?.extra?.argocdBaseUrl as string;

      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          httpTransports[newSessionId] = transport;
        }
      });

      transport.onclose = () => {
        if (transport.sessionId) {
          delete httpTransports[transport.sessionId];
        }
      };

      const server = createServer({
        argocdBaseUrl,
        argocdApiToken: argocdToken,
      });

      await server.connect(transport);
    } else {
      const errorMsg = sessionIdFromHeader
        ? `Invalid or expired session ID: ${sessionIdFromHeader}`
        : 'Bad Request: Not an initialization request and no valid session ID provided.';
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: errorMsg
        },
        id: req.body?.id !== undefined ? req.body.id : null
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  });

  const handleSessionRequest = async (req: express.Request, res: express.Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !httpTransports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await httpTransports[sessionId].handleRequest(req, res);
  };

  app.get('/mcp', handleSessionRequest);
  app.delete('/mcp', handleSessionRequest);
}

/**
 * Start OAuth 2.1-authenticated ArgoCD MCP servers for multiple environments
 * side by side in one process, sharing a single callback listener.
 *
 * Each environment's Okta app in this fork's target org has its OAuth
 * redirect_uri hardcoded to the same local port -- confirmed by testing (a
 * different port gets rejected by Okta with invalid_request). That means
 * only one process can ever bind that port as a dedicated listener, which is
 * why running two separate `argocd-mcp http --server-url ...` processes (one
 * per environment) can't work simultaneously. The fix isn't to avoid sharing
 * the port -- it's to share it deliberately: one callback listener, handed a
 * provider per environment, dispatching each incoming callback to whichever
 * provider's `state` it recognizes (see startCallbackServer). Each
 * environment still gets its own MCP server port, its own OAuth
 * authorize/token/register routes, and its own independent OAuth session --
 * only the physical callback listener is shared.
 */
export const connectMultiEnvHttpTransport = (
  callbackPort: number,
  environments: { name: string; port: number; serverUrl: string; insecure?: boolean }[]
) => {
  const providers = environments.map(
    (env) => new ArgocdOAuthProvider(env.serverUrl, callbackPort, env.insecure)
  );

  startCallbackServer(providers, callbackPort).catch((err) => {
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Failed to start shared OAuth callback server');
    process.exit(1);
  });

  environments.forEach((env, i) => {
    const provider = providers[i];
    const app = express();
    app.use(express.json());

    app.get('/healthz', (_, res) => {
      res.status(200).json({ status: 'ok' });
    });

    const httpTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};
    installOAuthMcpRoutes(app, provider, `http://localhost:${env.port}`, httpTransports);

    logger.info(
      { name: env.name, serverUrl: env.serverUrl, port: env.port, callbackPort },
      'OAuth 2.1 authentication enabled for HTTP transport (multi-environment)'
    );
    app.listen(env.port);
  });
};

export const connectHttpTransport = (port: number, options?: {
  serverUrl?: string;
  insecure?: boolean;
  callbackPort?: number;
}) => {
  const app = express();
  app.use(express.json());

  app.get('/healthz', (_, res) => {
    res.status(200).json({ status: 'ok' });
  });

  const httpTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

  if (options?.serverUrl) {
    // OAuth 2.1 mode: MCP clients authenticate via OAuth flow proxied to ArgoCD OIDC
    const callbackPort = options.callbackPort ?? 8085;
    const mcpBaseUrl = `http://localhost:${port}`;
    const provider = new ArgocdOAuthProvider(options.serverUrl, callbackPort, options.insecure);

    installOAuthMcpRoutes(app, provider, mcpBaseUrl, httpTransports);

    // Start standalone callback server on the Dex-registered port
    startCallbackServer(provider, callbackPort).catch((err) => {
      logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Failed to start OAuth callback server');
      process.exit(1);
    });

    logger.info(
      { serverUrl: options.serverUrl, port },
      'OAuth 2.1 authentication enabled for HTTP transport'
    );
  } else {
    // Legacy mode: header-based auth
    app.post('/mcp', async (req, res) => {
      const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
      let transport: StreamableHTTPServerTransport;

      if (sessionIdFromHeader && httpTransports[sessionIdFromHeader]) {
        transport = httpTransports[sessionIdFromHeader];
      } else if (!sessionIdFromHeader && isInitializeRequest(req.body)) {
        const argocdBaseUrl =
          (req.headers['x-argocd-base-url'] as string) || process.env.ARGOCD_BASE_URL || '';
        const argocdApiToken =
          (req.headers['x-argocd-api-token'] as string) || process.env.ARGOCD_API_TOKEN || '';

        if (argocdBaseUrl == '' || argocdApiToken == '') {
          res
            .status(400)
            .send('x-argocd-base-url and x-argocd-api-token must be provided in headers.');
          return;
        }

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            httpTransports[newSessionId] = transport;
          }
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            delete httpTransports[transport.sessionId];
          }
        };

        // Check if stored auth exists for token refresh capability
        const storedAuth = await loadToken(argocdBaseUrl);
        const tokenRefreshProvider = storedAuth
          ? createTokenRefreshProvider(argocdBaseUrl)
          : undefined;

        const server = createServer({
          argocdBaseUrl,
          argocdApiToken,
          tokenRefreshProvider
        });

        await server.connect(transport);
      } else {
        const errorMsg = sessionIdFromHeader
          ? `Invalid or expired session ID: ${sessionIdFromHeader}`
          : 'Bad Request: Not an initialization request and no valid session ID provided.';
        res.status(400).json({
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: errorMsg
          },
          id: req.body?.id !== undefined ? req.body.id : null
        });
        return;
      }

      await transport.handleRequest(req, res, req.body);
    });

    const handleSessionRequest = async (req: express.Request, res: express.Response) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !httpTransports[sessionId]) {
        res.status(400).send('Invalid or missing session ID');
        return;
      }
      const transport = httpTransports[sessionId];
      await transport.handleRequest(req, res);
    };

    app.get('/mcp', handleSessionRequest);
    app.delete('/mcp', handleSessionRequest);
  }

  logger.info(`Connecting to Http Stream transport on port: ${port}`);
  app.listen(port);
};
