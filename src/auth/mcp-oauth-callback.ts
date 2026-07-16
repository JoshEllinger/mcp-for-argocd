import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import type { ArgocdOAuthProvider } from './mcp-oauth-provider.js';
import { logger } from '../logging/logging.js';

/**
 * Start a standalone HTTP server on `port` to receive the upstream OIDC callback.
 * This runs on a separate port (default 8085) matching what's registered in Dex
 * (and, for this fork's target org, Okta) as the redirect_uri for the ArgoCD
 * CLI/native client.
 *
 * Accepts one provider or several. Multiple providers share this single
 * listener -- each environment's OAuth flow (authorize/token/register, and
 * its own MCP server port) stays independent, but only one process can ever
 * bind the shared callback port, so running N environments side by side means
 * running N providers' authorize/token routes in this one process and
 * dispatching each incoming callback to whichever provider's `state` it
 * matches (states are cryptographically random per RFC 6749 -- collision
 * between two providers' pending states is not a realistic concern).
 *
 * Returns a shutdown function to close the server.
 */
export function startCallbackServer(
  providers: ArgocdOAuthProvider | ArgocdOAuthProvider[],
  port: number = 8085
): Promise<() => Promise<void>> {
  const providerList = Array.isArray(providers) ? providers : [providers];

  return new Promise((resolve, reject) => {
    const server: Server = createServer(
      (req: IncomingMessage, res: ServerResponse) => {
        if (!req.url?.startsWith('/auth/callback')) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
          return;
        }

        const url = new URL(req.url, `http://localhost:${port}`);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');
        const errorDescription = url.searchParams.get('error_description');

        if (error) {
          logger.error({ error, errorDescription }, 'Upstream OIDC authentication failed');
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end(`Authentication failed: ${errorDescription || error}`);
          return;
        }

        if (!code || !state) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Missing code or state parameter');
          return;
        }

        const owner = providerList.find((p) => p.hasPendingState(state));
        if (!owner) {
          logger.error({ state }, 'No provider recognized this callback state');
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Unknown or expired authentication state. Please try logging in again.');
          return;
        }

        owner
          .handleUpstreamCallback(code, state)
          .then((redirectUrl) => {
            res.writeHead(302, { Location: redirectUrl });
            res.end();
          })
          .catch((err) => {
            logger.error(
              { error: err instanceof Error ? err.message : String(err) },
              'Failed to handle upstream callback'
            );
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Authentication callback failed. Please try again.');
          });
      }
    );

    const shutdown = (): Promise<void> => {
      return new Promise((resolveShutdown) => {
        server.close(() => resolveShutdown());
      });
    };

    server.on('error', (err) => {
      reject(new Error(`Failed to start callback server on port ${port}: ${err.message}`));
    });

    server.listen(port, '127.0.0.1', () => {
      logger.info({ port }, 'OAuth callback server listening');
      resolve(shutdown);
    });
  });
}
