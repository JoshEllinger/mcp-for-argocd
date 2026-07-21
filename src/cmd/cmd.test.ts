import { describe, it, expect } from 'vitest';
import { formatErrorWithCause } from './cmd.js';

// `new Error(message, { cause })` is an ES2022 constructor overload not in
// this project's ES2016-targeted type lib, even though the runtime supports
// it. Build the fixture the same way `err.cause` is read in cmd.ts -- via an
// unknown cast -- rather than widen the project's global lib target for it.
function errorWithCause(message: string, cause: unknown): Error {
  const err = new Error(message) as Error & { cause?: unknown };
  err.cause = cause;
  return err;
}

describe('formatErrorWithCause', () => {
  it('returns the message alone for an error with no cause', () => {
    const err = new Error('fetch failed');
    expect(formatErrorWithCause(err)).toBe('fetch failed');
  });

  it('appends a single cause', () => {
    const cause = new Error('getaddrinfo ENOTFOUND c-amex-prod-argocd.b.lucidworks.cloud');
    const err = errorWithCause('fetch failed', cause);
    expect(formatErrorWithCause(err)).toBe(
      'fetch failed\n  Caused by: getaddrinfo ENOTFOUND c-amex-prod-argocd.b.lucidworks.cloud'
    );
  });

  it('walks a chain of nested causes', () => {
    const root = new Error('connect ECONNREFUSED 34.11.44.82:443');
    const middle = errorWithCause('connect failed', root);
    const err = errorWithCause('fetch failed', middle);
    expect(formatErrorWithCause(err)).toBe(
      'fetch failed\n  Caused by: connect failed\n  Caused by: connect ECONNREFUSED 34.11.44.82:443'
    );
  });

  it('stringifies a non-Error thrown value', () => {
    expect(formatErrorWithCause('plain string')).toBe('plain string');
  });

  it('ignores a non-Error cause', () => {
    const err = errorWithCause('fetch failed', 'not an error object');
    expect(formatErrorWithCause(err)).toBe('fetch failed');
  });
});
