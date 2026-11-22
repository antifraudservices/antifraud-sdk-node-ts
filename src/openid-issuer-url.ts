/** Canonical base URL for a hosted issuer. A path identifies one issuer, not an origin wildcard. */
export function parseOpenIdIssuerUrl(value: string): URL {
  const url = new URL(value)
  const path = url.pathname === '/' ? '' : url.pathname
  if (url.protocol !== 'https:' || value !== url.origin + path
    || !/^(?:\/[A-Za-z0-9._~-]+)*$/u.test(path)) {
    throw new TypeError('OpenID issuer requires a canonical HTTPS base URL')
  }
  return url
}
