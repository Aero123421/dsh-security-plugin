/**
 * Same-machine classification for RPC requests. DSH has already applied its
 * Host/Origin trust fence and browser authentication before a route runs;
 * this only decides whether the page is on the Host's own machine, which
 * gates high-risk settings. It deliberately ignores `Forwarded` and
 * `X-Forwarded-*` headers: a request that arrives through a reverse proxy or
 * names a LAN address is remote.
 */

/** Hostname (lowercase, no port, IPv6 without brackets) from a `host` header value. */
function hostnameFromAuthority(authority: string): string | undefined {
  const value = authority.trim().toLowerCase()
  if (value === '') return undefined
  if (value.startsWith('[')) {
    const end = value.indexOf(']')
    if (end < 0) return undefined
    const rest = value.slice(end + 1)
    if (rest !== '' && !/^:\d{1,5}$/.test(rest)) return undefined
    return value.slice(1, end)
  }
  const colon = value.indexOf(':')
  if (colon < 0) return value
  // A second colon without brackets is not a valid authority (bare IPv6).
  if (value.indexOf(':', colon + 1) >= 0) return value === '::1' ? '::1' : undefined
  const port = value.slice(colon + 1)
  if (port !== '' && !/^\d{1,5}$/.test(port)) return undefined
  return value.slice(0, colon)
}

function isLoopbackIpv4(hostname: string): boolean {
  const parts = hostname.split('.')
  if (parts.length !== 4 || parts[0] !== '127') return false
  return parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function isLoopbackIpv6(hostname: string): boolean {
  // `::1` and its fully written forms such as `0:0:0:0:0:0:0:1`.
  if (!/^[0-9a-f:]+$/.test(hostname)) return false
  const halves = hostname.split('::')
  if (halves.length > 2) return false
  const groups = halves.flatMap(half => (half === '' ? [] : half.split(':')))
  if (groups.some(group => group === '' || group.length > 4)) return false
  if (halves.length === 1 && groups.length !== 8) return false
  if (halves.length === 2 && groups.length > 7) return false
  const values = groups.map(group => Number.parseInt(group, 16))
  const last = values.at(-1)
  return last === 1 && values.slice(0, -1).every(value => value === 0)
}

/** Whether a bare hostname names this machine. */
export function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '')
  if (host === 'localhost' || host.endsWith('.localhost')) return true
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  return isLoopbackIpv4(bare) || isLoopbackIpv6(bare)
}

/**
 * Whether the request came from the Host's own machine.
 *
 * - URL protocols other than `http:`/`https:` (DSH Desktop's in-process
 *   carrier) are loopback.
 * - Otherwise the `host` header decides, falling back to the URL hostname
 *   when no `host` header is present.
 */
export function isLoopbackRequest(request: Request): boolean {
  let url: URL
  try {
    url = new URL(request.url)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return true
  const header = request.headers.get('host')
  const hostname = header === null ? url.hostname : hostnameFromAuthority(header)
  return hostname !== undefined && isLoopbackHostname(hostname)
}
