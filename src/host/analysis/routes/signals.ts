/** Route observations steer review; absence of a static auth hint is not a vulnerability. */
import type { Endpoint, Signal, Snapshot } from '../types.ts'

export const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE', 'ANY'])
// Deliberately small: complete path segments, not arbitrary substrings like "administer".
const SENSITIVE_ROUTE = /(?:^|\/)(?:admin|internal|debug)(?:\/|$|[.?])/i

export function routeSignals(endpoints: readonly Endpoint[], snapshot: Snapshot): Signal[] {
  return endpoints
    .filter(e => e.authHints.length === 0 && (MUTATING_METHODS.has(e.method) || SENSITIVE_ROUTE.test(e.route)))
    .map(endpoint => {
      const location = endpoint.handler ?? endpoint.declaredAt
      const file = snapshot.files.get(location.path)
      const snippet =
        file?.content
          .split('\n')
          .slice(location.startLine - 1, Math.min(location.endLine, location.startLine + 2))
          .join('\n') ?? ''
      return {
        analyzer: 'routes',
        ruleId: 'routes.unguarded',
        kind: 'sink',
        title: 'Risky endpoint without static auth hints',
        category: 'authz',
        severity: 'medium',
        confidence: 'low',
        location,
        snippet,
        message:
          'A mutating or sensitive route has no detected authentication or authorization hints. Check app/router middleware and intended public access before drawing a conclusion.',
        fingerprintParts: ['routes.unguarded', endpoint.method, endpoint.route, location.path],
      }
    })
}
