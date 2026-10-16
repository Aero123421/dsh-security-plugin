import { describe, expect, it } from 'vitest'
import { buildJsModel } from '../../../src/host/analysis/sast/js-facts.ts'
import { buildPyModel } from '../../../src/host/analysis/sast/py-facts.ts'
import { Expr } from '../../../src/host/analysis/sast/taint.ts'

describe('incremental taint state', () => {
  it.each(['js', 'py'])('matches fresh replay for increasing, repeated, and backward offsets (%s)', lang => {
    const source =
      lang === 'js'
        ? `const outer = req.body;
function f(req, outer) {
 let x = req.query.name;
 use(x); x = 'safe'; use(x); x += req.body.other; use(x);
 function nested(x) { use(x); x = req.body; use(x); }
 use(outer);
}`
        : `outer = request.args
@app.get('/items')
def f(name: str):
    x = request.args.get('x')
    use(x)
    x = 'safe'
    use(x)
    x += request.form.get('x')
    use(x)
`
    const model = lang === 'js' ? buildJsModel('app.js', source) : buildPyModel('app.py', source)
    const expr = new Expr(model)
    const spans = model.calls.flatMap(call => call.args)
    for (const span of [...spans, ...spans, ...spans.toReversed()]) {
      expect(expr.taint(span)).toEqual(new Expr(model).taint(span))
      expect(expr.wholeBody(span)).toEqual(new Expr(model).wholeBody(span))
    }
  })

  it('does not replay every alias event on repeated increasing queries', () => {
    const count = 6000
    const source = `function f(req) {\n${Array.from({ length: count }, (_, i) => `const x${i} = req.query.x; use(x${i});`).join('\n')}\n}`
    const model = buildJsModel('large.js', source)
    const expr = new Expr(model)
    // Warm event construction, then observe alias-map lookups separately from parsing.
    const spans = model.calls.filter(c => c.callee === 'use').map(c => c.args[0]!)
    const started = performance.now()
    let writes = 0
    const originalSet = Map.prototype.set
    Map.prototype.set = function (key, value) {
      writes++
      return originalSet.call(this, key, value)
    }
    try {
      for (const span of spans) expect(expr.taint(span)?.source).toBe('req.query.x')
    } finally {
      Map.prototype.set = originalSet
    }
    const ms = performance.now() - started
    expect(spans).toHaveLength(count)
    expect(writes).toBeLessThan(count * 10)
    expect(ms).toBeLessThan(1500)
  })
})
