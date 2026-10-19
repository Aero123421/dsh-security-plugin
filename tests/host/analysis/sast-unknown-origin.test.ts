import { describe, expect, it } from 'vitest'
import { expectedHits, hits, MODES, ofRule, PY_MODES, sast } from './sast-helpers.ts'

/**
 * A dangerous API receiving a dynamic value whose origin is not visible (a parameter, a stored record) is a
 * low-severity `sink`: it steers AI review and never becomes a finding. Fixed hosts, same-site paths,
 * sanitized file names and framework-built URLs stay silent.
 */

const JS_SERVICE = `const fs = require('fs')
const path = require('path')
const axios = require('axios')
const ROOT = '/srv/storage'
export async function readObject(key) {
  return fs.promises.readFile(path.join(ROOT, key)) // SINK
}
export function removeUpload(file) {
  fs.unlinkSync(file.path) // SINK
}
export async function readSafe(key) {
  return fs.promises.readFile(path.join(ROOT, path.basename(key)))
}
export async function readSafeAlias(key) {
  const name = path.basename(key)
  return fs.promises.readFile(\`\${ROOT}/\${name}\`)
}
export function prepare(dir) {
  fs.mkdirSync(dir, { recursive: true })
  return fs.existsSync(dir)
}
export function readConfig() {
  return fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8')
}
export async function deliver(tenant, event) {
  await fetch(tenant.webhookUrl, { method: 'POST', body: JSON.stringify(event) }) // SINK
}
export async function importFrom(url) {
  const { data } = await axios.get(url, { timeout: 5000 }) // SINK
  return data
}
export async function status() {
  return fetch('https://status.example.com/api/v1')
}
export async function item(id) {
  return fetch(\`https://api.example.com/items/\${id}\`)
}
export function back(res, returnTo) {
  res.redirect(returnTo) // SINK
}
export function toOrder(res, id) {
  res.redirect(\`/orders/\${id}\`)
}
export function toLogin(req) {
  return NextResponse.redirect(new URL('/login', req.url))
}
`

describe.each(MODES)('JavaScript sinks of unknown origin (%s mode)', (_mode, handle) => {
  it('marks dynamic paths, URLs and redirect targets for review', async () => {
    const signals = await sast({ 'src/services/storage.js': JS_SERVICE }, handle)
    const lines = expectedHits(JS_SERVICE)
    const reported = ['js.path-traversal', 'js.ssrf', 'js.open-redirect'].flatMap(rule => hits(signals, rule))
    expect(reported.sort()).toEqual(lines.sort())
    for (const signal of signals) {
      expect(signal).toMatchObject({ kind: 'sink', severity: 'low', confidence: 'low' })
      expect(signal.message).toContain('Where the value comes from is not visible here')
    }
  })

  it('keeps request-controlled values reportable as before', async () => {
    const code = `const fs = require('fs')
app.get('/f', async (req, res) => {
  fs.readFile('/srv/' + req.query.name, cb) // VULN
  await fetch(req.query.url) // VULN
  res.redirect(req.query.next) // VULN
})`
    const signals = await sast({ 'src/server.js': code }, handle)
    const reported = ['js.path-traversal', 'js.ssrf', 'js.open-redirect'].flatMap(rule => hits(signals, rule))
    expect(reported.sort()).toEqual(expectedHits(code).sort())
  })

  it('leaves outgoing requests in browser code alone', async () => {
    const component = `import { useEffect } from 'react'
export function Feed({ url }) {
  useEffect(() => { fetch(url).then(r => r.json()) }, [url])
  return null
}`
    const client = `'use client'
export async function load(endpoint) { return fetch(endpoint) }`
    for (const [path, code] of [
      ['src/components/Feed.tsx', component],
      ['src/lib/client.ts', client],
      ['src/lib/feed.ts', component],
    ] as const) {
      expect(ofRule(await sast({ [path]: code }, handle), 'js.ssrf')).toEqual([])
    }
  })
})

const PY_SERVICE = `import os
import requests
from flask import redirect, url_for
from werkzeug.utils import secure_filename

ROOT = os.environ.get("STORAGE_ROOT", "/srv/storage")


def read_object(key):
    with open(os.path.join(ROOT, key), "rb") as fh:  # SINK
        return fh.read()


def read_safe(name):
    with open(os.path.join(ROOT, secure_filename(name))) as fh:
        return fh.read()


def listing(folder):
    return os.listdir(folder)


def defaults():
    with open(os.path.join(ROOT, "defaults.json")) as fh:
        return fh.read()


def deliver(hook, event):
    requests.post(hook.url, json=event, timeout=5)  # SINK


def status():
    return requests.get("https://status.example.com/api/v1", timeout=5)


def item(item_id):
    return requests.get(f"https://api.example.com/items/{item_id}", timeout=5)


def go_back(target):
    return redirect(target)  # SINK


def home():
    return redirect(url_for("index"))
`

describe.each(PY_MODES)('Python sinks of unknown origin (%s mode)', (_mode, handle) => {
  it('marks dynamic paths, URLs and redirect targets for review', async () => {
    const signals = await sast({ 'app/services/storage.py': PY_SERVICE }, handle)
    const reported = ['py.path-traversal', 'py.ssrf', 'py.open-redirect'].flatMap(rule => hits(signals, rule))
    expect(reported.sort()).toEqual(expectedHits(PY_SERVICE).sort())
    for (const signal of signals) expect(signal).toMatchObject({ kind: 'sink', severity: 'low', confidence: 'low' })
  })

  it('keeps request-controlled values reportable as before', async () => {
    const code = `import requests
from flask import request, redirect, send_file
@app.get("/x")
def view():
    requests.get(request.args["url"], timeout=5)  # VULN
    send_file("/srv/" + request.args["name"])  # VULN
    return redirect(request.args["next"])  # VULN
`
    const signals = await sast({ 'app/views.py': code }, handle)
    const reported = ['py.path-traversal', 'py.ssrf', 'py.open-redirect'].flatMap(rule => hits(signals, rule))
    expect(reported.sort()).toEqual(expectedHits(code).sort())
  })
})
