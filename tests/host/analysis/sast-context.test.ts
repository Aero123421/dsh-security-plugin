import { describe, expect, it } from 'vitest'
import { expectedHits, hits, MODES, PY_MODES, sast } from './sast-helpers.ts'

/**
 * Rules that depend on the code around the match: what a receiver is, what the enclosing functions are for,
 * where a token comes from. Lines marked `VULN`/`SINK` must be reported for the rule; unmarked lines must not.
 */
interface Case {
  readonly rule: string
  readonly name: string
  readonly path?: string
  readonly code: string
}

const JS_CASES: readonly Case[] = [
  {
    rule: 'js.mass-assignment',
    name: 'only data-layer receivers write the whole body into a record',
    code: `const teamService = require('../services/teamService')
const AuditLog = require('../models/AuditLog')
router.post('/', async (req, res) => {
  await teamService.create(req.body)
  await this.usersService.create(req.body)
  await tenantService.update(req.user, req.params.id, req.body)
  await UserService.create(req.body)
  await api.create(req.body)
  await stripe.customers.create(req.body)
  await AuditLog.create({ actor: req.user.id, action: req.body.action })
  await AuditLog.create(req.body) // VULN
  await models.User.create(req.body) // VULN
  await prisma.user.create({ data: req.body }) // VULN
  await this.prisma.order.update({ where: { id }, data: req.body }) // VULN
  await this.userRepository.update(req.params.id, req.body) // VULN
  await this.userModel.findByIdAndUpdate(req.params.id, req.body) // VULN
  await knex('users').insert(req.body) // VULN
  const user = await User.findByPk(req.params.id)
  await user.update(req.body) // VULN
  const settings = loadSettings()
  await settings.update(req.body)
})`,
  },
  {
    rule: 'js.weak-password-hash',
    name: 'a fast digest hashes a password when its function or a later use says so',
    path: 'src/lib/passwords.js',
    code: `const crypto = require('crypto')
export function hashPassword(value) {
  return crypto.createHash('md5').update(value).digest('hex') // VULN
}
export const verifyPassword = (value, stored) => crypto.createHash('sha1').update(value).digest('hex') === stored // VULN
function legacyHash(pw) {
  const h = crypto.createHash('md5') // VULN
  h.update(pw)
  return h.digest('hex')
}
function hashUserPassword(salt, input) {
  const h = crypto.createHash('sha1') // VULN
  h.update(salt + input)
  return h.digest('hex')
}
function hashCredentials(salt, input) {
  const h = crypto.createHash('sha1')
  h.update(salt + input)
  return h.digest('hex')
}
function digestLogin(salt, pw) {
  return crypto.createHash('sha1') // VULN
    .update(salt + pw)
    .digest('hex')
}
function fileEtag(buffer) {
  return crypto.createHash('md5').update(buffer).digest('hex')
}
async function changePassword(req, res) {
  const avatar = crypto.createHash('md5').update(req.user.email).digest('hex')
  res.json({ avatar })
}
function passwordResetToken(user) {
  return crypto.createHash('md5').update(user.id + Date.now()).digest('hex')
}
function hashPasswordProfile(user) {
  return { gravatar: crypto.createHash('md5').update(user.email).digest('hex') }
}`,
  },
  {
    rule: 'js.insecure-random',
    name: 'callbacks that build a token inherit the name of the function returning it',
    path: 'src/lib/tokens.js',
    code: `export function newApiKey() {
  return 'sk_' + [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('') // VULN
}
export function generateResetToken(length = 24) {
  return Array.from({ length }, function () {
    return ALPHABET[Math.floor(Math.random() * ALPHABET.length)] // VULN
  }).join('')
}
export function shuffleTokens(tokens) {
  return tokens.sort(() => Math.random() - 0.5)
}
export function rotateTokens(users) {
  users.forEach(user => {
    setTimeout(() => refresh(user), Math.random() * 1000)
  })
}
export function maybeRotateToken() {
  if (Math.random() < 0.1) rotate()
  return 0.5 > Math.random() ? 'a' : 'b'
}
export function pickColor() {
  return COLORS.map(() => COLORS[Math.floor(Math.random() * COLORS.length)])
}`,
  },
]

describe.each(MODES)('JavaScript rules that read their context (%s mode)', (_mode, handle) => {
  it.each(JS_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path ?? 'src/routes/team.js']: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })

  it('js.weak-password-hash: reads a digest chain that starts on the line before the call', async () => {
    const code = `import crypto from 'node:crypto'
export function digest(salt, pw) {
  return crypto
    .createHash('md5')
    .update(salt + pw)
    .digest('hex')
}
`
    const signals = await sast({ 'src/utils/crypto.ts': code }, handle)
    expect(hits(signals, 'js.weak-password-hash')).toEqual(['3 vulnerability'])
  })
})

const PY_CASES: readonly Case[] = [
  {
    rule: 'py.weak-password-hash',
    name: 'a fast digest hashes a password when its function or a later use says so',
    code: `import hashlib

def hash_password(raw):
    return hashlib.md5(raw.encode()).hexdigest()  # VULN

def check(user, candidate):
    digest = hashlib.sha1(candidate.encode()).hexdigest()  # VULN
    return digest == user.password_hash

def legacy(pw):
    return hashlib.new("md5", pw.encode()).hexdigest()  # VULN

def file_etag(data):
    return hashlib.md5(data).hexdigest()

def change_password(user, new):
    avatar = hashlib.md5(user.email.encode()).hexdigest()
    user.set_password(new)
    return avatar

def password_reset_token(user):
    return hashlib.md5(f"{user.id}{user.last_login}".encode()).hexdigest()
`,
  },
  {
    rule: 'py.insecure-random',
    name: 'coin flips and shuffles are not secrets',
    code: `import random

def generate_token():
    return "".join(random.choice(ALPHABET) for _ in range(32))  # VULN

def maybe_rotate_token():
    if random.random() < 0.1:
        rotate()
    return random.randint(0, 9) >= 5
`,
  },
]

describe.each(PY_MODES)('Python rules that read their context (%s mode)', (_mode, handle) => {
  it.each(PY_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path ?? 'app/auth.py']: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })
})

describe.each(PY_MODES)('Django URL converters (%s mode)', (_mode, handle) => {
  it('does not treat a view parameter every route fills with <int:…> or <uuid:…> as text', async () => {
    const views = `from .models import Product
def product_detail(request, product_id):
    return Product.objects.raw(f"SELECT * FROM shop_product WHERE id = {product_id}")
def safe_detail(request, product_id):
    return Product.objects.raw(f"SELECT * FROM shop_product WHERE id = {product_id}")  # VULN
def order_detail(request, order_id):
    return Product.objects.raw(f"SELECT * FROM shop_order WHERE id = '{order_id}'")
def by_slug(request, tag):
    return Product.objects.raw(f"SELECT * FROM shop_product WHERE tag = '{tag}'")  # VULN
def legacy_item(request, item_id):
    return Product.objects.raw(f"SELECT * FROM shop_item WHERE id = {item_id}")
def mixed(request, pk):
    return Product.objects.raw(f"SELECT * FROM shop_item WHERE id = {pk}")  # VULN
def unrouted(request, pk):
    return Product.objects.raw(f"SELECT * FROM shop_item WHERE id = {pk}")  # VULN
`
    const urls = `from django.urls import path, re_path
from . import views
from .views import by_slug
urlpatterns = [
    path("products/<int:product_id>/", views.product_detail),
    path("products/<str:product_id>/safe/", views.safe_detail),
    path("orders/<uuid:order_id>/", views.order_detail),
    path("tags/<slug:tag>/", by_slug),
    re_path(r"^legacy/(?P<item_id>\\d+)/$", views.legacy_item),
    path("mixed/<int:pk>/", views.mixed),
    path("mixed/<pk>/raw/", views.mixed),
]
`
    const signals = await sast({ 'shop/urls.py': urls, 'shop/views.py': views }, handle)
    expect(hits(signals, 'py.sql-injection')).toEqual(expectedHits(views))
    // Without the URLconf the converters are unknown, so every view parameter stays request data.
    const alone = await sast({ 'shop/views.py': views }, handle)
    expect(hits(alone, 'py.sql-injection').filter(h => h.endsWith('vulnerability'))).toHaveLength(7)
  })
})
