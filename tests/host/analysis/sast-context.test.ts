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
]

describe.each(MODES)('JavaScript rules that read their context (%s mode)', (_mode, handle) => {
  it.each(JS_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path ?? 'src/routes/team.js']: code }, handle)
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
