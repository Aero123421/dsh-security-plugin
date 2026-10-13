const express = require('express')
const usersRouter = require('./routes/users')
const adminRouter = require('./routes/admin')
const { requireAuth, rateLimit } = require('./middleware')

const app = express()
app.use(express.json())

app.get('/health', (req, res) => res.send('ok'))
app.post('/login', rateLimit, async (req, res) => {
  res.json({ ok: true })
})

app.use('/api/users', requireAuth, usersRouter)
app.use('/admin', adminRouter)
app.use('/legacy', require('./missing-router'))

// biome-ignore format: the multi-line chain is what the extractor is tested on
app.route('/items/:itemId')
  .get(listItem)
  .delete(requireAuth, deleteItem)

function listItem(req, res) {
  res.json({})
}

function deleteItem(req, res) {
  res.sendStatus(204)
}

module.exports = app
