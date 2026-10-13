const { Router } = require('express')
const router = Router()

router.get('/', (req, res) => res.json([]))
router.get('/:id', isAdmin, getUser)
router.put('/:id/profile', (req, res) => res.json({}))

async function getUser(req, res) {
  res.json({ id: req.params.id })
}

module.exports = router
