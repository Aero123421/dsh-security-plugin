const express = require('express')
const router = express.Router()

router.get('/stats', (req, res) => res.json({}))
router.use(requireAdmin)
router.delete('/users/:userId', (req, res) => res.sendStatus(204))

module.exports = router
