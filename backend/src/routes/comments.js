const express = require('express')
const router = express.Router()
const { createComment, deleteComment } = require('../controllers/commentsController')
const { authenticateToken } = require('../middleware/auth')

router.post('/', authenticateToken, createComment)
router.delete('/:id', authenticateToken, deleteComment)

module.exports = router
