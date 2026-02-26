const express = require('express')
const router = express.Router()
const postsController = require('../controllers/postsController')
const { authenticateToken } = require('../middleware/auth')

router.get('/', postsController.listPosts)
router.get('/:id', postsController.getPost)
router.get('/:id/comments', postsController.listCommentsForPost)

router.post('/', authenticateToken, postsController.createPost)
router.put('/:id', authenticateToken, postsController.updatePost)
router.delete('/:id', authenticateToken, postsController.deletePost)

module.exports = router
