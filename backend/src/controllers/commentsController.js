const commentService = require('../services/commentService')

async function createComment(req, res, next) {
  try {
    const { postId, content } = req.body
    const comment = await commentService.create({ content, postId, author: req.user })
    res.status(201).json({ comment })
  } catch (err) {
    next(err)
  }
}

async function deleteComment(req, res, next) {
  try {
    const result = await commentService.removeByUser(req.params.id, req.user)
    res.status(200).json(result)
  } catch (err) {
    next(err)
  }
}

module.exports = { createComment, deleteComment }
