const { AppError } = require('../errors')
const { parseId } = require('../utils/id')
const commentRepository = require('../repositories/commentRepository')
const { isOwnerOrAdmin } = require('../utils/authz')

async function create({ content, postId, author }) {
  const parsedPostId = parseId(postId, { message: 'invalid postId', code: 'INVALID_POSTID' })
  if (!content || typeof content !== 'string') throw new AppError('content required', 400, 'CONTENT_REQUIRED')

  const exists = await commentRepository.postExists(parsedPostId)
  if (!exists) throw new AppError('post not found', 404, 'POST_NOT_FOUND')

  const authorId = author && (author.id ?? author.userId)
  const comment = await commentRepository.create({ content, postId: parsedPostId, authorId })
  comment.author_name = author && author.name || null
  return comment
}

async function findById(id) {
  return commentRepository.findById(id)
}

async function remove(id) {
  return commentRepository.remove(id)
}

async function removeByUser(idInput, user) {
  const id = parseId(idInput)

  const existing = await findById(id)
  if (!existing) throw new AppError('comment not found', 404, 'COMMENT_NOT_FOUND')

  if (!isOwnerOrAdmin(user, existing.author_id)) throw new AppError('forbidden', 403, 'FORBIDDEN')

  await remove(id)
  return { message: 'comment deleted' }
}

module.exports = { create, findById, remove, removeByUser }
