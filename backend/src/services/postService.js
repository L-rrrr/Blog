const { AppError } = require('../errors')
const { parseId } = require('../utils/id')
const postRepository = require('../repositories/postRepository')

async function listPublished() {
  return postRepository.listPublished()
}

async function findById(id) {
  return postRepository.findById(id)
}

async function getAccessiblePost(idInput, user) {
  const id = parseId(idInput)
  const post = await findById(id)
  if (!post) throw new AppError('post not found', 404, 'POST_NOT_FOUND')
  if (post.published) return post

  if (!user) throw new AppError('post not published', 403, 'POST_NOT_PUBLISHED')
  const isOwner = (user.id ?? user.userId) === post.author_id
  const isAdmin = user.role === 'ADMIN'
  if (isOwner || isAdmin) return post
  throw new AppError('forbidden', 403, 'FORBIDDEN')
}

async function create({ title, content, author }) {
  if (!title || typeof title !== 'string') throw new AppError('title is required', 400, 'TITLE_REQUIRED')
  const authorId = author && (author.id ?? author.userId)
  return postRepository.create({ title, content, authorId, published: true })
}

async function update(id, { title, content, published }) {
  return postRepository.update(id, { title, content, published })
}

async function updateByUser(idInput, user, { title, content, published }) {
  const id = parseId(idInput)
  const existing = await findById(id)
  if (!existing) throw new AppError('post not found', 404, 'POST_NOT_FOUND')

  const isOwner = (user && (user.id ?? user.userId)) === existing.author_id
  const isAdmin = user && user.role === 'ADMIN'
  if (!isOwner && !isAdmin) throw new AppError('forbidden', 403, 'FORBIDDEN')

  const newPublished = (typeof published === 'boolean' && isAdmin) ? published : existing.published
  const newTitle = title || existing.title
  const newContent = content || existing.content
  return update(id, { title: newTitle, content: newContent, published: newPublished })
}

async function removeByUser(idInput, user) {
  const id = parseId(idInput)
  const existing = await findById(id)
  if (!existing) throw new AppError('post not found', 404, 'POST_NOT_FOUND')
  const isOwner = (user && (user.id ?? user.userId)) === existing.author_id
  const isAdmin = user && user.role === 'ADMIN'
  if (!isOwner && !isAdmin) throw new AppError('forbidden', 403, 'FORBIDDEN')
  return remove(id)
}

async function remove(id) {
  return postRepository.remove(id)
}

async function listComments(postId) {
  const parsedPostId = parseId(postId)
  return postRepository.listComments(parsedPostId)
}

module.exports = { listPublished, findById, create, update, remove, listComments, getAccessiblePost, updateByUser, removeByUser }
