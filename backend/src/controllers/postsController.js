const postService = require('../services/postService')

async function listPosts(req, res, next) {
  try {
    const posts = await postService.listPublished()
    res.json({ posts })
  } catch (err) {
    next(err)
  }
}

async function getPost(req, res, next) {
  try {
    const post = await postService.getAccessiblePost(req.params.id, req.user)
    res.json({ post })
  } catch (err) {
    next(err)
  }
}

async function createPost(req, res, next) {
  try {
    const { title, content } = req.body
    const post = await postService.create({ title, content, author: req.user })
    post.author_name = req.user && req.user.name || null
    res.status(201).json({ post })
  } catch (err) {
    next(err)
  }
}

async function updatePost(req, res, next) {
  try {
    const { title, content, published } = req.body
    const post = await postService.updateByUser(req.params.id, req.user, { title, content, published })
    res.json({ post })
  } catch (err) {
    next(err)
  }
}

async function deletePost(req, res, next) {
  try {
    await postService.removeByUser(req.params.id, req.user)
    res.status(200).json({ message: 'post deleted' })
  } catch (err) {
    next(err)
  }
}

async function listCommentsForPost(req, res, next) {
  try {
    const comments = await postService.listComments(req.params.id)
    res.json({ comments })
  } catch (err) {
    next(err)
  }
}

module.exports = { listPosts, getPost, createPost, updatePost, deletePost, listCommentsForPost }
