const db = require('../db')

async function postExists(postId) {
  const result = await db.query('SELECT id FROM posts WHERE id = $1', [postId])
  return result.rows.length > 0
}

async function create({ content, postId, authorId }) {
  const q = `
    INSERT INTO comments (content, post_id, author_id)
    VALUES ($1, $2, $3)
    RETURNING id, content, post_id, author_id, created_at
  `
  const result = await db.query(q, [content, postId, authorId])
  return result.rows[0]
}

async function findById(id) {
  const result = await db.query('SELECT id, author_id FROM comments WHERE id = $1', [id])
  return result.rows[0] || null
}

async function remove(id) {
  return db.query('DELETE FROM comments WHERE id = $1', [id])
}

module.exports = { postExists, create, findById, remove }
