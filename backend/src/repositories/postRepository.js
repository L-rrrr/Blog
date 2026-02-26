const db = require('../db')

async function listPublished() {
  const q = `
    SELECT p.id, p.title, p.content, p.published, p.author_id, u.name AS author_name, p.created_at
    FROM posts p
    LEFT JOIN users u ON p.author_id = u.id
    WHERE p.published = true
    ORDER BY p.created_at DESC
  `
  const result = await db.query(q)
  return result.rows
}

async function findById(id) {
  const q = `
    SELECT p.id, p.title, p.content, p.published, p.author_id, u.name AS author_name, p.created_at
    FROM posts p
    LEFT JOIN users u ON p.author_id = u.id
    WHERE p.id = $1
    LIMIT 1
  `
  const result = await db.query(q, [id])
  return result.rows[0] || null
}

async function create({ title, content, authorId, published = true }) {
  const q = `
    INSERT INTO posts (title, content, published, author_id)
    VALUES ($1, $2, $3, $4)
    RETURNING id, title, content, published, author_id, created_at
  `
  const result = await db.query(q, [title, content || null, published, authorId])
  return result.rows[0]
}

async function update(id, { title, content, published }) {
  const q = `
    UPDATE posts SET title = $1, content = $2, published = $3
    WHERE id = $4
    RETURNING id, title, content, published, author_id, created_at
  `
  const result = await db.query(q, [title, content, published, id])
  return result.rows[0]
}

async function remove(id) {
  return db.query('DELETE FROM posts WHERE id = $1', [id])
}

async function listComments(postId) {
  const q = `
    SELECT c.id, c.content, c.post_id, c.author_id, u.name AS author_name, c.created_at
    FROM comments c
    LEFT JOIN users u ON c.author_id = u.id
    WHERE c.post_id = $1
    ORDER BY c.created_at ASC
  `
  const result = await db.query(q, [postId])
  return result.rows
}

module.exports = { listPublished, findById, create, update, remove, listComments }
