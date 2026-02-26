const db = require('../db')

async function findByEmail(email) {
  const result = await db.query('SELECT id, email, name, password, role FROM users WHERE email = $1', [email])
  return result.rows[0] || null
}

async function findById(id) {
  const result = await db.query('SELECT id, email, name, role, created_at FROM users WHERE id = $1', [id])
  return result.rows[0] || null
}

async function createUser({ email, name, passwordHash }) {
  const insert = await db.query(
    'INSERT INTO users (email, name, password) VALUES ($1, $2, $3) RETURNING id, email, name, role, created_at',
    [email, name || null, passwordHash]
  )
  return insert.rows[0]
}

module.exports = { findByEmail, findById, createUser }
