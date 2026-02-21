const jwt = require('jsonwebtoken')

async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
  if (!token) return res.status(401).json({ error: 'token missing' })
  const secret = process.env.JWT_SECRET
  if (!secret) return res.status(500).json({ error: 'server misconfiguration' })
  try {
    const payload = jwt.verify(token, secret)
    const result = await require('../db').query('SELECT id, email, name, role FROM users WHERE id=$1', [payload.userId])
    req.user = result.rows[0] || payload
    next()
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' })
  }
}

function authorizeRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthenticated' })
    if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden' })
    }
    next()
  }
}

module.exports = { authenticateToken, authorizeRole }