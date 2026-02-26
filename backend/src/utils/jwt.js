const jwt = require('jsonwebtoken')

function signToken(user) {
  const payload = { userId: user.id, role: user.role, email: user.email }
  const secret = process.env.JWT_SECRET || 'please-change-this-secret'
  const expiresIn = process.env.JWT_EXPIRES || '1h'
  return jwt.sign(payload, secret, { expiresIn })
}

function verifyToken(token) {
  const secret = process.env.JWT_SECRET || 'please-change-this-secret'
  return jwt.verify(token, secret)
}

function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') return null
  return authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
}

module.exports = { signToken, verifyToken, extractBearerToken }
