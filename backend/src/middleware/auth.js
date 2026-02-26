const { AppError } = require('../errors')
const { verifyToken, extractBearerToken } = require('../utils/jwt')
const db = require('../db')

async function authenticateToken(req, res, next) {
  const token = extractBearerToken(req.headers.authorization)
  if (!token) return next(new AppError('token missing', 401, 'TOKEN_MISSING'))
  const secret = process.env.JWT_SECRET
  if (!secret) return next(new AppError('server misconfiguration', 500, 'SERVER_MISCONFIG'))
  try {
    const payload = verifyToken(token)
    const result = await db.query('SELECT id, email, name, role FROM users WHERE id=$1', [payload.userId])
    req.user = result.rows[0] || payload
    next()
  } catch (err) {
    return next(new AppError('invalid token', 401, 'INVALID_TOKEN'))
  }
}

function authorizeRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return next(new AppError('unauthenticated', 401, 'UNAUTHENTICATED'))
    if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
      return next(new AppError('forbidden', 403, 'FORBIDDEN'))
    }
    next()
  }
}

module.exports = { authenticateToken, authorizeRole }