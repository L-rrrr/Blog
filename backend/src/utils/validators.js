const { AppError } = require('../errors')

function isValidEmail(email) {
  return typeof email === 'string' && /@/.test(email)
}

function validateAuthInput({ email, password }, options = {}) {
  const { requireStrongPassword = false } = options

  if (!email || !password) {
    throw new AppError('email and password required', 400, 'EMAIL_REQUIRED')
  }

  if (!isValidEmail(email)) {
    throw new AppError('invalid email', 400, 'INVALID_EMAIL')
  }

  if (requireStrongPassword && (typeof password !== 'string' || password.length < 8)) {
    throw new AppError('password must be at least 8 characters', 400, 'WEAK_PASSWORD')
  }
}

module.exports = { isValidEmail, validateAuthInput }
