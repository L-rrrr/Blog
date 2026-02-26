const bcrypt = require('bcrypt')
const { AppError } = require('../errors')
const userRepo = require('../repositories/userRepository')
const { signToken } = require('../utils/jwt')

async function findUserByEmail(email) {
  return userRepo.findByEmail(email)
}

async function findUserById(id) {
  return userRepo.findById(id)
}

async function createUser({ email, name, passwordHash }) {
  return userRepo.createUser({ email, name, passwordHash })
}

async function register({ email, password, name }) {
  if (!email || !password) throw new AppError('email and password required', 400, 'EMAIL_REQUIRED')
  if (typeof email !== 'string' || !/@/.test(email)) throw new AppError('invalid email', 400, 'INVALID_EMAIL')
  if (typeof password !== 'string' || password.length < 8) throw new AppError('password must be at least 8 characters', 400, 'WEAK_PASSWORD')

  const exists = await findUserByEmail(email)
  if (exists) throw new AppError('email already registered', 409, 'EMAIL_EXISTS')

  const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10)
  const passwordHash = await bcrypt.hash(password, saltRounds)

  const user = await createUser({ email, name: name || null, passwordHash })
  const token = signToken(user)
  return { user, token }
}

async function authenticate({ email, password }) {
  if (!email || !password) throw new AppError('email and password required', 400, 'EMAIL_REQUIRED')
  if (typeof email !== 'string' || !/@/.test(email)) throw new AppError('invalid email', 400, 'INVALID_EMAIL')

  const user = await findUserByEmail(email)
  if (!user) throw new AppError('email does not exist', 401, 'EMAIL_NOT_FOUND')

  const match = await bcrypt.compare(password, user.password)
  if (!match) throw new AppError('incorrect password', 401, 'INCORRECT_PASSWORD')

  const token = signToken(user)
  return { user, token }
}

module.exports = { findUserByEmail, findUserById, createUser, register, authenticate }
