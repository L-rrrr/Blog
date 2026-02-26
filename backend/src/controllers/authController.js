const authService = require('../services/authService')
const { AppError } = require('../errors')

async function register(req, res, next) {
  try {
    const { user, token } = await authService.register(req.body)
    res.status(201).json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } })
  } catch (err) {
    next(err)
  }
}

async function login(req, res, next) {
  try {
    const { user, token } = await authService.authenticate(req.body)
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } })
  } catch (err) {
    next(err)
  }
}

async function me(req, res, next) {
  try {
    const uid = req.user && (req.user.id ?? req.user.userId)
    const user = await authService.findUserById(uid)
    if (!user) return next(new AppError('user not found', 404, 'USER_NOT_FOUND'))
    res.json({ user })
  } catch (err) {
    next(err)
  }
}

module.exports = { register, login, me }
