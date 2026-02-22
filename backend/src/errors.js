class AppError extends Error {
  constructor(message, status = 400, code = 'BAD_REQUEST', details = null) {
    super(message)
    this.name = 'AppError'
    this.status = status
    this.code = code
    if (details) this.details = details
    Error.captureStackTrace(this, this.constructor)
  }
}

function errorHandler(logger = console) {
  return (err, req, res, next) => {
    // Preserve existing CORS error behavior
    if (err && err.message && err.message.startsWith('CORS:')) {
      return res.status(403).json({ error: err.message })
    }

    const status = err.status || err.statusCode || 500
    const code = err.code || (status >= 500 ? 'INTERNAL_ERROR' : 'BAD_REQUEST')
    const message = status >= 500 ? 'internal server error' : (err.message || 'error')

    const requestId = req.headers['x-request-id'] || `${Date.now()}-${Math.random().toString(36).slice(2,8)}`

    // Structured log for internal use
    logger.error && logger.error({ msg: err.message, code, status, requestId, route: req.originalUrl, stack: err.stack, user: req.user && req.user.userId })

    const payload = { error: message, code, requestId }
    if (process.env.NODE_ENV !== 'production') payload.stack = err.stack

    res.status(status).json(payload)
  }
}

module.exports = { AppError, errorHandler }
