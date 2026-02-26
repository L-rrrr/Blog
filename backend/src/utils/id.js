const { AppError } = require('../errors')

function parseId(idInput, options = {}) {
  const { message = 'invalid id', code = 'INVALID_ID' } = options
  const id = parseInt(idInput, 10)
  if (Number.isNaN(id)) {
    throw new AppError(message, 400, code)
  }
  return id
}

module.exports = { parseId }
