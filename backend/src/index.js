const db = require('./db')
require('dotenv').config()
const app = require('./app')

const PORT = process.env.PORT || 4000

let server = null
function start() {
  server = app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`)
  })
}

// Graceful shutdown
async function shutdown(signal) {
  console.log(`Received ${signal} - closing server...`)
  try {
    if (server) {
      server.close(() => console.log('HTTP server closed'))
    }
    if (db && db.pool) {
      await db.pool.end()
      console.log('DB pool closed')
    }
    process.exit(0)
  } catch (err) {
    console.error('Error during shutdown', err)
    process.exit(1)
  }
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))

// Only start the server when the file is run directly.
if (require.main === module) start()

module.exports = { start, shutdown }
