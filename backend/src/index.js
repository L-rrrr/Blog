const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const db = require('./db')
const cors = require('cors')
const rateLimit = require('express-rate-limit')
require('dotenv').config()

// Require JWT secret for safe operation
if (!process.env.JWT_SECRET) {
  console.error('Missing JWT_SECRET in environment - aborting startup')
  process.exit(1)
}

const app = express()
const PORT = process.env.PORT || 4000

// Tighten CORS: allow only configured origins (comma-separated) or localhost Vite default
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173').split(',').map(s => s.trim())
app.use(cors({
  origin: function (origin, callback) {
    // allow non-browser (curl, server-side) requests with no origin
    if (!origin) return callback(null, true)
    if (allowedOrigins.includes(origin)) {
      return callback(null, true)
    }
    return callback(new Error('CORS: origin not allowed'))
  }
}))

// Helper: simple email validation
function isValidEmail(email) {
  return typeof email === 'string' && /@/.test(email)
}

// Register endpoint
app.post('/auth/register', async (req, res, next) => {
  try {
    const { email, password, name } = req.body
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' })
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'invalid email' })
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'password must be at least 8 characters' })
    }

    // Check existing
    const exists = await db.query('SELECT id FROM users WHERE email = $1', [email])
    if (exists.rows.length > 0) {
      return res.status(409).json({ error: 'email already registered' })
    }

    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10)
    const passwordHash = await bcrypt.hash(password, saltRounds)

    const insert = await db.query(
      'INSERT INTO users (email, name, password) VALUES ($1, $2, $3) RETURNING id, email, name, role, created_at',
      [email, name || null, passwordHash],
    )

    const user = insert.rows[0]
    res.status(201).json({ user })
  } catch (err) {
    next(err)
  }
})

// Login endpoint
app.post('/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' })
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'invalid email' })
    }

    const result = await db.query('SELECT id, email, name, password, role FROM users WHERE email = $1', [email])
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'email does not exist' })
    }

    const user = result.rows[0]
    const match = await bcrypt.compare(password, user.password)
    if (!match) {
      return res.status(400).json({ error: 'incorrect password' })
    }

    const payload = { userId: user.id, role: user.role, email: user.email }
    const secret = process.env.JWT_SECRET || 'please-change-this-secret'
    const expiresIn = process.env.JWT_EXPIRES || '1h'
    const token = jwt.sign(payload, secret, { expiresIn })

    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } })
  } catch (err) {
    next(err)
  }
})

// Apply a strict rate limiter for auth endpoints to mitigate brute-force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
})

app.use('/auth', authLimiter)

// Protected route: return current user (requires valid JWT)
const { authenticateToken } = require('./middleware/auth')
app.get('/auth/me', authenticateToken, async (req, res, next) => {
  try {
    const result = await db.query('SELECT id, email, name, role, created_at FROM users WHERE id = $1', [req.user.userId])
    if (result.rows.length === 0) return res.status(404).json({ error: 'user not found' })
    res.json({ user: result.rows[0] })
  } catch (err) {
    next(err)
  }
})

// Basic error handler
app.use((err, req, res, next) => {
  console.error(err)
  // if it's a CORS error, return 403
  if (err && err.message && err.message.startsWith('CORS:')) return res.status(403).json({ error: err.message })
  res.status(500).json({ error: 'internal server error' })
})

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

// Only start the server when the file is run directly; export `app` for tests.
if (require.main === module) start()

module.exports = app
