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
app.use(express.json())

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
const { authenticateToken, authorizeRole } = require('./middleware/auth')
app.get('/auth/me', authenticateToken, async (req, res, next) => {
  try {
    const result = await db.query('SELECT id, email, name, role, created_at FROM users WHERE id = $1', [req.user.userId])
    if (result.rows.length === 0) return res.status(404).json({ error: 'user not found' })
    res.json({ user: result.rows[0] })
  } catch (err) {
    next(err)
  }
})


// Public: list published posts
app.get('/posts', async (req, res, next) => {
  try {
    const q = `
      SELECT p.id, p.title, p.content, p.published, p.author_id, u.name AS author_name, p.created_at
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.published = true
      ORDER BY p.created_at DESC
    `
    const result = await db.query(q)
    res.json({ posts: result.rows })
  } catch (err) {
    next(err)
  }
})

// Get single post. If unpublished, allow only author or admin.
app.get('/posts/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return res.status(400).json({ error: 'invalid id' })

    const q = `
      SELECT p.id, p.title, p.content, p.published, p.author_id, u.name AS author_name, p.created_at
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = $1
      LIMIT 1
    `
    const result = await db.query(q, [id])
    if (result.rows.length === 0) return res.status(404).json({ error: 'post not found' })

    const post = result.rows[0]
    if (post.published) return res.json({ post })

    // Unpublished: require token and check ownership/role
    const authHeader = req.headers.authorization
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    if (!token) return res.status(403).json({ error: 'post not published' })

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET)
      const isOwner = payload.userId === post.author_id
      const isAdmin = payload.role === 'ADMIN'
      if (isOwner || isAdmin) return res.json({ post })
      return res.status(403).json({ error: 'forbidden' })
    } catch (err) {
      return res.status(401).json({ error: 'invalid token' })
    }
  } catch (err) {
    next(err)
  }
})

// Create a new post (protected)
app.post('/posts', authenticateToken, async (req, res, next) => {
  try {
    const { title, content } = req.body
    if (!title || typeof title !== 'string') return res.status(400).json({ error: 'title is required' })

    // Only admins may set published on creation; regular users create drafts
    const published = req.body.published === true && req.user.role === 'ADMIN'
    const authorId = req.user.userId

    const q = `
      INSERT INTO posts (title, content, published, author_id)
      VALUES ($1, $2, $3, $4)
      RETURNING id, title, content, published, author_id, created_at
    `
    const result = await db.query(q, [title, content || null, published, authorId])
    const post = result.rows[0]
    post.author_name = req.user.name || null
    res.status(201).json({ post })
  } catch (err) {
    next(err)
  }
})

// Update a post (author only unless admin)
app.put('/posts/:id', authenticateToken, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return res.status(400).json({ error: 'invalid id' })

    // Check existing post
    const existing = await db.query('SELECT id, author_id, published, title, content FROM posts WHERE id = $1', [id])
    if (existing.rows.length === 0) return res.status(404).json({ error: 'post not found' })
    const postRow = existing.rows[0]

    const isOwner = req.user.userId === postRow.author_id
    const isAdmin = req.user.role === 'ADMIN'
    if (!isOwner && !isAdmin) return res.status(403).json({ error: 'forbidden' })

    const { title, content } = req.body
    // Only admin can change published flag
    const published = typeof req.body.published === 'boolean' && isAdmin ? req.body.published : postRow.published

    const q = `
      UPDATE posts SET title = $1, content = $2, published = $3
      WHERE id = $4
      RETURNING id, title, content, published, author_id, created_at
    `
    const result = await db.query(q, [title || postRow.title, content || postRow.content, published, id])
    res.json({ post: result.rows[0] })
  } catch (err) {
    next(err)
  }
})

// Delete a post (author or admin)
app.delete('/posts/:id', authenticateToken, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return res.status(400).json({ error: 'invalid id' })

    const existing = await db.query('SELECT id, author_id FROM posts WHERE id = $1', [id])
    if (existing.rows.length === 0) return res.status(404).json({ error: 'post not found' })
    const postRow = existing.rows[0]

    const isOwner = req.user.userId === postRow.author_id
    const isAdmin = req.user.role === 'ADMIN'
    if (!isOwner && !isAdmin) return res.status(403).json({ error: 'forbidden' })

    await db.query('DELETE FROM posts WHERE id = $1', [id])
    res.status(200).json({ message: 'post deleted' })
  } catch (err) {
    next(err)
  }
})

// Create a comment on a post (authenticated)
app.post('/comments', authenticateToken, async (req, res, next) => {
  try {
    const { postId, content } = req.body
    const parsedPostId = parseInt(postId, 10)
    if (Number.isNaN(parsedPostId)) return res.status(400).json({ error: 'invalid postId' })
    if (!content || typeof content !== 'string') return res.status(400).json({ error: 'content required' })

    // Ensure post exists
    const postCheck = await db.query('SELECT id FROM posts WHERE id = $1', [parsedPostId])
    if (postCheck.rows.length === 0) return res.status(404).json({ error: 'post not found' })

    const q = `
      INSERT INTO comments (content, post_id, author_id)
      VALUES ($1, $2, $3)
      RETURNING id, content, post_id, author_id, created_at
    `
    const result = await db.query(q, [content, parsedPostId, req.user.userId])
    const comment = result.rows[0]
    comment.author_name = req.user.name || null
    res.status(201).json({ comment })
  } catch (err) {
    next(err)
  }
})

// Delete a comment (author or admin)
app.delete('/comments/:id', authenticateToken, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return res.status(400).json({ error: 'invalid id' })

    const existing = await db.query('SELECT id, author_id FROM comments WHERE id = $1', [id])
    if (existing.rows.length === 0) return res.status(404).json({ error: 'comment not found' })
    const commentRow = existing.rows[0]

    const isOwner = req.user.userId === commentRow.author_id
    const isAdmin = req.user.role === 'ADMIN'
    if (!isOwner && !isAdmin) return res.status(403).json({ error: 'forbidden' })

    await db.query('DELETE FROM comments WHERE id = $1', [id])
    res.status(200).json({ message: 'comment deleted' })
  } catch (err) {
    next(err)
  }
})

// Basic error handler
app.use((err, req, res, next) => {
  console.error(err && err.stack ? err.stack : err)
  // if it's a CORS error, return 403
  if (err && err.message && err.message.startsWith('CORS:')) return res.status(403).json({ error: err.message })
  if (process.env.NODE_ENV !== 'production') {
    return res.status(500).json({ error: 'internal server error', details: err && (err.stack || err.message) })
  }
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
