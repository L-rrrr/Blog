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
const allowedOrigins = (process.env.ALLOWED_ORIGINS).split(',').map(s => s.trim())
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

const { AppError } = require('./errors')

// Register endpoint
app.post('/auth/register', async (req, res, next) => {
  try {
    const { email, password, name } = req.body
    if (!email || !password) {
      return next(new AppError('email and password required', 400, 'EMAIL_REQUIRED'))
    }
    if (!isValidEmail(email)) {
      return next(new AppError('invalid email', 400, 'INVALID_EMAIL'))
    }
    if (typeof password !== 'string' || password.length < 8) {
      return next(new AppError('password must be at least 8 characters', 400, 'WEAK_PASSWORD'))
    }

    // Check existing
    const exists = await db.query('SELECT id FROM users WHERE email = $1', [email])
    if (exists.rows.length > 0) {
      return next(new AppError('email already registered', 409, 'EMAIL_EXISTS'))
    }

    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10)
    const passwordHash = await bcrypt.hash(password, saltRounds)

    const insert = await db.query(
      'INSERT INTO users (email, name, password) VALUES ($1, $2, $3) RETURNING id, email, name, role, created_at',
      [email, name || null, passwordHash],
    )

    const user = insert.rows[0]

    // Issue JWT on registration so users are signed-in after creating account
    const payload = { userId: user.id, role: user.role, email: user.email }
    const secret = process.env.JWT_SECRET || 'please-change-this-secret'
    const expiresIn = process.env.JWT_EXPIRES || '1h'
    const token = jwt.sign(payload, secret, { expiresIn })

    res.status(201).json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } })
  } catch (err) {
    next(err)
  }
})

// Login endpoint
app.post('/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body
    if (!email || !password) {
      return next(new AppError('email and password required', 400, 'EMAIL_REQUIRED'))
    }
    if (!isValidEmail(email)) {
      return next(new AppError('invalid email', 400, 'INVALID_EMAIL'))
    }

    const result = await db.query('SELECT id, email, name, password, role FROM users WHERE email = $1', [email])
    if (result.rows.length === 0) {
      return next(new AppError('email does not exist', 401, 'EMAIL_NOT_FOUND'))
    }

    const user = result.rows[0]
    const match = await bcrypt.compare(password, user.password)
    if (!match) {
      return next(new AppError('incorrect password', 400, 'INCORRECT_PASSWORD'))
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
const { authenticateToken} = require('./middleware/auth')
app.get('/auth/me', authenticateToken, async (req, res, next) => {
  try {
    const uid = req.user && (req.user.id ?? req.user.userId)
    const result = await db.query('SELECT id, email, name, role, created_at FROM users WHERE id = $1', [uid])
    if (result.rows.length === 0) return next(new AppError('user not found', 404, 'USER_NOT_FOUND'))
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
    if (Number.isNaN(id)) return next(new AppError('invalid id', 400, 'INVALID_ID'))

    const q = `
      SELECT p.id, p.title, p.content, p.published, p.author_id, u.name AS author_name, p.created_at
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = $1
      LIMIT 1
    `
    const result = await db.query(q, [id])
    if (result.rows.length === 0) return next(new AppError('post not found', 404, 'POST_NOT_FOUND'))

    const post = result.rows[0]
    if (post.published) return res.json({ post })

    // Unpublished: require token and check ownership/role
    const authHeader = req.headers.authorization
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    if (!token) return next(new AppError('post not published', 403, 'POST_NOT_PUBLISHED'))

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET)
      const isOwner = payload.userId === post.author_id
      const isAdmin = payload.role === 'ADMIN'
      if (isOwner || isAdmin) return res.json({ post })
      return next(new AppError('forbidden', 403, 'FORBIDDEN'))
    } catch (err) {
      return next(new AppError('invalid token', 401, 'INVALID_TOKEN'))
    }
  } catch (err) {
    next(err)
  }
})

// Create a new post (protected)
app.post('/posts', authenticateToken, async (req, res, next) => {
  try {
    const { title, content } = req.body
    if (!title || typeof title !== 'string') return next(new AppError('title is required', 400, 'TITLE_REQUIRED'))

    // New behavior: posts are published by default on creation
    const published = true
    const authorId = req.user && (req.user.id ?? req.user.userId)

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
    if (Number.isNaN(id)) return next(new AppError('invalid id', 400, 'INVALID_ID'))

    // Check existing post
    const existing = await db.query('SELECT id, author_id, published, title, content FROM posts WHERE id = $1', [id])
    if (existing.rows.length === 0) return next(new AppError('post not found', 404, 'POST_NOT_FOUND'))
    const postRow = existing.rows[0]

    const isOwner = (req.user && (req.user.id ?? req.user.userId)) === postRow.author_id
    const isAdmin = req.user.role === 'ADMIN'
    if (!isOwner && !isAdmin) return next(new AppError('forbidden', 403, 'FORBIDDEN'))

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
    if (Number.isNaN(id)) return next(new AppError('invalid id', 400, 'INVALID_ID'))

    const existing = await db.query('SELECT id, author_id FROM posts WHERE id = $1', [id])
    if (existing.rows.length === 0) return next(new AppError('post not found', 404, 'POST_NOT_FOUND'))
    const postRow = existing.rows[0]

    const isOwner = (req.user && (req.user.id ?? req.user.userId)) === postRow.author_id
    const isAdmin = req.user.role === 'ADMIN'
    if (!isOwner && !isAdmin) return next(new AppError('forbidden', 403, 'FORBIDDEN'))

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
    if (Number.isNaN(parsedPostId)) return next(new AppError('invalid postId', 400, 'INVALID_POSTID'))
    if (!content || typeof content !== 'string') return next(new AppError('content required', 400, 'CONTENT_REQUIRED'))

    // Ensure post exists
    const postCheck = await db.query('SELECT id FROM posts WHERE id = $1', [parsedPostId])
    if (postCheck.rows.length === 0) return next(new AppError('post not found', 404, 'POST_NOT_FOUND'))

    const q = `
      INSERT INTO comments (content, post_id, author_id)
      VALUES ($1, $2, $3)
      RETURNING id, content, post_id, author_id, created_at
    `
    const authorId = req.user && (req.user.id ?? req.user.userId)
    const result = await db.query(q, [content, parsedPostId, authorId])
    const comment = result.rows[0]
    comment.author_name = req.user.name || null
    res.status(201).json({ comment })
  } catch (err) {
    next(err)
  }
})

// Get comments for a post (public)
app.get('/posts/:id/comments', async (req, res, next) => {
  try {
    const postId = parseInt(req.params.id, 10)
    if (Number.isNaN(postId)) return next(new AppError('invalid id', 400, 'INVALID_ID'))

    const q = `
      SELECT c.id, c.content, c.post_id, c.author_id, u.name AS author_name, c.created_at
      FROM comments c
      LEFT JOIN users u ON c.author_id = u.id
      WHERE c.post_id = $1
      ORDER BY c.created_at ASC
    `
    const result = await db.query(q, [postId])
    res.json({ comments: result.rows })
  } catch (err) {
    next(err)
  }
})

// Delete a comment (author or admin)
app.delete('/comments/:id', authenticateToken, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return next(new AppError('invalid id', 400, 'INVALID_ID'))

    const existing = await db.query('SELECT id, author_id FROM comments WHERE id = $1', [id])
    if (existing.rows.length === 0) return next(new AppError('comment not found', 404, 'COMMENT_NOT_FOUND'))
    const commentRow = existing.rows[0]

    const isOwner = (req.user && (req.user.id ?? req.user.userId)) === commentRow.author_id
    const isAdmin = req.user.role === 'ADMIN'
    if (!isOwner && !isAdmin) return next(new AppError('forbidden', 403, 'FORBIDDEN'))

    await db.query('DELETE FROM comments WHERE id = $1', [id])
    res.status(200).json({ message: 'comment deleted' })
  } catch (err) {
    next(err)
  }
})

// Centralized error handler
const { errorHandler } = require('./errors')
app.use(errorHandler(console))

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
