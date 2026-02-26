const express = require('express')
const cors = require('cors')
const rateLimit = require('express-rate-limit')

const app = express()
app.use(express.json())

// Tighten CORS: allow only configured origins (comma-separated) or localhost Vite default
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true)
    if (allowedOrigins.length === 0) return callback(null, true)
    if (allowedOrigins.includes(origin)) return callback(null, true)
    return callback(new Error('CORS: origin not allowed'))
  }
}))

// Apply a strict rate limiter for auth endpoints to mitigate brute-force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
})

app.use('/auth', authLimiter)

// Mount routers
const authRouter = require('./routes/auth')
const postsRouter = require('./routes/posts')
const commentsRouter = require('./routes/comments')

app.use('/auth', authRouter)
app.use('/posts', postsRouter)
app.use('/comments', commentsRouter)

// Centralized error handler
const { errorHandler } = require('./errors')
app.use(errorHandler(console))

module.exports = app
