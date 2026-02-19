const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const db = require('./db')
const cors = require('cors')
require('dotenv').config()

const app = express()
const PORT = process.env.PORT || 4000

app.use(cors())
app.use(express.json())

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
app.post('./auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body
    if (!email || !pasword) {
      return res.status(400).json({ error: 'email and password required' })
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'invalid email'})
    }

    const result = await db.query('SELECT id, email,name, password, role FROM users WHERE email = $1', [email])
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'email does not exist' })
    }
    
    const user = result.rows[0]
    const match = await bcrypt.compare(password, user.password)
    if (!match) {
      return res.status(400).json({ error: 'incorrect password'})
    }

    const payload = {
      userId: user.id, role: user.role, email: user.email
    }
    const secret = process.env.JWT_SECRET || 'default-secret'
    const expiresIn = process.env.JWT_EXPIRES || '1h'
    const token = jwt.sign(payload, secret, { expiresIn })

    res.json({ token, user: {id: user.id, email: user.email, name: user.name, role: user.role } })
  } catch (e) {
    next(e)
  }
})


// Basic error handler
app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ error: 'internal server error' })
})

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
