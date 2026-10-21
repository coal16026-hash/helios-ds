import crypto from 'node:crypto'

/* Same auth core as api/auth.js (the Vercel function) so a standalone
   Node/Render deployment behaves identically. */

const DB_REPO = process.env.DB_REPO || ''
const DB_PATH = process.env.DB_PATH || 'users.json'
const DB_TOKEN = process.env.DB_TOKEN || ''
const AUTH_SECRET = process.env.AUTH_SECRET || 'helios-dev-secret-change-me'
const SESSION_DAYS = 30

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

const memory = { users: {} }

async function dbRead() {
  if (!DB_REPO || !DB_TOKEN) return memory
  const res = await fetch(
    `https://api.github.com/repos/${DB_REPO}/contents/${DB_PATH}`,
    {
      headers: {
        Authorization: `Bearer ${DB_TOKEN}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'helios-auth',
      },
      signal: AbortSignal.timeout(15000),
    }
  )
  if (res.status === 404) return { users: {} }
  if (!res.ok) throw new Error(`db read failed: ${res.status}`)
  const json = await res.json()
  return JSON.parse(Buffer.from(json.content || '', 'base64').toString('utf8') || '{"users":{}}')
}

async function dbWrite(db) {
  if (!DB_REPO || !DB_TOKEN) {
    memory.users = db.users
    return
  }
  const content = Buffer.from(
    JSON.stringify({ ...db, updatedAt: Date.now() }, null, 2),
    'utf8'
  ).toString('base64')
  const headers = {
    Authorization: `Bearer ${DB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'User-Agent': 'helios-auth',
  }
  const created = await fetch(
    `https://api.github.com/repos/${DB_REPO}/contents/${DB_PATH}`,
    {
      method: 'PUT',
      headers,
      body: JSON.stringify({ message: 'helios: update accounts', content, branch: 'main' }),
      signal: AbortSignal.timeout(15000),
    }
  )
  if (created.ok) return
  if (created.status !== 422) throw new Error(`db write failed: ${created.status}`)

  const current = await fetch(
    `https://api.github.com/repos/${DB_REPO}/contents/${DB_PATH}`,
    { headers, signal: AbortSignal.timeout(15000) }
  )
  if (!current.ok) throw new Error(`db read failed: ${current.status}`)
  const json = await current.json()
  const updated = await fetch(
    `https://api.github.com/repos/${DB_REPO}/contents/${DB_PATH}`,
    {
      method: 'PUT',
      headers,
      body: JSON.stringify({
        message: 'helios: update accounts',
        content,
        sha: json.sha,
        branch: 'main',
      }),
      signal: AbortSignal.timeout(15000),
    }
  )
  if (!updated.ok) throw new Error(`db write failed: ${updated.status}`)
}

const hashPassword = (password, salt) =>
  new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) =>
      err ? reject(err) : resolve(key.toString('hex'))
    )
  })

async function makeRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex')
  return { salt, hash: await hashPassword(password, salt) }
}

async function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false
  const hash = await hashPassword(password, record.salt)
  const a = Buffer.from(hash, 'hex')
  const b = Buffer.from(record.hash, 'hex')
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

const sign = (payload) =>
  crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('base64url')

function makeToken(email) {
  const payload = Buffer.from(
    JSON.stringify({ email, exp: Date.now() + SESSION_DAYS * 864e5 })
  ).toString('base64url')
  return `${payload}.${sign(payload)}`
}

function readToken(token) {
  if (!token || typeof token !== 'string') return null
  const [payload, signature] = token.split('.')
  if (!payload || !signature) return null
  const a = Buffer.from(signature)
  const b = Buffer.from(sign(payload))
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
    if (!data?.email || !data?.exp || data.exp < Date.now()) return null
    return data
  } catch {
    return null
  }
}

const normalizeEmail = (email) => String(email || '').trim().toLowerCase()
const isEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)

async function handle(body) {
  const action = String(body?.action || '')

  if (action === 'signup') {
    const email = normalizeEmail(body.email)
    const name = String(body.name || '').trim()
    const password = String(body.password || '')
    if (!isEmail(email)) return { ok: false, error: 'Enter a valid email address.' }
    if (!name) return { ok: false, error: 'Enter your name.' }
    if (password.length < 8) return { ok: false, error: 'Use at least 8 characters.' }

    const db = await dbRead()
    if (db.users?.[email]) {
      return { ok: false, error: 'An account with this email already exists. Log in instead.' }
    }
    const record = await makeRecord(password)
    db.users = db.users || {}
    db.users[email] = { name, ...record, createdAt: Date.now() }
    await dbWrite(db)
    return { ok: true, token: makeToken(email), email, name }
  }

  if (action === 'login') {
    const email = normalizeEmail(body.email)
    const password = String(body.password || '')
    if (!isEmail(email)) return { ok: false, error: 'Enter a valid email address.' }
    if (!password) return { ok: false, error: 'Enter your password.' }
    const db = await dbRead()
    const record = db.users?.[email]
    if (!record || !(await verifyPassword(password, record))) {
      return { ok: false, error: 'Email or password is incorrect.' }
    }
    return { ok: true, token: makeToken(email), email, name: record.name }
  }

  if (action === 'session') {
    const data = readToken(body.token)
    if (!data) return { ok: false, error: 'Not signed in.' }
    const db = await dbRead()
    const record = db.users?.[data.email]
    if (!record) return { ok: false, error: 'Not signed in.' }
    return { ok: true, email: data.email, name: record.name }
  }

  if (action === 'logout') return { ok: true }

  return { ok: false, error: 'Unknown action.' }
}

export async function handleAuth(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') {
    res.writeHead(204)
    return res.end()
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: false, error: 'Method not allowed.' }))
  }

  let body = {}
  try {
    let raw = ''
    for await (const chunk of req) {
      raw += chunk
      if (raw.length > 100000) throw new Error('body too large')
    }
    body = raw ? JSON.parse(raw) : {}
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: false, error: 'Invalid request.' }))
  }

  try {
    const result = await handle(body)
    res.writeHead(result.ok ? 200 : 400, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(result))
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: err.message || 'Auth failed.' }))
  }
}
