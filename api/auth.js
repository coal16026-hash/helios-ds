import crypto from 'node:crypto'

/* ------------------------------------------------------------------ config */

const DB_REPO = process.env.DB_REPO || ''
const DB_PATH = process.env.DB_PATH || 'users.json'
const DB_TOKEN = process.env.DB_TOKEN || ''
const AUTH_SECRET = process.env.AUTH_SECRET || 'helios-dev-secret-change-me'
const SESSION_DAYS = 30
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, '')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

/* --------------------------------------------------------------- oauth cfg */

const OAUTH = {
  google: {
    label: 'Google',
    clientId: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    scope: 'openid email profile',
    extra: { access_type: 'online', prompt: 'select_account' },
    async profile(accessToken) {
      const res = await fetch('https://openapis.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      const j = await res.json()
      if (!j.email) throw new Error('Google did not return an email address.')
      return { email: j.email, name: j.name || j.given_name || j.email.split('@')[0], id: j.sub }
    },
  },
  github: {
    label: 'GitHub',
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    authorize: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token',
    scope: 'read:user user:email',
    extra: {},
    async profile(accessToken) {
      const headers = {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'helios',
      }
      const user = await fetch('https://api.github.com/user', { headers }).then((r) => r.json())
      let email = user.email
      if (!email) {
        const list = await fetch('https://api.github.com/user/emails', { headers }).then((r) => r.json())
        const primary = (list || []).find((e) => e.primary && e.verified) || (list || [])[0]
        email = primary?.email
      }
      if (!email) throw new Error('GitHub did not return a verified email address.')
      return { email, name: user.name || user.login, id: String(user.id) }
    },
  },
  discord: {
    label: 'Discord',
    clientId: process.env.DISCORD_CLIENT_ID || '',
    clientSecret: process.env.DISCORD_CLIENT_SECRET || '',
    authorize: 'https://discord.com/oauth2/authorize',
    token: 'https://discord.com/api/oauth2/token',
    scope: 'identify email',
    extra: { prompt: 'consent' },
    async profile(accessToken) {
      const res = await fetch('https://discord.com/api/users/@me', {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      const j = await res.json()
      if (!j.email) throw new Error('Discord did not return an email address.')
      return { email: j.email, name: j.global_name || j.username, id: j.id }
    },
  },
}

const configuredProviders = () =>
  Object.fromEntries(
    Object.entries(OAUTH).map(([key, cfg]) => [key, Boolean(cfg.clientId && cfg.clientSecret)])
  )

/* ------------------------------------------------------------- store layer */

const memory = { users: {} }

async function dbRead() {
  if (!DB_REPO || !DB_TOKEN) return memory
  const res = await fetch(`https://api.github.com/repos/${DB_REPO}/contents/${DB_PATH}`, {
    headers: {
      Authorization: `Bearer ${DB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'helios-auth',
    },
    signal: AbortSignal.timeout(15000),
  })
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

/* ----------------------------------------------------------------- crypto */

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

/* ------------------------------------------------------------------ oauth */

const b64url = (buf) => Buffer.from(buf).toString('base64url')
const fromB64url = (value) => Buffer.from(value, 'base64url').toString('utf8')

const sha256 = (value) => crypto.createHash('sha256').update(value).digest()

function redirectUriFor(req) {
  // Always the canonical app origin so the registered callback URI matches,
  // no matter which Vercel deployment URL the user started the flow from.
  if (APP_URL) return `${APP_URL}/api/auth`
  const host = req.headers['x-forwarded-host'] || req.headers.host
  const proto = req.headers['x-forwarded-proto'] || (host?.includes('localhost') ? 'http' : 'https')
  return `${proto}://${host}/api/auth`
}

function appUrlFor(req) {
  if (APP_URL) return APP_URL
  const referer = req.headers.referer || req.headers.origin
  if (referer) {
    try {
      return new URL(referer).origin
    } catch {
      /* fall through */
    }
  }
  const host = req.headers['x-forwarded-host'] || req.headers.host
  return `${host?.includes('localhost') ? 'http' : 'https'}://${host}`
}

function startOauth(provider, req) {
  const cfg = OAUTH[provider]
  if (!cfg) return { error: 'Unknown provider.' }
  if (!cfg.clientId || !cfg.clientSecret) {
    return { error: `${cfg.label} sign-in is not configured on the server.` }
  }

  const verifier = b64url(crypto.randomBytes(32))
  const challenge = b64url(sha256(verifier))
  const redirectUri = redirectUriFor(req)
  const statePayload = JSON.stringify({ p: provider, v: verifier, r: redirectUri })
  const state = `${b64url(statePayload)}.${sign(statePayload)}`

  const params = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: cfg.scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...cfg.extra,
  })

  return { url: `${cfg.authorize}?${params.toString()}` }
}

async function finishOauth(provider, code, state, req) {
  const cfg = OAUTH[provider]
  if (!cfg) throw new Error('Unknown provider.')

  const [payload, signature] = String(state || '').split('.')
  if (!payload || !signature) throw new Error('Invalid OAuth state.')
  const expected = sign(fromB64url(payload))
  const a = Buffer.from(signature)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('Invalid OAuth state.')
  }
  const stateData = JSON.parse(fromB64url(payload))
  if (stateData.p !== provider) throw new Error('OAuth state mismatch.')

  const tokenRes = await fetch(cfg.token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: stateData.r || redirectUriFor(req),
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code_verifier: stateData.v,
    }),
  })
  const tokenJson = await tokenRes.json().catch(() => ({}))
  if (!tokenRes.ok || !tokenJson?.access_token) {
    throw new Error(tokenJson?.error_description || tokenJson?.error || 'OAuth token exchange failed.')
  }

  const profile = await cfg.profile(tokenJson.access_token)
  const email = String(profile.email || '').trim().toLowerCase()
  if (!email) throw new Error('No email address was returned by the provider.')

  const db = await dbRead()
  db.users = db.users || {}
  const existing = db.users[email]
  if (existing) {
    existing.linked = existing.linked || []
    if (!existing.linked.includes(provider)) existing.linked.push(provider)
    if (profile.name && !existing.nameFromUser) existing.name = profile.name
  } else {
    db.users[email] = {
      name: profile.name || email.split('@')[0],
      oauth: { [provider]: { id: profile.id } },
      linked: [provider],
      createdAt: Date.now(),
    }
  }
  await dbWrite(db)

  return { email, name: db.users[email].name, token: makeToken(email) }
}

/* ----------------------------------------------------------------- routes */

const normalizeEmail = (email) => String(email || '').trim().toLowerCase()
const isEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)

function cookieFor(token) {
  const maxAge = SESSION_DAYS * 86400
  return `helios_session=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax`
}

async function handle(body, req) {
  const action = String(body?.action || '')

  if (action === 'providers') {
    return { ok: true, providers: configuredProviders() }
  }

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
    const fromCookie = req?.headers?.cookie?.match(/(?:^|;\s*)helios_session=([^;]+)/)?.[1]
    const data = readToken(body?.token) || readToken(fromCookie)
    if (!data) return { ok: false, error: 'Not signed in.' }
    const db = await dbRead()
    const record = db.users?.[data.email]
    if (!record) return { ok: false, error: 'Not signed in.' }
    // Re-issue a token so the browser can keep a bearer token in localStorage.
    return { ok: true, email: data.email, name: record.name, token: makeToken(data.email) }
  }

  if (action === 'logout') return { ok: true }

  return { ok: false, error: 'Unknown action.' }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (req.method === 'OPTIONS') {
    res.writeHead(204)
    return res.end()
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)

  /* --- OAuth start (GET /api/auth?action=oauth-start&provider=google) --- */
  if (req.method === 'GET' && url.searchParams.get('action') === 'oauth-start') {
    const provider = String(url.searchParams.get('provider') || '')
    const result = startOauth(provider, req)
    if (result.error) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ ok: false, error: result.error }))
    }
    res.writeHead(302, { Location: result.url, 'Cache-Control': 'no-store' })
    return res.end()
  }

  /* --- OAuth callback (GET /api/auth?code=...&state=...) --- */
  if (req.method === 'GET' && url.searchParams.get('code')) {
    const provider = String(url.searchParams.get('provider') || '')
    const code = String(url.searchParams.get('code') || '')
    const state = String(url.searchParams.get('state') || '')
    const app = appUrlFor(req)
    try {
      const result = await finishOauth(provider, code, state, req)
      res.writeHead(302, {
        Location: `${app}/app?bootstrap=${encodeURIComponent(result.token)}`,
        'Set-Cookie': cookieFor(result.token),
        'Cache-Control': 'no-store',
      })
      return res.end()
    } catch (err) {
      const message = encodeURIComponent(err.message || 'Sign-in failed.')
      res.writeHead(302, { Location: `${app}/?error=${message}`, 'Cache-Control': 'no-store' })
      return res.end()
    }
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
    const result = await handle(body, req)
    if (result.ok && result.token) res.setHeader('Set-Cookie', cookieFor(result.token))
    res.writeHead(result.ok ? 200 : 400, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(result))
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: err.message || 'Auth failed.' }))
  }
}
