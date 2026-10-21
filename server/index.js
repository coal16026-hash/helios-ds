import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { handleAuth } from './auth.js'

const PORT = process.env.PORT || 8787

const list = (v) =>
  String(v || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

const KEYS = {
  google: list(process.env.GOOGLE_KEYS),
  unorouter: list(process.env.UNOROUTER_KEYS),
  openrouter: list(process.env.OPENROUTER_KEYS),
  agnes: list(process.env.AGNES_KEYS),
}

const BASE = {
  google:
    process.env.GOOGLE_BASE ||
    'https://generativelanguage.googleapis.com/v1beta/openai',
  unorouter: process.env.UNOROUTER_BASE || 'https://api.unorouter.com/v1',
  openrouter: process.env.OPENROUTER_BASE || 'https://openrouter.ai/api/v1',
  agnes: process.env.AGNES_BASE || 'https://apihub.agnes-ai.com/v1',
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (chunk) => {
      data += chunk
      if (data.length > 2e6) {
        reject(new Error('body too large'))
        req.destroy()
      }
    })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })

const shuffle = (arr) => {
  const copy = arr.slice()
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[copy[i], copy[j]] = [copy[j], copy[i]]
  }
  return copy
}

async function chat(req, res) {
  const parsed = JSON.parse(await readBody(req))
  const { prov, model, body, stream } = parsed

  const keys = KEYS[prov]
  const base = BASE[prov]
  if (!keys || !keys.length || !base) {
    res.writeHead(500, CORS)
    return res.end(JSON.stringify({ error: `no keys for provider "${prov}"` }))
  }

  const controller = new AbortController()
  req.on('close', () => controller.abort())

  let lastError = null
  for (const key of shuffle(keys)) {
    if (controller.signal.aborted) return
    try {
      const up = await fetch(`${base}/chat/completions`, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({ model, ...body }),
      })

      if (up.status === 429 || up.status >= 500) {
        lastError = `HTTP ${up.status}`
        await up.body?.cancel?.()
        continue
      }

      res.writeHead(up.status, {
        ...CORS,
        'Content-Type': stream ? 'text/event-stream' : 'application/json',
        'Cache-Control': 'no-cache',
      })

      if (stream) {
        const reader = up.body.getReader()
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          res.write(value)
        }
      } else {
        res.end(await up.text())
      }
      return
    } catch (err) {
      if (err.name === 'AbortError') return
      lastError = err.message
    }
  }

  res.writeHead(502, CORS)
  res.end(
    JSON.stringify({ error: lastError || `all ${prov} keys failed` })
  )
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)

  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS)
    return res.end()
  }

  if (url.pathname === '/api/auth' && req.method === 'POST') {
    return handleAuth(req, res)
  }

  if ((url.pathname === '/api/chat' || url.pathname === '/chat') && req.method === 'POST') {
    try {
      await chat(req, res)
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500, CORS)
        res.end(JSON.stringify({ error: err.message || 'proxy error' }))
      }
    }
    return
  }

  /* Serve the frontend from the repo root so a standalone deploy is complete. */
  const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const page = url.pathname === '/' ? 'login.html' : 'index.html'
  if (url.pathname === '/' || url.pathname === '/app' || url.pathname === '/app/' || url.pathname === '/login.html') {
    const file = path.join(ROOT, page)
    if (fs.existsSync(file)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      return fs.createReadStream(file).pipe(res)
    }
  }
  if (url.pathname === '/health') {
    res.writeHead(200, { ...CORS, 'Content-Type': 'application/json' })
    return res.end(
      JSON.stringify({
        ok: true,
        providers: Object.fromEntries(
          Object.entries(KEYS).map(([k, v]) => [k, v.length])
        ),
      })
    )
  }

  res.writeHead(404, CORS)
  res.end('not found')
})

server.listen(PORT, () => {
  console.log(
    `[helios-api] :${PORT} keys=${Object.entries(KEYS)
      .map(([k, v]) => `${k}=${v.length}`)
      .join(' ')}`
  )
})
