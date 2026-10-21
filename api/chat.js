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
  google: process.env.GOOGLE_BASE || 'https://generativelanguage.googleapis.com/v1beta/openai',
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
      }
    })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (req.method === 'OPTIONS') {
    res.writeHead(204)
    return res.end()
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'text/plain' })
    return res.end('method not allowed')
  }

  try {
    const parsed = JSON.parse(await readBody(req))
    const { prov, model, body, stream } = parsed

    const keys = KEYS[prov]
    const base = BASE[prov]
    if (!keys || !keys.length || !base) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ error: `no keys for provider "${prov}"` }))
    }

    const controller = new AbortController()
    req.on('close', () => controller.abort())

    let lastError = null
    for (const key of keys) {
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
          ...(stream
            ? { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' }
            : { 'Content-Type': 'application/json' }),
          ...CORS,
        })

        if (stream) {
          const reader = up.body.getReader()
          for (;;) {
            const { done, value } = await reader.read()
            if (done) break
            res.write(value)
          }
          res.end()
        } else {
          res.end(await up.text())
        }
        return
      } catch (err) {
        if (err.name === 'AbortError') return
        lastError = err.message
      }
    }

    res.writeHead(502, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: lastError || `all ${prov} keys failed` }))
  } catch (err) {
    if (!res.writableEnded) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: err.message || 'proxy error' }))
    }
  }
}
