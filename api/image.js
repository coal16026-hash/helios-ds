const list = (v) =>
  String(v || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

const AGNES_BASE = process.env.AGNES_BASE || 'https://apihub.agnes-ai.com/v1'
const AGNES_KEYS = list(process.env.AGNES_KEYS)
const IMAGE_MODEL = 'agnes-image-2.5-flash'

const SIZES = new Set(['1K', '2K', '3K', '4K'])
const RATIOS = new Set(['1:1', '3:4', '4:3', '16:9', '9:16', '2:3', '3:2', '21:9'])

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

const validSize = (value) => {
  const size = String(value || '').trim()
  if (SIZES.has(size.toUpperCase())) return size.toUpperCase()
  if (/^\d{2,5}x\d{2,5}$/.test(size)) return size
  return '1K'
}

const validRatio = (value) => {
  const ratio = String(value || '').trim()
  return RATIOS.has(ratio) ? ratio : '1:1'
}

export default async function handler(req, res) {
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

  let input = {}
  try {
    let raw = ''
    for await (const chunk of req) {
      raw += chunk
      if (raw.length > 8e6) throw new Error('body too large')
    }
    input = raw ? JSON.parse(raw) : {}
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: false, error: 'Invalid request.' }))
  }

  const prompt = String(input.prompt || '').trim()
  if (!prompt) {
    res.writeHead(400, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: false, error: 'A prompt is required.' }))
  }
  if (!AGNES_KEYS.length) {
    res.writeHead(500, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: false, error: 'No image provider configured.' }))
  }

  const size = validSize(input.size)
  const ratio = validRatio(input.ratio)

  // Reference images for image-to-image / multi-image composition.
  const images = Array.isArray(input.image)
    ? input.image.filter((v) => typeof v === 'string' && v.trim()).slice(0, 4)
    : []

  const body = {
    model: IMAGE_MODEL,
    prompt: prompt.slice(0, 4000),
    size,
    extra_body: { response_format: 'url' },
  }
  if (ratio) body.ratio = ratio
  if (images.length) body.extra_body.image = images

  let lastError = null
  for (const key of AGNES_KEYS) {
    try {
      const upstream = await fetch(`${AGNES_BASE}/images/generations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(120000),
      })

      if (upstream.status === 429 || upstream.status >= 500) {
        lastError = `HTTP ${upstream.status}`
        await upstream.body?.cancel?.()
        await new Promise((resolve) => setTimeout(resolve, 250))
        continue
      }

      const json = await upstream.json().catch(() => null)
      if (!upstream.ok) {
        const detail =
          json?.error?.message || json?.message || json?.error || `HTTP ${upstream.status}`
        res.writeHead(upstream.status, { 'Content-Type': 'application/json' })
        return res.end(JSON.stringify({ ok: false, error: String(detail).slice(0, 300) }))
      }

      const item = json?.data?.[0]
      const url = item?.url || (item?.b64_json ? `data:image/png;base64,${item.b64_json}` : null)
      if (!url) {
        lastError = 'The provider returned no image.'
        continue
      }

      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(
        JSON.stringify({
          ok: true,
          url,
          size,
          ratio,
          revised_prompt: item?.revised_prompt || null,
          created: json?.created || Date.now(),
        })
      )
    } catch (err) {
      lastError = err.message
    }
  }

  res.writeHead(502, { 'Content-Type': 'application/json' })
  res.end(
    JSON.stringify({ ok: false, error: lastError || 'The image model did not answer.' })
  )
}
