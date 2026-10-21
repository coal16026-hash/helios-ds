/**
 * Turn on real password-reset emails.
 *
 *   $env:RESEND_API_KEY="re_xxxx"      # from resend.com/api-keys
 *   $env:RESEND_FROM="Helios <hello@yourdomain.com>"   # a verified domain
 *   node scripts/setup-mailer.mjs
 *
 * Without a mailer the reset link is shown on screen instead of emailed.
 */
import { spawn } from 'node:child_process'

const PAIRS = [
  ['RESEND_API_KEY', 'Resend → API Keys → Create API Key'],
  ['RESEND_FROM', 'Resend → Domains (verify a domain, or use a verified sender)'],
]

function run(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: 'inherit', shell: process.platform === 'win32' })
    child.on('exit', (code) => resolve(code || 0))
  })
}

let added = 0
for (const [key, where] of PAIRS) {
  const value = process.env[key]
  if (!value) {
    console.log(`- ${key}: skipped (not set)`)
    console.log(`  get one from: ${where}`)
    continue
  }
  await run('npx', ['vercel', 'env', 'add', key, 'production', '--value', value, '--yes'])
  added++
  console.log(`+ ${key}: added to Vercel`)
}

if (added) {
  console.log('\nRedeploying so the mailer takes effect...')
  await run('npx', ['vercel', '--prod', '--yes'])
  console.log('\nDone. Password reset links will now be emailed.')
} else {
  console.log('\nSet RESEND_API_KEY and run this again.')
}
