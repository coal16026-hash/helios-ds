/**
 * Wire the OAuth provider credentials into Vercel and redeploy.
 *
 *   $env:GITHUB_CLIENT_ID="...";  $env:GITHUB_CLIENT_SECRET="..."
 *   $env:DISCORD_CLIENT_ID="..."; $env:DISCORD_CLIENT_SECRET="..."
 *   node scripts/setup-oauth.mjs
 *
 * Register this exact callback URL with each provider:
 *   https://helios-frontend-zeta.vercel.app/api/auth
 */
import { spawn } from 'node:child_process'

const PAIRS = [
  ['GITHUB', 'GitHub → Settings → Developer settings → OAuth Apps → New OAuth App'],
  ['DISCORD', 'Discord Developer Portal → OAuth2 → General Information → Redirects'],
]

const VERCEL = 'npx'
const args = (v) => ['vercel', ...v]

function run(command, commandArgs) {
  return new Promise((resolve) => {
    const child = spawn(command, commandArgs, { stdio: 'inherit', shell: process.platform === 'win32' })
    child.on('exit', (code) => resolve(code || 0))
  })
}

let added = 0

for (const [prefix, where] of PAIRS) {
  const id = process.env[`${prefix}_CLIENT_ID`]
  const secret = process.env[`${prefix}_CLIENT_SECRET`]
  if (!id || !secret) {
    console.log(`- ${prefix}: skipped (missing ${prefix}_CLIENT_ID / ${prefix}_CLIENT_SECRET)`)
    console.log(`  create one at: ${where}`)
    continue
  }
  await run(VERCEL, args(['env', 'add', `${prefix}_CLIENT_ID`, 'production', '--value', id, '--yes']))
  await run(VERCEL, args(['env', 'add', `${prefix}_CLIENT_SECRET`, 'production', '--value', secret, '--yes']))
  added++
  console.log(`+ ${prefix}: credentials added`)
}

if (added) {
  console.log('\nRedeploying so the new env vars take effect...')
  await run(VERCEL, args(['--prod', '--yes']))
  console.log('\nDone. Sign in with that provider on the login screen.')
} else {
  console.log('\nNothing was added. Set the env vars and run this again.')
}
