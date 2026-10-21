/* The standalone Node server (Render / local) reuses the exact same auth
   implementation as the Vercel function so both behave identically. */
import handler from '../api/auth.js'

export const handleAuth = handler
