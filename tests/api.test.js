import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { api, setTokens, clearTokens, getAccessToken, setUnauthorizedHandler } from '../src/services/api.js'

const storage = new Map()
globalThis.localStorage = {
  getItem: (key) => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, value),
  removeItem: (key) => storage.delete(key),
}
const originalFetch = globalThis.fetch
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
beforeEach(() => { storage.clear(); setTokens({ access_token: 'old', refresh_token: 'refresh' }); setUnauthorizedHandler(() => {}) })
afterEach(async () => { globalThis.fetch = originalFetch; await new Promise((resolve) => setTimeout(resolve, 5)) })

test('concurrent protected requests share one token refresh', async () => {
  let refreshes = 0
  globalThis.fetch = async (url, options) => {
    if (url.endsWith('/auth/refresh')) { refreshes++; await new Promise((resolve) => setTimeout(resolve, 10)); return json({ access_token: 'new' }) }
    return options.headers.Authorization === 'Bearer new' ? json({ total: 0 }) : json({}, 401)
  }
  await Promise.all([api.sessions.list(), api.alerts.stats(), api.dashboard.stats()])
  assert.equal(refreshes, 1)
  assert.equal(getAccessToken(), 'new')
})

test('exports recover an expired token and preserve download metadata', async () => {
  globalThis.fetch = async (url, options) => {
    if (url.endsWith('/auth/refresh')) return json({ access_token: 'new' })
    if (options.headers.Authorization !== 'Bearer new') return json({}, 401)
    assert.match(url, /protocol=ssh/)
    return new Response('data', { headers: { 'Content-Disposition': 'attachment; filename="sessions.csv"', 'X-Export-Count': '5000', 'X-Export-Truncated': 'true' } })
  }
  const result = await api.export.sessions({ format: 'csv', protocol: 'ssh' })
  assert.equal(result.filename, 'sessions.csv')
  assert.equal(result.count, 5000)
  assert.equal(result.truncated, true)
  assert.equal(await result.blob.text(), 'data')
})

test('invalid login preserves server error without attempting refresh', async () => {
  let calls = 0
  globalThis.fetch = async () => { calls++; return json({ detail: 'Incorrect email or password' }, 401) }
  await assert.rejects(api.auth.login('a@example.com', 'wrong'), /Incorrect email or password/)
  assert.equal(calls, 1)
  assert.equal(getAccessToken(), 'old')
})

test('logout during refresh cannot restore a signed-out session', async () => {
  globalThis.fetch = async (url) => {
    if (url.endsWith('/auth/refresh')) { clearTokens(); return json({ access_token: 'new' }) }
    return json({}, 401)
  }
  await assert.rejects(api.sessions.list(), /session has expired/)
  assert.equal(getAccessToken(), null)
})

test('a rejected refreshed token signs the user out', async () => {
  let unauthorized = 0
  setUnauthorizedHandler(() => unauthorized++)
  globalThis.fetch = async (url) => url.endsWith('/auth/refresh') ? json({ access_token: 'new' }) : json({}, 401)
  await assert.rejects(api.sessions.list(), /session has expired/)
  assert.equal(getAccessToken(), null)
  assert.equal(unauthorized, 1)
})

test('cancellation remains distinguishable from connection failure', async () => {
  globalThis.fetch = async () => { throw new DOMException('Cancelled', 'AbortError') }
  await assert.rejects(api.sessions.list(), { name: 'AbortError' })
})

test('download network failures produce an actionable error', async () => {
  globalThis.fetch = async () => { throw new TypeError('Failed to fetch') }
  await assert.rejects(api.export.sessions(), /Cannot reach the API/)
})
