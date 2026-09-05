import { test, expect } from '@playwright/test'

const session = {
  id: 1, session_uuid: 'test-session-1', attacker_ip: '192.0.2.10',
  protocol: 'ssh', status: 'completed', started_at: '2026-01-01T10:00:00Z',
  attack_category: 'reconnaissance', is_anomalous: true, geo: { country: 'AE' },
  detected_tools: [], detected_intents: [], mitre_techniques: [], mitre_tactics: [],
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('access_token', 'test-token'))
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    let body = {}
    if (url.pathname.endsWith('/auth/me')) body = { email: 'analyst@example.com', role: 'analyst' }
    else if (url.pathname.endsWith('/sessions/')) body = { sessions: [session], total: 1 }
    else if (url.pathname.endsWith('/sessions/1')) body = session
    else if (url.pathname.endsWith('/nodes/')) body = []
    else if (url.pathname.endsWith('/honeypot/status')) body = { reachable: true, running: true, protocols: ['ssh'] }
    else if (url.pathname.endsWith('/alerts/stats')) body = { new: 3 }
    else if (url.pathname.endsWith('/export/')) {
      return route.fulfill({ body: 'Session ID,Protocol\ntest-session-1,ssh\n', headers: { 'Access-Control-Expose-Headers': 'Content-Disposition, X-Export-Count, X-Export-Truncated', 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="sessions.csv"', 'X-Export-Count': '1', 'X-Export-Truncated': 'false' } })
    }
    await route.fulfill({ json: body })
  })
})

test('restores filters from links and exports the same investigation', async ({ page }) => {
  await page.goto('/sessions?protocol=ssh&exclude_scanners=true')
  await expect(page.getByRole('heading', { name: 'Sessions', exact: true })).toBeVisible()
  await expect(page.getByText('1 matching sessions', { exact: true })).toBeVisible()
  await expect(page.getByRole('combobox', { name: 'Protocol', exact: true })).toHaveValue('ssh')
  const request = page.waitForRequest((req) => req.url().includes('/export/'))
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'CSV', exact: true }).click()
  expect(new URL((await request).url()).searchParams.get('exclude_scanners')).toBe('true')
  expect((await download).suggestedFilename()).toBe('sessions.csv')
  await expect(page.getByRole('status')).toContainText('Exported 1 matching sessions')
  await page.getByRole('button', { name: 'Remove protocol filter' }).click()
  await expect(page).not.toHaveURL(/protocol=/)
  await page.reload()
  await expect(page.getByRole('combobox', { name: 'Protocol', exact: true })).toHaveValue('')
})

test('session browsing stays usable on narrow screens', async ({ page }, testInfo) => {
  await page.goto('/sessions')
  await expect(page.getByText('1 matching sessions', { exact: true })).toBeVisible()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.getByRole('button', { name: /192\.0\.2\.10/ }).click()
  if (testInfo.project.name === 'mobile') {
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toHaveCount(0)
  }
  await expect(page).toHaveURL(/session=1/)
  await page.screenshot({ path: testInfo.outputPath('sessions.png'), fullPage: true })
})

test('latest search wins even when an older request completes later', async ({ page }) => {
  await page.route('**/sessions/?**', async (route) => {
    const search = new URL(route.request().url()).searchParams.get('search')
    if (search === 'old') await new Promise((resolve) => setTimeout(resolve, 700))
    await route.fulfill({ json: { sessions: [{ ...session, attacker_ip: search === 'old' ? '192.0.2.99' : '192.0.2.10' }], total: 1 } })
  })
  await page.goto('/sessions')
  const input = page.getByRole('searchbox')
  const oldRequest = page.waitForRequest((req) => new URL(req.url()).searchParams.get('search') === 'old')
  await input.fill('old')
  await oldRequest
  await input.fill('new')
  await expect(page.getByRole('button', { name: /192\.0\.2\.10/ })).toBeVisible()
  await page.waitForTimeout(850)
  await expect(page.getByRole('button', { name: /192\.0\.2\.99/ })).toHaveCount(0)
})
