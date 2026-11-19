import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, mkdtemp, rmdir, unlink } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { chromium } from 'playwright'

const frontend = fileURLToPath(new URL('..', import.meta.url))
const backend = fileURLToPath(new URL('../../backend', import.meta.url))
const preview = process.argv.includes('--preview')
const screenshots = process.argv.includes('--screenshots') ? join(frontend, '..', 'docs', 'screenshots') : null
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const origin = (port) => 'http://127.0.0.1:' + port
const logs = []
const network = []

function launch(program, args, cwd, env) {
  const child = spawn(program, args, { cwd, env: { ...process.env, ...env }, windowsHide: true })
  child.on('error', (error) => logs.push(error.message))
  for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => logs.push(String(chunk)))
  return child
}

async function stop(child) {
  if (child?.pid && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit')
    child.kill()
    await exited
  }
}

async function listen() {
  const server = createServer((socket) => socket.end())
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return server
}

async function freePort() {
  const server = await listen()
  const port = server.address().port
  await close(server)
  return port
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
}

async function waitReady(url) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const response = await fetch(url, { signal: AbortSignal.timeout(500) }).catch(() => null)
    if (response?.ok) return response
    await pause(100)
  }
  throw new Error('Server did not start at ' + url)
}

function checkContract(paths) {
  for (const { method, path } of network) {
    const route = Object.keys(paths).find((template) => {
      const expected = template.split('/')
      const actual = path.split('/')
      return expected.length === actual.length && expected.every((part, index) =>
        part === actual[index] || (part.startsWith('{') && actual[index].length > 0))
    })
    assert.ok(route && paths[route][method.toLowerCase()], method + ' ' + path + ' is missing from OpenAPI')
  }
}

async function exercise(page, web, api, servicePort) {
  const text = (name) => page.getByText(name, { exact: true })
  const button = (name) => page.getByRole('button', { name, exact: true })
  const field = (name) => page.getByLabel(name, { exact: true })
  const link = (name) => page.getByRole('link', { name, exact: true })
  const heading = (name) => page.getByRole('heading', { name, exact: true })
  const dialog = page.getByRole('dialog')
  const responseFor = (method, path) => page.waitForResponse((response) =>
    response.request().method() === method && new URL(response.url()).pathname === '/api' + path)

  await page.goto(web)
  await text('Operational').waitFor()
  const health = responseFor('GET', '/health')
  await button('Refresh').click()
  assert.equal((await health).status(), 200)
  await button('Apply date range').click()
  await text('Registered assets').waitFor()
  for (const [action, name] of [['Open scans', 'Scans'], ['Generate reports', 'Reports'], ['Manage assets', 'Assets']]) {
    await link(action).click()
    await heading(name).waitFor()
    await link('Overview').click()
    await heading('Overview').waitFor()
  }

  await link('Assets').click()
  await text('No assets in the inventory yet.').waitFor()
  await button('Add asset').click()
  await dialog.getByRole('button', { name: 'Close', exact: true }).click()
  await dialog.waitFor({ state: 'hidden' })
  await button('Add asset').click()
  await page.keyboard.press('Escape')
  await dialog.waitFor({ state: 'hidden' })
  await button('Add asset').click()
  await dialog.getByLabel('IP address', { exact: true }).fill('192.168.17.10')
  await dialog.getByLabel('Display name', { exact: true }).fill('Loopback E2E')
  await dialog.getByLabel('Asset type', { exact: true }).fill('Server')
  const rejected = responseFor('POST', '/assets')
  await button('Save asset').click()
  assert.equal((await rejected).status(), 403)
  await dialog.getByRole('alert').getByText('IP address is outside the approved scope.').waitFor()
  await dialog.getByLabel('IP address', { exact: true }).fill('127.0.0.1')
  await dialog.getByLabel('Group', { exact: true }).fill('Control room')
  await dialog.getByLabel('Tags (one per line)', { exact: true }).fill('managed\nloopback')
  await dialog.getByLabel('Notes', { exact: true }).fill('Local integration record')
  const created = responseFor('POST', '/assets')
  await button('Save asset').click()
  const createdResponse = await created
  assert.equal(createdResponse.status(), 201)
  const asset = await createdResponse.json()
  assert.equal(asset.ip_address, '127.0.0.1')
  await button('Loopback E2E').waitFor()
  await page.reload()
  await button('Loopback E2E').click()
  await page.getByText('Control room', { exact: true }).last().waitFor()
  await page.getByText('Local integration record', { exact: true }).waitFor()
  assert.equal((await (await fetch(api + '/api/assets/' + asset.id)).json()).display_name, 'Loopback E2E')
  await button('Edit').click()
  await dialog.getByLabel('Display name', { exact: true }).fill('Renamed loopback')
  await button('Save asset').click()
  await heading('Renamed loopback').waitFor()
  await field('Search assets').fill('no match')
  await text('No assets match your search.').waitFor()
  await field('Search assets').fill('')
  await field('Filter asset availability').selectOption('reachable')
  await text('No assets match your search.').waitFor()
  await field('Filter asset availability').selectOption('')
  await button('Close details').click()
  await button('Refresh').click()
  await button('Renamed loopback').click()
  await button('Check availability').click()
  await text('127.0.0.1 is reachable on TCP ' + servicePort + '.').waitFor()
  await pause(1050)
  await button('Discover').click()
  await dialog.getByLabel('IP addresses, one per line', { exact: true }).fill('127.0.0.1')
  await dialog.getByRole('button', { name: 'Validate targets' }).click()
  await page.getByText('In scope: 127.0.0.1', { exact: true }).waitFor()
  await dialog.getByRole('checkbox').check()
  await dialog.getByRole('button', { name: 'Discover assets' }).click()
  await page.getByText(/Discovery #.+completed/).waitFor()
  await dialog.getByLabel('IP addresses, one per line', { exact: true }).fill('127.0.0.1\n::1')
  await dialog.getByRole('checkbox').check()
  await dialog.getByRole('button', { name: 'Discover assets' }).click()
  await dialog.getByRole('button', { name: 'Cancel discovery' }).click()
  await page.getByText(/Discovery #.+cancelled/).waitFor()
  await dialog.getByRole('button', { name: 'Close', exact: true }).click()
  await pause(1100)

  await link('Scans').click()
  await field('Service name').fill('Local E2E service')
  await field('TCP port').fill(String(servicePort))
  await field('I approve checks on this TCP port.').check()
  await button('Approve service').click()
  const services = field('Approved service endpoints')
  await services.locator('option').waitFor({ state: 'attached' })
  const serviceId = await services.locator('option').first().getAttribute('value')

  async function createJob() {
    await field('Approved assets').selectOption(String(asset.id))
    await services.selectOption(serviceId)
    await field('I am authorized to check every selected asset and service combination.').check()
    const creation = responseFor('POST', '/scan-jobs')
    await button('Create job').click()
    const job = await (await creation).json()
    await heading('Job #' + job.id + ' details').waitFor()
    return job.id
  }

  const completed = await createJob()
  await field('I approve each listed connection.').check()
  await button('Start job').click()
  await page.getByText(/completed.+1 of 1 checks/).waitFor()
  for (const format of ['JSON', 'CSV']) {
    const download = page.waitForEvent('download')
    await button('Export ' + format).click()
    assert.equal((await download).suggestedFilename(), 'scan-' + completed + '.' + format.toLowerCase())
  }
  await createJob()
  await button('Cancel job').click()
  await page.getByText(/cancelled.+0 of 1 checks/).waitFor()
  page.once('dialog', (confirm) => confirm.accept())
  await button('Revoke').click()
  await text('No approved services.').waitFor()
  await button('Job #' + completed).click()
  await heading('Job #' + completed + ' details').waitFor()

  await link('Scan History').click()
  await field('Start date (UTC)').fill('2000-01-01')
  await field('End date (UTC)').fill('2000-01-02')
  await text('No completed results match these filters.').waitFor()
  await button('Clear dates').click()
  await button('Renamed loopback').waitFor()
  await field('Connectivity status').selectOption('unknown')
  await text('No completed results match these filters.').waitFor()
  await field('Connectivity status').selectOption('reachable')
  await field('Search history').fill('Local E2E')
  await button('Renamed loopback').click()
  await text('inconclusive').waitFor()

  await link('Reports').click()
  await field('Start date (UTC)').fill('2000-01-01')
  await field('End date (UTC)').fill('2000-01-02')
  for (const kind of ['full', 'inventory', 'monitoring']) {
    await page.locator('input[name="report-kind"][value="' + kind + '"]').check()
    const pdf = page.waitForEvent('download')
    await button('Download PDF').click()
    assert.equal((await pdf).suggestedFilename(), 'luniscan-' + kind + '-2000-01-01-2000-01-02.pdf')
    await text('PDF ready. Download started.').waitFor()
  }
  for (const format of ['JSON', 'CSV']) {
    const download = page.waitForEvent('download')
    await button('Export job ' + completed + ' as ' + format).click()
    assert.equal((await download).suggestedFilename(), 'scan-' + completed + '.' + format.toLowerCase())
  }
  await page.route('**/api/scan-jobs/*/export/json', async (route) => {
    const missing = new URL('/api/scan-jobs/999999/export/json', web)
    await route.fulfill({ response: await route.fetch({ url: missing.href }) })
  })
  await button('Export job ' + completed + ' as JSON').click()
  await text('Scan job not found.').waitFor()
  assert.equal(new URL(page.url()).hash, '#reports')
  await page.unroute('**/api/scan-jobs/*/export/json')

  await link('Settings').click()
  await heading('Active network scope').waitFor()
  await page.getByText(/127\.0\.0\.1\/32/).waitFor()
  await button('Refresh scope').click()
  await page.getByText(/127\.0\.0\.1\/32/).waitFor()
  await field('IP address').fill('127.0.0.1')
  await button('Validate address').click()
  await text('127.0.0.1 is in the approved scope.').waitFor()
  await field('IP address').fill('192.168.17.10')
  await button('Validate address').click()
  await text('IP address is outside the approved scope.').waitFor()

  for (const name of ['Overview', 'Assets', 'Scans', 'Scan History', 'Reports', 'Settings']) {
    await link(name).click()
    await page.reload()
    await heading(name).waitFor()
  }
  await link('LuniScan').click()
  await heading('Overview').waitFor()
  await page.getByRole('figure', { name: 'Service connectivity distribution' })
    .locator('svg.recharts-surface').first().waitFor()
  if (screenshots) {
    await page.screenshot({ path: join(screenshots, 'overview.png'), fullPage: true, animations: 'disabled' })
  }

  await link('Assets').click()
  await button('Renamed loopback').click()
  await heading('Renamed loopback').waitFor()
  if (screenshots) await page.screenshot({ path: join(screenshots, 'assets.png'), animations: 'disabled' })
  await button('Delete').click()
  await button('Cancel').click()
  await heading('Renamed loopback').waitFor()
  await button('Delete').click()
  await button('Delete asset').click()
  await text('No assets in the inventory yet.').waitFor()

  await page.route('**/api/scope', (route) => route.fulfill({
    status: 503, contentType: 'application/json', body: '{"detail":"Scope display unavailable."}',
  }))
  await button('Refresh').click()
  await text('Scope details: Scope display unavailable.').waitFor()
  assert.equal(await button('Discover').isEnabled(), false)
  await button('Add asset').click()
  await dialog.getByLabel('IP address', { exact: true }).fill('127.0.0.1')
  await dialog.getByLabel('Display name', { exact: true }).fill('Scope UI recovery')
  await dialog.getByLabel('Asset type', { exact: true }).fill('Server')
  await button('Save asset').click()
  await button('Scope UI recovery').waitFor()
  await page.unroute('**/api/scope')
}

async function exercisePagination(page, web, python, database) {
  // Populate only the disposable database, without issuing extra network checks.
  await promisify(execFile)(python, ['-c', [
    'import sqlite3, sys',
    'with sqlite3.connect(sys.argv[1]) as db:',
    '    source = db.execute("SELECT job_id FROM scan_results LIMIT 1").fetchone()[0]',
    '    for _ in range(50):',
    '        job_id = db.execute("INSERT INTO scan_jobs (status, created_at, started_at, completed_at, asset_count, check_count, done_count, plan, failure) SELECT status, created_at, started_at, completed_at, asset_count, check_count, done_count, plan, failure FROM scan_jobs WHERE id = ?", (source,)).lastrowid',
    '        db.execute("INSERT INTO scan_results (job_id, asset_id, asset_name, ip_address, address_revision, service_id, service_name, port, status, error_category, checked_at) SELECT ?, asset_id, asset_name, ip_address, address_revision, service_id, service_name, port, status, error_category, checked_at FROM scan_results WHERE job_id = ?", (job_id, source))',
  ].join('\n'), database])
  const button = (name) => page.getByRole('button', { name, exact: true })
  await page.goto(web + '/#scan-history')
  await button('Next').click()
  await page.getByRole('row').nth(1).waitFor()
  assert.equal(await page.getByRole('row').count(), 2)
  await button('Previous').click()
  await button('Next').waitFor()
  await page.getByRole('link', { name: 'Overview', exact: true }).click()
  await button('Older events').click()
  await button('Previous events').click()
  await button('Older events').waitFor()
}

const folder = await mkdtemp(join(tmpdir(), 'luniscan-edge-'))
const database = join(folder, 'inventory.db')
const listener = await listen()
let apiProcess, webProcess, browser
try {
  const port = listener.address().port
  const apiPort = await freePort()
  const webPort = await freePort()
  const api = origin(apiPort)
  const web = origin(webPort)
  const python = join(backend, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
  apiProcess = launch(python, ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(apiPort)], backend, {
    LUNISCAN_DATABASE_URL: 'sqlite:///' + database.replaceAll('\\', '/'),
    LUNISCAN_APPROVED_SCOPE: '["127.0.0.1","::1"]',
    LUNISCAN_APPROVED_SERVICE_PORT: String(port),
  })
  webProcess = launch(process.execPath, [
    'node_modules/vite/bin/vite.js', ...(preview ? ['preview'] : []), '--strictPort', '--port', String(webPort),
  ], frontend, { LUNISCAN_API_PROXY_TARGET: api })
  const [openapi] = await Promise.all([waitReady(api + '/openapi.json'), waitReady(web)])
  const { paths } = await openapi.json()
  browser = await chromium.launch({ channel: 'msedge' })
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } })
  if (screenshots) await mkdir(screenshots, { recursive: true })
  const browserErrors = []
  const consoleErrors = []
  page.setDefaultTimeout(15000)
  page.on('pageerror', (error) => browserErrors.push(error.message))
  page.on('console', (message) => {
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource:')) {
      consoleErrors.push(message.text())
    }
  })
  page.on('response', (response) => {
    const path = new URL(response.url()).pathname
    if (path.startsWith('/api/')) network.push({ method: response.request().method(), path, status: response.status() })
  })
  await exercise(page, web, api, port)
  await exercisePagination(page, web, python, database)
  await page.setViewportSize({ width: 375, height: 812 })
  await page.emulateMedia({ reducedMotion: 'reduce' })
  for (const name of ['Overview', 'Assets', 'Scans', 'Scan History', 'Reports', 'Settings']) {
    await page.getByRole('link', { name, exact: true }).click()
    await page.getByRole('heading', { name, exact: true }).waitFor()
    await pause(350)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 375, name)
    if (screenshots && name === 'Overview') {
      await page.screenshot({ path: join(screenshots, 'overview-mobile.png'), animations: 'disabled' })
    }
  }
  checkContract(paths)
  assert.deepEqual(browserErrors, [])
  assert.deepEqual(consoleErrors, [])
  const errors = [...new Set(network.filter(({ status }) => status >= 400)
    .map(({ method, path, status }) => method + ' ' + path + ' ' + status))].sort()
  assert.deepEqual(errors, [
    'GET /api/scan-jobs/1/export/json 404', 'GET /api/scope 503',
    'POST /api/assets 403', 'POST /api/scope/validate 403',
  ].sort())
  assert.match(logs.join(''), /POST \/api\/assets HTTP\/1\.1" 201/)
  console.log('Edge integration passed against Vite ' + (preview ? 'preview' : 'development') +
    '. Every browser API request matched FastAPI OpenAPI.')
} catch (error) {
  console.error(error, '\nBrowser requests:', network, '\nServer logs:\n', logs.join(''))
  process.exitCode = 1
} finally {
  await browser?.close()
  await Promise.all([stop(apiProcess), stop(webProcess)])
  await close(listener)
  await unlink(database).catch((error) => { if (error.code !== 'ENOENT') throw error })
  await rmdir(folder)
}
