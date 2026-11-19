import { useEffect, useState, type FormEvent } from 'react'
import { Bar, BarChart, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from 'recharts'
import { inventoryApi, type Asset } from './inventoryApi'
import {
  certificateStates, healthStates, monitorApi, protocols,
  type Alert, type Check, type Detail, type Profile, type ProfileInput, type Protocol, type Summary,
} from './monitorApi'
import { errorText, panelStyle } from './ReportingControls'
import { StatusBadge } from './StatusBadge'

const display = (value: string) => value.replaceAll('_', ' ')
const date = (value: string | null) => value ? new Date(value).toLocaleString() : '—'

function Options({ values }: { values: readonly string[] }) {
  return <>{values.map((value) => <option key={value} value={value}>{display(value)}</option>)}</>
}

function ProfileForm({ assets, existing, busy, onSave }: {
  assets: Asset[]; existing?: Profile; busy: boolean; onSave: (profile: ProfileInput) => void
}) {
  const [protocol, setProtocol] = useState<Protocol>(existing?.protocol ?? 'tcp')
  const web = protocol === 'http' || protocol === 'https'

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const field = (name: string) => String(fields.get(name) ?? '').trim()
    const asset = assets.find((item) => item.id === Number(field('asset_id')))
    if (!existing && !asset) return
    const expected = field('expected_content')
    const input: ProfileInput = {
      asset_id: existing?.asset_id ?? asset!.id,
      ip_address: existing?.ip_address ?? asset!.ip_address,
      protocol, port: existing?.port ?? Number(field('port')),
      name: field('name'), hostname: field('hostname') || null, timeout_ms: Number(field('timeout_ms')),
      path: web ? field('path') : '/',
      status_min: web ? Number(field('status_min')) : 200,
      status_max: web ? Number(field('status_max')) : 299,
      enabled: fields.has('enabled'), confirm_approval: fields.has('confirm_approval'),
    }
    if (expected || !existing || fields.has('clear_content')) input.expected_content = expected || null
    onSave(input)
  }

  return <form onSubmit={submit}>
    <fieldset disabled={busy} className="grid gap-3 sm:grid-cols-2">
      <label className="asset-label">Profile name<input className="asset-input" name="name" required maxLength={80} defaultValue={existing?.name} /></label>
      {!existing && <>
        <label className="asset-label">Approved asset<select aria-label="Approved asset" className="asset-input" name="asset_id" required defaultValue="">
          <option value="" disabled>Select an asset</option>{assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.display_name} · {asset.ip_address}</option>)}
        </select></label>
        <label className="asset-label">Protocol<select aria-label="Protocol" className="asset-input" value={protocol} onChange={(event) => setProtocol(event.target.value as Protocol)}>
          <Options values={protocols} />
        </select></label>
        <label className="asset-label">Approved TCP port<input className="asset-input" name="port" type="number" required min={1} max={65535} /></label>
      </>}
      <label className="asset-label">Hostname (optional)<input className="asset-input" name="hostname" maxLength={253} defaultValue={existing?.hostname ?? ''} /></label>
      <label className="asset-label">Timeout (ms)<input className="asset-input" name="timeout_ms" type="number" required min={250} max={3000} defaultValue={existing?.timeout_ms ?? 1500} /></label>
      {web && <>
        <label className="asset-label">Health path<input className="asset-input" name="path" required maxLength={128} defaultValue={existing?.path ?? '/'} /></label>
        <label className="asset-label">Expected response marker<input className="asset-input" name="expected_content" maxLength={128} placeholder="Optional non-sensitive text" /></label>
        {existing?.checks_content && <label className="flex gap-2 text-sm sm:col-span-2"><input type="checkbox" name="clear_content" /> Remove the saved marker</label>}
        <label className="asset-label">Minimum HTTP status<input className="asset-input" name="status_min" type="number" required min={200} max={599} defaultValue={existing?.status_min ?? 200} /></label>
        <label className="asset-label">Maximum HTTP status<input className="asset-input" name="status_max" type="number" required min={200} max={599} defaultValue={existing?.status_max ?? 299} /></label>
      </>}
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={existing?.enabled ?? true} /> Allow manual checks</label>
      <label className="flex gap-2 text-sm sm:col-span-2"><input type="checkbox" name="confirm_approval" required /> I authorize this destination and port.</label>
      <button className="asset-button asset-primary w-fit">{existing ? 'Save profile' : 'Create profile'}</button>
    </fieldset>
  </form>
}

function AlertList({ alerts, busy, onAcknowledge }: { alerts: Alert[]; busy: boolean; onAcknowledge: (id: number) => void }) {
  if (!alerts.length) return <p className="text-sm text-muted">No alerts match this view.</p>
  return <ul className="divide-y divide-line">
    {alerts.map((alert) => <li className="flex flex-wrap items-center justify-between gap-3 py-3" key={alert.id}>
      <div className="min-w-0 text-sm">
        <p className="break-words">{alert.profile_name} · <span className="capitalize">{display(alert.kind)}</span></p>
        <p className="text-xs text-muted">{alert.severity} · {alert.status} · {date(alert.created_at)}</p>
        {alert.acknowledged_at && <p className="text-xs text-muted">Acknowledged {date(alert.acknowledged_at)}</p>}
        {alert.resolved_at && <p className="text-xs text-muted">Resolved {date(alert.resolved_at)}</p>}
      </div>
      {alert.status === 'active' && <button type="button" className="asset-button" disabled={busy}
        onClick={() => onAcknowledge(alert.id)}>Acknowledge alert #{alert.id}</button>}
    </li>)}
  </ul>
}

function CheckList({ history }: { history: Check[] }) {
  if (!history.length) return <p className="text-sm text-muted">No checks recorded.</p>
  return <ul className="divide-y divide-line">{history.map((check) => <li key={check.id} className="flex flex-wrap items-center gap-2 py-2 text-sm">
    <span className="font-mono text-xs text-muted">#{check.profile_id}</span><StatusBadge status={check.health} />
    {check.previous_health && check.previous_health !== check.health && <span>Previously {check.previous_health}</span>}
    {check.http_status !== null && <span>HTTP {check.http_status}{check.expected_status === false && ' · unexpected'}</span>}
    <span>{check.duration_ms} ms · {display(check.outcome)}</span>
    {check.content_match !== null && <span>Content {check.content_match ? 'matched' : 'mismatch'}</span>}
    {check.error && <span className="text-muted">{display(check.error)}</span>}
    <time className="text-xs text-muted">{date(check.checked_at)}</time>
  </li>)}</ul>
}

function Trends({ summary }: { summary: Summary }) {
  if (!summary.daily.length) return <p className="text-sm text-muted">Run a manual check to start collecting trends.</p>
  return <div className="two-pane scan-compose">
    <figure className={panelStyle} aria-label="Service health trend">
      <figcaption className="text-sm">Check outcomes by UTC day</figcaption>
      <div className="h-48 min-w-0 overflow-x-clip"><ResponsiveContainer width="100%" height="100%">
        <BarChart data={summary.daily} accessibilityLayer><XAxis dataKey="day" tickFormatter={(day) => day.slice(5)} /><YAxis allowDecimals={false} width={28} />
          <Tooltip /><Legend /><Bar dataKey="healthy" fill="#9bccad" isAnimationActive={false} />
          <Bar dataKey="failed" fill="#e9a5ab" isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer></div>
    </figure>
    <figure className={panelStyle} aria-label="HTTP response time trend">
      <figcaption className="text-sm">Average HTTP response time (ms)</figcaption>
      {summary.daily.every((item) => item.mean_http_ms === null) ? <p className="mt-3 text-sm text-muted">No HTTP responses recorded.</p> :
        <div className="h-48 min-w-0 overflow-x-clip"><ResponsiveContainer width="100%" height="100%">
          <LineChart data={summary.daily} accessibilityLayer><XAxis dataKey="day" tickFormatter={(day) => day.slice(5)} />
            <YAxis width={36} /><Tooltip /><Line dataKey="mean_http_ms" stroke="#e8be9e" isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer></div>}
    </figure>
  </div>
}

export default function MonitoringPage() {
  const [tab, setTab] = useState<'services' | 'alerts'>('services')
  const [assets, setAssets] = useState<Asset[]>([])
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [detail, setDetail] = useState<Detail | null>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const [editing, setEditing] = useState(false)
  const [adding, setAdding] = useState(false)
  const [filters, setFilters] = useState<Record<string, string>>({})
  const [alertFilter, setAlertFilter] = useState('')
  const [severity, setSeverity] = useState('')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [revision, setRevision] = useState(0)
  const [offset, setOffset] = useState(0)
  const [alertOffset, setAlertOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    Promise.all([
      inventoryApi.list(controller.signal), monitorApi.summary(controller.signal),
    ]).then(([items, stats]) => {
      if (!controller.signal.aborted) { setAssets(items); setSummary(stats) }
    }).catch((cause) => { if (!controller.signal.aborted) setError(errorText(cause)) })
    return () => controller.abort()
  }, [revision])

  useEffect(() => {
    const controller = new AbortController()
    const query = new URLSearchParams({ offset: String(offset), limit: '25' })
    Object.entries(filters).forEach(([key, value]) => { if (value) query.set(key, value) })
    setLoading(true)
    monitorApi.profiles(query, controller.signal).then((items) => {
      if (!controller.signal.aborted) setProfiles(items)
    }).catch((cause) => { if (!controller.signal.aborted) setError(errorText(cause)) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [filters, offset, revision])

  useEffect(() => {
    if (selected === null) return
    const controller = new AbortController()
    monitorApi.detail(selected, controller.signal).then((item) => {
      if (!controller.signal.aborted) setDetail(item)
    }).catch((cause) => { if (!controller.signal.aborted) setError(errorText(cause)) })
    return () => controller.abort()
  }, [selected, revision])

  useEffect(() => {
    if (tab !== 'alerts') return
    const controller = new AbortController()
    const query = new URLSearchParams({ offset: String(alertOffset), limit: '25' })
    if (alertFilter) query.set('status', alertFilter)
    if (severity) query.set('severity', severity)
    monitorApi.alerts(query, controller.signal).then((items) => {
      if (!controller.signal.aborted) setAlerts(items)
    }).catch((cause) => { if (!controller.signal.aborted) setError(errorText(cause)) })
    return () => controller.abort()
  }, [tab, alertFilter, severity, alertOffset, revision])

  async function act(action: () => Promise<void>) {
    setError('')
    setBusy(true)
    try { await action(); setRevision((old) => old + 1) }
    catch (cause) { setError(errorText(cause)) }
    finally { setBusy(false) }
  }

  function selectProfile(id: number | null) {
    setSelected(id)
    setDetail(null)
    setEditing(false)
  }

  const acknowledge = (id: number) => void act(async () => { await monitorApi.acknowledge(id) })
  const filter = (key: string, value: string) => { setFilters((current) => ({ ...current, [key]: value })); setOffset(0) }
  const current = detail?.profile
  const cert = detail?.certificate

  return <div className="workspace-stack">
    <div className="flex flex-wrap gap-2">
      <button className="asset-button" aria-pressed={tab === 'services'} onClick={() => setTab('services')}>Monitored services</button>
      <button className="asset-button" aria-pressed={tab === 'alerts'} onClick={() => setTab('alerts')}>Alert Center</button>
      <button className="asset-button" disabled={busy} onClick={() => { setError(''); setRevision((old) => old + 1) }}>Refresh monitoring</button>
    </div>
    {error && <p role="alert" className="break-words text-sm text-rose-300">{error}</p>}
    {tab === 'alerts' ? <section className={panelStyle}>
      <h2>Alert Center</h2>
      <div className="my-3 grid gap-3 sm:grid-cols-2">
        <label className="asset-label">Alert status<select aria-label="Alert status" className="asset-input" value={alertFilter}
          onChange={(event) => { setAlertFilter(event.target.value); setAlertOffset(0) }}>
          <option value="">All statuses</option><Options values={['active', 'acknowledged', 'resolved']} />
        </select></label>
        <label className="asset-label">Severity<select aria-label="Severity" className="asset-input" value={severity}
          onChange={(event) => { setSeverity(event.target.value); setAlertOffset(0) }}>
          <option value="">All severities</option><Options values={['warning', 'critical']} />
        </select></label>
      </div>
      <AlertList alerts={alerts} busy={busy} onAcknowledge={acknowledge} />
      {alertOffset > 0 && <button className="asset-button" onClick={() => setAlertOffset(alertOffset - 25)}>Previous alerts</button>}
      {alerts.length === 25 && <button className="asset-button" onClick={() => setAlertOffset(alertOffset + 25)}>More alerts</button>}
    </section> : <>
      {summary ? <section aria-label="Monitoring summary" className="inventory-summary grid grid-cols-2 sm:grid-cols-5">
        <div className="inventory-stat"><p className="text-sm text-muted">Monitored services</p><p>{Object.values(summary.profiles).reduce((a, b) => a + b, 0)}</p></div>
        {healthStates.map((state) => <div key={state} className="inventory-stat"><p className="text-sm capitalize text-muted">{state}</p><p>{summary.profiles[state] ?? 0}</p></div>)}
      </section> : <p role="status" className="text-sm text-muted">Loading summary…</p>}
      <section className={panelStyle}>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><h2>Approved monitoring profiles</h2>
          <button className="asset-button asset-primary" disabled={busy} onClick={() => setAdding((value) => !value)}>{adding ? 'Close profile form' : 'New profile'}</button>
        </div>
        {adding && <div className="mb-4 border-b border-line pb-4"><ProfileForm assets={assets} busy={busy}
          onSave={(input) => void act(async () => { const created = await monitorApi.add(input); setAdding(false); selectProfile(created.id) })} /></div>}
        <div className="workspace-toolbar mb-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
          <label className="asset-label">Asset filter<select aria-label="Asset filter" className="asset-input" value={filters.asset_id ?? ''}
            onChange={(event) => filter('asset_id', event.target.value)}><option value="">All assets</option>
            {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.display_name}</option>)}</select></label>
          {([['protocol', 'Protocol filter', protocols], ['health', 'Health filter', healthStates],
            ['certificate_state', 'Certificate filter', certificateStates]] as const).map(([key, title, values]) =>
            <label key={key} className="asset-label">{title}<select aria-label={title} className="asset-input" value={filters[key] ?? ''}
              onChange={(event) => filter(key, event.target.value)}><option value="">All</option><Options values={values} /></select></label>)}
          <label className="asset-label">Profile ID filter<input className="asset-input" type="number" min={1} step={1} value={filters.profile_id ?? ''}
            onChange={(event) => filter('profile_id', event.target.value)} /></label>
        </div>
        {loading ? <p role="status">Loading profiles…</p> : profiles.length === 0 ? <p className="text-sm text-muted">No matching profiles.</p> :
          <div className="overflow-x-auto"><table className="editorial-table w-full min-w-[38rem] text-left text-sm">
            <thead><tr>{['Service', 'Asset', 'Protocol', 'Port', 'Health', 'Duration', 'Last checked', 'Certificate'].map((label) => <th className="p-2" key={label}>{label}</th>)}</tr></thead>
            <tbody className="divide-y divide-line">{profiles.map((item) => <tr key={item.id}>
              <td className="p-2"><button className="asset-button whitespace-normal text-left" onClick={() => selectProfile(item.id)}>{item.name}</button></td>
              <td className="p-2">{item.asset_name ?? 'Removed asset'}</td><td className="p-2 uppercase">{item.protocol}</td><td className="p-2">{item.port}</td>
              <td className="p-2"><StatusBadge status={item.enabled ? item.health : 'disabled'} /></td>
              <td className="p-2">{item.duration_ms === null ? '—' : item.duration_ms + ' ms'}</td>
              <td className="p-2">{date(item.last_checked)}</td><td className="p-2">{item.certificate_state ? display(item.certificate_state) : '—'}</td>
            </tr>)}</tbody>
          </table></div>}
        {offset > 0 && <button className="asset-button" onClick={() => setOffset(offset - 25)}>Previous profiles</button>}
        {profiles.length === 25 && <button className="asset-button" onClick={() => setOffset(offset + 25)}>More profiles</button>}
      </section>
      {current && detail && <section className={panelStyle} aria-label="Service details">
        <h2 className="break-words">{current.name}</h2>
        <p className="my-2 break-words text-sm text-muted">#{current.id} · {current.asset_name ?? 'Removed asset'} · {current.ip_address} · TCP {current.port} · {current.protocol.toUpperCase()} · {current.timeout_ms} ms timeout</p>
        <p className="break-words text-sm text-muted">Host/SNI {current.hostname ?? 'IP address'} · Last successful {date(current.last_success)} · Last failed {date(current.last_failure)}</p>
        {(current.protocol === 'http' || current.protocol === 'https') && <p className="break-words text-sm text-muted">
          {current.path} · Expected HTTP {current.status_min}–{current.status_max} · Content check {current.checks_content ? 'enabled' : 'disabled'}
        </p>}
        <div className="my-3 flex flex-wrap gap-2">
          <button className="asset-button asset-primary" disabled={busy || !current.enabled || !current.asset_name}
            onClick={() => void act(async () => { await monitorApi.check(current.id) })}>Run manual check</button>
          <button className="asset-button" disabled={busy || !current.asset_name} onClick={() => setEditing(!editing)}>{editing ? 'Close editor' : 'Edit profile'}</button>
          <button className="asset-button" disabled={busy} onClick={() => {
            if (window.confirm('Archive this monitoring profile?')) void act(async () => { await monitorApi.archive(current.id); selectProfile(null) })
          }}>Archive profile</button>
        </div>
        {busy && <p role="status" className="text-sm text-muted">Request in progress…</p>}
        {editing && <ProfileForm key={current.id} assets={assets} existing={current} busy={busy}
          onSave={(input) => void act(async () => { await monitorApi.edit(current.id, input); setEditing(false) })} />}
        <div className="two-pane settings-layout mt-4">
          <section>
            <h3 className="mb-2 font-semibold">TLS Certificate Intelligence</h3>
            {cert ? <dl className="settings-facts text-sm">
              <div><dt>State</dt><dd>{display(cert.state)}</dd></div>
              <div><dt>Verification</dt><dd>{cert.verified === true ? 'Verified' : cert.verified === false ? 'Failed' : 'Unavailable'}</dd></div>
              <div><dt>Hostname</dt><dd>{cert.hostname_valid === true ? 'Matched' : cert.hostname_valid === false ? 'Mismatch' : 'Unavailable'}</dd></div>
              <div><dt>Subject</dt><dd className="break-words">{cert.subject ?? 'Unavailable'}</dd></div>
              <div><dt>Issuer</dt><dd className="break-words">{cert.issuer ?? 'Unavailable'}</dd></div>
              <div><dt>Valid from</dt><dd>{date(cert.valid_from)}</dd></div>
              <div><dt>Expires</dt><dd>{date(cert.expires_at)}{cert.days_remaining !== null && ' · ' + cert.days_remaining + ' days'}</dd></div>
              <div><dt>Inspected</dt><dd>{date(cert.inspected_at)}</dd></div>
            </dl> : <p className="text-sm text-muted">No certificate observation recorded.</p>}
          </section>
          <section>
            <h3 className="mb-2 font-semibold">Response time history</h3>
            {detail.history.length ? <div className="h-44 min-w-0 overflow-x-clip"><ResponsiveContainer width="100%" height="100%">
              <LineChart data={[...detail.history].reverse()} accessibilityLayer><XAxis dataKey="checked_at" hide />
                <YAxis width={44} /><Tooltip labelFormatter={(value) => date(String(value))} /><Line dataKey="duration_ms" stroke="#e8be9e" isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer></div> : <p className="text-sm text-muted">No measurements yet.</p>}
            <h3 className="mb-2 font-semibold">Related alerts</h3><AlertList alerts={detail.alerts} busy={busy} onAcknowledge={acknowledge} />
          </section>
        </div>
        <h3 className="mb-2 mt-4 font-semibold">Health history</h3>
        <CheckList history={detail.history} />
      </section>}
      {summary && <>
        <Trends summary={summary} />
        <div className="two-pane settings-layout">
          <section className={panelStyle}><h2 className="mb-2">Recent checks</h2><CheckList history={summary.recent} /></section>
          <section className={panelStyle}><h2 className="mb-2">Latest status changes</h2><CheckList history={summary.transitions} /></section>
        </div>
        <section className={panelStyle}><h2>Certificate and alert overview</h2>
          <p className="mt-2 text-sm text-muted">{Object.entries(summary.certificates).map(([state, count]) => count + ' ' + display(state)).join(' · ') || 'No TLS observations recorded.'}</p>
          <p className="mt-2 text-sm text-muted">{Object.entries(summary.alerts).map(([level, count]) => count + ' ' + level).join(' · ') || 'No open alerts.'}</p>
        </section>
      </>}
    </>}
  </div>
}
