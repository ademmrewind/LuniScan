import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Bar, BarChart, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { inventoryApi, type Asset } from './inventoryApi'
import { monitorApi, type Profile } from './monitorApi'
import { errorText, panelStyle } from './ReportingControls'
import {
  securityApi, severities, type Assessment, type AssessmentDetail, type Finding,
  type FindingDetail, type SecuritySummary, type Severity,
} from './securityApi'

const label = (value: string) => value.replaceAll('_', ' ')
const date = (value: string | null) => value ? new Date(value).toLocaleString() : '—'
const active = (item: Assessment | null) => item?.status === 'pending' || item?.status === 'running'
const pageSize = 20

export function SeverityTag({ severity }: { severity: Severity | null }) {
  return severity && <span className={'severity-tag severity-' + severity}>{severity}</span>
}

function Pagination({ offset, count, setOffset, noun }: {
  offset: number; count: number; setOffset: (value: number) => void; noun: string
}) {
  return <div className="mt-3 flex flex-wrap gap-2">
    {offset > 0 && <button className="asset-button" onClick={() => setOffset(offset - pageSize)}>Previous {noun}</button>}
    {count === pageSize && <button className="asset-button" onClick={() => setOffset(offset + pageSize)}>More {noun}</button>}
  </div>
}

export default function SecurityAssessmentPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [assetId, setAssetId] = useState('')
  const [profileId, setProfileId] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [summary, setSummary] = useState<SecuritySummary | null>(null)
  const [history, setHistory] = useState<Assessment[] | null>(null)
  const [detail, setDetail] = useState<AssessmentDetail | null>(null)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [finding, setFinding] = useState<FindingDetail | null>(null)
  const [findingId, setFindingId] = useState<number | null>(null)
  const [filters, setFilters] = useState({ severity: '', status: '', asset_id: '' })
  const [historyOffset, setHistoryOffset] = useState(0)
  const [findingsOffset, setFindingsOffset] = useState(0)
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [profilesLoading, setProfilesLoading] = useState(false)
  const synchronizedRuns = useRef(new Set<number>())

  useEffect(() => {
    const controller = new AbortController()
    const signal = controller.signal
    Promise.all([inventoryApi.list(signal), securityApi.summary(signal)]).then(([items, totals]) => {
      if (signal.aborted) return
      setAssets(items)
      setSummary(totals)
      setSelectedId((current) => current ?? totals.recent.find(active)?.id ?? null)
    }).catch((cause) => { if (!signal.aborted) setError(errorText(cause)) })
    return () => controller.abort()
  }, [revision])

  useEffect(() => {
    if (!assetId) return
    const controller = new AbortController()
    setProfilesLoading(true)
    monitorApi.profiles(new URLSearchParams({ asset_id: assetId, limit: '100' }), controller.signal)
      .then((items) => {
        if (!controller.signal.aborted) setProfiles(items.filter((item) => item.enabled && ['http', 'https'].includes(item.protocol)))
      }).catch((cause) => { if (!controller.signal.aborted) setError(errorText(cause)) })
      .finally(() => { if (!controller.signal.aborted) setProfilesLoading(false) })
    return () => controller.abort()
  }, [assetId])

  useEffect(() => {
    const controller = new AbortController()
    const signal = controller.signal
    const query = new URLSearchParams({ offset: String(historyOffset), limit: String(pageSize) })
    setHistory(null)
    securityApi.assessments(query, signal).then((items) => { if (!signal.aborted) setHistory(items) })
      .catch((cause) => { if (!signal.aborted) { setError(errorText(cause)); setHistory([]) } })
    return () => controller.abort()
  }, [revision, historyOffset])

  useEffect(() => {
    const controller = new AbortController()
    const signal = controller.signal
    const query = new URLSearchParams({ offset: String(findingsOffset), limit: String(pageSize) })
    Object.entries(filters).forEach(([key, value]) => { if (value) query.set(key, value) })
    setFindings(null)
    securityApi.findings(query, signal).then((items) => { if (!signal.aborted) setFindings(items) })
      .catch((cause) => { if (!signal.aborted) { setError(errorText(cause)); setFindings([]) } })
    return () => controller.abort()
  }, [revision, findingsOffset, filters])

  useEffect(() => {
    if (selectedId === null) return
    const controller = new AbortController()
    const id = selectedId
    let timer: number | undefined
    async function poll() {
      try {
        const result = await securityApi.assessment(id, controller.signal)
        if (controller.signal.aborted) return
        setDetail(result)
        if (active(result)) timer = window.setTimeout(() => void poll(), 500)
        else if (!synchronizedRuns.current.has(id)) {
          synchronizedRuns.current.add(id)
          setRevision((value) => value + 1)
        }
      } catch (cause) { if (!controller.signal.aborted) setError(errorText(cause)) }
    }
    void poll()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [selectedId, revision])

  useEffect(() => {
    if (findingId === null) return
    const controller = new AbortController()
    securityApi.finding(findingId, controller.signal)
      .then((item) => { if (!controller.signal.aborted) setFinding(item) })
      .catch((cause) => { if (!controller.signal.aborted) setError(errorText(cause)) })
    return () => controller.abort()
  }, [findingId, revision])

  async function act(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    try { await action(); setRevision((value) => value + 1) }
    catch (cause) { setError(errorText(cause)) }
    finally { setBusy(false) }
  }

  function selectAssessment(id: number) {
    if (id === selectedId) return
    setDetail(null)
    setSelectedId(id)
  }

  function selectFinding(id: number) {
    if (id === findingId) return
    setFinding(null)
    setFindingId(id)
  }

  function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!assetId || !profileId || !confirmed) return
    void act(async () => {
      const item = await securityApi.start(Number(assetId), Number(profileId), confirmed)
      selectAssessment(item.id)
      setConfirmed(false)
    })
  }

  function filter(key: keyof typeof filters, value: string) {
    setFilters((old) => ({ ...old, [key]: value }))
    setFindingsOffset(0)
  }

  return <div className="workspace-stack">
    {error && <p role="alert" className="break-words text-sm text-rose-300">{error}</p>}
    {summary && <section aria-label="Assessment overview" className="inventory-summary grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-6">
      <div className="inventory-stat"><p className="text-sm">Total assessments</p><p>{summary.assessment_count}</p></div>
      <div className="inventory-stat"><p className="text-sm">Assets with open findings</p><p>{summary.assets_with_open_findings}</p></div>
      {severities.map((level) => <div className="inventory-stat" key={level}><p className="text-sm capitalize">{level}</p><p>{summary.open_counts[level] ?? 0}</p></div>)}
    </section>}
    <div className="two-pane scan-compose">
      <section className={panelStyle}>
        <h2 className="mb-3">New assessment</h2>
        <form onSubmit={start}>
          <fieldset className="space-y-3" disabled={busy || active(detail)}>
            <label className="asset-label">Assessment asset<select aria-label="Assessment asset" className="asset-input" value={assetId} required
              onChange={(event) => { setAssetId(event.target.value); setProfiles([]); setProfileId(''); setConfirmed(false) }}>
              <option value="">Select registered asset</option>
              {assets.map((asset) => <option value={asset.id} key={asset.id}>{asset.display_name} · {asset.ip_address}</option>)}
            </select></label>
            <label className="asset-label">Assessment service<select aria-label="Assessment service" className="asset-input" value={profileId} required
              disabled={!assetId || profilesLoading} onChange={(event) => { setProfileId(event.target.value); setConfirmed(false) }}>
              <option value="">{profilesLoading ? 'Loading profiles…' : 'Select enabled HTTP(S) profile'}</option>
              {profiles.map((service) => <option value={service.id} key={service.id}>{service.name} · {service.protocol.toUpperCase()} {service.port}</option>)}
            </select></label>
            {assetId && !profilesLoading && !profiles.length && <p className="text-sm text-muted">Create an enabled HTTP or HTTPS profile in <a className="underline" href="#monitoring">Service Monitoring</a>.</p>}
            <label className="flex gap-2 text-sm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} required />
              I authorize assessment of this endpoint.</label>
            <button className="asset-button asset-primary" disabled={!assetId || !profileId || !confirmed}>Start assessment</button>
          </fieldset>
        </form>
      </section>
      <section className={panelStyle}>
        <h2 className="mb-2">Configuration trends</h2>
        <p className="text-sm text-muted">Latest assessment: {summary?.recent[0] ? label(summary.recent[0].status) + ' · ' + date(summary.recent[0].created_at) : 'none yet'}</p>
        {summary?.trends.length ? <div className="mt-3 h-48 min-w-0 overflow-x-clip">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={summary.trends} accessibilityLayer><XAxis dataKey="day" tickFormatter={(day) => day.slice(5)} />
              <YAxis allowDecimals={false} width={28} /><Tooltip /><Legend />
              <Bar dataKey="completed" name="Completed runs" fill="#9bccad" isAnimationActive={false} />
              <Bar dataKey="findings" name="Finding observations" fill="#e8be9e" isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div> : <p className="mt-3 text-sm text-muted">No completed observations in the last 30 days.</p>}
      </section>
    </div>
    <section className={panelStyle}>
      <h2 className="mb-2">Assessment history</h2>
      {!history ? <p role="status">Loading history…</p> : !history.length ? <p className="text-sm text-muted">No assessments yet.</p> :
        <ul className="divide-y divide-line">{history.map((item) => <li className="flex flex-wrap items-center gap-3 py-2 text-sm" key={item.id}>
          <button className="asset-button" onClick={() => selectAssessment(item.id)}>Assessment #{item.id}</button>
          <span className="break-words">{item.asset_name} · {item.service_name}</span>
          <span className="capitalize text-muted">{item.status}</span><time className="text-xs text-muted">{date(item.created_at)}</time>
        </li>)}</ul>}
      <Pagination offset={historyOffset} count={history?.length ?? 0} setOffset={setHistoryOffset} noun="assessments" />
    </section>
    {selectedId !== null && <section className={panelStyle} aria-label="Assessment results">
      {!detail ? <p role="status">Loading assessment details…</p> : <>
        <h2>Assessment #{detail.id} results</h2>
        <p className="mt-2 break-words text-sm">{detail.asset_name} · {detail.service_name} · {detail.protocol.toUpperCase()} {detail.ip_address}:{detail.port}{detail.path}</p>
        <p role="status" className="my-2 text-sm capitalize">{detail.status} · {date(detail.completed_at ?? detail.started_at ?? detail.created_at)}</p>
        <p className="text-xs text-muted">Started {date(detail.started_at)} · Completed {date(detail.completed_at)}</p>
        {active(detail) && <div className="flex flex-wrap items-center gap-3">
          <progress aria-label="Assessment progress" className="w-44 accent-editorial" />
          <button className="asset-button" disabled={busy} onClick={() => void act(async () => { await securityApi.cancel(detail.id) })}>Cancel assessment</button>
        </div>}
        {detail.failure && <p className="text-sm text-rose-300">{label(detail.failure)}</p>}
        {detail.summary && <>
          <p className="text-sm text-muted">Coverage: {detail.summary.assessed} assessed · {detail.summary.inconclusive} inconclusive · {detail.summary.not_applicable} not applicable.</p>
          <p className="my-2 text-sm">{severities.map((level) => (detail.summary?.counts[level] ?? 0) + ' ' + level).join(' · ')}</p>
          <p className="break-words text-sm text-muted">HTTP {detail.evidence?.http_status ?? 'unavailable'} · TLS {detail.evidence?.tls_version ?? 'unavailable'} · Cipher {detail.evidence?.tls_cipher ?? 'unavailable'}.</p>
          {detail.evidence?.tls_assessment && <p className="text-sm text-muted">TLS classification: {label(detail.evidence.tls_assessment)}</p>}
          {detail.evidence?.certificate && <p className="break-words text-sm text-muted">
            Certificate {label(detail.evidence.certificate.state)} · Valid from {date(detail.evidence.certificate.valid_from)} · Expires {date(detail.evidence.certificate.expires_at)}
          </p>}
          <div className="my-3 flex flex-wrap gap-2">
            {(['pdf', 'json', 'csv'] as const).map((format) => <button className="asset-button" key={format} disabled={busy}
              onClick={() => void act(() => securityApi.export(detail.id, format))}>Export assessment {format.toUpperCase()}</button>)}
          </div>
          <ul className="divide-y divide-line">{detail.observations.map((item) => <li key={item.rule} className="py-3 text-sm">
            <div className="flex flex-wrap items-center gap-2"><strong>{item.title}</strong>
              <span className="capitalize text-muted">{label(item.evaluation)}</span><SeverityTag severity={item.severity} />
              {item.finding_id !== null && <button className="asset-button" onClick={() => selectFinding(item.finding_id!)}>View finding #{item.finding_id}</button>}
            </div>
            <p className="mt-1 break-words text-muted">{item.evidence}</p>
          </li>)}</ul>
        </>}
      </>}
    </section>}
    <section className={panelStyle}>
      <h2 className="mb-2">Configuration findings</h2>
      <p className="mb-3 text-sm text-muted">Informational findings are review items. Low indicates a missing or weak defense. Medium indicates a documented transport or trust problem.</p>
      <div className="workspace-toolbar mb-3 grid gap-2 sm:grid-cols-3">
        <label className="asset-label">Finding severity<select aria-label="Finding severity" className="asset-input" value={filters.severity} onChange={(event) => filter('severity', event.target.value)}>
          <option value="">All severities</option>{severities.map((value) => <option key={value}>{value}</option>)}
        </select></label>
        <label className="asset-label">Finding status<select aria-label="Finding status" className="asset-input" value={filters.status} onChange={(event) => filter('status', event.target.value)}>
          <option value="">All statuses</option>{['open', 'acknowledged', 'resolved'].map((value) => <option key={value}>{value}</option>)}
        </select></label>
        <label className="asset-label">Finding asset<select aria-label="Finding asset" className="asset-input" value={filters.asset_id} onChange={(event) => filter('asset_id', event.target.value)}>
          <option value="">All assets</option>{assets.map((item) => <option key={item.id} value={item.id}>{item.display_name}</option>)}
        </select></label>
      </div>
      {!findings ? <p role="status">Loading findings…</p> : !findings.length ? <p className="text-sm text-muted">No matching findings.</p> :
        <div className="overflow-x-auto"><table className="editorial-table min-w-[31rem] w-full text-left text-sm">
          <thead><tr>{['Finding', 'Service', 'Severity', 'Status'].map((item) => <th key={item} className="p-2">{item}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{findings.map((item) => <tr key={item.id}>
            <td className="p-2"><button className="asset-button text-left" onClick={() => selectFinding(item.id)}>{item.title}</button></td>
            <td className="p-2">{item.service_name}</td><td className="p-2"><SeverityTag severity={item.severity} /></td>
            <td className="p-2 capitalize">{item.status}</td>
          </tr>)}</tbody>
        </table></div>}
      <Pagination offset={findingsOffset} count={findings?.length ?? 0} setOffset={setFindingsOffset} noun="findings" />
    </section>
    {findingId !== null && <section className={panelStyle} aria-label="Finding details">
      {!finding ? <p role="status">Loading finding details…</p> : <>
        <h2>{finding.title}</h2>
        <p className="my-2 break-words text-sm">{finding.asset_name} · {finding.service_name} · {finding.status} <SeverityTag severity={finding.severity} /></p>
        <dl className="settings-facts text-sm">
          <div><dt>Observed configuration</dt><dd className="break-words">{finding.evidence}</dd></div>
          <div><dt>Security implication</dt><dd className="break-words">{finding.explanation}</dd></div>
          <div><dt>Remediation</dt><dd className="break-words">{finding.recommendation}</dd></div>
          <div><dt>First observed</dt><dd>{date(finding.first_observed)}</dd></div>
          <div><dt>Last observed</dt><dd>{date(finding.last_observed)}</dd></div>
          {finding.acknowledged_at && <div><dt>Acknowledged</dt><dd>{date(finding.acknowledged_at)}</dd></div>}
          {finding.resolved_at && <div><dt>Resolved</dt><dd>{date(finding.resolved_at)}</dd></div>}
        </dl>
        {finding.status === 'open' && <button className="asset-button asset-primary mt-3" disabled={busy}
          onClick={() => void act(async () => { await securityApi.acknowledge(finding.id) })}>Acknowledge finding</button>}
        <h3 className="mb-2 mt-4 font-medium">Related assessments</h3>
        <ul className="space-y-1 text-sm text-muted">{finding.history.map((item) => <li key={item.assessment_id}>
          Assessment #{item.assessment_id} · {label(item.observation.evaluation)} · {date(item.completed_at)}
        </li>)}</ul>
      </>}
    </section>}
  </div>
}
