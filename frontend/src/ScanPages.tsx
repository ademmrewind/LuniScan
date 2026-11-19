import { useEffect, useState, type FormEvent } from 'react'
import { inventoryApi, type Asset } from './inventoryApi'
import { scanApi, type Comparison, type HistoryResult, type JobDetail, type ScanJob, type Service } from './scanApi'
import { StatusBadge } from './StatusBadge'
import { DateFields, panelStyle } from './ReportingControls'

const panel = panelStyle
const date = (value: string) => new Date(value).toLocaleString()
const label = (value: string) => value.replaceAll('_', ' ')
const failure = (cause: unknown) => cause instanceof Error ? cause.message : 'The request failed.'

function Notice({ error }: { error: string }) {
  return error ? <p role="alert" className="rounded-lg border border-rose-400/30 p-3 text-sm text-rose-200">{error}</p> : null
}

export function ScansPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [services, setServices] = useState<Service[]>([])
  const [jobs, setJobs] = useState<ScanJob[]>([])
  const [detail, setDetail] = useState<JobDetail | null>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const [assetIds, setAssetIds] = useState<number[]>([])
  const [serviceIds, setServiceIds] = useState<number[]>([])
  const [revision, setRevision] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmStart, setConfirmStart] = useState(false)
  const running = jobs.some((job) => job.status === 'running')

  useEffect(() => {
    const controller = new AbortController()
    const signal = controller.signal
    async function load() {
      try {
        const [assetList, serviceList, jobList, job] = await Promise.all([
          inventoryApi.list(signal), scanApi.services(signal), scanApi.jobs(signal),
          selected === null ? null : scanApi.job(selected, signal),
        ])
        if (signal.aborted) return
        setAssets(assetList)
        setServices(serviceList)
        setJobs(jobList)
        setDetail(job)
      } catch (cause) {
        if (!signal.aborted) setError(failure(cause))
      } finally {
        if (!signal.aborted) setLoading(false)
      }
    }
    void load()
    const timer = running ? window.setInterval(load, 1000) : undefined
    return () => {
      controller.abort()
      window.clearInterval(timer)
    }
  }, [revision, running, selected])

  async function act(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    try {
      await action()
      setRevision((old) => old + 1)
    } catch (cause) {
      setError(failure(cause))
    } finally {
      setBusy(false)
    }
  }

  function selectJob(id: number) {
    if (id === selected) return
    setSelected(id)
    setDetail(null)
    setConfirmStart(false)
  }

  function addService(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const fields = new FormData(form)
    void act(async () => {
      await scanApi.addService(String(fields.get('name')), Number(fields.get('port')))
      form.reset()
    })
  }

  function createJob(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    void act(async () => {
      const job = await scanApi.create(assetIds, serviceIds)
      form.reset()
      setAssetIds([])
      setServiceIds([])
      selectJob(job.id)
    })
  }

  const activeServices = services.filter((service) => service.active)
  const count = assetIds.length * serviceIds.length
  return (
    <div className="workspace-stack">
      <Notice error={error} />
      {loading && <p role="status" className="text-sm text-muted">Loading scans…</p>}
      <div className="two-pane scan-compose">
        <section className={panel}>
          <h2 className="mb-4 font-semibold">Approved services</h2>
          <form onSubmit={addService} className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_7rem]">
              <label className="asset-label">Service name<input name="name" className="asset-input" maxLength={80} required /></label>
              <label className="asset-label">TCP port<input name="port" type="number" min={1} max={65535} step={1} className="asset-input" required /></label>
            </div>
            <label className="flex gap-2 text-sm"><input type="checkbox" required />I approve checks on this TCP port.</label>
            <button className="asset-button" disabled={busy || loading}>Approve service</button>
          </form>
          <ul className="mt-4 divide-y divide-line text-sm">
            {activeServices.map((service) => <li key={service.id} className="flex items-center justify-between gap-2 py-2">
              <span className="min-w-0 break-words">{service.name} · TCP {service.port}</span>
              <button className="asset-button" disabled={busy} onClick={() => {
                if (window.confirm('Revoke approval for ' + service.name + '?')) void act(async () => {
                  await scanApi.revoke(service.id)
                  setServiceIds((ids) => ids.filter((id) => id !== service.id))
                })
              }}>Revoke</button>
            </li>)}
          </ul>
          {!loading && !activeServices.length && <p className="mt-3 text-sm text-muted">No approved services.</p>}
        </section>
        <section className={panel}>
          <h2 className="mb-4 font-semibold">Create scan job</h2>
          <form onSubmit={createJob} className="space-y-3">
            <div className="asset-label">
              <label htmlFor="job-assets">Approved assets</label>
              <select id="job-assets" multiple required className="asset-input" value={assetIds.map(String)}
                onChange={(event) => setAssetIds(Array.from(event.target.selectedOptions, (option) => Number(option.value)))}>
                {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.display_name} · {asset.ip_address}</option>)}
              </select>
            </div>
            {!loading && !assets.length && <p className="text-sm text-muted">Add an asset in Inventory before creating a job.</p>}
            <div className="asset-label">
              <label htmlFor="job-services">Approved service endpoints</label>
              <select id="job-services" multiple required className="asset-input" value={serviceIds.map(String)}
                onChange={(event) => setServiceIds(Array.from(event.target.selectedOptions, (option) => Number(option.value)))}>
                {activeServices.map((service) => <option key={service.id} value={service.id}>{service.name} · TCP {service.port}</option>)}
              </select>
            </div>
            <p className="text-sm text-muted">{count} checks · Up to 8 assets, 4 services and 12 checks</p>
            <label className="flex gap-2 text-sm"><input type="checkbox" required />I am authorized to check every selected asset and service combination.</label>
            <button className="asset-button asset-primary" disabled={busy || !count || count > 12 || assetIds.length > 8 || serviceIds.length > 4}>Create job</button>
          </form>
        </section>
      </div>
      <section className={panel + ' job-register'}>
        <h2 className="mb-3 font-semibold">Scan jobs</h2>
        {!loading && !jobs.length && <p className="text-sm text-muted">No scan jobs yet.</p>}
        <ul className="divide-y divide-line text-sm">
          {jobs.map((job) => <li key={job.id} className="job-row">
            <button className="asset-button" aria-pressed={selected === job.id} onClick={() => selectJob(job.id)}>Job #{job.id}</button>
            <StatusBadge status={job.status} /><span>{job.progress}%</span>
            <progress aria-label={'Job ' + job.id + ' progress'} value={job.progress} max={100} className="w-full min-w-0 accent-editorial" />
            <span className="text-muted">{date(job.created_at)}</span>
          </li>)}
        </ul>
      </section>
      {detail && (
        <section className={panel} aria-label="Selected scan job">
          <h2 className="mb-2 font-semibold">Job #{detail.id} details</h2>
          <p className="text-sm capitalize" role="status">{detail.status} · {detail.done_count} of {detail.check_count} checks</p>
          <progress aria-label="Scan progress" className="my-2 w-full accent-teal-400" value={detail.progress} max={100} />
          <p className="mb-3 text-sm text-muted">{detail.summary.reachable} reachable · {detail.summary.unreachable} unreachable · {detail.summary.unknown} unknown</p>
          {detail.failure && <p className="mb-3 text-sm capitalize text-rose-200">{label(detail.failure)}</p>}
          {detail.status === 'pending' && (
            <div className="mb-3 space-y-2">
              <ul className="space-y-1 text-sm text-muted">{detail.plan.map((endpoint) => <li key={endpoint.asset_id + ':' + endpoint.service_id} className="break-words">
                {endpoint.asset_name} ({endpoint.ip_address}) · {endpoint.service_name} · TCP {endpoint.port}
              </li>)}</ul>
              <label className="flex gap-2 text-sm"><input type="checkbox" checked={confirmStart} onChange={(event) => setConfirmStart(event.target.checked)} />I approve each listed connection.</label>
            </div>
          )}
          <div className="mb-3 flex flex-wrap gap-2">
            {detail.status === 'pending' && <button className="asset-button asset-primary" disabled={busy || !confirmStart || running}
              onClick={() => void act(async () => { await scanApi.start(detail.id); setConfirmStart(false) })}>Start job</button>}
            {(detail.status === 'pending' || detail.status === 'running') && <button className="asset-button" disabled={busy}
              onClick={() => void act(async () => { await scanApi.cancel(detail.id); setConfirmStart(false) })}>Cancel job</button>}
            {detail.status === 'completed' && (['json', 'csv'] as const).map((format) => <button key={format}
              className="asset-button" disabled={busy} onClick={() => void act(() => scanApi.export(detail.id, format))}>
              Export {format.toUpperCase()}</button>)}
          </div>
          {detail.results.length > 0 && <ResultsTable results={detail.results} />}
        </section>
      )}
    </div>
  )
}

function ResultsTable({ results, onSelect }: {
  results: (JobDetail['results'][number] | HistoryResult)[]
  onSelect?: (result: HistoryResult) => void
}) {
  return (
    <div className="overflow-x-auto">
      <table className="editorial-table w-full text-left text-sm">
        <thead className="border-b border-line text-muted"><tr>
          <th className="p-2">Asset</th><th className="p-2">Service</th><th className="p-2">Status</th>
          <th className="p-2">Checked at</th>{onSelect && <th className="p-2">Job duration</th>}
        </tr></thead>
        <tbody className="divide-y divide-line">{results.map((result) => <tr key={result.id}>
          <td className="p-2">
            {onSelect && 'duration_seconds' in result
              ? <button className="break-all text-left text-teal-200 hover:underline" onClick={() => onSelect(result)}>{result.asset_name}</button>
              : <span className="break-all">{result.asset_name}</span>}
            <p className="break-all text-xs text-muted">{result.ip_address}</p>
          </td>
          <td className="p-2"><span className="break-all">{result.service_name}</span><p className="text-xs text-muted">TCP {result.port}</p></td>
          <td className="p-2"><StatusBadge status={result.status} /></td>
          <td className="p-2">{date(result.checked_at)}</td>
          {'duration_seconds' in result && <td className="p-2">{result.duration_seconds.toFixed(2)} s</td>}
        </tr>)}</tbody>
      </table>
    </div>
  )
}

export function ScanHistoryPage() {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('')
  const [range, setRange] = useState({ start: '', end: '' })
  const [offset, setOffset] = useState(0)
  const [rows, setRows] = useState<HistoryResult[]>([])
  const [selected, setSelected] = useState<HistoryResult | null>(null)
  const [comparison, setComparison] = useState<Comparison | null>(null)
  const [comparisonError, setComparisonError] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError('')
    const timer = window.setTimeout(() => {
      const filters = new URLSearchParams({ q: query, offset: String(offset) })
      if (status) filters.set('status', status)
      if (range.start) filters.set('start', range.start)
      if (range.end) filters.set('end', range.end)
      scanApi.history(filters, controller.signal).then(setRows).catch((cause) => {
        if (!controller.signal.aborted) setError(failure(cause))
      }).finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    }, 200)
    return () => { window.clearTimeout(timer); controller.abort() }
  }, [query, status, range, offset])

  useEffect(() => {
    if (!selected) return
    const controller = new AbortController()
    scanApi.compare(selected.id, controller.signal).then(setComparison).catch((cause) => {
      if (!controller.signal.aborted) setComparisonError(failure(cause))
    })
    return () => controller.abort()
  }, [selected])

  function view(result: HistoryResult | null) {
    if (result?.id === selected?.id) return
    setSelected(result)
    setComparison(null)
    setComparisonError('')
  }

  return (
    <div className="workspace-stack">
      <div className="workspace-toolbar grid gap-3 sm:grid-cols-2">
        <label className="asset-label">Search history<input className="asset-input" type="search" maxLength={100} placeholder="Asset, IP address or service"
          value={query} onChange={(event) => { setQuery(event.target.value); setOffset(0); view(null) }} /></label>
        <div className="asset-label"><label htmlFor="history-status">Connectivity status</label>
          <select id="history-status" className="asset-input" value={status}
          onChange={(event) => { setStatus(event.target.value); setOffset(0); view(null) }}>
          <option value="">All statuses</option><option value="reachable">Reachable</option>
          <option value="unreachable">Unreachable</option><option value="unknown">Unknown</option>
          </select></div>
        <DateFields range={range} onChange={(next) => { setRange(next); setOffset(0); view(null) }} />
        <button className="asset-button self-end sm:justify-self-start" type="button" disabled={!range.start && !range.end}
          onClick={() => { setRange({ start: '', end: '' }); setOffset(0); view(null) }}>Clear dates</button>
      </div>
      <Notice error={error} />
      <section aria-label="Completed scan results" className={panel}>
        {loading ? <p role="status" className="text-sm text-muted">Loading history…</p>
          : rows.length ? <ResultsTable results={rows} onSelect={view} />
            : !error && <p className="text-sm text-muted">No completed results match these filters.</p>}
        <div className="mt-3 flex gap-2">
          {offset > 0 && <button className="asset-button" disabled={loading} onClick={() => {setOffset(offset - 50); view(null)}}>Previous</button>}
          {rows.length === 50 && offset < 100000 && <button className="asset-button" disabled={loading} onClick={() => {setOffset(offset + 50); view(null)}}>Next</button>}
        </div>
      </section>
      {selected && <section className={panel} aria-label="Result details">
        <h2 className="mb-2 break-words font-semibold">{selected.asset_name} · {selected.service_name}</h2>
        <p className="text-sm">Job #{selected.job_id} · TCP {selected.port} · {date(selected.checked_at)}</p>
        <p className="mt-2 text-sm capitalize">{selected.status}{selected.error_category && ' · ' + label(selected.error_category)}</p>
        <Notice error={comparisonError} />
        {comparison ? <div className="mt-3 border-t border-line pt-3 text-sm">
          <p className="capitalize">{label(comparison.change)}</p>
          <p className="text-muted">{comparison.previous ? 'Previous check: ' + comparison.previous.status + ' · ' + date(comparison.previous.checked_at) : 'No earlier completed check for this endpoint.'}</p>
        </div> : !comparisonError && <p className="mt-3 text-sm text-muted">Loading comparison…</p>}
      </section>}
    </div>
  )
}
