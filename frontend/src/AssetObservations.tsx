import { useEffect, useState } from 'react'
import { inventoryApi, type AssetIntelligence, type Observation, type ServiceObservation } from './inventoryApi'
import { StatusBadge } from './StatusBadge'

function Results({ observations }: { observations: (Observation | ServiceObservation)[] }) {
  if (!observations.length) return <p className="text-sm text-muted">No observations recorded.</p>
  return <ul className="divide-y divide-line">
    {observations.map((result, index) => <li className="space-y-1 py-2 text-sm" key={result.checked_at + ':' + index}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="break-words">{'service_name' in result ? result.service_name : 'Availability check'} · TCP {result.port ?? '—'}</span>
        <StatusBadge status={result.status} />
      </div>
      <div className="break-words text-xs text-muted">
        {result.ip_address} · {new Date(result.checked_at).toLocaleString()}
        {result.duration_ms !== null && ' · ' + result.duration_ms + ' ms'}
        {result.error_category && ' · ' + result.error_category.replaceAll('_', ' ')}
      </div>
    </li>)}
  </ul>
}

export function AssetObservations({ assetId, revision }: { assetId: number; revision: number }) {
  const [data, setData] = useState<AssetIntelligence | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    setError('')
    inventoryApi.intelligence(assetId, controller.signal).then((details) => {
      if (!controller.signal.aborted) setData(details)
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Unable to load observations.')
    })
    return () => controller.abort()
  }, [assetId, revision])

  if (error) return <p role="alert" className="mt-4 text-sm text-rose-300">{error}</p>
  if (!data) return <p role="status" className="mt-4 text-sm text-muted">Loading observations…</p>
  return <div className="mt-5 space-y-4 border-t border-line pt-4">
    <p className="text-sm text-muted">Latest TCP check: {data.last_connectivity_check ? new Date(data.last_connectivity_check).toLocaleString() : 'Never'}</p>
    <section>
      <h3 className="mb-2 font-semibold">Latest service results</h3>
      <p className="text-xs text-muted">Approved services used: {data.monitored_services.length
        ? data.monitored_services.map((service) => service.name + ' (TCP ' + service.port + ')').join(', ') : 'None recorded'}</p>
      <Results observations={data.latest_results} />
    </section>
    <details className="border-y border-line py-2"><summary className="cursor-pointer text-sm font-medium">Availability history</summary>
      <Results observations={data.availability_history} />
    </details>
    <details className="border-b border-line pb-2"><summary className="cursor-pointer text-sm font-medium">Service history</summary>
      <Results observations={data.service_history} />
    </details>
    <details className="border-b border-line pb-2"><summary className="cursor-pointer text-sm font-medium">Recent jobs and connectivity changes</summary>
      {data.recent_jobs.length === 0 && <p className="mt-2 text-sm text-muted">No recorded scan jobs.</p>}
      <ul className="my-2 space-y-1 text-sm">{data.recent_jobs.map((job) =>
        <li key={job.id}>Job #{job.id} · {job.status} · {new Date(job.created_at).toLocaleString()}</li>)}</ul>
      {data.changes.length === 0 && <p className="text-sm text-muted">No recorded connectivity changes.</p>}
      <ul className="my-2 space-y-1 text-sm">{data.changes.map((change) =>
        <li key={change.id}>{change.service_name} · {change.before} → {change.after} · {new Date(change.checked_at).toLocaleString()}</li>)}</ul>
    </details>
  </div>
}
