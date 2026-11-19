import { useEffect, useState } from 'react'
import { errorText } from './ReportingControls'
import { securityApi, severities, type Finding, type SecuritySummary } from './securityApi'

export function AssetSecurity({ assetId }: { assetId: number }) {
  const [summary, setSummary] = useState<SecuritySummary | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    const signal = controller.signal
    const query = new URLSearchParams({ asset_id: String(assetId), unresolved: 'true', limit: '5' })
    Promise.all([securityApi.summary(signal, assetId), securityApi.findings(query, signal)])
      .then(([results, issues]) => {
        if (!signal.aborted) { setSummary(results); setFindings(issues) }
      }).catch((cause) => { if (!signal.aborted) setError(errorText(cause)) })
    return () => controller.abort()
  }, [assetId])

  return <details className="border-t border-line py-3">
    <summary className="cursor-pointer text-sm font-medium">Security assessments</summary>
    {error ? <p role="alert" className="mt-2 text-sm text-rose-300">{error}</p> :
      !summary ? <p role="status" className="mt-2 text-sm text-muted">Loading assessments…</p> : <>
        <p className="my-2 text-sm text-muted">{summary.recent[0] ?
          'Latest #' + summary.recent[0].id + ' · ' + summary.recent[0].status + ' · ' + new Date(summary.recent[0].created_at).toLocaleString() :
          'No security assessments recorded.'}</p>
        <p className="text-xs text-muted">{severities.map((level) => (summary.open_counts[level] ?? 0) + ' ' + level).join(' · ')}</p>
        {summary.recent.length > 0 && <ul className="mt-2 space-y-1 text-sm">
          {summary.recent.slice(0, 3).map((item) => <li key={item.id}>#{item.id} · {item.service_name} · {item.status}</li>)}
        </ul>}
        {findings.length > 0 && <ul className="mt-2 divide-y divide-line text-sm">
          {findings.map((item) => <li key={item.id} className="py-2">
            <strong>{item.title}</strong><p className="break-words text-muted">{item.recommendation}</p>
          </li>)}
        </ul>}
        <a className="asset-button mt-2" href="#assessment">Open Security Assessment</a>
      </>}
  </details>
}
