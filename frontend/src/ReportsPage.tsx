import { Download, FileText } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { analyticsApi, initialRange, type ReportKind } from './analyticsApi'
import { DateFields, errorText, panelStyle } from './ReportingControls'
import { scanApi, type ScanJob } from './scanApi'

const reportDescriptions: Record<ReportKind, string> = {
  full: 'Inventory, approvals, latest connectivity results, job history, and change summary.',
  inventory: 'Current asset inventory and approved services, with a summary for the selected dates.',
  monitoring: 'Approved services, latest connectivity results, job history, and change summary.',
}

export function ReportsPage() {
  const [kind, setKind] = useState<ReportKind>('full')
  const [range, setRange] = useState(initialRange)
  const [jobs, setJobs] = useState<ScanJob[] | null>(null)
  const [jobError, setJobError] = useState('')
  const [exportError, setExportError] = useState('')
  const [exporting, setExporting] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)
  const currentDownload = useRef<AbortController | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(10000)])
    scanApi.jobs(signal).then((items) => {
      if (!controller.signal.aborted) setJobs(items.filter((job) => job.status === 'completed'))
    }).catch((cause) => {
      if (!controller.signal.aborted) setJobError(errorText(cause))
    })
    return () => {
      controller.abort()
      currentDownload.current?.abort()
    }
  }, [])

  async function download(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (currentDownload.current) return
    const controller = new AbortController()
    currentDownload.current = controller
    setBusy(true)
    setError('')
    setDone(false)
    try {
      await analyticsApi.pdf(kind, range, controller.signal)
      setDone(true)
    } catch (cause) {
      if (!controller.signal.aborted) setError(errorText(cause))
    } finally {
      currentDownload.current = null
      if (!controller.signal.aborted) setBusy(false)
    }
  }

  async function exportJob(id: number, format: 'json' | 'csv') {
    setExporting(true)
    setExportError('')
    try {
      await scanApi.export(id, format)
    } catch (cause) {
      setExportError(errorText(cause))
    } finally {
      setExporting(false)
    }
  }

  return <div className="two-pane report-layout">
    <section className={panelStyle} aria-busy={busy}>
      <h2 className="mb-4 flex items-center gap-2 font-semibold"><FileText size={18} className="text-sky-300" aria-hidden="true" /> PDF report</h2>
      <form onSubmit={download}>
        <fieldset disabled={busy} className="space-y-4">
          <div className="asset-label">
            <fieldset className="grid gap-2">
              <legend className="mb-2">Report type</legend>
              {([['full', 'Full report'], ['inventory', 'Asset inventory'], ['monitoring', 'Service monitoring']] as const)
                .map(([value, title]) => <label key={value} className={'report-choice ' + (kind === value ? 'is-selected' : '')}>
                  <input className="accent-editorial" type="radio" name="report-kind" value={value} checked={kind === value}
                    onChange={() => setKind(value)} /><span>{title}</span>
                </label>)}
            </fieldset>
            <p className="text-xs font-normal text-muted">{reportDescriptions[kind]}</p>
          </div>
          <DateFields range={range} onChange={setRange} />
          <button className="asset-button asset-primary"><Download size={16} aria-hidden="true" /> Download PDF</button>
        </fieldset>
      </form>
      {busy && <div role="status" className="mt-4 max-w-lg text-sm text-muted">
        <p>Generating PDF…</p><progress aria-label="Generating PDF" className="mt-2 w-full accent-teal-400" />
      </div>}
      {done && <p role="status" className="mt-3 text-sm text-teal-200">PDF ready. Download started.</p>}
      {error && <p role="alert" className="mt-3 text-sm text-rose-200">{error}</p>}
    </section>
    <section className={panelStyle}>
      <h2 className="font-semibold">Completed job exports</h2>
      <p className="mt-1 text-xs text-muted">Completed jobs from the latest 50 scan jobs.</p>
      {jobError && <p role="alert" className="mt-4 text-sm text-rose-200">{jobError}</p>}
      {exportError && <p role="alert" className="mt-4 text-sm text-rose-200">{exportError}</p>}
      {exporting && <p role="status" className="mt-4 text-sm text-muted">Preparing export…</p>}
      {!jobs && !jobError && <p role="status" className="mt-4 text-sm text-muted">Loading jobs…</p>}
      {jobs?.length === 0 && <p className="mt-4 text-sm text-muted">No completed jobs are available.</p>}
      <ul className="mt-3 divide-y divide-line">
        {jobs?.map((job) => <li key={job.id} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm">
          <div><p>Job #{job.id} · {job.check_count} checks</p>
            {job.completed_at && <p className="text-xs text-muted">{new Date(job.completed_at).toLocaleString()}</p>}
          </div>
          <div className="flex gap-2">
            {(['json', 'csv'] as const).map((format) => <button key={format} className="asset-button" disabled={exporting}
              aria-label={'Export job ' + job.id + ' as ' + format.toUpperCase()}
              onClick={() => void exportJob(job.id, format)}>{format.toUpperCase()}</button>)}
          </div>
        </li>)}
      </ul>
    </section>
  </div>
}
