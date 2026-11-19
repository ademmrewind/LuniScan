import { useEffect, useState, type FormEvent } from 'react'
import { inventoryApi, type DiscoveryRun, type Scope } from './inventoryApi'
import { StatusBadge } from './StatusBadge'

function message(error: unknown) {
  return error instanceof Error ? error.message : 'The request failed.'
}

export function DiscoveryPanel({ scope, onSettled }: { scope: Scope; onSettled: () => void }) {
  const [input, setInput] = useState('')
  const [approved, setApproved] = useState(false)
  const [verified, setVerified] = useState<string[] | null>(null)
  const [runs, setRuns] = useState<DiscoveryRun[]>([])
  const [run, setRun] = useState<DiscoveryRun | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const runningId = run?.status === 'running' ? run.id : null
  const targets = input.trim().split(/[\s,]+/).filter(Boolean)

  useEffect(() => {
    const controller = new AbortController()
    inventoryApi.discoveryRuns(controller.signal).then((items) => {
      if (controller.signal.aborted) return
      setRuns(items)
      setRun((current) => current ?? items.find((item) => item.status === 'running') ?? null)
    }).catch((cause) => { if (!controller.signal.aborted) setError(message(cause)) })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (runningId === null) return
    const controller = new AbortController()
    let timer: number | undefined
    async function poll(id: number) {
      try {
        const updated = await inventoryApi.discoveryRun(id, controller.signal)
        if (controller.signal.aborted) return
        setError('')
        setRun((current) => current?.id === id && current.status === 'running' ? updated : current)
        setRuns((items) => [updated, ...items.filter((item) => item.id !== id)].slice(0, 20))
      } catch (cause) {
        if (!controller.signal.aborted) setError(message(cause))
      }
      if (!controller.signal.aborted) timer = window.setTimeout(() => void poll(id), 600)
    }
    timer = window.setTimeout(() => void poll(runningId), 250)
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [runningId])

  const settledId = run && run.status !== 'running' ? run.id : null
  useEffect(() => { if (settledId !== null) onSettled() }, [settledId, onSettled])

  async function act(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    try { await action() } catch (cause) { setError(message(cause)) } finally { setBusy(false) }
  }

  function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!approved || busy || runningId !== null || targets.length > scope.discovery_limit) return
    void act(async () => {
      const started = await inventoryApi.discover(targets)
      setRun(started)
      setRuns((items) => [started, ...items.filter((item) => item.id !== started.id)].slice(0, 20))
      setApproved(false)
    })
  }

  return <div className="space-y-5">
    <form onSubmit={start}>
      <fieldset className="space-y-4" disabled={busy || runningId !== null}>
        <div className="space-y-1 border border-line bg-canvas p-3 text-sm text-muted">
          <p className="break-words">Approved ranges <strong className="text-slate-100">{scope.networks.join(', ')}</strong></p>
          <p>TCP {scope.service_port} · Up to {scope.discovery_limit} literal IP addresses</p>
        </div>
        <div className="asset-label">
          <label htmlFor="discovery-targets">IP addresses, one per line</label>
          <textarea id="discovery-targets" className="asset-input" required rows={4} maxLength={512} value={input}
            onChange={(event) => { setInput(event.target.value); setApproved(false); setVerified(null) }} />
        </div>
        {targets.length > scope.discovery_limit && <p role="alert">Too many targets.</p>}
        {verified && <p role="status" className="break-all text-sm text-teal-300">In scope: {verified.join(', ')}</p>}
        <label className="flex items-start gap-3 text-sm">
          <input type="checkbox" required checked={approved} onChange={(event) => setApproved(event.target.checked)} />
          I confirm that I am authorized to check every listed address.
        </label>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="asset-button" disabled={!targets.length || targets.length > scope.discovery_limit}
            onClick={() => void act(async () => {
              setVerified(null)
              const checked = await Promise.all(targets.map((address) => inventoryApi.validate(address)))
              setVerified(checked.map((target) => target.ip_address))
            })}>Validate targets</button>
          <button className="asset-button asset-primary" disabled={!approved || !targets.length || targets.length > scope.discovery_limit}>Discover assets</button>
        </div>
      </fieldset>
    </form>
    {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
    {run && <section className="editorial-panel space-y-3">
      <h3 className="font-medium">Discovery #{run.id} {run.status}</h3>
      <p className="text-sm text-muted" aria-live="polite">{run.results.length} of {run.targets.length} targets checked · TCP {run.port}</p>
      <progress className="w-full accent-editorial" aria-label="Discovery progress" value={run.results.length} max={run.targets.length} />
      {run.failure && <p role="alert" className="text-sm text-rose-300">{run.failure.replaceAll('_', ' ')}</p>}
      {run.status === 'running' && <button className="asset-button" disabled={busy} onClick={() => void act(async () => {
        const cancelled = await inventoryApi.cancelDiscovery(run.id)
        setRun(cancelled)
        setRuns((items) => [cancelled, ...items.filter((item) => item.id !== cancelled.id)].slice(0, 20))
      })}>Cancel discovery</button>}
      <ul className="divide-y divide-line text-sm">
        {run.targets.map((target) => {
          const result = run.results.find((item) => item.ip_address === target)
          return <li key={target} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <span className="break-all font-mono">{target}</span>
            {result ? <span className="flex flex-wrap items-center gap-2"><StatusBadge status={result.status} />
              <span className="text-muted">{result.duration_ms ?? '—'} ms{result.error_category ? ' · ' + result.error_category : ''}</span>
            </span> : <span className="text-muted">{run.status === 'running' ? 'Pending' : 'Not checked'}</span>}
          </li>
        })}
      </ul>
    </section>}
    {runs.length > 0 && <div>
      <h3 className="mb-2 text-sm font-medium">Recent discovery runs</h3>
      <ul className="flex flex-wrap gap-2">
        {runs.map((item) => <li key={item.id}><button className="asset-button" type="button"
          disabled={busy || runningId !== null} aria-pressed={run?.id === item.id}
          onClick={() => setRun(item)}>#{item.id} {item.status}</button></li>)}
      </ul>
    </div>}
  </div>
}
