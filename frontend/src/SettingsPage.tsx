import { useEffect, useState, type FormEvent } from 'react'
import { inventoryApi, type Scope } from './inventoryApi'
import { errorText, panelStyle } from './ReportingControls'

export function SettingsPage() {
  const [scope, setScope] = useState<Scope | null>(null)
  const [revision, setRevision] = useState(0)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [value, setValue] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState('')
  const [validationError, setValidationError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    inventoryApi.scope(controller.signal).then((data) => {
      if (!controller.signal.aborted) setScope(data)
    }).catch((cause) => {
      if (!controller.signal.aborted) setLoadError(errorText(cause))
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false)
    })
    return () => controller.abort()
  }, [revision])

  async function validate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setChecking(true)
    setResult('')
    setValidationError('')
    try {
      const validated = await inventoryApi.validate(value.trim())
      setResult(validated.ip_address + ' is in the approved scope.')
    } catch (cause) {
      setValidationError(errorText(cause))
    } finally {
      setChecking(false)
    }
  }

  return <div className="two-pane settings-layout">
    <section className={panelStyle} aria-busy={loading}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-semibold">Active network scope</h2>
        <button className="asset-button" disabled={loading} onClick={() => {
          setLoading(true)
          setLoadError('')
          setRevision((old) => old + 1)
        }}>Refresh scope</button>
      </div>
      {loading && <p role="status" className="mt-3 text-sm text-muted">Loading scope…</p>}
      {loadError && <p role="alert" className="mt-3 text-sm text-rose-300">{loadError}</p>}
      {scope && !loadError && <dl className="settings-facts mt-4 text-sm">
        <div><dt className="text-muted">Approved ranges</dt>
          <dd className="mt-1 break-words">{scope.networks.join(', ')}</dd></div>
        <div><dt className="text-muted">Availability check port</dt><dd className="mt-1">TCP {scope.service_port}</dd></div>
        <div><dt className="text-muted">Discovery limit</dt><dd className="mt-1">{scope.discovery_limit} targets</dd></div>
      </dl>}
      <p className="mt-4 text-sm text-muted">Change scope in the backend environment and restart the API to apply it.</p>
    </section>
    <section className={panelStyle}>
      <h2 className="font-semibold">Validate an IP address</h2>
      <p className="mt-1 text-sm text-muted">Validation checks the configured allowlist without opening a TCP connection.</p>
      <form onSubmit={(event) => void validate(event)} className="mt-3 flex flex-wrap items-end gap-3">
        <label className="asset-label min-w-0 grow sm:max-w-xs">IP address
          <input className="asset-input" required maxLength={45} value={value} disabled={checking}
            onChange={(event) => { setValue(event.target.value); setResult(''); setValidationError('') }} />
        </label>
        <button className="asset-button asset-primary" disabled={checking || !value.trim()}>
          {checking ? 'Validating…' : 'Validate address'}
        </button>
      </form>
      {result && <p role="status" className="mt-3 text-sm text-teal-300">{result}</p>}
      {validationError && <p role="alert" className="mt-3 text-sm text-rose-300">{validationError}</p>}
    </section>
  </div>
}
