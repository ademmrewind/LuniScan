import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { Plus, Radar, RefreshCw, Search, X } from 'lucide-react'
import { inventoryApi, type Asset, type AssetInput, type Availability, type Scope } from './inventoryApi'
import { StatusBadge } from './StatusBadge'

const statuses = ['reachable', 'unreachable', 'unknown'] as const

type DialogState = { kind: 'add' | 'discover' } | { kind: 'edit' | 'delete'; asset: Asset }

function Modal({ title, children, onClose, busy }: {
  title: string
  children: ReactNode
  onClose: () => void
  busy: boolean
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = ref.current
    dialog?.showModal()
    return () => dialog?.close()
  }, [])

  return (
    <dialog ref={ref} aria-labelledby="modal-title"
      className="editorial-dialog m-auto max-h-[calc(100dvh-2rem)] w-[calc(100%-2rem)] max-w-lg overflow-y-auto border border-line bg-panel p-5 text-slate-100 sm:p-6"
      onCancel={(event) => { event.preventDefault(); if (!busy) onClose() }}>
      <div className="mb-5 flex items-center justify-between gap-4">
        <h2 id="modal-title" className="text-xl font-semibold">{title}</h2>
        <button type="button" className="asset-button" aria-label="Close" disabled={busy} onClick={onClose}>
          <X size={17} />
        </button>
      </div>
      {children}
    </dialog>
  )
}

function AssetForm({ asset, busy, onSave }: {
  asset?: Asset
  busy: boolean
  onSave: (values: AssetInput) => void
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const value = (key: keyof AssetInput) => String(form.get(key) ?? '').trim()
    onSave({
      ip_address: value('ip_address'),
      hostname: value('hostname') || null,
      display_name: value('display_name'),
      description: value('description'),
      asset_type: value('asset_type'),
      operating_system: value('operating_system') || null,
    })
  }
  return (
    <form onSubmit={submit}>
      <fieldset disabled={busy} className="grid gap-4 sm:grid-cols-2">
        <label className="asset-label">IP address<input className="asset-input" name="ip_address" required maxLength={45} defaultValue={asset?.ip_address} /></label>
        <label className="asset-label">Display name<input className="asset-input" name="display_name" required maxLength={100} defaultValue={asset?.display_name} /></label>
        <label className="asset-label">Hostname (optional)<input className="asset-input" name="hostname" maxLength={253} defaultValue={asset?.hostname ?? ''} /></label>
        <label className="asset-label">Asset type<input className="asset-input" name="asset_type" required maxLength={50} defaultValue={asset?.asset_type} /></label>
        <label className="asset-label sm:col-span-2">Operating system (optional)<input className="asset-input" name="operating_system" maxLength={100} defaultValue={asset?.operating_system ?? ''} /></label>
        <label className="asset-label sm:col-span-2">Description<textarea className="asset-input" name="description" rows={3} maxLength={1000} defaultValue={asset?.description} /></label>
        <button type="submit" className="asset-button asset-primary sm:col-span-2 sm:justify-self-end">{busy ? 'Saving…' : 'Save asset'}</button>
      </fieldset>
    </form>
  )
}

function DiscoveryForm({ scope, busy, onDiscover }: {
  scope: Scope
  busy: boolean
  onDiscover: (targets: string[]) => void
}) {
  return (
    <form onSubmit={(event) => {
      event.preventDefault()
      const data = new FormData(event.currentTarget)
      onDiscover(String(data.get('targets')).trim().split(/[\s,]+/).filter(Boolean))
    }}>
      <fieldset disabled={busy} className="space-y-4">
        <div className="space-y-1 rounded-xl border border-line bg-canvas p-3 text-sm text-muted">
          <p>Approved ranges <span className="break-words text-slate-100">{scope.networks.join(', ')}</span></p>
          <p>Service endpoint TCP {scope.service_port} · Up to {scope.discovery_limit} IP addresses</p>
        </div>
        <label className="asset-label">IP addresses, one per line
          <textarea className="asset-input" name="targets" required rows={4} maxLength={512} />
        </label>
        <label className="flex items-start gap-3 text-sm">
          <input type="checkbox" required className="mt-1 accent-teal-400" />
          I confirm that I am authorized to check every listed address.
        </label>
        <button className="asset-button asset-primary" type="submit">{busy ? 'Checking targets…' : 'Discover assets'}</button>
      </fieldset>
    </form>
  )
}

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Never'
}

export function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [scope, setScope] = useState<Scope | null>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<Availability | ''>('')
  const [revision, setRevision] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [listError, setListError] = useState('')
  const [scopeError, setScopeError] = useState('')
  const [dialogError, setDialogError] = useState('')
  const [message, setMessage] = useState('')
  const [dialog, setDialog] = useState<DialogState | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(5000)])
    inventoryApi.list(signal)
      .then((items) => {
        if (controller.signal.aborted) return
        setAssets(items)
      })
      .catch((cause: Error) => {
        if (!controller.signal.aborted) setListError(cause.message)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    inventoryApi.scope(signal).then((approvedScope) => {
      if (!controller.signal.aborted) setScope(approvedScope)
    }).catch((cause: Error) => {
      if (controller.signal.aborted) return
      setScope(null)
      setScopeError(cause.message)
    })
    return () => controller.abort()
  }, [revision])

  function refresh() {
    setLoading(true)
    setError('')
    setListError('')
    setScopeError('')
    setRevision((value) => value + 1)
  }

  function openDialog(next: DialogState) {
    setDialogError('')
    setDialog(next)
  }

  async function perform(action: () => Promise<string>) {
    setBusy(true)
    setError('')
    setDialogError('')
    setMessage('')
    try {
      setMessage(await action())
      setDialog(null)
      refresh()
    } catch (cause) {
      const detail = cause instanceof Error ? cause.message : 'The request failed.'
      if (dialog) setDialogError(detail)
      else setError(detail)
    } finally {
      setBusy(false)
    }
  }

  const search = query.trim().toLowerCase()
  const visible = assets.filter((asset) =>
    (!statusFilter || asset.status === statusFilter) &&
    [asset.display_name, asset.ip_address, asset.hostname, asset.asset_type, asset.operating_system, asset.status]
      .some((value) => value?.toLowerCase().includes(search)),
  )
  const active = assets.find((asset) => asset.id === selected)
  const actionDisabled = loading || busy

  return (
    <div className="workspace-stack">
      <div className="inventory-summary grid grid-cols-2 lg:grid-cols-4">
        {['total', ...statuses].map((status) => (
          <div key={status} className="inventory-stat">
            <p className="text-sm capitalize text-muted">{status === 'total' ? 'Total assets' : status}</p>
            <p className="mt-1 text-2xl font-semibold">{(loading || listError) && !assets.length ? '—' : status === 'total'
              ? assets.length : assets.filter((asset) => asset.status === status).length}</p>
          </div>
        ))}
      </div>
      <div className="workspace-toolbar flex flex-wrap items-center gap-2">
        <label className="relative min-w-0 grow sm:max-w-xs">
          <Search size={16} className="absolute top-3 left-3 text-muted" aria-hidden="true" />
          <input type="search" aria-label="Search assets" placeholder="Search assets"
            className="asset-input pl-9" value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
        <select aria-label="Filter asset availability" className="asset-input w-auto max-w-full"
          value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as Availability | '')}>
          <option value="">All availability</option>
          {statuses.map((status) => <option key={status} value={status}>{status}</option>)}
        </select>
        <button className="asset-button" onClick={refresh} disabled={actionDisabled}><RefreshCw size={16} /> Refresh</button>
        <button className="asset-button" onClick={() => openDialog({ kind: 'discover' })} disabled={actionDisabled || !scope}>
          <Radar size={16} /> Discover
        </button>
        <button className="asset-button asset-primary" onClick={() => openDialog({ kind: 'add' })} disabled={actionDisabled || !!listError}>
          <Plus size={16} /> Add asset
        </button>
      </div>
      {error && <p role="alert" className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200">{error}</p>}
      {listError && <p role="alert" className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200">{listError}</p>}
      {scopeError && scopeError !== listError && <p role="alert" className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200">Scope details: {scopeError}</p>}
      {message && <p role="status" className="break-words rounded-lg border border-teal-400/25 bg-teal-400/10 p-3 text-sm text-teal-200">{message}</p>}
      {active && (
        <section aria-labelledby="asset-details" className="asset-drawer surface rounded-xl border border-line bg-panel p-4 sm:p-5">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 id="asset-details" className="break-words text-lg font-semibold">{active.display_name}</h2>
              <p className="mt-1 break-all font-mono text-sm text-muted">{active.ip_address}</p>
            </div>
            <button className="asset-button" aria-label="Close details" onClick={() => setSelected(null)}><X size={16} /></button>
          </div>
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div><dt className="text-muted">Availability</dt><dd className="mt-1.5"><StatusBadge status={active.status} /></dd></div>
            <div><dt className="text-muted">Asset type</dt><dd className="break-words">{active.asset_type}</dd></div>
            <div><dt className="text-muted">Hostname</dt><dd className="break-words">{active.hostname ?? '—'}</dd></div>
            <div><dt className="text-muted">Operating system</dt><dd className="break-words">{active.operating_system ?? '—'}</dd></div>
            <div><dt className="text-muted">First seen</dt><dd>{formatDate(active.first_seen)}</dd></div>
            <div><dt className="text-muted">Last checked</dt><dd>{formatDate(active.last_checked)}</dd></div>
            {active.description && <div className="sm:col-span-2"><dt className="text-muted">Description</dt><dd className="break-words whitespace-pre-wrap">{active.description}</dd></div>}
          </dl>
          <div className="mt-5 flex flex-wrap gap-2">
            <button className="asset-button" disabled={actionDisabled || !scope} onClick={() => void perform(async () => {
              const updated = await inventoryApi.check(active.id)
              return updated.ip_address + ' is ' + updated.status + ' on TCP ' + scope?.service_port + '.'
            })}>Check availability</button>
            <button className="asset-button" disabled={actionDisabled} onClick={() => openDialog({ kind: 'edit', asset: active })}>Edit</button>
            <button className="asset-button text-rose-300" disabled={actionDisabled} onClick={() => openDialog({ kind: 'delete', asset: active })}>Delete</button>
          </div>
        </section>
      )}
      <section aria-label="Asset inventory" aria-busy={loading} className="table-surface">
        {loading && <div role="status" className="space-y-3 p-4 text-sm text-muted">Loading assets…
          <div aria-hidden="true" className="skeleton h-5 w-3/4 rounded" />
          <div aria-hidden="true" className="skeleton h-5 w-1/2 rounded" />
        </div>}
        {!loading && !listError && visible.length === 0 && (
          <p className="p-5 text-sm text-muted">{search || statusFilter ? 'No assets match your search.' : 'No assets in the inventory yet.'}</p>
        )}
        {visible.length > 0 && (
          <div className="overflow-x-auto">
            <table className="editorial-table w-full table-fixed text-left text-sm">
              <thead className="border-b border-line text-muted">
                <tr><th className="w-3/5 p-3 sm:w-2/5">Asset</th><th className="p-3">Status</th>
                  <th className="hidden p-3 md:table-cell">Type</th><th className="hidden p-3 sm:table-cell">Last checked</th></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {visible.map((asset) => (
                  <tr key={asset.id} className={selected === asset.id ? 'bg-teal-400/5' : undefined}>
                    <td className="p-3">
                      <button onClick={() => setSelected(asset.id)} className="max-w-full break-words text-left font-medium text-teal-200 hover:underline">
                        {asset.display_name}
                      </button>
                      <div className="break-all font-mono text-xs text-muted">{asset.ip_address}</div>
                    </td>
                    <td className="p-3"><StatusBadge status={asset.status} /></td>
                    <td className="hidden break-words p-3 md:table-cell">{asset.asset_type}</td>
                    <td className="hidden p-3 sm:table-cell">{formatDate(asset.last_checked)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {dialog && (
        <Modal title={{ add: 'Add asset', edit: 'Edit asset', delete: 'Delete asset', discover: 'Discover assets' }[dialog.kind]}
          busy={busy} onClose={() => setDialog(null)}>
          {dialogError && <p role="alert" className="mb-4 text-sm text-rose-300">{dialogError}</p>}
          {(dialog.kind === 'add' || dialog.kind === 'edit') && <AssetForm asset={dialog.kind === 'edit' ? dialog.asset : undefined}
            busy={busy} onSave={(values) => void perform(async () => {
              const saved = dialog.kind === 'edit'
                ? await inventoryApi.edit(dialog.asset.id, values) : await inventoryApi.add(values)
              setSelected(saved.id)
              return dialog.kind === 'edit' ? 'Asset updated.' : 'Asset added.'
            })} />}
          {dialog.kind === 'delete' && (
            <>
              <p className="mb-5 break-words text-sm text-muted">Remove {dialog.asset.display_name} ({dialog.asset.ip_address}) from inventory?</p>
              <div className="flex justify-end gap-2">
                <button className="asset-button" disabled={busy} onClick={() => setDialog(null)}>Cancel</button>
                <button className="asset-button text-rose-300" disabled={busy} onClick={() => void perform(async () => {
                  await inventoryApi.remove(dialog.asset.id)
                  setSelected(null)
                  return 'Asset deleted.'
                })}>{busy ? 'Deleting…' : 'Delete asset'}</button>
              </div>
            </>
          )}
          {dialog.kind === 'discover' && scope && (
            <DiscoveryForm scope={scope} busy={busy} onDiscover={(targets) => void perform(async () => {
              const job = await inventoryApi.discover(targets)
              return 'Discovery #' + job.id + ' completed. ' + job.results
                .map((result) => result.ip_address + ' — ' + result.status).join(' · ')
            })} />
          )}
        </Modal>
      )}
    </div>
  )
}
