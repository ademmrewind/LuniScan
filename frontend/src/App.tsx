import {
  Activity, Boxes, Database, FileDown, History, LayoutDashboard,
  Radar, RefreshCw, Settings, ShieldCheck,
} from 'lucide-react'
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { gsap } from 'gsap'
import { getHealth, staleApiMessage, type Health } from './api'
import { AssetsPage } from './AssetsPage'
import { ScanHistoryPage, ScansPage } from './ScanPages'
import { ReportsPage } from './ReportsPage'
import { SettingsPage } from './SettingsPage'

const OverviewPage = lazy(() => import('./OverviewPage'))

const navigation = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard, description: 'Track asset availability, service checks, and recent activity.' },
  { id: 'assets', label: 'Assets', icon: Boxes, description: 'Manage your inventory and check approved laboratory endpoints.' },
  { id: 'scans', label: 'Scans', icon: Radar, description: 'Check approved service endpoints and track scan jobs.' },
  { id: 'scan-history', label: 'Scan History', icon: History, description: 'Review completed checks and compare connectivity changes.' },
  { id: 'reports', label: 'Reports', icon: FileDown, description: 'Generate PDF reports and export completed scan results.' },
  { id: 'settings', label: 'Settings', icon: Settings, description: 'Approved scope is configured in the backend environment.' },
] as const

const healthLabels = {
  checking: ['Checking', 'Checking'],
  healthy: ['Operational', 'Available'],
  degraded: ['Reachable', 'Unavailable'],
  offline: ['Unreachable', 'Unknown'],
  outdated: ['Incompatible', 'Reported available'],
}

function getPage() {
  return navigation.find((item) => '#' + item.id === window.location.hash) ?? navigation[0]
}

export function App() {
  const [page, setPage] = useState(getPage)
  const [health, setHealth] = useState<Health | 'checking'>('checking')
  const [lastChecked, setLastChecked] = useState<Date | null>(null)
  const [revision, setRevision] = useState(0)
  const content = useRef<HTMLElement>(null)

  useEffect(() => {
    if (!content.current || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const transition = gsap.fromTo(content.current, { opacity: 0.72 }, { opacity: 1, duration: 0.24, clearProps: 'opacity' })
    return () => { transition.revert() }
  }, [page.id])

  useEffect(() => {
    const updatePage = () => setPage(getPage())
    window.addEventListener('hashchange', updatePage)
    return () => window.removeEventListener('hashchange', updatePage)
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    async function refresh() {
      const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(5000)])
      const result = await getHealth(signal).catch(() => 'offline' as const)
      if (controller.signal.aborted) return
      setHealth(result)
      setLastChecked(new Date())
    }
    void refresh()
    const interval = window.setInterval(refresh, 30000)
    return () => {
      controller.abort()
      window.clearInterval(interval)
    }
  }, [revision])

  const [apiLabel, databaseLabel] = healthLabels[health]

  return (
    <div className="min-h-dvh">
      <header className="shell-header">
        <div className="shell-bar">
        <a href="#overview" className="shell-brand">
          <span className="brand-mark">
            <ShieldCheck size={22} aria-hidden="true" />
          </span>
          <span>LuniScan</span>
        </a>
        <nav aria-label="Main navigation" className="shell-navigation">
          {navigation.map(({ id, label, icon: Icon }) => (
            <a key={id} href={'#' + id} aria-current={page.id === id ? 'page' : undefined}
              className="nav-link">
              <Icon size={17} aria-hidden="true" />
              {label}
            </a>
          ))}
        </nav>
        <div className={'shell-health tone-' + health} role="status">
          <span aria-hidden="true" />
          {health === 'healthy' ? 'API online' : 'API ' + health}
        </div>
        </div>
      </header>
      <main ref={content} data-page={page.id} className="mx-auto w-full min-w-0 max-w-[90rem] px-4 py-8 sm:px-8 lg:px-10 lg:py-12">
        {page.id !== 'overview' && <header className="page-heading mb-7">
          <h1 className="display-heading">{page.label}</h1>
          <p className="mt-2 text-sm text-muted sm:text-base">{page.description}</p>
        </header>}
        {health === 'outdated' && <p role="alert" className="mb-5 rounded-xl border border-amber-400/30 bg-amber-400/10 p-3 text-sm text-amber-200">{staleApiMessage}</p>}
        {page.id === 'assets' && <AssetsPage />}
        {page.id === 'scans' && <ScansPage />}
        {page.id === 'scan-history' && <ScanHistoryPage />}
        {page.id === 'reports' && <ReportsPage />}
        {page.id === 'settings' && <SettingsPage />}
        {page.id === 'overview' && (
          <section aria-labelledby="overview-heading" className="operations-hero">
            <div className="operations-figure" aria-hidden="true">
              {Array.from({ length: 13 }, (_, index) => (
                <span key={index} className="operations-orbit" style={{
                  inset: (index * 2.1) + '%',
                  transform: 'rotateY(-27deg) rotateX(21deg) rotateZ(' + (index * 13 - 25) + 'deg)',
                  animationDelay: (index * 34) + 'ms',
                }} />
              ))}
            </div>
            <div className="operations-content">
            <header className="mb-8">
              <h1 id="overview-heading" className="display-heading overview-title">Overview</h1>
              <p className="mt-4 max-w-md text-sm text-muted sm:text-base">{page.description}</p>
            </header>
            <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-sm font-medium">System health</h2>
              <button type="button" disabled={health === 'checking'} onClick={() => {
                setHealth('checking')
                setRevision((value) => value + 1)
              }} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm hover:bg-slate-800 disabled:opacity-50">
                <RefreshCw size={15} aria-hidden="true" />
                Refresh
              </button>
            </div>
            <div className="grid gap-3 sm:grid-cols-2" aria-live="polite">
              <StatusCard icon={Activity} title="Backend API" status={apiLabel} tone={health === 'degraded' ? 'healthy' : health} />
              <StatusCard icon={Database} title="SQLite database" status={databaseLabel} tone={health === 'offline' ? 'checking' : health} />
            </div>
            <p className="mt-5 text-xs text-muted">
              {lastChecked ? 'Last checked at ' + lastChecked.toLocaleTimeString() : 'Waiting for the first health check'}
            </p>
            <nav aria-label="Quick access" className="mt-4 flex flex-wrap gap-2">
              <a href="#assets" className="asset-button asset-primary">Manage assets</a>
              <a href="#scans" className="asset-button">Open scans</a>
              <a href="#reports" className="asset-button">Generate reports</a>
            </nav>
            </div>
          </section>
        )}
        {page.id === 'overview' && <Suspense fallback={<p role="status" className="mt-5 text-sm text-muted">Loading dashboard…</p>}>
          <OverviewPage />
        </Suspense>}
      </main>
    </div>
  )
}

const statusColors = {
  healthy: 'text-teal-300',
  degraded: 'text-amber-300',
  offline: 'text-rose-300',
  outdated: 'text-amber-300',
  checking: 'text-muted',
}

function StatusCard({ icon: Icon, title, status, tone }: {
  icon: typeof Activity
  title: string
  status: string
  tone: Health | 'checking'
}) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-line bg-canvas p-4">
      <span className="rounded-lg bg-slate-800 p-2.5 text-slate-200"><Icon size={19} aria-hidden="true" /></span>
      <div>
        <h3 className="text-sm font-medium">{title}</h3>
        <p className={'mt-1 text-sm ' + statusColors[tone]}>{status}</p>
      </div>
    </div>
  )
}
