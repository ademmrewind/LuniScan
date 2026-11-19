import { Activity, Boxes, CheckCircle2, CircleHelp, CircleX, Network, Radio, TimerOff } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { analyticsApi, initialRange, type DailyActivity, type Dashboard, type Timeline } from './analyticsApi'
import { DateFields, errorText, panelStyle } from './ReportingControls'

const muted = '#b7b4bb'
const grid = '#303039'
const teal = '#9bccad'
const blue = '#a5b6d8'
const rose = '#e9a5ab'
const slate = '#a8a3b0'
const tooltip = { background: '#18171c', border: '1px solid #45404a', borderRadius: 3 }
const asDate = (value: string) => new Date(value).toLocaleString()
const dayLabel = (value: string) => value.slice(5)

function Chart({ title, description, hasData, children, wide = false }: {
  title: string; description: string; hasData: boolean; children: ReactNode; wide?: boolean
}) {
  return <figure className={panelStyle + (wide ? ' xl:col-span-2' : '')} aria-label={title}>
    <figcaption>
      <h2 className="font-semibold">{title}</h2>
      <p className="mt-1 text-xs text-muted">{description}</p>
    </figcaption>
    <div className="mt-3 h-56 min-w-0 overflow-x-clip">
      {hasData ? children : <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-line px-4 text-center text-sm text-muted">
        No observations to display.
      </div>}
    </div>
  </figure>
}

function Distribution({ title, description, counts }: {
  title: string; description: string; counts: Dashboard['metrics']['asset_status']
}) {
  const data = [
    { name: 'Reachable', value: counts.reachable, fill: teal },
    { name: 'Unreachable', value: counts.unreachable, fill: rose },
    { name: 'Unknown', value: counts.unknown, fill: slate },
  ]
  return <Chart title={title} description={description} hasData={data.some(({ value }) => value > 0)}>
    <ResponsiveContainer width="100%" height="100%">
      <PieChart accessibilityLayer title={title} desc={description}>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={45} outerRadius={73} isAnimationActive={false} stroke="#141419" strokeWidth={2}>
          {data.map(({ name, fill }) => <Cell key={name} fill={fill} />)}
        </Pie>
        <Tooltip contentStyle={tooltip} itemStyle={{ color: '#f1f5f9' }} />
        <Legend formatter={(label) => <span className="text-xs text-muted">{label}</span>} />
      </PieChart>
    </ResponsiveContainer>
  </Chart>
}

type SeriesKey = Exclude<keyof DailyActivity, 'day'>
interface Series { key: SeriesKey; name: string; color: string }
const activity: Series[] = [
  { key: 'created', name: 'Created', color: blue }, { key: 'started', name: 'Started', color: '#c4b5fd' },
  { key: 'completed', name: 'Completed', color: teal }, { key: 'failed', name: 'Failed', color: rose },
  { key: 'cancelled', name: 'Cancelled', color: slate },
]
const changes: Series[] = [
  { key: 'newly_reachable', name: 'Newly reachable', color: teal },
  { key: 'became_unreachable', name: 'Became unreachable', color: rose },
]

function Trend({ title, description, data, series, bars, wide }: {
  title: string; description: string; data: DailyActivity[]; series: Series[]; bars?: boolean; wide?: boolean
}) {
  const Component = bars ? BarChart : LineChart
  return <Chart title={title} description={description} wide={wide}
    hasData={data.some((day) => series.some(({ key }) => day[key] > 0))}>
    <ResponsiveContainer width="100%" height="100%">
      <Component data={data} title={title} desc={description} accessibilityLayer margin={{ top: 8, left: 0, right: 10, bottom: 0 }}>
        <CartesianGrid stroke={grid} vertical={false} strokeDasharray="3 4" />
        <XAxis dataKey="day" tickFormatter={dayLabel} tick={{ fill: muted, fontSize: 11 }} minTickGap={22} />
        <YAxis allowDecimals={false} tick={{ fill: muted, fontSize: 11 }} width={28} />
        <Tooltip contentStyle={tooltip} labelStyle={{ color: '#f1f5f9' }}
          cursor={bars ? { fill: '#263244', opacity: 0.55 } : { stroke: '#64748b' }} />
        <Legend formatter={(value) => <span className="text-xs text-muted">{value}</span>} />
        {series.map(({ key, name, color }) => bars
          ? <Bar key={key} dataKey={key} name={name} fill={color} maxBarSize={32} radius={[3, 3, 0, 0]} isAnimationActive={false} />
          : <Line key={key} dataKey={key} name={name} stroke={color} type="linear" dot={data.length <= 14 ? { r: 2 } : false}
            strokeWidth={2} isAnimationActive={false} />)}
      </Component>
    </ResponsiveContainer>
  </Chart>
}

function MetricCards({ metrics }: { metrics: Dashboard['metrics'] }) {
  const cards = [
    ['Registered assets', metrics.assets, Boxes, 'text-sky-300'],
    ['Reachable assets', metrics.asset_status.reachable, Radio, 'text-teal-300'],
    ['Unreachable assets', metrics.asset_status.unreachable, CircleX, 'text-rose-300'],
    ['Unknown asset status', metrics.asset_status.unknown, CircleHelp, 'text-slate-300'],
    ['Approved services', metrics.approved_services, Network, 'text-sky-300'],
    ['Completed jobs', metrics.completed_jobs, CheckCircle2, 'text-teal-300'],
    ['Failed jobs', metrics.failed_jobs, Activity, 'text-rose-300'],
    ['Cancelled jobs', metrics.cancelled_jobs, TimerOff, 'text-slate-300'],
  ] as const
  return <section aria-label="Monitoring metrics" className="grid grid-cols-2 gap-3 xl:grid-cols-4">
    {cards.map(([label, value, Icon, tone]) => <div key={label} className={panelStyle + ' metric-card'}>
      <Icon className={tone} size={18} aria-hidden="true" />
      <p className="mt-3 text-xs font-medium text-muted sm:text-sm">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{value.toLocaleString()}</p>
    </div>)}
  </section>
}

const eventLabels: Record<string, string> = {
  job_created: 'Job created', job_started: 'Job started', job_completed: 'Job completed',
  job_cancelled: 'Job cancelled', job_failed: 'Job failed', asset_created: 'Asset created',
  asset_deleted: 'Asset deleted', newly_reachable: 'Newly reachable', became_unreachable: 'Became unreachable',
}

export default function OverviewPage() {
  const [draft, setDraft] = useState(initialRange)
  const [range, setRange] = useState(draft)
  const [data, setData] = useState<Dashboard | null>(null)
  const [timeline, setTimeline] = useState<Timeline | null>(null)
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')
  const [timelineError, setTimelineError] = useState('')
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(12000)])
    analyticsApi.dashboard(range, signal).then((result) => {
      if (!controller.signal.aborted) setData(result)
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(errorText(cause))
    })
    return () => controller.abort()
  }, [range, revision])

  useEffect(() => {
    const controller = new AbortController()
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(12000)])
    analyticsApi.timeline(range, offset, signal).then((result) => {
      if (!controller.signal.aborted) setTimeline(result)
    }).catch((cause) => {
      if (!controller.signal.aborted) setTimelineError(errorText(cause))
    })
    return () => controller.abort()
  }, [range, offset, revision])

  function apply() {
    setError('')
    setTimelineError('')
    setData(null)
    setTimeline(null)
    setOffset(0)
    setRange(draft)
    setRevision((old) => old + 1)
  }

  function timelinePage(next: number) {
    setTimelineError('')
    setTimeline(null)
    setOffset(next)
  }

  return <div className="workspace-stack mt-6">
    <section className="workspace-toolbar" aria-label="Dashboard date range">
      <form onSubmit={(event) => { event.preventDefault(); apply() }}
        className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-end">
        <DateFields range={draft} onChange={setDraft} />
        <button className="asset-button asset-primary">Apply date range</button>
      </form>
      <p className="mt-3 text-xs text-muted">Assets and approvals reflect current inventory. Job and connectivity metrics use the selected UTC dates.</p>
    </section>
    {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
    {!data && !error && <p role="status" className="text-sm text-muted">Loading dashboard…</p>}
    {data && <>
      <MetricCards metrics={data.metrics} />
      <div className="grid gap-4 xl:grid-cols-2">
        <Distribution title="Asset availability distribution" description="Current inventory status from asset availability checks." counts={data.metrics.asset_status} />
        <Distribution title="Service connectivity distribution" description="Recorded results from completed jobs in the selected period." counts={data.metrics.service_status} />
        <Trend title="Scan activity over time" description="Job lifecycle events per UTC day." data={data.daily} series={activity} wide />
        <Trend title="Daily completed scan jobs" description="Jobs counted on their UTC completion date." data={data.daily} series={[activity[2]]} bars />
        <Trend title="Connectivity changes over time" description="Transitions between reachable and unreachable for the same endpoint." data={data.daily} series={changes} bars />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <section className={panelStyle}>
          <h2 className="mb-3 font-semibold">Recent scan activity</h2>
          {!data.recent_jobs.length && <p className="text-sm text-muted">No scan jobs in this period.</p>}
          <ul className="divide-y divide-line text-sm">
            {data.recent_jobs.map((job) => <li key={job.id} className="flex flex-wrap items-center justify-between gap-2 py-2.5">
              <div><span className="font-medium">Job #{job.id}</span> <span className="text-muted">· {job.check_count} {job.check_count === 1 ? 'check' : 'checks'}</span>
                <p className="mt-0.5 text-xs text-muted">{asDate(job.completed_at ?? job.created_at)}</p></div>
              <span className="rounded-full border border-line px-2.5 py-1 text-xs capitalize">{job.status}</span>
            </li>)}
          </ul>
        </section>
        <section className={panelStyle}>
          <h2 className="mb-3 font-semibold">Latest connectivity changes</h2>
          {!data.latest_changes.length && <p className="text-sm text-muted">No conclusive connectivity changes in this period.</p>}
          <ul className="divide-y divide-line text-sm">
            {data.latest_changes.map((change) => <li key={change.id} className="py-2.5">
              <p className="break-words">{change.asset_name} · {change.service_name}</p>
              <span className={change.after === 'reachable' ? 'text-teal-300' : 'text-rose-300'}>{change.before} → {change.after}</span>
              <p className="mt-0.5 text-xs text-muted">Job #{change.job_id} · {asDate(change.checked_at)}</p>
            </li>)}
          </ul>
        </section>
      </div>
    </>}
    <section className={panelStyle} aria-busy={!timeline && !timelineError}>
      <h2 className="mb-3 font-semibold">Activity timeline</h2>
      {timelineError && <p role="alert" className="text-sm text-rose-300">{timelineError}</p>}
      {!timeline && !timelineError && <p role="status" className="text-sm text-muted">Loading activity…</p>}
      {timeline && !timeline.events.length && <p className="text-sm text-muted">No recorded events in this period.</p>}
      <ol className="divide-y divide-line">
        {timeline?.events.map((event) => <li key={event.kind + ':' + event.source_id} className="flex flex-wrap justify-between gap-2 py-2.5 text-sm">
          <div className="min-w-0">
            <p className="font-medium">{eventLabels[event.kind]}</p>
            <p className="break-words text-xs text-muted">
              {event.job_id !== null && 'Job #' + event.job_id + ' · '}
              {event.asset_id !== null && 'Asset #' + event.asset_id + ' · '}
              {event.description}
            </p>
          </div>
          <time className="text-xs text-muted" dateTime={event.occurred_at}>{asDate(event.occurred_at)}</time>
        </li>)}
      </ol>
      <div className="flex gap-2">
        {offset > 0 && <button className="asset-button mt-3" onClick={() => timelinePage(Math.max(0, offset - 20))}>Previous events</button>}
        {timeline?.next_offset != null && <button className="asset-button mt-3" onClick={() => timelinePage(timeline.next_offset!)}>Older events</button>}
      </div>
    </section>
  </div>
}
