import { downloadFile } from './api'
import { request, type Availability } from './inventoryApi'
import type { ScanJob } from './scanApi'

export interface DateRange { start: string; end: string }
export interface DailyActivity {
  day: string
  created: number
  started: number
  completed: number
  failed: number
  cancelled: number
  newly_reachable: number
  became_unreachable: number
}

export interface Dashboard {
  metrics: {
    assets: number
    asset_status: Record<Availability, number>
    approved_services: number
    completed_jobs: number
    failed_jobs: number
    cancelled_jobs: number
    service_status: Record<Availability, number>
    changes: { newly_reachable: number; became_unreachable: number }
  }
  daily: DailyActivity[]
  recent_jobs: Pick<ScanJob, 'id' | 'status' | 'created_at' | 'completed_at' | 'check_count'>[]
  latest_changes: {
    id: number; job_id: number; asset_id: number; asset_name: string; service_name: string
    before: Availability; after: Availability; checked_at: string
  }[]
}

export interface ActivityEvent {
  source_id: number
  kind: string
  occurred_at: string
  job_id: number | null
  asset_id: number | null
  description: string
}

export interface Timeline { events: ActivityEvent[]; next_offset: number | null }
export type ReportKind = 'full' | 'inventory' | 'monitoring'

export function periodQuery(range: DateRange): URLSearchParams {
  return new URLSearchParams({ start: range.start, end: range.end })
}

export function initialRange(): DateRange {
  const end = new Date()
  const start = new Date(end)
  start.setUTCDate(start.getUTCDate() - 29)
  return { start: start.toISOString().slice(0, 10), end: end.toISOString().slice(0, 10) }
}

export const analyticsApi = {
  dashboard: (range: DateRange, signal: AbortSignal) =>
    request<Dashboard>('/analytics/overview?' + periodQuery(range), { signal }),
  timeline: (range: DateRange, offset: number, signal: AbortSignal) => {
    const query = periodQuery(range)
    query.set('offset', String(offset))
    return request<Timeline>('/analytics/timeline?' + query, { signal })
  },
  pdf(kind: ReportKind, range: DateRange, signal: AbortSignal) {
    const query = periodQuery(range)
    query.set('kind', kind)
    return downloadFile('/reports/pdf?' + query, 'application/pdf', `luniscan-${kind}-${range.start}-${range.end}.pdf`, signal)
  },
}
