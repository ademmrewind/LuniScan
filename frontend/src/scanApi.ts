import { downloadFile } from './api'
import { request, submit, type Availability } from './inventoryApi'

export interface Service { id: number; name: string; port: number; active: boolean }
export interface ScanJob {
  id: number
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  created_at: string
  started_at: string | null
  completed_at: string | null
  asset_count: number
  check_count: number
  done_count: number
  progress: number
  summary: Record<Availability, number>
  failure: string | null
}
export interface Endpoint {
  asset_id: number
  asset_name: string
  ip_address: string
  service_id: number
  service_name: string
  port: number
}
export interface Result extends Endpoint {
  id: number
  job_id: number
  status: Availability
  checked_at: string
  error_category: string | null
}
export interface JobDetail extends ScanJob { plan: Endpoint[]; results: Result[] }
export interface HistoryResult extends Result { duration_seconds: number }
export interface Comparison {
  result: Result
  previous: Result | null
  change: 'newly_reachable' | 'became_unreachable' | 'unchanged' | 'inconclusive'
}

const confirmation = { confirm_approval: true }
export const scanApi = {
  services: (signal: AbortSignal) => request<Service[]>('/services', { signal }),
  addService: (name: string, port: number) => submit<Service>('/services', 'POST', { name, port, ...confirmation }),
  revoke: (id: number) => request<void>('/services/' + id, { method: 'DELETE' }),
  jobs: (signal: AbortSignal) => request<ScanJob[]>('/scan-jobs', { signal }),
  job: (id: number, signal: AbortSignal) => request<JobDetail>('/scan-jobs/' + id, { signal }),
  create: (asset_ids: number[], service_ids: number[]) =>
    submit<ScanJob>('/scan-jobs', 'POST', { asset_ids, service_ids, ...confirmation }),
  start: (id: number) => submit<ScanJob>('/scan-jobs/' + id + '/start', 'POST', confirmation),
  cancel: (id: number) => submit<ScanJob>('/scan-jobs/' + id + '/cancel', 'POST', confirmation),
  history: (query: URLSearchParams, signal: AbortSignal) =>
    request<HistoryResult[]>('/scan-history?' + query.toString(), { signal }),
  compare: (id: number, signal: AbortSignal) =>
    request<Comparison>('/scan-history/' + id + '/comparison', { signal }),
  export: (id: number, format: 'json' | 'csv') =>
    downloadFile(`/scan-jobs/${id}/export/${format}`, format === 'json' ? 'application/json' : 'text/csv', `scan-${id}.${format}`),
}
