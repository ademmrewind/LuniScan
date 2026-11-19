import { apiFetch, checkedResponse } from './api'

export type Availability = 'reachable' | 'unreachable' | 'unknown'

export interface AssetInput {
  ip_address: string
  hostname: string | null
  display_name: string
  description: string
  asset_type: string
  operating_system: string | null
  group_name: string | null
  tags: string[]
  notes: string
}

export interface Asset extends AssetInput {
  id: number
  status: Availability
  first_seen: string
  last_checked: string | null
  last_seen: string | null
}

export interface Scope {
  networks: string[]
  service_port: number
  discovery_limit: number
}

export interface Observation {
  ip_address: string
  status: Availability
  checked_at: string
  port: number | null
  duration_ms: number | null
  error_category: string | null
}

export interface DiscoveryRun {
  id: number
  created_at: string
  completed_at: string | null
  status: 'running' | 'completed' | 'cancelled' | 'failed'
  port: number
  failure: string | null
  targets: string[]
  results: Observation[]
}

export interface ServiceObservation extends Observation {
  service_name: string
  job_id: number
}

export interface AssetIntelligence {
  last_connectivity_check: string | null
  monitored_services: { id: number; name: string; port: number }[]
  latest_results: ServiceObservation[]
  availability_history: Observation[]
  service_history: ServiceObservation[]
  recent_jobs: { id: number; status: string; created_at: string }[]
  changes: { id: number; service_name: string; before: string; after: string; checked_at: string }[]
}

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await checkedResponse(await apiFetch(path, options), 'application/json', path)
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function submit<T>(path: string, method: 'POST' | 'PUT', body: object) {
  return request<T>(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export const inventoryApi = {
  list: (signal: AbortSignal) => request<Asset[]>('/assets', { signal }),
  scope: (signal: AbortSignal) => request<Scope>('/scope', { signal }),
  validate: (ip_address: string) => submit<{ ip_address: string; approved: boolean }>('/scope/validate', 'POST', { ip_address }),
  add: (asset: AssetInput) => submit<Asset>('/assets', 'POST', asset),
  edit: (id: number, asset: AssetInput) => submit<Asset>('/assets/' + id, 'PUT', asset),
  remove: (id: number) => request<void>('/assets/' + id, { method: 'DELETE' }),
  check: (id: number) => submit<Asset>('/assets/' + id + '/check', 'POST', {}),
  intelligence: (id: number, signal: AbortSignal) => request<AssetIntelligence>('/assets/' + id + '/intelligence', { signal }),
  discoveryRuns: (signal: AbortSignal) => request<DiscoveryRun[]>('/discovery-runs', { signal }),
  discoveryRun: (id: number, signal: AbortSignal) => request<DiscoveryRun>('/discovery-runs/' + id, { signal }),
  cancelDiscovery: (id: number) => submit<DiscoveryRun>('/discovery-runs/' + id + '/cancel', 'POST', {}),
  discover: (targets: string[]) => submit<DiscoveryRun>('/discovery-runs', 'POST', {
    targets,
    confirm_scope: true,
  }),
}
