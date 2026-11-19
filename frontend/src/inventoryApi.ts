import { apiFetch, checkedResponse } from './api'

export type Availability = 'reachable' | 'unreachable' | 'unknown'

export interface AssetInput {
  ip_address: string
  hostname: string | null
  display_name: string
  description: string
  asset_type: string
  operating_system: string | null
}

export interface Asset extends AssetInput {
  id: number
  status: Availability
  first_seen: string
  last_checked: string | null
}

export interface Scope {
  networks: string[]
  service_port: number
  discovery_limit: number
}

interface DiscoveryJob {
  id: number
  completed_at: string
  results: { ip_address: string; status: Availability; checked_at: string }[]
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
  discover: (targets: string[]) => submit<DiscoveryJob>('/discovery-jobs', 'POST', {
    targets,
    confirm_scope: true,
  }),
}

