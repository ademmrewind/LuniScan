import { request, submit } from './inventoryApi'

export const protocols = ['tcp', 'http', 'https', 'tls'] as const
export const healthStates = ['healthy', 'degraded', 'unreachable', 'unknown'] as const
export const certificateStates = ['valid', 'expiring_soon', 'expired', 'untrusted', 'hostname_mismatch', 'inconclusive'] as const
export type Protocol = typeof protocols[number]
export type Health = typeof healthStates[number]

export interface ProfileInput {
  asset_id: number
  ip_address: string
  name: string
  protocol: Protocol
  port: number
  hostname: string | null
  timeout_ms: number
  path: string
  status_min: number
  status_max: number
  expected_content?: string | null
  enabled: boolean
  confirm_approval: boolean
}

export interface Profile extends Omit<ProfileInput, 'expected_content' | 'confirm_approval'> {
  id: number
  asset_name: string | null
  health: Health
  checks_content: boolean
  certificate_state: string | null
  duration_ms: number | null
  last_checked: string | null
  last_success: string | null
  last_failure: string | null
}

export interface Certificate {
  state: string
  subject: string | null
  issuer: string | null
  valid_from: string | null
  expires_at: string | null
  days_remaining: number | null
  verified: boolean | null
  hostname_valid: boolean | null
  inspected_at: string
}

export interface Check {
  id: number
  profile_id: number
  health: Health
  outcome: string
  duration_ms: number
  error: string | null
  http_status: number | null
  expected_status: boolean | null
  content_match: boolean | null
  certificate: Certificate | null
  previous_health: Health | null
  checked_at: string
}

export interface Alert {
  id: number
  profile_id: number
  asset_id: number
  profile_name: string
  kind: string
  severity: 'critical' | 'warning'
  status: 'active' | 'acknowledged' | 'resolved'
  created_at: string
  acknowledged_at: string | null
  resolved_at: string | null
}

export interface Detail {
  profile: Profile
  history: Check[]
  certificate: Certificate | null
  alerts: Alert[]
}

export interface Summary {
  profiles: Partial<Record<Health, number>>
  certificates: Record<string, number>
  alerts: Record<string, number>
  daily: { day: string; healthy: number; failed: number; mean_http_ms: number | null }[]
  recent: Check[]
  transitions: Check[]
}

const root = '/monitoring'
const profile = (id: number) => root + '/profiles/' + id

export const monitorApi = {
  profiles: (query: URLSearchParams, signal: AbortSignal) =>
    request<Profile[]>(root + '/profiles?' + query, { signal }),
  summary: (signal: AbortSignal) => request<Summary>(root + '/summary', { signal }),
  detail: (id: number, signal: AbortSignal) => request<Detail>(profile(id), { signal }),
  add: (input: ProfileInput) => submit<Profile>(root + '/profiles', 'POST', input),
  edit: (id: number, input: ProfileInput) => submit<Profile>(profile(id), 'PUT', input),
  archive: (id: number) => request<void>(profile(id), { method: 'DELETE' }),
  check: (id: number) => submit<Check>(profile(id) + '/check', 'POST', {}),
  alerts: (query: URLSearchParams, signal: AbortSignal) => request<Alert[]>(root + '/alerts?' + query, { signal }),
  acknowledge: (id: number) => submit<Alert>(root + '/alerts/' + id + '/acknowledge', 'POST', {}),
}
