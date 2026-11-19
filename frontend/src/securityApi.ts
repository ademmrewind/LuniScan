import { downloadFile } from './api'
import { request, submit } from './inventoryApi'
import type { Certificate } from './monitorApi'

export const severities = ['informational', 'low', 'medium', 'high'] as const
export type Severity = typeof severities[number]
export type Status = 'pending' | 'running' | 'completed' | 'cancelled' | 'failed'

export interface Coverage {
  assessed: number
  inconclusive: number
  not_applicable: number
  counts: Partial<Record<Severity, number>>
}

export interface Assessment {
  id: number
  profile_id: number
  asset_id: number
  asset_name: string
  service_name: string
  ip_address: string
  port: number
  protocol: string
  path: string
  authorized: boolean
  status: Status
  created_at: string
  started_at: string | null
  completed_at: string | null
  failure: string | null
  summary: Coverage | null
}

export interface Observation {
  rule: string
  title: string
  category: 'http_header' | 'tls'
  evaluation: 'pass' | 'finding' | 'inconclusive' | 'not_applicable'
  severity: Severity | null
  present: boolean | null
  evidence: string
  explanation: string
  recommendation: string
}

export interface AssessmentDetail extends Assessment {
  evidence: { http_status: number | null; connection: string; duration_ms: number; error: string | null; certificate: Certificate | null; tls_version: string | null; tls_cipher: string | null; tls_assessment: string | null } | null
  observations: (Observation & { finding_id: number | null })[]
}

export interface Finding extends Observation {
  id: number
  assessment_id: number
  asset_id: number
  profile_id: number
  asset_name: string
  service_name: string
  status: 'open' | 'acknowledged' | 'resolved' | 'inconclusive'
  first_observed: string
  last_observed: string
  acknowledged_at: string | null
  resolved_at: string | null
}

export interface FindingDetail extends Finding {
  history: { assessment_id: number; completed_at: string | null; observation: Observation }[]
}

export interface SecuritySummary {
  assessment_count: number
  assets_with_open_findings: number
  open_counts: Partial<Record<Severity, number>>
  recent: Assessment[]
  trends: { day: string; completed: number; findings: number }[]
}

const root = '/security'
const assessment = (id: number) => root + '/assessments/' + id
const finding = (id: number) => root + '/findings/' + id

export const securityApi = {
  summary: (signal: AbortSignal, assetId?: number) => request<SecuritySummary>(
    root + '/summary' + (assetId === undefined ? '' : '?asset_id=' + assetId), { signal }),
  assessments: (query: URLSearchParams, signal: AbortSignal) => request<Assessment[]>(root + '/assessments?' + query, { signal }),
  assessment: (id: number, signal: AbortSignal) => request<AssessmentDetail>(assessment(id), { signal }),
  start: (asset_id: number, profile_id: number, confirm_authorization: boolean) =>
    submit<Assessment>(root + '/assessments', 'POST', { asset_id, profile_id, confirm_authorization }),
  cancel: (id: number) => submit<Assessment>(assessment(id) + '/cancel', 'POST', {}),
  findings: (query: URLSearchParams, signal: AbortSignal) => request<Finding[]>(root + '/findings?' + query, { signal }),
  finding: (id: number, signal: AbortSignal) => request<FindingDetail>(finding(id), { signal }),
  acknowledge: (id: number) => submit<Finding>(finding(id) + '/acknowledge', 'POST', {}),
  export: (id: number, format: 'pdf' | 'json' | 'csv') => downloadFile(
    assessment(id) + '/export/' + format,
    { pdf: 'application/pdf', json: 'application/json', csv: 'text/csv' }[format],
    'security-assessment-' + id + '.' + format,
  ),
}
