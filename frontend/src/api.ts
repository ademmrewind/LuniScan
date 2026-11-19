export type Health = 'healthy' | 'degraded' | 'offline' | 'outdated'

export const staleApiMessage =
  'This backend is missing the current API contract. Restart LuniScan from the backend folder and verify the Vite API proxy target.'

export function apiFetch(path: string, options?: RequestInit, timeoutMs = 20000) {
  const timeout = AbortSignal.timeout(timeoutMs)
  const signal = options?.signal ? AbortSignal.any([timeout, options.signal]) : timeout
  return fetch('/api' + path, { cache: 'no-store', ...options, signal })
}

export async function checkedResponse(response: Response, mediaType: string, path: string) {
  const contentType = response.headers.get('Content-Type')?.split(';', 1)[0]
  if (!response.ok) {
    const body = contentType === 'application/json' ? await response.json().catch(() => null) : null
    const detail: unknown = body?.detail
    if (response.status === 404 && (detail === 'Not Found' || detail == null)) {
      throw new Error(`HTTP 404 for /api${path.split('?')[0]}. ${staleApiMessage}`)
    }
    if (typeof detail === 'string') throw new Error(detail)
    if (Array.isArray(detail)) {
      throw new Error(detail.map((item) => {
        const field = Array.isArray(item.loc) ? item.loc.slice(1).join('.') : ''
        return field ? field + ' — ' + item.msg : item.msg
      }).join(' '))
    }
    throw new Error('The API request failed (HTTP ' + response.status + ').')
  }
  if (response.status !== 204 && contentType !== mediaType) {
    throw new Error('The frontend received an unexpected response from the API. Check the Vite proxy target.')
  }
  return response
}

export async function downloadFile(path: string, mediaType: string, filename: string, signal?: AbortSignal) {
  const response = await checkedResponse(await apiFetch(path, { signal }, 60000), mediaType, path)
  if (response.status === 204) throw new Error('The API returned an empty download.')
  const file = await response.blob()
  signal?.throwIfAborted()
  const url = URL.createObjectURL(file)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function getHealth(signal: AbortSignal): Promise<Health> {
  const response = await apiFetch('/health', {
    signal,
    headers: { Accept: 'application/json' },
  })
  if (response.status !== 200 && response.status !== 503) return 'offline'
  const data = await response.json()
  const version = /^(\d+)\.(\d+)\./.exec(response.headers.get('X-LuniScan-API-Version') ?? '')
  const compatible = version && (Number(version[1]) > 0 || Number(version[2]) >= 6)
  if (data?.status === 'ok' && data?.database === 'ok' && !compatible) {
    return 'outdated'
  }
  if (response.status === 200 && data?.status === 'ok' && data?.database === 'ok') {
    return 'healthy'
  }
  if (response.status === 503 && data?.status === 'degraded' && data?.database === 'unavailable') {
    return 'degraded'
  }
  return 'offline'
}
