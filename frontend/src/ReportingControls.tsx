import type { DateRange } from './analyticsApi'

export const panelStyle = 'surface editorial-panel min-w-0'
export const errorText = (error: unknown) => error instanceof Error ? error.message : 'The request failed.'

export function DateFields({ range, onChange }: { range: DateRange; onChange: (range: DateRange) => void }) {
  return <div className="grid min-w-0 gap-3 min-[380px]:grid-cols-2">
    <label className="asset-label min-w-0">Start date (UTC)
      <input className="asset-input min-w-0" type="date" required value={range.start} max={range.end || undefined}
        onChange={(event) => onChange({ ...range, start: event.target.value })} />
    </label>
    <label className="asset-label min-w-0">End date (UTC)
      <input className="asset-input min-w-0" type="date" required value={range.end} min={range.start || undefined}
        onChange={(event) => onChange({ ...range, end: event.target.value })} />
    </label>
  </div>
}
