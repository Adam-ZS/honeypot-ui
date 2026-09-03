import { useCallback, useEffect, useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight, Download, Search, SlidersHorizontal } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { useDebounced } from '../hooks/useDebounced'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import SessionDetailModal from '../components/SessionDetailModal'
import { LoadingRegion } from '../components/Loading'
import { CategoryTag } from '../components/Severity'
import { PROFILE_LABEL_SHORT } from '../lib/severity'

const PAGE_SIZE = 20

const CATEGORIES = ['benign', 'reconnaissance', 'exploitation', 'exfiltration']
const STATUSES = ['active', 'completed', 'terminated']

const EXPORT_FORMATS = [
  { id: 'json', label: 'JSON', hint: 'Full session records' },
  { id: 'cef', label: 'CEF', hint: 'ArcSight and syslog collectors' },
  { id: 'stix', label: 'STIX 2.1', hint: 'Threat intelligence platforms' },
]


const EMPTY_FILTERS = {
  search: '',
  status: '',
  attack_category: '',
  country: '',
  is_anomalous: '',
}

export default function SessionLogs() {
  const { hasRole } = useAuth()
  const [sessions, setSessions] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [exporting, setExporting] = useState(null)
  const [selected, setSelected] = useState(null)
  const [showFilters, setShowFilters] = useState(false)
  const [filters, setFilters] = useState(EMPTY_FILTERS)

  const debouncedSearch = useDebounced(filters.search)
  const canExport = hasRole('analyst')

  const query = useMemo(
    () => ({ ...filters, search: debouncedSearch }),
    [filters, debouncedSearch],
  )

  const activeFilterCount = useMemo(
    () =>
      Object.entries(filters).filter(([key, value]) => key !== 'search' && value !== '')
        .length,
    [filters],
  )

  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true)
      const data = await api.sessions.list({ page, page_size: PAGE_SIZE, ...query })
      setSessions(data.sessions || [])
      setTotal(data.total || 0)
      setError(null)
    } catch (err) {
      setError(err.message)
      setSessions([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [page, query])

  useEffect(() => {
    const timer = setTimeout(fetchSessions, 0)
    return () => clearTimeout(timer)
  }, [fetchSessions])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const updateFilter = (key, value) => {
    // Reset to the first page here rather than in an effect: a filter change
    // invalidates the current page, and doing it during the same event avoids
    // a render pass that would fetch page N of the new result set.
    setPage(1)
    setFilters((current) => ({ ...current, [key]: value }))
  }

  const clearFilters = () => {
    setPage(1)
    setFilters((current) => ({ ...EMPTY_FILTERS, search: current.search }))
  }

  const handleExport = async (format) => {
    setExporting(format)
    try {
      // The API returns the real file with its own Content-Disposition name;
      // the previous version re-encoded every format as JSON and always
      // saved it with a .json extension.
      const { blob, filename } = await api.export.sessions({ format })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      setError(null)
    } catch (err) {
      setError(`Export failed: ${err.message}`)
    } finally {
      setExporting(null)
    }
  }

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      {error && <ErrorBanner message={error} onRetry={fetchSessions} />}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-bone-mute"
              strokeWidth={1.75}
            />
            <input
              type="search"
              aria-label="Search sessions by address or session ID"
              placeholder="Address or session ID"
              value={filters.search}
              onChange={(e) => updateFilter('search', e.target.value)}
              className="field w-64 pl-8"
            />
          </div>
          <button
            type="button"
            aria-expanded={showFilters}
            onClick={() => setShowFilters((open) => !open)}
            className="control flex items-center gap-1.5"
            style={showFilters ? { borderColor: 'var(--color-signal)' } : undefined}
          >
            <SlidersHorizontal className="h-3.5 w-3.5" strokeWidth={2} />
            Filters
            {activeFilterCount > 0 && (
              <span className="readout ml-0.5 rounded-full bg-signal px-1.5 text-[11px] font-semibold text-void">
                {activeFilterCount}
              </span>
            )}
          </button>
        </div>

        {canExport && (
          <div className="flex items-center gap-2">
            {EXPORT_FORMATS.map(({ id, label, hint }) => (
              <button
                key={id}
                type="button"
                disabled={exporting !== null}
                onClick={() => handleExport(id)}
                title={hint}
                className="control flex items-center gap-1.5"
              >
                <Download className="h-3.5 w-3.5" strokeWidth={2} />
                {exporting === id ? 'Preparing…' : label}
              </button>
            ))}
          </div>
        )}
      </div>

      {showFilters && (
        <div className="panel flex flex-wrap items-end gap-3 p-3">
          <label className="flex flex-col gap-1">
            <span className="label">Status</span>
            <select
              value={filters.status}
              onChange={(e) => updateFilter('status', e.target.value)}
              className="control capitalize"
            >
              <option value="">Any</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="label">Category</span>
            <select
              value={filters.attack_category}
              onChange={(e) => updateFilter('attack_category', e.target.value)}
              className="control capitalize"
            >
              <option value="">Any</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="label">Country code</span>
            <input
              type="text"
              placeholder="NL"
              maxLength={2}
              value={filters.country}
              onChange={(e) => updateFilter('country', e.target.value.toUpperCase())}
              className="field w-24"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="label">Anomaly</span>
            <select
              value={filters.is_anomalous}
              onChange={(e) => updateFilter('is_anomalous', e.target.value)}
              className="control"
            >
              <option value="">Any</option>
              <option value="true">Flagged only</option>
              <option value="false">Not flagged</option>
            </select>
          </label>

          {activeFilterCount > 0 && (
            <button
              type="button"
              onClick={clearFilters}
              className="ml-auto font-display text-[13px] font-medium text-bone-dim transition-colors hover:text-signal"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <caption className="sr-only">Captured honeypot sessions</caption>
            <thead>
              <tr className="border-b border-rule-soft">
                {['Started', 'Session', 'Source', 'Protocol', 'Origin', 'Category', 'Profile', 'Anomaly'].map((h) => (
                  <th
                    key={h}
                    scope="col"
                    className="label whitespace-nowrap px-4 py-2 font-medium"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8}>
                    <LoadingRegion label="Loading sessions" />
                  </td>
                </tr>
              ) : sessions.length === 0 ? (
                <tr>
                  <td colSpan={8}>
                    <EmptyState
                      title="No sessions match"
                      hint={
                        activeFilterCount > 0
                          ? 'Try widening or clearing the filters.'
                          : 'Sessions appear here as the honeypot engine captures traffic.'
                      }
                    />
                  </td>
                </tr>
              ) : (
                sessions.map((session) => (
                  <tr
                    key={session.id}
                    onClick={() => setSelected(session)}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setSelected(session)
                      }
                    }}
                    // The whole row opens the session: a 16px eye icon in the
                    // last column was a needlessly small target for the only
                    // action the table has.
                    className="cursor-pointer border-b border-rule-soft/60 transition-colors last:border-0 hover:bg-raised/60"
                  >
                    <td className="readout whitespace-nowrap px-4 py-2.5 text-[13px] text-bone-mute">
                      {new Date(session.started_at).toLocaleString()}
                    </td>
                    <td
                      className="readout whitespace-nowrap px-4 py-2.5 text-[13px] text-bone-dim"
                      title={session.session_uuid}
                    >
                      {session.session_uuid.slice(0, 8)}
                    </td>
                    <td className="readout whitespace-nowrap px-4 py-2.5 text-[13px] text-bone">
                      {session.attacker_ip}
                    </td>
                    <td className="readout whitespace-nowrap px-4 py-2.5 text-[13px] uppercase text-bone-dim">
                      {session.protocol || '—'}
                    </td>
                    <td className="readout whitespace-nowrap px-4 py-2.5 text-[13px] text-bone-dim">
                      {session.geo?.country || '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      <CategoryTag category={session.attack_category} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-[13px] text-bone-dim">
                      {PROFILE_LABEL_SHORT[session.attacker_profile] || PROFILE_LABEL_SHORT.unknown}
                    </td>
                    <td className="px-4 py-2.5">
                      {session.is_anomalous ? (
                        <span className="tag" style={{ color: 'var(--color-sev-critical)' }}>
                          Flagged
                        </span>
                      ) : (
                        <span className="text-[13px] text-bone-mute">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between border-t border-rule-soft px-4 py-2.5">
            <p className="readout text-[13px] text-bone-mute">
              {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of{' '}
              {total.toLocaleString()}
            </p>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                aria-label="Previous page"
                className="control px-2"
              >
                <ChevronLeft className="h-4 w-4" strokeWidth={2} />
              </button>
              <span className="readout px-2 text-[13px] text-bone-dim">
                {page} / {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                aria-label="Next page"
                className="control px-2"
              >
                <ChevronRight className="h-4 w-4" strokeWidth={2} />
              </button>
            </div>
          </div>
        )}
      </div>

      <SessionDetailModal session={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
