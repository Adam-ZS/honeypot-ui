import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ChevronLeft, ChevronRight, Download, Search, SlidersHorizontal } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { useDebounced } from '../hooks/useDebounced'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import SessionDetail from '../components/SessionDetail'
import { LoadingRegion } from '../components/Loading'

import {
  CATEGORY_COLOR, CATEGORY_LABEL, HANDS_ON_PROFILES,
  PROFILE_LABEL_SHORT,
} from '../lib/severity'

const PAGE_SIZE = 25

const CATEGORIES = ['benign', 'reconnaissance', 'exploitation', 'exfiltration']
const STATUSES = ['active', 'completed', 'terminated']

const EXPORT_FORMATS = [
  { id: 'json', label: 'JSON', hint: 'Full session records' },
  { id: 'cef', label: 'CEF', hint: 'ArcSight and syslog collectors' },
  { id: 'stix', label: 'STIX', hint: 'Threat intelligence platforms' },
]

const EMPTY_FILTERS = {
  search: '',
  status: '',
  attack_category: '',
  country: '',
  is_anomalous: '',
  // Off by default: hiding traffic silently would misrepresent what the
  // honeypot saw. It is offered because scanner probes otherwise dominate
  // every count.
  exclude_scanners: '',
}

/** One row in the list. Compact — the detail panel carries the depth. */
function SessionRow({ session, selected, onSelect }) {
  const color = CATEGORY_COLOR[session.attack_category] || CATEGORY_COLOR.unknown
  const handsOn = HANDS_ON_PROFILES.has(session.attacker_profile)

  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(session)}
        aria-current={selected ? 'true' : undefined}
        className={`flex w-full items-center gap-3 border-l-2 px-3 py-[7px] text-left transition-colors ${
          selected
            ? 'border-l-paper bg-ink-2'
            : 'border-l-transparent hover:bg-ink-2/60'
        }`}
      >
        <span
          className="h-6 w-[3px] shrink-0 rounded-[1px]"
          style={{ background: color }}
          aria-hidden="true"
        />

        <span className="min-w-0 flex-1">
          <span className="flex items-baseline gap-2">
            <span className="readout truncate text-[13px] text-paper">
              {session.attacker_ip}
            </span>
            <span className="readout shrink-0 text-[11px] uppercase text-paper-3">
              {session.protocol || '—'}
            </span>
            {handsOn && (
              <span className="tag shrink-0" style={{ color: 'var(--color-s4)' }}>
                {PROFILE_LABEL_SHORT[session.attacker_profile]}
              </span>
            )}
          </span>
          <span className="mt-0.5 flex items-baseline gap-1.5 text-[12px] text-paper-3">
            <span className="truncate">
              {CATEGORY_LABEL[session.attack_category] || CATEGORY_LABEL.unknown}
            </span>
            <span aria-hidden="true">·</span>
            <span className="shrink-0">{session.geo?.country || '—'}</span>
            <span aria-hidden="true">·</span>
            <span className="readout shrink-0">
              {new Date(session.started_at).toLocaleString(undefined, {
                month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
              })}
            </span>
          </span>
        </span>

        {session.is_anomalous && (
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full bg-s4"
            title="Flagged as anomalous"
          />
        )}
      </button>
    </li>
  )
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
  const [searchParams] = useSearchParams()

  const debouncedSearch = useDebounced(filters.search)
  const canExport = hasRole('analyst')

  const query = useMemo(
    () => ({ ...filters, search: debouncedSearch }),
    [filters, debouncedSearch],
  )

  const activeFilterCount = useMemo(
    () =>
      Object.entries(filters).filter(([k, v]) => k !== 'search' && v !== '').length,
    [filters],
  )

  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true)
      const data = await api.sessions.list({ page, page_size: PAGE_SIZE, ...query })
      const rows = data.sessions || []
      setSessions(rows)
      setTotal(data.total || 0)
      // Open on the first result rather than an empty detail pane, so the
      // page shows what it does before anything is clicked. Only when the
      // current selection is gone, so paging does not steal focus.
      //
      // A ?session= parameter wins over both: it is how an alert links to the
      // session that caused it, and arriving on the wrong row would make that
      // link pointless. Fetched directly, because the session may not be on
      // the page the list happens to be showing.
      const requested = Number(searchParams.get('session'))
      if (requested) {
        const known = rows.find((r) => r.id === requested)
        setSelected(known ?? (await api.sessions.get(requested).catch(() => null)))
      } else {
        setSelected((current) =>
          current && rows.some((r) => r.id === current.id) ? current : rows[0] ?? null,
        )
      }
      setError(null)
    } catch (err) {
      setError(err.message)
      setSessions([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [page, query, searchParams])

  useEffect(() => {
    const timer = setTimeout(fetchSessions, 0)
    return () => clearTimeout(timer)
  }, [fetchSessions])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const updateFilter = (key, value) => {
    // Reset to the first page here rather than in an effect: a filter change
    // invalidates the current page, and doing it in the same event avoids a
    // render pass that would fetch page N of the new result set.
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
      // an earlier version re-encoded every format as JSON and always saved
      // it with a .json extension.
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
    <div className="mx-auto flex h-full max-w-[1600px] flex-col gap-3">
      {error && <ErrorBanner message={error} onRetry={fetchSessions} />}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-paper-3"
              strokeWidth={1.75}
            />
            <input
              type="search"
              aria-label="Search sessions by address or session ID"
              placeholder="Address or session ID"
              value={filters.search}
              onChange={(e) => updateFilter('search', e.target.value)}
              className="field w-60 pl-8"
            />
          </div>
          <button
            type="button"
            aria-expanded={showFilters}
            onClick={() => setShowFilters((open) => !open)}
            className="control"
            style={showFilters ? { borderColor: 'var(--color-paper-2)' } : undefined}
          >
            <SlidersHorizontal className="h-3.5 w-3.5" strokeWidth={2} />
            Filters
            {activeFilterCount > 0 && (
              <span className="readout rounded-full bg-paper px-1.5 text-[11px] font-semibold text-ink-0">
                {activeFilterCount}
              </span>
            )}
          </button>
        </div>

        {canExport && (
          <div className="flex items-center gap-1.5">
            <span className="mr-1 hidden text-[12px] text-paper-3 sm:inline">Export</span>
            {EXPORT_FORMATS.map(({ id, label, hint }) => (
              <button
                key={id}
                type="button"
                disabled={exporting !== null}
                onClick={() => handleExport(id)}
                title={hint}
                className="control"
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
            <span className="eyebrow">Status</span>
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
            <span className="eyebrow">Category</span>
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
            <span className="eyebrow">Country</span>
            <input
              type="text"
              placeholder="NL"
              maxLength={2}
              value={filters.country}
              onChange={(e) => updateFilter('country', e.target.value.toUpperCase())}
              className="field w-20"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="eyebrow">Research scanners</span>
            <select
              value={filters.exclude_scanners}
              onChange={(e) => updateFilter('exclude_scanners', e.target.value)}
              className="control"
              title="Censys, Shodan and Shadowserver scan every public address continuously. They are always recorded; this decides whether they are shown."
            >
              <option value="">Include</option>
              <option value="true">Exclude</option>
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="eyebrow">Anomaly</span>
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
              className="ml-auto text-[13px] font-medium text-paper-2 transition-colors hover:text-paper"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {/*
        Master–detail rather than a modal: an analyst comparing sessions can
        step down the list and watch the right-hand panel change, instead of
        opening and dismissing a dialog for each one.
      */}
      <div className="grid min-h-0 flex-1 gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,26rem)]">
        <section className="panel flex min-h-0 flex-col overflow-hidden">
          {loading ? (
            <LoadingRegion label="Loading sessions" />
          ) : sessions.length === 0 ? (
            <EmptyState
              title="No sessions match"
              hint={
                activeFilterCount > 0
                  ? 'Try widening or clearing the filters.'
                  : 'Sessions appear here as the honeypot engine captures traffic.'
              }
            />
          ) : (
            <ul className="min-h-0 flex-1 overflow-y-auto">
              {sessions.map((session) => (
                <SessionRow
                  key={session.id}
                  session={session}
                  selected={selected?.id === session.id}
                  onSelect={setSelected}
                />
              ))}
            </ul>
          )}

          {total > PAGE_SIZE && (
            <div className="flex shrink-0 items-center justify-between border-t border-line px-3 py-2">
              <p className="readout text-[12px] text-paper-3">
                {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of{' '}
                {total.toLocaleString()}
              </p>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  aria-label="Previous page"
                  className="control px-1.5"
                >
                  <ChevronLeft className="h-4 w-4" strokeWidth={2} />
                </button>
                <span className="readout px-1.5 text-[12px] text-paper-2">
                  {page} / {totalPages}
                </span>
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  aria-label="Next page"
                  className="control px-1.5"
                >
                  <ChevronRight className="h-4 w-4" strokeWidth={2} />
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Desktop: a standing panel. Narrow: a sheet, only once something
            is selected, because there is no room for both. */}
        <aside className="panel hidden min-h-0 lg:block">
          <SessionDetail session={selected} />
        </aside>

        {selected && (
          <div
            className="fixed inset-0 z-50 flex items-end bg-ink-0/85 lg:hidden"
            onClick={() => setSelected(null)}
            role="presentation"
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-label={`Session ${selected.session_uuid}`}
              className="panel max-h-[85vh] w-full overflow-hidden rounded-b-none"
              onClick={(e) => e.stopPropagation()}
            >
              <SessionDetail session={selected} onClose={() => setSelected(null)} />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

