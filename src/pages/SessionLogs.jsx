import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ChevronLeft, ChevronRight, Download, Eye, Filter, Search,
} from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { useDebounced } from '../hooks/useDebounced'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import SessionDetailModal from '../components/SessionDetailModal'

const PAGE_SIZE = 20

const CATEGORIES = ['benign', 'reconnaissance', 'exploitation', 'exfiltration']
const STATUSES = ['active', 'completed', 'terminated']
const EXPORT_FORMATS = ['json', 'cef', 'stix']

const CATEGORY_BADGE = {
  exfiltration: 'bg-accent-red/10 text-accent-red border-accent-red/30',
  exploitation: 'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
  reconnaissance: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  benign: 'bg-accent-green/10 text-accent-green border-accent-green/30',
}

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

  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true)
      const data = await api.sessions.list({
        page,
        page_size: PAGE_SIZE,
        ...query,
      })
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
    <div className="space-y-4 animate-fade-in">
      {error && <ErrorBanner message={error} onRetry={fetchSessions} />}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="search"
              aria-label="Search sessions by IP or UUID"
              placeholder="Search IP, UUID..."
              value={filters.search}
              onChange={(e) => updateFilter('search', e.target.value)}
              className="bg-surface-700 border border-border rounded-lg pl-9 pr-4 py-2 text-sm font-mono text-white placeholder-gray-600 outline-none focus:border-accent-blue w-64"
            />
          </div>
          <button
            type="button"
            aria-expanded={showFilters}
            onClick={() => setShowFilters((open) => !open)}
            className={`flex items-center gap-2 px-3 py-2 text-sm font-mono rounded-lg border transition-all ${
              showFilters
                ? 'bg-surface-600 border-border text-white'
                : 'border-border/50 text-gray-400 hover:text-white'
            }`}
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>
        </div>

        {canExport && (
          <div className="flex items-center gap-2">
            {EXPORT_FORMATS.map((format) => (
              <button
                key={format}
                type="button"
                disabled={exporting !== null}
                onClick={() => handleExport(format)}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-mono bg-surface-700 border border-border rounded-lg text-gray-300 hover:text-white hover:bg-surface-600 disabled:opacity-50 transition-all uppercase"
              >
                <Download className="w-3.5 h-3.5" />
                {exporting === format ? 'Exporting...' : format}
              </button>
            ))}
          </div>
        )}
      </div>

      {showFilters && (
        <div className="bg-surface-800 border border-border rounded-xl p-4 grid grid-cols-2 md:grid-cols-4 gap-3 animate-fade-in">
          <label className="contents">
            <select
              aria-label="Filter by status"
              value={filters.status}
              onChange={(e) => updateFilter('status', e.target.value)}
              className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue capitalize"
            >
              <option value="">All statuses</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>

          <select
            aria-label="Filter by attack category"
            value={filters.attack_category}
            onChange={(e) => updateFilter('attack_category', e.target.value)}
            className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue capitalize"
          >
            <option value="">All categories</option>
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>

          <input
            type="text"
            aria-label="Filter by ISO country code"
            placeholder="Country code (e.g. NL)"
            maxLength={2}
            value={filters.country}
            onChange={(e) => updateFilter('country', e.target.value.toUpperCase())}
            className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-gray-600 outline-none focus:border-accent-blue"
          />

          <select
            aria-label="Filter by anomaly flag"
            value={filters.is_anomalous}
            onChange={(e) => updateFilter('is_anomalous', e.target.value)}
            className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
          >
            <option value="">Anomaly: all</option>
            <option value="true">Anomalous only</option>
            <option value="false">Normal only</option>
          </select>
        </div>
      )}

      <div className="bg-surface-800 border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <caption className="sr-only">Captured honeypot sessions</caption>
            <thead>
              <tr className="border-b border-border">
                {['Time', 'Session', 'Attacker IP', 'Protocol', 'Country', 'Category', 'Profile', 'Anomaly', ''].map((header) => (
                  <th key={header} scope="col" className="text-left text-[10px] font-mono text-gray-500 uppercase tracking-widest px-4 py-3 whitespace-nowrap">
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center">
                    <div className="flex items-center justify-center gap-3">
                      <div className="w-5 h-5 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
                      <span className="font-mono text-sm text-gray-400">Loading sessions...</span>
                    </div>
                  </td>
                </tr>
              ) : sessions.length === 0 ? (
                <tr>
                  <td colSpan={9}>
                    <EmptyState
                      title="No sessions found"
                      hint="Adjust the filters, or wait for the honeypot engine to capture traffic."
                    />
                  </td>
                </tr>
              ) : (
                sessions.map((session) => (
                  <tr key={session.id} className="border-b border-border/50 hover:bg-surface-700 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-400 whitespace-nowrap">
                      {new Date(session.started_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-accent-blue whitespace-nowrap" title={session.session_uuid}>
                      {session.session_uuid.slice(0, 8)}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-white whitespace-nowrap">
                      {session.attacker_ip}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-400 uppercase">
                      {session.protocol || '—'}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-400 whitespace-nowrap">
                      {session.geo?.country || '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      {/* Shows the model's actual category. The old severity
                          column derived a label from the category alone, which
                          disagreed with the severity the backend computed. */}
                      <span className={`text-[10px] font-mono border px-2 py-0.5 rounded-full uppercase ${CATEGORY_BADGE[session.attack_category] || 'bg-surface-600 text-gray-300 border-border'}`}>
                        {session.attack_category || 'unclassified'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-gray-400">
                      {session.attacker_profile || 'unknown'}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                        session.is_anomalous
                          ? 'bg-accent-red/10 text-accent-red border-accent-red/30'
                          : 'bg-surface-600 text-gray-400 border-border'
                      }`}>
                        {session.is_anomalous ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        type="button"
                        onClick={() => setSelected(session)}
                        aria-label={`View details for session ${session.session_uuid}`}
                        className="p-1.5 text-gray-500 hover:text-accent-blue transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <span className="text-xs font-mono text-gray-500">
              {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of {total}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                aria-label="Previous page"
                className="p-1.5 text-gray-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-xs font-mono text-gray-400">
                Page {page} of {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                aria-label="Next page"
                className="p-1.5 text-gray-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      <SessionDetailModal session={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
