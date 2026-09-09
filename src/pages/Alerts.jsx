import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Check, CircleSlash, ExternalLink } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadingRegion } from '../components/Loading'
import { SEVERITY_COLOR, SEVERITY_ORDER } from '../lib/severity'

/*
 * Alerts.
 *
 * The endpoints have existed since the first version and three of the four
 * raised RecursionError, so nothing could have consumed them even if a page
 * had been built. The rail counted unread alerts and linked to the session
 * list, because there was nowhere else to send anyone.
 *
 * The work of a queue is triage, so the page is built around the two actions
 * that empty it — acknowledge and resolve — rather than around reading.
 */

const PAGE_SIZE = 25

const STATUS_LABEL = {
  new: 'New',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

/* Ordered by what an analyst does next, not alphabetically. */
const STATUS_FILTERS = ['new', 'acknowledged', 'resolved', 'false_positive']

function timeAgo(iso) {
  const seconds = (Date.now() - new Date(iso).getTime()) / 1000
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

function AlertRow({ alert, busy, onUpdate, canAct }) {
  const color = SEVERITY_COLOR[alert.severity] || 'var(--color-paper-3)'
  const open = alert.status === 'new' || alert.status === 'acknowledged'

  return (
    <li className="border-t border-line first:border-t-0">
      <article className="flex gap-3 px-3.5 py-3">
        <span
          className="mt-[3px] h-full w-[3px] shrink-0 rounded-[1px]"
          style={{ background: color }}
          aria-hidden="true"
        />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <h3 className="min-w-0 flex-1 text-[13px] font-medium text-paper">
              {alert.title}
            </h3>
            <span className="tag shrink-0" style={{ color }}>
              {alert.severity}
            </span>
            {!open && (
              <span className="tag shrink-0" style={{ color: 'var(--color-paper-3)' }}>
                {STATUS_LABEL[alert.status]}
              </span>
            )}
          </div>

          {alert.description && (
            <p className="mt-1 text-[12px] leading-relaxed text-paper-2">
              {alert.description}
            </p>
          )}

          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-paper-3">
            <span className="readout">{timeAgo(alert.created_at)}</span>
            <Link
              to={`/sessions?session=${alert.session_id}`}
              className="inline-flex items-center gap-1 transition-colors hover:text-paper"
            >
              Session {alert.session_id}
              <ExternalLink className="h-3 w-3" strokeWidth={2} />
            </Link>
            {alert.mitre_techniques?.length > 0 && (
              <span className="readout">
                {alert.mitre_techniques.map((t) => t.id).join(' · ')}
              </span>
            )}
          </div>

          {canAct && open && (
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {alert.status === 'new' && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onUpdate(alert.id, 'acknowledged')}
                  className="control gap-1.5"
                >
                  <Check className="h-3.5 w-3.5" strokeWidth={2} />
                  Acknowledge
                </button>
              )}
              <button
                type="button"
                disabled={busy}
                onClick={() => onUpdate(alert.id, 'resolved')}
                className="control gap-1.5"
              >
                Resolve
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => onUpdate(alert.id, 'false_positive')}
                className="control gap-1.5"
                title="Mark as a false positive — this is the signal that the detection rule needs adjusting"
              >
                <CircleSlash className="h-3.5 w-3.5" strokeWidth={2} />
                False positive
              </button>
            </div>
          )}
        </div>
      </article>
    </li>
  )
}

export default function Alerts() {
  const { hasRole } = useAuth()
  const canAct = hasRole('analyst')

  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [status, setStatus] = useState('new')
  const [severity, setSeverity] = useState('')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: PAGE_SIZE }
      if (status) params.status = status
      if (severity) params.severity = severity
      const [list, summary] = await Promise.all([
        api.alerts.list(params),
        api.alerts.stats(),
      ])
      setAlerts(list.alerts || [])
      setTotal(list.total || 0)
      setStats(summary)
      setError(null)
    } catch (err) {
      setError(err.message || 'Could not load alerts')
    } finally {
      setLoading(false)
    }
  }, [page, status, severity])

  useEffect(() => {
    // Deferred by a tick rather than called in the effect body: `load` sets
    // loading state synchronously, which would cascade a second render.
    // Same idiom as the session list.
    const timer = setTimeout(load, 0)
    return () => clearTimeout(timer)
  }, [load])

  const update = async (id, nextStatus) => {
    setBusyId(id)
    try {
      await api.alerts.update(id, { status: nextStatus })
      await load()
    } catch (err) {
      setError(err.message || 'Could not update the alert')
    } finally {
      setBusyId(null)
    }
  }

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="mx-auto flex h-full max-w-[1100px] flex-col gap-3">
      {error && <ErrorBanner message={error} onRetry={load} />}

      {/* The counts are the queue's shape: how much is waiting, how much has
          been touched, how much is done. */}
      {stats && (
        <div className="panel grid grid-cols-3 divide-x divide-line">
          {[
            ['Waiting', stats.new, 'var(--color-s4)'],
            ['Acknowledged', stats.acknowledged, 'var(--color-s2)'],
            ['Closed', stats.resolved, 'var(--color-paper-3)'],
          ].map(([label, value, color]) => (
            <div key={label} className="px-4 py-3">
              <p className="eyebrow">{label}</p>
              <p
                className="readout mt-1 text-[22px] font-semibold tabular-nums"
                style={{ color }}
              >
                {value ?? 0}
              </p>
            </div>
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Status</span>
          <select
            value={status}
            onChange={(e) => { setStatus(e.target.value); setPage(1) }}
            className="control"
          >
            <option value="">Any</option>
            {STATUS_FILTERS.map((s) => (
              <option key={s} value={s}>{STATUS_LABEL[s]}</option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Severity</span>
          <select
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
            className="control capitalize"
          >
            <option value="">Any</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>

        {total > 0 && (
          <p className="ml-auto text-[12px] text-paper-3">
            {total} alert{total === 1 ? '' : 's'}
          </p>
        )}
      </div>

      <section className="panel flex min-h-0 flex-1 flex-col overflow-hidden">
        {loading ? (
          <LoadingRegion label="Loading alerts" />
        ) : alerts.length === 0 ? (
          <EmptyState
            title={status === 'new' ? 'Nothing waiting' : 'No alerts match'}
            hint={
              status === 'new'
                ? 'Alerts appear here when a session matches a configured threshold. Thresholds are set under Settings.'
                : 'Try a different status or severity.'
            }
          />
        ) : (
          <ul className="min-h-0 flex-1 overflow-y-auto">
            {alerts.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                busy={busyId === alert.id}
                onUpdate={update}
                canAct={canAct}
              />
            ))}
          </ul>
        )}

        {pages > 1 && (
          <div className="flex items-center justify-between border-t border-line px-3 py-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
              className="control"
            >
              Previous
            </button>
            <span className="readout text-[12px] text-paper-3">
              {page} / {pages}
            </span>
            <button
              type="button"
              disabled={page >= pages}
              onClick={() => setPage((p) => p + 1)}
              className="control"
            >
              Next
            </button>
          </div>
        )}
      </section>
    </div>
  )
}
