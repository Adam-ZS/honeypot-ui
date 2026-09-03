import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, WifiOff } from 'lucide-react'
import { api } from '../services/api'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { SkeletonBlock } from '../components/Loading'
import { SeverityRail } from '../components/Severity'
import { CATEGORY_COLOR, CATEGORY_LABEL, CATEGORY_ORDER } from '../lib/severity'

const REFRESH_MS = 15000


function LoadingSkeleton() {
  return (
    <div className="space-y-4">
      <SkeletonBlock className="h-28" />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => <SkeletonBlock key={i} className="h-20" />)}
      </div>
      <SkeletonBlock className="h-32" />
      <SkeletonBlock className="h-64" />
    </div>
  )
}

/**
 * The one figure that demands action. Total sessions is a vanity number; what
 * an analyst arrives wanting to know is how much is waiting for them, so that
 * gets the primary treatment and the accent — and only when it is non-zero.
 */
function PrimaryReading({ stats }) {
  const count = stats?.high_severity_alerts ?? 0
  const active = stats?.active_sessions ?? 0
  const today = stats?.sessions_today ?? 0

  return (
    <section className="panel flex flex-wrap items-center justify-between gap-6 p-5">
      <div className="flex items-center gap-5">
        <p
          className="readout text-[56px] font-semibold leading-none"
          style={{ color: count > 0 ? 'var(--color-signal)' : 'var(--color-bone-mute)' }}
        >
          {count.toLocaleString()}
        </p>
        <div>
          <h2 className="text-xl font-semibold leading-tight text-bone">
            {count === 0 ? 'Nothing needs review' : 'Needs review'}
          </h2>
          <p className="mt-0.5 text-sm text-bone-dim">
            {count === 0
              ? 'No unacknowledged high-severity alerts.'
              : `Unacknowledged high-severity ${count === 1 ? 'alert' : 'alerts'}.`}
          </p>
        </div>
      </div>

      <dl className="flex items-center gap-6">
        <div>
          <dt className="label">In progress</dt>
          <dd className="readout mt-0.5 text-2xl text-bone">{active.toLocaleString()}</dd>
        </div>
        <div className="h-9 w-px bg-rule-soft" aria-hidden="true" />
        <div>
          <dt className="label">Captured today</dt>
          <dd className="readout mt-0.5 text-2xl text-bone">{today.toLocaleString()}</dd>
        </div>
      </dl>
    </section>
  )
}

/** Secondary readings. Deliberately quiet — context, not headline. */
function InstrumentStrip({ stats }) {
  const readings = [
    { label: 'Sessions captured', value: stats?.total_sessions ?? 0 },
    { label: 'Honeypot nodes', value: stats?.active_honeypots ?? 0 },
    { label: 'Source addresses', value: stats?.unique_threat_origins ?? 0 },
    { label: 'Countries seen', value: stats?.unique_countries ?? 0 },
  ]

  return (
    <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {readings.map(({ label, value }) => (
        <div key={label} className="panel px-4 py-3">
          <p className="label">{label}</p>
          <p className="readout mt-1 text-2xl text-bone">{value.toLocaleString()}</p>
        </div>
      ))}
    </section>
  )
}

function EngineOffline({ detail }) {
  return (
    <section className="panel border-sev-high/40 p-4">
      <div className="flex items-start gap-3">
        <WifiOff className="mt-0.5 h-4 w-4 shrink-0 text-sev-high" strokeWidth={1.75} />
        <div>
          <h2 className="text-base font-semibold text-bone">Honeypot engine unreachable</h2>
          <p className="mt-1 max-w-2xl text-sm text-bone-dim">
            {detail || 'The backend could not contact the honeypot engine.'}{' '}
            Emulation status, blocked addresses and isolation checks stay
            unavailable until it reconnects. Captured sessions are unaffected.
          </p>
        </div>
      </div>
    </section>
  )
}

function EngineStatus({ status }) {
  const isolationChecked =
    status.isolation && Object.keys(status.isolation).length > 0

  const readings = [
    { label: 'Mode', value: status.mode ?? 'unknown' },
    { label: 'Active sessions', value: String(status.active_sessions ?? 0) },
    { label: 'Blocked addresses', value: String(status.blocked_ips ?? 0) },
    {
      label: 'Isolation',
      // "Unverified" rather than a warning: the engine has simply not run its
      // checks yet, which is not the same as failing them.
      value: isolationChecked
        ? status.isolation.overall_secure ? 'Verified' : 'Failing'
        : 'Unverified',
      tone: isolationChecked
        ? status.isolation.overall_secure ? 'var(--color-sev-low)' : 'var(--color-sev-high)'
        : 'var(--color-bone-mute)',
    },
  ]

  return (
    <section className="panel">
      <div className="panel-head">
        <h2 className="text-base font-semibold text-bone">Engine</h2>
        <span className="flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${status.running ? 'bg-sev-low pulse-live' : 'bg-sev-critical'}`}
            aria-hidden="true"
          />
          <span className="font-display text-[13px] font-medium text-bone-dim">
            {status.running ? 'Running' : 'Stopped'}
          </span>
        </span>
      </div>

      <dl className="grid grid-cols-2 divide-rule-soft sm:grid-cols-4 sm:divide-x">
        {readings.map(({ label, value, tone }) => (
          <div key={label} className="px-4 py-3">
            <dt className="label">{label}</dt>
            <dd
              className="readout mt-1 text-sm capitalize"
              style={{ color: tone || 'var(--color-bone)' }}
            >
              {value}
            </dd>
          </div>
        ))}
      </dl>

      <div className="flex flex-wrap gap-x-6 gap-y-1.5 border-t border-rule-soft px-4 py-3">
        <span className="text-[13px] text-bone-mute">
          Protocols{' '}
          <span className="readout uppercase text-bone-dim">
            {status.protocols?.length ? status.protocols.join(' · ') : 'none'}
          </span>
        </span>
        <span className="text-[13px] text-bone-mute">
          Sessions seen{' '}
          <span className="readout text-bone-dim">{status.total_sessions ?? 0}</span>
        </span>
        <span className="text-[13px] text-bone-mute">
          Banner rotation{' '}
          <span style={{ color: status.anti_fingerprinting ? 'var(--color-sev-low)' : 'var(--color-bone-mute)' }}>
            {status.anti_fingerprinting ? 'on' : 'off'}
          </span>
        </span>
        <span className="text-[13px] text-bone-mute">
          Adaptive responses{' '}
          <span style={{ color: status.adaptive_response ? 'var(--color-sev-low)' : 'var(--color-bone-mute)' }}>
            {status.adaptive_response ? 'on' : 'off'}
          </span>
        </span>
      </div>
    </section>
  )
}

/**
 * Categories are parts of one whole, so they are drawn as one whole: a single
 * segmented bar rather than four separate progress tracks, which invited
 * reading each percentage against its own scale.
 */
function CategoryBreakdown({ distribution }) {
  const total = Object.values(distribution).reduce((a, b) => a + b, 0)

  const segments = CATEGORY_ORDER
    .map((category) => ({
      category,
      count: distribution[category] ?? 0,
      color: CATEGORY_COLOR[category] || 'var(--color-bone-mute)',
    }))
    .filter((s) => s.count > 0)

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2 className="text-base font-semibold text-bone">What was caught</h2>
          <p className="mt-0.5 text-[13px] text-bone-mute">
            {total.toLocaleString()} classified {total === 1 ? 'session' : 'sessions'}
          </p>
        </div>
        <Link
          to="/sessions"
          className="flex shrink-0 items-center gap-1 font-display text-[13px] font-medium text-bone-dim transition-colors hover:text-signal"
        >
          All sessions
          <ArrowRight className="h-3.5 w-3.5" strokeWidth={2} />
        </Link>
      </div>

      {segments.length === 0 ? (
        <EmptyState
          title="Nothing classified yet"
          hint="Categories appear once the engine captures and analyses its first session."
        />
      ) : (
        <div className="p-4">
          <div className="flex h-3 w-full gap-px overflow-hidden rounded-[2px]">
            {segments.map(({ category, count, color }) => (
              <div
                key={category}
                style={{ width: `${(count / total) * 100}%`, background: color }}
                title={`${CATEGORY_LABEL[category] || category}: ${count}`}
              />
            ))}
          </div>

          <dl className="mt-4 grid gap-x-6 gap-y-2 sm:grid-cols-2">
            {segments.map(({ category, count, color }) => (
              <div key={category} className="flex items-baseline gap-2.5">
                <span
                  className="h-2 w-2 shrink-0 translate-y-px rounded-full"
                  style={{ background: color }}
                  aria-hidden="true"
                />
                <dt className="flex-1 text-sm text-bone-dim">
                  {CATEGORY_LABEL[category] || category}
                </dt>
                <dd className="readout text-sm text-bone">
                  {count.toLocaleString()}
                  <span className="ml-2 text-bone-mute">
                    {Math.round((count / total) * 100)}%
                  </span>
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </section>
  )
}

function AlertQueue({ alerts, eventsBySession }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2 className="text-base font-semibold text-bone">Alert queue</h2>
          <p className="mt-0.5 text-[13px] text-bone-mute">
            Unacknowledged detections, newest first
          </p>
        </div>
      </div>

      {alerts.length === 0 ? (
        <EmptyState
          title="Queue is clear"
          hint="New detections land here as the engine classifies them."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <caption className="sr-only">Unacknowledged alerts</caption>
            <thead>
              <tr className="border-b border-rule-soft">
                {['Time', 'Source', 'Origin', 'Detection', 'Severity'].map((h) => (
                  <th
                    key={h}
                    scope="col"
                    className="label px-4 py-2 font-medium whitespace-nowrap"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => {
                const event = eventsBySession.get(alert.session_id)
                return (
                  <tr
                    key={alert.id}
                    className="border-b border-rule-soft/60 transition-colors last:border-0 hover:bg-raised/50"
                  >
                    <td className="readout whitespace-nowrap px-4 py-2.5 text-[13px] text-bone-mute">
                      {new Date(alert.created_at).toLocaleString()}
                    </td>
                    <td className="readout whitespace-nowrap px-4 py-2.5 text-[13px] text-bone">
                      {event?.attacker_ip || '—'}
                    </td>
                    <td className="readout whitespace-nowrap px-4 py-2.5 text-[13px] text-bone-dim">
                      {event?.geo_country || '—'}
                    </td>
                    <td className="px-4 py-2.5 text-sm text-bone-dim">{alert.title}</td>
                    <td className="px-4 py-2.5">
                      <SeverityRail level={alert.severity} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [liveEvents, setLiveEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [engine, setEngine] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [statsData, eventsData, alertsData, engineStatus] = await Promise.all([
        api.dashboard.stats(),
        api.dashboard.liveEvents(50),
        api.alerts.list({ page: 1, page_size: 8, status: 'new' }),
        api.honeypot.status().catch(() => null),
      ])
      setStats(statsData)
      setLiveEvents(eventsData || [])
      setAlerts(alertsData.alerts || [])
      setEngine(engineStatus)
      setError(null)
    } catch (err) {
      // Surface failures instead of only writing them to the console, which
      // left the dashboard silently frozen on stale numbers.
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    // Deferred so the effect body performs no synchronous state update.
    const timer = setTimeout(fetchData, 0)
    const interval = setInterval(fetchData, REFRESH_MS)
    return () => {
      clearTimeout(timer)
      clearInterval(interval)
    }
  }, [fetchData])

  if (loading) return <LoadingSkeleton />

  // Index live events by session id so the alert table can resolve each
  // alert's source. This used to compare a session UUID against a numeric
  // session id, so the IP and origin columns were always "—".
  const eventsBySession = new Map(liveEvents.map((e) => [e.session_id, e]))

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      {error && <ErrorBanner message={error} onRetry={fetchData} />}

      <PrimaryReading stats={stats} />
      <InstrumentStrip stats={stats} />

      {engine?.reachable
        ? <EngineStatus status={engine} />
        : <EngineOffline detail={engine?.detail} />}

      <CategoryBreakdown distribution={stats?.attack_distribution || {}} />
      <AlertQueue alerts={alerts} eventsBySession={eventsBySession} />
    </div>
  )
}

