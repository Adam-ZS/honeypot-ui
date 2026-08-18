import { useCallback, useEffect, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight, Globe, Lock, Server, Shield, Terminal, WifiOff,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { api } from '../services/api'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'

const SEVERITY_STYLES = {
  critical: 'bg-accent-red/10 text-accent-red border-accent-red/30',
  high: 'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
  medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  low: 'bg-accent-green/10 text-accent-green border-accent-green/30',
}

const CATEGORY_LABELS = {
  exploitation: 'Exploitation',
  reconnaissance: 'Reconnaissance',
  exfiltration: 'Exfiltration',
  benign: 'Benign',
  unknown: 'Unclassified',
}

const CATEGORY_COLORS = {
  exploitation: 'bg-accent-red',
  reconnaissance: 'bg-accent-blue',
  exfiltration: 'bg-accent-orange',
  benign: 'bg-accent-green',
  unknown: 'bg-gray-600',
}

const REFRESH_MS = 15000

function LoadingSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-surface-800 border border-border rounded-xl p-5 h-32" />
        ))}
      </div>
      <div className="bg-surface-800 border border-border rounded-xl h-80" />
    </div>
  )
}

function StatCard({ label, value, detail, icon: Icon, color, border }) {
  return (
    <div className={`bg-surface-800 border ${border} rounded-xl p-5 transition-all hover:bg-surface-700`}>
      <div className="flex items-start justify-between mb-4">
        <p className="text-xs font-mono text-gray-400 uppercase tracking-widest">{label}</p>
        <div className="p-1.5 rounded-lg bg-surface-600">
          <Icon className={`w-4 h-4 ${color}`} />
        </div>
      </div>
      <p className={`text-3xl font-mono font-bold ${color}`}>{value.toLocaleString()}</p>
      <p className="mt-2 text-xs font-mono text-gray-500 flex items-center gap-1">
        <ArrowUpRight className="w-3 h-3" />
        {detail}
      </p>
    </div>
  )
}

function EngineOffline({ detail }) {
  return (
    <div className="bg-surface-800 border border-accent-orange/30 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-1">
        <WifiOff className="w-4 h-4 text-accent-orange" />
        <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
          Honeypot Engine Unreachable
        </h2>
      </div>
      <p className="text-xs font-mono text-gray-500">
        {detail || 'The backend could not contact the honeypot engine.'} Live
        emulation status, blocked IPs and isolation checks are unavailable
        until it reconnects.
      </p>
    </div>
  )
}

function EngineStatus({ status }) {
  const isolationChecked = status.isolation && Object.keys(status.isolation).length > 0
  const tiles = [
    { icon: Terminal, tint: 'text-accent-cyan', label: 'Mode', value: status.mode ?? 'unknown' },
    { icon: Activity, tint: 'text-accent-orange', label: 'Active', value: `${status.active_sessions} sessions` },
    { icon: Server, tint: 'text-accent-blue', label: 'Blocked IPs', value: status.blocked_ips },
    {
      icon: Lock,
      tint: status.isolation?.overall_secure ? 'text-accent-green' : 'text-accent-orange',
      label: 'Isolation',
      // Report "unverified" rather than claiming a warning when the engine
      // has not run its isolation checks yet.
      value: isolationChecked
        ? (status.isolation.overall_secure ? 'Verified' : 'Failing')
        : 'Unverified',
    },
  ]

  return (
    <div className="bg-surface-800 border border-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
            Honeypot Engine Status
          </h2>
          <p className="text-xs font-mono text-gray-500 mt-0.5">
            Emulation services &amp; security posture
          </p>
        </div>
        <span className={`flex items-center gap-1.5 text-xs font-mono ${status.running ? 'text-accent-green' : 'text-accent-red'}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${status.running ? 'bg-accent-green' : 'bg-accent-red'}`} />
          {status.running ? 'Running' : 'Stopped'}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {tiles.map(({ icon: Icon, tint, label, value }) => (
          <div key={label} className="bg-surface-700 rounded-lg p-3 border border-border/50">
            <div className="flex items-center gap-2 mb-2">
              <Icon className={`w-3.5 h-3.5 ${tint}`} />
              <span className="text-[10px] font-mono text-gray-400 uppercase">{label}</span>
            </div>
            <p className="font-mono text-sm font-semibold text-white capitalize">{value}</p>
          </div>
        ))}
      </div>

      <div className="mt-4 flex flex-wrap gap-4 text-xs font-mono text-gray-500">
        <span>
          Protocols:{' '}
          <span className="text-white">
            {status.protocols?.length ? status.protocols.join(', ') : 'none'}
          </span>
        </span>
        <span>Sessions seen: <span className="text-white">{status.total_sessions}</span></span>
        <span>
          Anti-fingerprint:{' '}
          <span className={status.anti_fingerprinting ? 'text-accent-green' : 'text-gray-500'}>
            {status.anti_fingerprinting ? 'on' : 'off'}
          </span>
        </span>
        <span>
          Adaptive:{' '}
          <span className={status.adaptive_response ? 'text-accent-green' : 'text-gray-500'}>
            {status.adaptive_response ? 'on' : 'off'}
          </span>
        </span>
      </div>
    </div>
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

  const distribution = stats?.attack_distribution || {}
  const totalClassified = Object.values(distribution).reduce((a, b) => a + b, 0)
  const categoryBars = Object.entries(distribution)
    .map(([category, count]) => ({
      category,
      count,
      pct: totalClassified ? Math.round((count / totalClassified) * 100) : 0,
    }))
    .sort((a, b) => b.count - a.count)

  const cards = [
    {
      label: 'Total Sessions',
      value: stats?.total_sessions ?? 0,
      detail: `${stats?.sessions_today ?? 0} today`,
      icon: Activity,
      color: 'text-accent-blue',
      border: 'border-accent-blue/20',
    },
    {
      label: 'Open High-Severity Alerts',
      value: stats?.high_severity_alerts ?? 0,
      detail: `${stats?.active_sessions ?? 0} sessions in progress`,
      icon: AlertTriangle,
      color: 'text-accent-red',
      border: 'border-accent-red/20',
    },
    {
      label: 'Active Honeypots',
      // Show the real count. This previously fell back to a hardcoded 4
      // whenever the true value was 0.
      value: stats?.active_honeypots ?? 0,
      detail:
        (stats?.active_honeypots ?? 0) === 0
          ? 'No nodes registered'
          : 'Registered nodes',
      icon: Shield,
      color: 'text-accent-green',
      border: 'border-accent-green/20',
    },
    {
      label: 'Unique Threat Origins',
      value: stats?.unique_threat_origins ?? 0,
      detail: `Across ${stats?.unique_countries ?? 0} known ${
        (stats?.unique_countries ?? 0) === 1 ? 'country' : 'countries'
      }`,
      icon: Globe,
      color: 'text-accent-cyan',
      border: 'border-accent-cyan/20',
    },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      {error && <ErrorBanner message={error} onRetry={fetchData} />}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {cards.map((card) => <StatCard key={card.label} {...card} />)}
      </div>

      {engine?.reachable ? (
        <EngineStatus status={engine} />
      ) : (
        <EngineOffline detail={engine?.detail} />
      )}

      <div className="bg-surface-800 border border-border rounded-xl p-5">
        <div className="flex items-baseline justify-between mb-1">
          <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
            Attack Distribution
          </h2>
          <Link to="/sessions" className="text-xs font-mono text-accent-cyan hover:underline">
            View sessions
          </Link>
        </div>
        <p className="text-xs font-mono text-gray-500 mb-5">
          Classified sessions by category ({totalClassified.toLocaleString()} total)
        </p>

        {categoryBars.length === 0 ? (
          <EmptyState
            title="No classified sessions yet"
            hint="Categories appear here once the honeypot engine ingests its first session."
          />
        ) : (
          <div className="space-y-3">
            {categoryBars.map(({ category, count, pct }) => (
              <div key={category}>
                <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                  <span>{CATEGORY_LABELS[category] || category}</span>
                  <span>
                    {count.toLocaleString()} ({pct}%)
                  </span>
                </div>
                <div className="h-1.5 bg-surface-600 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${CATEGORY_COLORS[category] || 'bg-gray-600'} rounded-full transition-all duration-700`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-surface-800 border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
            New Alerts
          </h2>
          <p className="text-xs font-mono text-gray-500 mt-0.5">
            Unacknowledged high-severity detections
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <caption className="sr-only">Unacknowledged alerts</caption>
            <thead>
              <tr className="border-b border-border">
                {['Timestamp', 'IP Address', 'Origin', 'Detection', 'Severity'].map((h) => (
                  <th key={h} scope="col" className="text-left text-[10px] font-mono text-gray-500 uppercase tracking-widest px-5 py-3">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-8 text-center font-mono text-sm text-gray-500">
                    No new alerts
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => {
                  const event = eventsBySession.get(alert.session_id)
                  return (
                    <tr key={alert.id} className="border-b border-border/50 hover:bg-surface-700 transition-colors">
                      <td className="px-5 py-3 font-mono text-xs text-gray-400 whitespace-nowrap">
                        {new Date(alert.created_at).toLocaleString()}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-accent-blue whitespace-nowrap">
                        {event?.attacker_ip || '—'}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400">
                        {event?.geo_country || 'Unknown'}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-300">{alert.title}</td>
                      <td className="px-5 py-3">
                        <span className={`inline-block text-[10px] font-mono font-semibold border rounded-full px-2.5 py-0.5 uppercase tracking-wider ${SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.low}`}>
                          {alert.severity}
                        </span>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
