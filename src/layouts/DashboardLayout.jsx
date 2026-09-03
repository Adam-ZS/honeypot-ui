import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { useEffect, useRef, useState } from 'react'
import {
  LayoutDashboard, Map, FileText, Settings,
  Bell, ChevronDown, LogOut, Menu, X,
} from 'lucide-react'
import { useAuth } from '../context/useAuth'
import { api } from '../services/api'

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/map', label: 'Origins', icon: Map },
  { to: '/sessions', label: 'Sessions', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

const STATUS_POLL_MS = 30000

/** The console's mark: a hexagonal cell, drawn rather than pulled from an icon set. */
function Mark({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden="true" fill="none">
      <path
        d="M12 2.6 20.5 7.3v9.4L12 21.4 3.5 16.7V7.3L12 2.6Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M12 8.2 16 10.4v4.4L12 17l-4-2.2v-4.4L12 8.2Z"
        fill="currentColor"
        opacity="0.9"
      />
    </svg>
  )
}

/**
 * Persistent engine readout. This is the one fact that is always relevant
 * regardless of which page an analyst is on — if the engine is down, nothing
 * else on screen is being updated — so it stays pinned in the rail.
 */
function EngineReadout({ engine, nodeCount }) {
  const state =
    engine === null ? 'unknown'
      : !engine.reachable ? 'unreachable'
        : engine.running ? 'running' : 'stopped'

  const dot = {
    unknown: 'bg-bone-mute',
    unreachable: 'bg-sev-critical',
    stopped: 'bg-sev-high',
    running: 'bg-sev-low pulse-live',
  }[state]

  const text = {
    unknown: 'Checking engine',
    unreachable: 'Engine unreachable',
    stopped: 'Engine stopped',
    running: 'Engine running',
  }[state]

  return (
    <div className="border-t border-rule-soft px-4 py-3.5">
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 shrink-0 rounded-full ${dot}`} aria-hidden="true" />
        <span className="font-display text-[13px] font-medium text-bone">{text}</span>
      </div>

      <dl className="mt-2.5 space-y-1">
        <div className="flex items-baseline justify-between gap-2">
          <dt className="font-display text-xs text-bone-mute">Nodes</dt>
          <dd className="readout text-xs text-bone-dim">
            {nodeCount === null ? '—' : nodeCount}
          </dd>
        </div>
        <div className="flex items-baseline justify-between gap-2">
          <dt className="font-display text-xs text-bone-mute">Protocols</dt>
          <dd className="readout truncate text-xs uppercase text-bone-dim">
            {engine?.protocols?.length ? engine.protocols.join(' · ') : '—'}
          </dd>
        </div>
      </dl>
    </div>
  )
}

export default function DashboardLayout() {
  const { user, logout } = useAuth()
  const [railOpen, setRailOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const [engine, setEngine] = useState(null)
  const [nodeCount, setNodeCount] = useState(null)
  const [newAlerts, setNewAlerts] = useState(0)
  const location = useLocation()
  const profileRef = useRef(null)

  useEffect(() => {
    let cancelled = false

    const poll = async () => {
      const [status, nodes, alertStats] = await Promise.all([
        api.honeypot.status().catch(() => ({ reachable: false })),
        api.nodes.list(true).catch(() => null),
        api.alerts.stats().catch(() => null),
      ])
      if (cancelled) return
      setEngine(status)
      setNodeCount(nodes ? nodes.length : null)
      setNewAlerts(alertStats?.new ?? 0)
    }

    poll()
    const interval = setInterval(poll, STATUS_POLL_MS)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  // Dismiss the profile menu on Escape, matching the modal's behaviour.
  useEffect(() => {
    if (!profileOpen) return undefined
    const onKey = (e) => { if (e.key === 'Escape') setProfileOpen(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [profileOpen])

  const page = NAV.find((n) => n.to === location.pathname)

  return (
    <div className="flex h-screen overflow-hidden bg-void">
      {railOpen && (
        <div
          className="fixed inset-0 z-20 bg-void/80 lg:hidden"
          onClick={() => setRailOpen(false)}
          role="presentation"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-30 flex w-56 flex-col border-r border-rule-soft bg-panel transition-transform duration-200 lg:static lg:translate-x-0 ${
          railOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-rule-soft px-4">
          <Mark className="h-[22px] w-[22px] text-signal" />
          <span className="font-display text-[17px] font-semibold leading-none tracking-tight text-bone">
            HoneySentinel
          </span>
          <button
            type="button"
            onClick={() => setRailOpen(false)}
            className="ml-auto text-bone-mute hover:text-bone lg:hidden"
            aria-label="Close menu"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto p-2">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              // Closing the rail here rather than in an effect on the path:
              // it is a response to the tap, so it belongs in the handler and
              // costs no extra render pass.
              onClick={() => setRailOpen(false)}
              className={({ isActive }) =>
                `relative flex items-center gap-2.5 rounded-[2px] px-2.5 py-2 font-display text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-raised text-bone'
                    : 'text-bone-dim hover:bg-raised/60 hover:text-bone'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {/* The active marker is the accent, spent once: a filled
                      bar against the rail rather than a tinted background. */}
                  <span
                    className={`absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r ${
                      isActive ? 'bg-signal' : 'bg-transparent'
                    }`}
                    aria-hidden="true"
                  />
                  <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                  {label}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <EngineReadout engine={engine} nodeCount={nodeCount} />
      </aside>

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-rule-soft bg-panel px-4 lg:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setRailOpen(true)}
              className="text-bone-dim hover:text-bone lg:hidden"
              aria-label="Open menu"
            >
              <Menu className="h-5 w-5" />
            </button>
            <h1 className="truncate text-lg font-semibold leading-none text-bone">
              {page?.label ?? 'Overview'}
            </h1>
          </div>

          <div className="flex items-center gap-1.5">
            <NavLink
              to="/sessions"
              className="relative rounded-[2px] p-2 text-bone-dim transition-colors hover:text-bone"
              aria-label={
                newAlerts > 0
                  ? `${newAlerts} unacknowledged alerts. Go to sessions.`
                  : 'No unacknowledged alerts'
              }
            >
              <Bell className="h-[18px] w-[18px]" strokeWidth={1.75} />
              {newAlerts > 0 && (
                <span className="readout absolute right-0.5 top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-sev-critical px-1 text-[10px] font-semibold text-bone">
                  {newAlerts > 99 ? '99+' : newAlerts}
                </span>
              )}
            </NavLink>

            <div className="relative" ref={profileRef}>
              <button
                type="button"
                onClick={() => setProfileOpen((open) => !open)}
                aria-expanded={profileOpen}
                aria-haspopup="menu"
                className="flex items-center gap-2 rounded-[2px] border border-rule px-2 py-1.5 transition-colors hover:border-bone-mute"
              >
                <span className="readout flex h-5 w-5 shrink-0 items-center justify-center rounded-[2px] bg-signal text-[11px] font-semibold text-void">
                  {user?.email?.[0]?.toUpperCase() || '?'}
                </span>
                <span className="hidden max-w-[140px] truncate font-display text-[13px] text-bone-dim sm:block">
                  {user?.email || ''}
                </span>
                <ChevronDown className="h-3.5 w-3.5 shrink-0 text-bone-mute" />
              </button>

              {profileOpen && (
                <>
                  <div
                    className="fixed inset-0 z-40"
                    onClick={() => setProfileOpen(false)}
                    role="presentation"
                  />
                  <div
                    role="menu"
                    className="panel absolute right-0 z-50 mt-1.5 w-60 shadow-2xl shadow-void/60"
                  >
                    <div className="border-b border-rule-soft px-3.5 py-3">
                      <p className="font-display text-xs text-bone-mute">Signed in as</p>
                      <p className="readout mt-0.5 truncate text-[13px] text-bone">
                        {user?.email}
                      </p>
                      <span className="tag mt-2 capitalize" style={{ color: 'var(--color-signal)' }}>
                        {user?.role || 'analyst'}
                      </span>
                    </div>
                    <div className="p-1.5">
                      <button
                        type="button"
                        role="menuitem"
                        onClick={() => { logout(); setProfileOpen(false) }}
                        className="flex w-full items-center gap-2 rounded-[2px] px-2.5 py-2 font-display text-sm font-medium text-bone-dim transition-colors hover:bg-raised hover:text-sev-critical"
                      >
                        <LogOut className="h-4 w-4" strokeWidth={1.75} />
                        Sign out
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
