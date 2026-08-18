import { useCallback, useEffect, useMemo, useState } from 'react'
import { CircleMarker, MapContainer, Popup, TileLayer, Tooltip } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { MapPinOff } from 'lucide-react'
import { api } from '../services/api'
import ErrorBanner from '../components/ErrorBanner'

const SEVERITY_CONFIG = {
  critical: { color: '#f85149', radius: 10, opacity: 0.9 },
  high: { color: '#e3692a', radius: 8, opacity: 0.8 },
  medium: { color: '#58a6ff', radius: 6, opacity: 0.7 },
  low: { color: '#3fb950', radius: 4, opacity: 0.6 },
}

const FILTERS = ['all', 'critical', 'high', 'medium', 'low']
const REFRESH_MS = 10000

export default function LiveMap() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')

  const fetchEvents = useCallback(async () => {
    try {
      setEvents((await api.dashboard.liveEvents(200)) || [])
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    // Deferred so the effect body performs no synchronous state update.
    const timer = setTimeout(fetchEvents, 0)
    const interval = setInterval(fetchEvents, REFRESH_MS)
    return () => {
      clearTimeout(timer)
      clearInterval(interval)
    }
  }, [fetchEvents])

  // An event is mappable only when geolocation actually resolved. Sessions
  // without a location are counted separately rather than silently dropped.
  const locatable = useMemo(
    () =>
      events.filter(
        (e) => typeof e.geo_lat === 'number' && typeof e.geo_lon === 'number',
      ),
    [events],
  )

  // Counts per severity are computed once over the whole set, so each filter
  // button shows its own total. The button label previously interpolated an
  // object and rendered "[object Object]" on every severity chip.
  const countsBySeverity = useMemo(() => {
    const counts = { all: locatable.length }
    for (const key of Object.keys(SEVERITY_CONFIG)) counts[key] = 0
    for (const event of locatable) {
      if (event.severity in counts) counts[event.severity] += 1
    }
    return counts
  }, [locatable])

  const visible = useMemo(
    () => (filter === 'all' ? locatable : locatable.filter((e) => e.severity === filter)),
    [locatable, filter],
  )

  const unlocatable = events.length - locatable.length

  return (
    <div className="space-y-4">
      {error && <ErrorBanner message={error} onRetry={fetchEvents} />}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-4">
          <span className="text-xs font-mono text-gray-400">
            {visible.length} of {events.length} events mapped
          </span>
          <div className="flex flex-wrap gap-2">
            {FILTERS.map((key) => (
              <button
                key={key}
                type="button"
                aria-pressed={filter === key}
                onClick={() => setFilter(key)}
                className={`px-3 py-1 text-xs font-mono rounded-full border transition-all capitalize ${
                  filter === key
                    ? 'bg-surface-600 border-border text-white'
                    : 'border-border/50 text-gray-500 hover:text-gray-300'
                }`}
              >
                {key} ({countsBySeverity[key] ?? 0})
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => (
            <div key={sev} className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cfg.color }} />
              <span className="text-[10px] font-mono text-gray-500 uppercase">{sev}</span>
            </div>
          ))}
        </div>
      </div>

      {unlocatable > 0 && (
        <div className="flex items-center gap-2 text-xs font-mono text-gray-500 bg-surface-800 border border-border rounded-lg px-3 py-2">
          <MapPinOff className="w-3.5 h-3.5 shrink-0" />
          {unlocatable} event{unlocatable === 1 ? '' : 's'} could not be
          geolocated and {unlocatable === 1 ? 'is' : 'are'} not shown. Configure
          GEOIP_DB_PATH with a MaxMind GeoLite2 database to resolve locations.
        </div>
      )}

      <div className="h-[calc(100vh-14rem)] rounded-xl overflow-hidden border border-border">
        {loading ? (
          <div className="h-full bg-surface-800 flex items-center justify-center">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
              <span className="font-mono text-sm text-gray-400">Loading threat map...</span>
            </div>
          </div>
        ) : (
          <MapContainer
            center={[20, 0]}
            zoom={2}
            style={{ height: '100%', width: '100%', background: '#0d1117' }}
            worldCopyJump
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://carto.com/">CARTO</a> &copy; OpenStreetMap contributors'
            />

            {visible.map((event) => {
              const cfg = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.low
              return (
                <CircleMarker
                  key={event.session_uuid}
                  center={[event.geo_lat, event.geo_lon]}
                  radius={cfg.radius}
                  pathOptions={{
                    color: cfg.color,
                    fillColor: cfg.color,
                    fillOpacity: cfg.opacity,
                    weight: 1,
                  }}
                >
                  <Tooltip direction="top" offset={[0, -10]}>
                    <div className="font-mono text-xs">
                      <div className="font-semibold">{event.attacker_ip}</div>
                      <div>{event.geo_country_name || event.geo_country || 'Unknown'}</div>
                    </div>
                  </Tooltip>
                  <Popup>
                    <div className="font-mono text-xs space-y-1">
                      <div className="font-semibold">{event.attacker_ip}</div>
                      <div>Country: {event.geo_country_name || event.geo_country || 'Unknown'}</div>
                      <div>Protocol: {event.protocol || 'unknown'}</div>
                      <div>Category: {event.attack_category || 'unclassified'}</div>
                      <div>
                        Severity: <span style={{ color: cfg.color }}>{event.severity}</span>
                      </div>
                      <div>{new Date(event.timestamp).toLocaleString()}</div>
                    </div>
                  </Popup>
                </CircleMarker>
              )
            })}
          </MapContainer>
        )}
      </div>
    </div>
  )
}
