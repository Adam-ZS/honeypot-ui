import { useCallback, useEffect, useMemo, useState } from 'react'
import { CircleMarker, MapContainer, Popup, TileLayer, Tooltip } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { MapPinOff } from 'lucide-react'
import { api } from '../services/api'
import ErrorBanner from '../components/ErrorBanner'
import { LoadingRegion } from '../components/Loading'
import { SEVERITY_ORDER, SEVERITY_COLOR } from '../lib/severity'

const REFRESH_MS = 10000

/**
 * Marker radius follows the severity scale, so the map encodes magnitude by
 * size as well as hue — the same calibration the session table uses.
 */
const MARKER = {
  low: { radius: 4, opacity: 0.55 },
  medium: { radius: 6, opacity: 0.65 },
  high: { radius: 8, opacity: 0.75 },
  critical: { radius: 10, opacity: 0.85 },
}

const FILTERS = ['all', ...SEVERITY_ORDER]

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
    for (const key of SEVERITY_ORDER) counts[key] = 0
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
    <div className="flex h-full flex-col gap-3">
      {error && <ErrorBanner message={error} onRetry={fetchEvents} />}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {FILTERS.map((key) => {
            const isActive = filter === key
            const color = key === 'all' ? 'var(--color-bone)' : SEVERITY_COLOR[key]
            return (
              <button
                key={key}
                type="button"
                aria-pressed={isActive}
                onClick={() => setFilter(key)}
                className="control flex items-center gap-1.5 capitalize"
                style={isActive ? { borderColor: color, background: 'var(--color-raised)' } : undefined}
              >
                {key !== 'all' && (
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ background: color }}
                    aria-hidden="true"
                  />
                )}
                {key === 'all' ? 'All' : key}
                <span className="readout text-[13px] text-bone-mute">
                  {countsBySeverity[key] ?? 0}
                </span>
              </button>
            )
          })}
        </div>

        <p className="text-[13px] text-bone-mute">
          <span className="readout text-bone-dim">{visible.length}</span> of{' '}
          <span className="readout text-bone-dim">{events.length}</span> events plotted
        </p>
      </div>

      {unlocatable > 0 && (
        <div className="flex items-start gap-2.5 rounded-[3px] border border-rule-soft bg-panel px-3.5 py-2.5">
          <MapPinOff className="mt-0.5 h-4 w-4 shrink-0 text-bone-mute" strokeWidth={1.75} />
          <p className="text-[13px] text-bone-dim">
            <span className="readout text-bone">{unlocatable}</span>{' '}
            {unlocatable === 1 ? 'event has' : 'events have'} no location and{' '}
            {unlocatable === 1 ? 'is' : 'are'} not plotted. Point{' '}
            <span className="readout text-bone-dim">GEOIP_DB_PATH</span> at a MaxMind
            GeoLite2 database to resolve them.
          </p>
        </div>
      )}

      <div className="panel min-h-[24rem] flex-1 overflow-hidden">
        {loading ? (
          <LoadingRegion label="Loading origins" className="h-full" />
        ) : (
          <MapContainer
            center={[20, 0]}
            zoom={2}
            minZoom={2}
            style={{ height: '100%', width: '100%' }}
            worldCopyJump
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://carto.com/">CARTO</a> &copy; OpenStreetMap contributors'
            />

            {visible.map((event) => {
              const marker = MARKER[event.severity] || MARKER.low
              const color = SEVERITY_COLOR[event.severity] || 'var(--color-bone-mute)'
              return (
                <CircleMarker
                  key={event.session_uuid}
                  center={[event.geo_lat, event.geo_lon]}
                  radius={marker.radius}
                  pathOptions={{
                    color,
                    fillColor: color,
                    fillOpacity: marker.opacity,
                    weight: 1,
                  }}
                >
                  <Tooltip direction="top" offset={[0, -10]}>
                    <span className="readout text-xs font-semibold">
                      {event.attacker_ip}
                    </span>
                    <br />
                    <span className="text-xs">
                      {event.geo_country_name || event.geo_country || 'Unknown origin'}
                    </span>
                  </Tooltip>
                  <Popup>
                    <div className="min-w-44 space-y-1">
                      <p className="readout text-xs font-semibold">{event.attacker_ip}</p>
                      <p className="text-xs">
                        {event.geo_country_name || event.geo_country || 'Unknown origin'}
                      </p>
                      <p className="text-xs capitalize">
                        {event.protocol || 'unknown'} ·{' '}
                        {event.attack_category || 'unclassified'}
                      </p>
                      <p className="text-xs capitalize" style={{ color }}>
                        {event.severity} severity
                      </p>
                      <p className="readout text-[11px] opacity-70">
                        {new Date(event.timestamp).toLocaleString()}
                      </p>
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
