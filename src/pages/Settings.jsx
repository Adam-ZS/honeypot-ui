import { useState, useEffect, useCallback } from 'react'
import { Mail, Plus, Trash2, Webhook } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import ErrorBanner from '../components/ErrorBanner'
import EmptyState from '../components/EmptyState'
import { LoadingRegion } from '../components/Loading'
import { SeverityRail } from '../components/Severity'
import { SEVERITY_ORDER } from '../lib/severity'

const BLANK_THRESHOLD = {
  name: '',
  min_severity: 'medium',
  anomaly_score_threshold: 0.7,
  email_enabled: true,
  webhook_enabled: false,
}

function Panel({ title, description, action, children }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2 className="text-base font-semibold text-bone">{title}</h2>
          {description && (
            <p className="mt-0.5 max-w-xl text-[13px] text-bone-mute">{description}</p>
          )}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

/** Checkbox with its label, used for the two delivery channels. */
function Toggle({ checked, onChange, disabled, icon: Icon, children }) {
  return (
    <label
      className={`flex items-center gap-2 ${disabled ? 'opacity-50' : 'cursor-pointer'}`}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="h-3.5 w-3.5 accent-signal"
      />
      <span className="flex items-center gap-1.5 font-display text-[13px] font-medium text-bone-dim">
        <Icon className="h-3.5 w-3.5" strokeWidth={1.75} />
        {children}
      </span>
    </label>
  )
}

/** Shared editor for both creating and editing a threshold. */
function ThresholdForm({ value, onChange, onSubmit, onCancel, submitLabel }) {
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="flex flex-col gap-1">
          <span className="label">Name</span>
          <input
            type="text"
            value={value.name}
            placeholder="Critical only"
            onChange={(e) => onChange({ ...value, name: e.target.value })}
            className="field"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="label">Alert at or above</span>
          <select
            value={value.min_severity}
            onChange={(e) => onChange({ ...value, min_severity: e.target.value })}
            className="control capitalize"
          >
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="label">Anomaly score above</span>
          <input
            type="number"
            step="0.05"
            min="0"
            max="1"
            value={value.anomaly_score_threshold}
            onChange={(e) =>
              onChange({
                ...value,
                anomaly_score_threshold: Number.isFinite(parseFloat(e.target.value))
                  ? parseFloat(e.target.value)
                  : 0,
              })
            }
            className="field"
          />
        </label>
      </div>

      <div className="flex flex-wrap items-center gap-5">
        <Toggle
          checked={value.email_enabled}
          onChange={(v) => onChange({ ...value, email_enabled: v })}
          icon={Mail}
        >
          Email
        </Toggle>
        <Toggle
          checked={value.webhook_enabled}
          onChange={(v) => onChange({ ...value, webhook_enabled: v })}
          icon={Webhook}
        >
          Webhook
        </Toggle>
      </div>

      <div className="flex items-center gap-2 pt-1">
        <button
          type="button"
          onClick={onSubmit}
          disabled={!value.name.trim()}
          className="control control-primary"
        >
          {submitLabel}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="font-display text-[13px] font-medium text-bone-dim transition-colors hover:text-bone"
        >
          Cancel
        </button>
      </div>
    </div>
  )
}

function ThresholdRow({ threshold, onUpdate, onDelete, canEdit }) {
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState(threshold)

  const startEditing = () => {
    setForm(threshold)
    setEditing(true)
  }

  const save = async () => {
    await onUpdate(threshold.id, form)
    setEditing(false)
  }

  if (editing) {
    return (
      <div className="border-b border-rule-soft p-4 last:border-0">
        <ThresholdForm
          value={form}
          onChange={setForm}
          onSubmit={save}
          onCancel={() => setEditing(false)}
          submitLabel="Save changes"
        />
      </div>
    )
  }

  const channels = [
    threshold.email_enabled && 'Email',
    threshold.webhook_enabled && 'Webhook',
  ].filter(Boolean)

  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-rule-soft px-4 py-3 last:border-0">
      <div className="min-w-40 flex-1">
        <p className="font-display text-sm font-semibold text-bone">{threshold.name}</p>
        <p className="mt-0.5 text-[13px] text-bone-mute">
          {channels.length ? `Notifies by ${channels.join(' and ').toLowerCase()}` : 'No delivery channel selected'}
        </p>
      </div>

      <div>
        <p className="label">At or above</p>
        <div className="mt-1">
          <SeverityRail level={threshold.min_severity} />
        </div>
      </div>

      <div>
        <p className="label">Anomaly above</p>
        <p className="readout mt-1 text-sm text-bone">
          {threshold.anomaly_score_threshold}
        </p>
      </div>

      <div className="flex items-center gap-3">
        <span
          className="tag"
          style={{
            color: threshold.is_active
              ? 'var(--color-sev-low)'
              : 'var(--color-bone-mute)',
          }}
        >
          {threshold.is_active ? 'Active' : 'Paused'}
        </span>
        {canEdit && (
          <>
            <button
              type="button"
              onClick={startEditing}
              className="font-display text-[13px] font-medium text-bone-dim transition-colors hover:text-signal"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={() => onDelete(threshold.id)}
              aria-label={`Delete ${threshold.name}`}
              className="text-bone-mute transition-colors hover:text-sev-critical"
            >
              <Trash2 className="h-4 w-4" strokeWidth={1.75} />
            </button>
          </>
        )}
      </div>
    </div>
  )
}

export default function Settings() {
  const { hasRole } = useAuth()
  const isAdmin = hasRole('admin')
  const [error, setError] = useState(null)
  const [thresholds, setThresholds] = useState([])
  const [systemConfig, setSystemConfig] = useState(null)
  const [honeypotMode, setHoneypotMode] = useState('active')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newThreshold, setNewThreshold] = useState(BLANK_THRESHOLD)

  const fetchData = useCallback(async () => {
    try {
      const [thresholdsData, configData] = await Promise.all([
        api.settings.thresholds(),
        api.settings.systemConfig(),
      ])
      setThresholds(thresholdsData || [])
      setSystemConfig(configData)
      setHoneypotMode(configData?.honeypot_mode || 'active')
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    // Deferred so no state update happens synchronously in the effect body.
    const timer = setTimeout(fetchData, 0)
    return () => clearTimeout(timer)
  }, [fetchData])

  const run = async (action) => {
    try {
      await action()
      setError(null)
      await fetchData()
      return true
    } catch (err) {
      setError(err.message)
      return false
    }
  }

  const handleUpdateThreshold = (id, data) =>
    run(() => api.settings.updateThreshold(id, data))

  const handleDeleteThreshold = (id) => {
    // Deleting a threshold silently stops alert delivery, so confirm first.
    if (!window.confirm('Delete this threshold? Alerts matching it will stop being delivered.')) {
      return Promise.resolve(false)
    }
    return run(() => api.settings.deleteThreshold(id))
  }

  const handleCreateThreshold = async () => {
    if (!newThreshold.name.trim()) return
    const ok = await run(() => api.settings.createThreshold(newThreshold))
    if (!ok) return
    setNewThreshold(BLANK_THRESHOLD)
    setCreating(false)
  }

  const handleUpdateMode = async () => {
    setSaving(true)
    await run(() => api.settings.updateSystemConfig({ honeypot_mode: honeypotMode }))
    setSaving(false)
  }

  if (loading) return <LoadingRegion label="Loading settings" className="py-24" />

  const modeChanged = honeypotMode !== (systemConfig?.honeypot_mode || 'active')

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      {error && <ErrorBanner message={error} onRetry={fetchData} />}

      {!isAdmin && (
        <div className="rounded-[3px] border border-rule-soft bg-panel px-4 py-3">
          <p className="text-[13px] text-bone-dim">
            You have read-only access. Changing the emulation mode or alert
            thresholds needs an administrator account.
          </p>
        </div>
      )}

      <Panel
        title="Emulation mode"
        description="How the honeypot responds to whoever connects to it."
      >
        <div className="p-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              {
                value: 'active',
                label: 'Active',
                desc: 'Answers connections, records the full session and every command.',
              },
              {
                value: 'passive',
                label: 'Passive',
                desc: 'Logs connection attempts only. Nothing is answered.',
              },
            ].map((mode) => {
              const selected = honeypotMode === mode.value
              return (
                <button
                  key={mode.value}
                  type="button"
                  disabled={!isAdmin}
                  onClick={() => setHoneypotMode(mode.value)}
                  aria-pressed={selected}
                  className={`rounded-[3px] border p-3.5 text-left transition-colors ${
                    selected
                      ? 'border-signal bg-raised'
                      : 'border-rule bg-void hover:border-bone-mute'
                  } ${!isAdmin ? 'cursor-not-allowed opacity-60' : ''}`}
                >
                  <span className="flex items-center gap-2">
                    <span
                      className={`h-2.5 w-2.5 shrink-0 rounded-full border-2 ${
                        selected ? 'border-signal bg-signal' : 'border-bone-mute'
                      }`}
                      aria-hidden="true"
                    />
                    <span className="font-display text-sm font-semibold text-bone">
                      {mode.label}
                    </span>
                  </span>
                  <span className="mt-1.5 block text-[13px] leading-relaxed text-bone-mute">
                    {mode.desc}
                  </span>
                </button>
              )
            })}
          </div>

          <div className="mt-3 flex items-center gap-3">
            <button
              type="button"
              onClick={handleUpdateMode}
              disabled={saving || !isAdmin || !modeChanged}
              className="control control-primary"
            >
              {saving ? 'Saving…' : 'Save mode'}
            </button>
            {modeChanged && !saving && (
              <span className="text-[13px] text-bone-mute">Unsaved change</span>
            )}
          </div>
        </div>

        <dl className="grid grid-cols-2 divide-rule-soft border-t border-rule-soft sm:grid-cols-3 sm:divide-x">
          <div className="px-4 py-3">
            <dt className="label">Registered nodes</dt>
            <dd className="readout mt-1 text-sm text-bone">
              {systemConfig?.active_nodes ?? 0}
            </dd>
          </div>
          <div className="px-4 py-3">
            <dt className="label">Protocols</dt>
            <dd className="readout mt-1 text-sm uppercase text-bone">
              {systemConfig?.protocols?.length
                ? systemConfig.protocols.join(' · ')
                : 'None'}
            </dd>
          </div>
          <div className="px-4 py-3">
            <dt className="label">Running as</dt>
            <dd className="readout mt-1 text-sm capitalize text-bone">
              {systemConfig?.honeypot_mode || 'active'}
            </dd>
          </div>
        </dl>
      </Panel>

      <Panel
        title="Alert thresholds"
        description="Rules that decide which detections are worth notifying someone about."
        action={
          isAdmin && (
            <button
              type="button"
              onClick={() => setCreating((open) => !open)}
              className="control flex shrink-0 items-center gap-1.5"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={2} />
              New threshold
            </button>
          )
        }
      >
        {creating && (
          <div className="border-b border-rule-soft bg-void/40 p-4">
            <ThresholdForm
              value={newThreshold}
              onChange={setNewThreshold}
              onSubmit={handleCreateThreshold}
              onCancel={() => { setCreating(false); setNewThreshold(BLANK_THRESHOLD) }}
              submitLabel="Create threshold"
            />
          </div>
        )}

        {thresholds.length > 0 ? (
          <div>
            {thresholds.map((t) => (
              <ThresholdRow
                key={t.id}
                threshold={t}
                canEdit={isAdmin}
                onUpdate={handleUpdateThreshold}
                onDelete={handleDeleteThreshold}
              />
            ))}
          </div>
        ) : (
          <EmptyState
            title="No thresholds yet"
            hint={
              isAdmin
                ? 'Create one to start receiving alerts about what the honeypot catches.'
                : 'An administrator can create one to start alert delivery.'
            }
          />
        )}
      </Panel>

      <Panel
        title="Integration"
        description="Where to point a SIEM or threat intelligence platform."
      >
        <dl className="divide-y divide-rule-soft">
          <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
            <dt className="label">API endpoint</dt>
            <dd className="readout text-[13px] break-all text-bone">
              {import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'}
            </dd>
          </div>
          <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
            <dt className="label">Export formats</dt>
            {/* JSON, CEF and STIX 2.1 are what the export route actually
                serves. This previously advertised TAXII, which is not
                implemented anywhere in the backend. */}
            <dd className="readout text-[13px] text-bone">JSON · CEF · STIX 2.1</dd>
          </div>
          <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
            <dt className="label">Alert delivery</dt>
            <dd className="readout text-[13px] text-bone">Email · Signed webhook</dd>
          </div>
        </dl>
      </Panel>
    </div>
  )
}
