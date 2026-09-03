import { useEffect, useRef } from 'react'
import { ExternalLink, X } from 'lucide-react'
import { CategoryTag } from './Severity'
import { PROFILE_LABEL } from '../lib/severity'

function percent(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '—'
}


/** A labelled value. Mono on the value only — the label is chrome, not data. */
function Fact({ label, children, mono = true }) {
  return (
    <div className="min-w-0">
      <dt className="label">{label}</dt>
      <dd className={`mt-0.5 truncate text-sm text-bone ${mono ? 'readout' : ''}`}>
        {children}
      </dd>
    </div>
  )
}

function Section({ title, note, children }) {
  return (
    <section className="border-t border-rule-soft px-5 py-4">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="font-display text-sm font-semibold text-bone">{title}</h3>
        {note && <span className="text-xs text-bone-mute">{note}</span>}
      </div>
      <div className="mt-3">{children}</div>
    </section>
  )
}

export default function SessionDetailModal({ session, onClose }) {
  const closeButtonRef = useRef(null)

  // Escape-to-close and initial focus: the modal was mouse-only, so keyboard
  // users could neither reach nor dismiss it.
  useEffect(() => {
    if (!session) return undefined
    const onKeyDown = (event) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    closeButtonRef.current?.focus()
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [session, onClose])

  // Restore page scrolling when the dialog owns the viewport.
  useEffect(() => {
    if (!session) return undefined
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = previous }
  }, [session])

  if (!session) return null

  const techniques = session.mitre_techniques || []
  const tactics = session.mitre_tactics || []
  const tools = session.detected_tools || []
  const intents = session.detected_intents || []

  const duration =
    typeof session.duration_seconds === 'number'
      ? session.duration_seconds < 60
        ? `${session.duration_seconds.toFixed(1)}s`
        : `${Math.floor(session.duration_seconds / 60)}m ${Math.round(session.duration_seconds % 60)}s`
      : 'In progress'

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-void/85 p-4 sm:items-center"
      onClick={onClose}
      role="presentation"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Session ${session.session_uuid}`}
        className="panel my-auto w-full max-w-3xl shadow-2xl shadow-void"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-start justify-between gap-4 px-5 py-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="readout text-lg font-semibold text-bone">
                {session.attacker_ip}
              </h2>
              <CategoryTag category={session.attack_category} />
              {session.is_anomalous && (
                <span className="tag" style={{ color: 'var(--color-sev-critical)' }}>
                  Anomalous
                </span>
              )}
            </div>
            <p className="readout mt-1 truncate text-xs text-bone-mute">
              {session.session_uuid}
            </p>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="Close session details"
            className="shrink-0 rounded-[2px] p-1.5 text-bone-dim transition-colors hover:text-bone"
          >
            <X className="h-5 w-5" strokeWidth={1.75} />
          </button>
        </header>

        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-t border-rule-soft px-5 py-4 sm:grid-cols-4">
          <Fact label="Origin" mono={false}>
            {session.geo?.country_name || session.geo?.country || 'Unknown'}
          </Fact>
          <Fact label="Protocol">
            <span className="uppercase">{session.protocol || '—'}</span>
          </Fact>
          <Fact label="Duration">{duration}</Fact>
          <Fact label="Status" mono={false}>
            <span className="capitalize">{session.status}</span>
          </Fact>
        </dl>

        <Section
          title="Model verdict"
          note={session.model_source === 'synthetic' ? 'Bootstrap model' : undefined}
        >
          <dl className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
            <Fact label="Category" mono={false}>
              <span className="capitalize">{session.attack_category || 'Unclassified'}</span>
            </Fact>
            <Fact label="Confidence">{percent(session.attack_confidence)}</Fact>
            <Fact label="Anomaly score">
              {typeof session.anomaly_score === 'number'
                ? session.anomaly_score.toFixed(3)
                : '—'}
            </Fact>
            <Fact label="Profile" mono={false}>
              {PROFILE_LABEL[session.attacker_profile] || PROFILE_LABEL.unknown}
            </Fact>
          </dl>
        </Section>

        <Section
          title="Command analysis"
          note={`${session.command_count ?? 0} ${session.command_count === 1 ? 'command' : 'commands'}`}
        >
          <div className="space-y-3">
            <div>
              <p className="label">Tools detected</p>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {tools.length ? (
                  tools.map((tool) => (
                    <span
                      key={tool}
                      className="tag"
                      style={{ color: 'var(--color-sev-high)' }}
                    >
                      {tool}
                    </span>
                  ))
                ) : (
                  <span className="text-[13px] text-bone-mute">None</span>
                )}
              </div>
            </div>
            <div>
              <p className="label">Intents</p>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {intents.length ? (
                  intents.map((intent) => (
                    <span
                      key={intent}
                      className="tag capitalize"
                      style={{ color: 'var(--color-cat-recon)' }}
                    >
                      {intent.replace(/_/g, ' ')}
                    </span>
                  ))
                ) : (
                  <span className="text-[13px] text-bone-mute">None</span>
                )}
              </div>
            </div>
          </div>
        </Section>

        {(techniques.length > 0 || tactics.length > 0) && (
          <Section
            title="MITRE ATT&CK"
            note={tactics.length ? tactics.map((t) => t.name).join(' · ') : undefined}
          >
            <ul className="flex flex-wrap gap-1.5">
              {techniques.map((technique) => (
                <li key={technique.id}>
                  <a
                    href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="tag transition-colors hover:border-signal"
                    style={{ color: 'var(--color-bone-dim)' }}
                  >
                    <span className="readout" style={{ color: 'var(--color-signal)' }}>
                      {technique.id}
                    </span>
                    {technique.name}
                    <ExternalLink className="h-3 w-3 opacity-60" strokeWidth={2} />
                  </a>
                </li>
              ))}
            </ul>
          </Section>
        )}

        {session.uploaded_files?.length > 0 && (
          <Section title="Files uploaded" note={`${session.uploaded_files.length}`}>
            <ul className="space-y-1">
              {session.uploaded_files.map((file) => (
                <li key={file} className="readout text-[13px] break-all text-bone-dim">
                  {file}
                </li>
              ))}
            </ul>
          </Section>
        )}
      </div>
    </div>
  )
}
