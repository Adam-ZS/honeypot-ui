import { useEffect, useRef } from 'react'
import { AlertTriangle, Clock, FileBox, Globe, Shield, Terminal, X } from 'lucide-react'

function percent(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '—'
}

function fixed(value, digits = 4) {
  return typeof value === 'number' ? value.toFixed(digits) : '—'
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

  if (!session) return null

  const techniques = session.mitre_techniques || []
  const tools = session.detected_tools || []
  const intents = session.detected_intents || []

  const facts = [
    { label: 'Attacker IP', value: session.attacker_ip, icon: Globe },
    {
      label: 'Country',
      value: session.geo?.country_name || session.geo?.country || 'Unknown',
      icon: Globe,
    },
    {
      label: 'Duration',
      value:
        typeof session.duration_seconds === 'number'
          ? `${session.duration_seconds.toFixed(1)}s`
          : 'In progress',
      icon: Clock,
    },
    { label: 'Status', value: session.status, icon: Shield },
  ]

  return (
    <div
      className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4"
      onClick={onClose}
      role="presentation"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Session details"
        className="bg-surface-800 border border-border rounded-xl w-full max-w-3xl max-h-[85vh] overflow-y-auto animate-slide-up"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-surface-800 border-b border-border px-6 py-4 flex items-center justify-between z-10">
          <div className="min-w-0">
            <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
              Session Details
            </h2>
            <p className="text-xs font-mono text-gray-500 mt-0.5 truncate">
              {session.session_uuid}
            </p>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="Close session details"
            className="p-2 text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {facts.map(({ label, value, icon: Icon }) => (
              <div key={label} className="bg-surface-700 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Icon className="w-3.5 h-3.5 text-gray-500" />
                  <span className="text-[10px] font-mono text-gray-500 uppercase">{label}</span>
                </div>
                <p className="text-sm font-mono text-white truncate">{value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3 flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-accent-red" />
                Model Classification
              </h3>
              <dl className="space-y-2">
                {[
                  ['Category', session.attack_category || 'unclassified'],
                  ['Confidence', percent(session.attack_confidence)],
                  ['Anomaly score', fixed(session.anomaly_score)],
                  ['Profile', session.attacker_profile || 'unknown'],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between">
                    <dt className="text-xs font-mono text-gray-500">{label}</dt>
                    <dd className="text-xs font-mono text-white">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>

            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3 flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-accent-cyan" />
                Command Analysis
              </h3>
              <div className="space-y-3">
                <div>
                  <span className="text-[10px] font-mono text-gray-500 uppercase">Detected tools</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {tools.length ? (
                      tools.map((tool) => (
                        <span key={tool} className="text-[10px] font-mono bg-accent-red/10 text-accent-red border border-accent-red/30 px-1.5 py-0.5 rounded">
                          {tool}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs font-mono text-gray-600">None detected</span>
                    )}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] font-mono text-gray-500 uppercase">Intents</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {intents.length ? (
                      intents.map((intent) => (
                        <span key={intent} className="text-[10px] font-mono bg-accent-blue/10 text-accent-blue border border-accent-blue/30 px-1.5 py-0.5 rounded">
                          {intent}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs font-mono text-gray-600">None detected</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {techniques.length > 0 && (
            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3">
                MITRE ATT&amp;CK Techniques
              </h3>
              <div className="flex flex-wrap gap-2">
                {techniques.map((technique) => (
                  <a
                    key={technique.id}
                    href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-xs font-mono bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30 px-2 py-1 rounded hover:bg-accent-cyan/20 transition-colors"
                  >
                    {technique.id}: {technique.name}
                  </a>
                ))}
              </div>
            </div>
          )}

          {session.uploaded_files?.length > 0 && (
            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3 flex items-center gap-2">
                <FileBox className="w-3.5 h-3.5" />
                Uploaded Files
              </h3>
              <ul className="space-y-1">
                {session.uploaded_files.map((file) => (
                  <li key={file} className="text-xs font-mono text-gray-300 break-all">
                    {file}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
