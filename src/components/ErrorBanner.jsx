import { RotateCw } from 'lucide-react'

/**
 * Surfaces a failed request instead of leaving it in the console. Says what
 * broke and offers the one action that might fix it — no apology, no vague
 * "something went wrong".
 */
export default function ErrorBanner({ message, onRetry }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-[4px] border border-s4/50 bg-ink-1 px-4 py-3"
    >
      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-s4" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <p className="text-[13px] font-semibold text-paper">Could not load this data</p>
        <p className="readout mt-0.5 text-[13px] break-words text-paper-2">{message}</p>
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className="control shrink-0">
          <RotateCw className="h-3.5 w-3.5" strokeWidth={2} />
          Try again
        </button>
      )}
    </div>
  )
}
