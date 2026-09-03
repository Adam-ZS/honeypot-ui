import { RotateCw } from 'lucide-react'

/**
 * Surfaces a failed request instead of leaving it in the console. Says what
 * broke and offers the one action that might fix it — no apology, no
 * generic "something went wrong".
 */
export default function ErrorBanner({ message, onRetry }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-[3px] border border-sev-critical/50 bg-sev-critical/10 px-4 py-3"
    >
      <span
        className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-sev-critical"
        aria-hidden="true"
      />
      <div className="min-w-0 flex-1">
        <p className="font-display text-sm font-semibold text-bone">
          Could not load this data
        </p>
        <p className="readout mt-0.5 text-[13px] break-words text-bone-dim">{message}</p>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="control flex shrink-0 items-center gap-1.5"
        >
          <RotateCw className="h-3.5 w-3.5" strokeWidth={2} />
          Try again
        </button>
      )}
    </div>
  )
}
