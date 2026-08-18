import { AlertCircle, RefreshCw } from 'lucide-react'

/** Surfaces a failed request to the user instead of only the console. */
export default function ErrorBanner({ message, onRetry }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 bg-accent-red/10 border border-accent-red/30 rounded-xl px-4 py-3"
    >
      <AlertCircle className="w-4 h-4 text-accent-red mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-mono text-accent-red font-semibold">
          Could not load data
        </p>
        <p className="text-xs font-mono text-gray-400 mt-0.5 break-words">{message}</p>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="flex items-center gap-1.5 text-xs font-mono text-accent-red hover:underline shrink-0"
        >
          <RefreshCw className="w-3 h-3" />
          Retry
        </button>
      )}
    </div>
  )
}
