/*
 * One loading treatment for the whole console, so a slow request looks the
 * same wherever it happens.
 */
export function Spinner({ label = 'Loading' }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <span
        className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-rule border-t-signal"
        aria-hidden="true"
      />
      <span className="font-display text-sm text-bone-dim">{label}</span>
    </span>
  )
}

/** Centred spinner for a whole panel or page region. */
export function LoadingRegion({ label, className = 'py-16' }) {
  return (
    <div className={`flex items-center justify-center ${className}`} role="status">
      <Spinner label={label} />
    </div>
  )
}

/**
 * Placeholder blocks matching the shape of what is about to arrive, so the
 * layout does not jump when it does.
 */
export function SkeletonBlock({ className = '' }) {
  return (
    <div
      className={`animate-pulse rounded-[3px] border border-rule-soft bg-panel ${className}`}
      aria-hidden="true"
    />
  )
}
