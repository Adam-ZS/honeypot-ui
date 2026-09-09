/* One loading treatment for the whole console, so a slow request looks the
   same wherever it happens. */
export function Spinner({ label = 'Loading' }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <span
        className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-line-2 border-t-paper"
        aria-hidden="true"
      />
      <span className="text-[13px] text-paper-2">{label}</span>
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

/** Placeholder matching the shape of what is arriving, so nothing jumps. */
export function SkeletonBlock({ className = '' }) {
  return (
    <div
      className={`animate-pulse rounded-[4px] border border-line bg-ink-1 ${className}`}
      aria-hidden="true"
    />
  )
}
