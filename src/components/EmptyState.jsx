/**
 * An empty screen is an invitation, not an apology. Each use says what would
 * put something here.
 */
export default function EmptyState({ title, hint, action }) {
  return (
    <div className="px-4 py-14 text-center">
      {/* An empty cell — what the console is actually reporting. */}
      <svg
        viewBox="0 0 32 32"
        className="mx-auto h-7 w-7 text-line-2"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M16 3.5 27.5 10v13L16 29.5 4.5 23V10L16 3.5Z"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeDasharray="3 3"
        />
      </svg>
      <p className="mt-3.5 font-display text-[15px] font-semibold text-paper-2">{title}</p>
      {hint && (
        <p className="mx-auto mt-1 max-w-xs text-[13px] leading-relaxed text-paper-3">
          {hint}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
