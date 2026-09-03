import { CATEGORY_COLOR, CATEGORY_LABEL, SEVERITY_COLOR, SEVERITY_ORDER } from '../lib/severity'

/*
 * Severity is the console's primary reading, so it gets a calibrated scale
 * rather than a coloured chip: four ticks filled to the level. Position
 * carries the magnitude and colour reinforces it, which keeps the reading
 * intact for a red-green colourblind analyst — the case where high and
 * critical are hardest to tell apart by hue.
 */

export function SeverityRail({ level, showLabel = true }) {
  const index = SEVERITY_ORDER.indexOf(level)
  const color = SEVERITY_COLOR[level] || 'var(--color-paper-3)'

  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap">
      <span
        className="inline-flex items-end gap-[2px]"
        role="img"
        aria-label={
          index === -1 ? 'Severity not rated' : `Severity ${index + 1} of 4, ${level}`
        }
      >
        {SEVERITY_ORDER.map((step, i) => (
          <span
            key={step}
            className="w-[3px] rounded-[1px]"
            style={{
              // Ticks grow along the scale, so the rail reads as a ramp
              // before colour is perceived at all.
              height: `${5 + i * 2.5}px`,
              background: i <= index ? color : 'var(--color-line-2)',
            }}
          />
        ))}
      </span>
      {showLabel && (
        <span
          className="text-[13px] font-medium capitalize leading-none"
          style={{ color: index === -1 ? 'var(--color-paper-3)' : color }}
        >
          {level || 'unrated'}
        </span>
      )}
    </span>
  )
}

/** Category label. Shares the severity ramp, ordered benign to exfiltration. */
export function CategoryTag({ category }) {
  const color = CATEGORY_COLOR[category] || CATEGORY_COLOR.unknown

  return (
    <span className="tag" style={{ color }}>
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: color }}
        aria-hidden="true"
      />
      <span style={{ color: 'var(--color-paper)' }}>
        {CATEGORY_LABEL[category] || CATEGORY_LABEL.unknown}
      </span>
    </span>
  )
}
