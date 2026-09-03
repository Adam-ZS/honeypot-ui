import { CATEGORY_COLOR, CATEGORY_LABEL, SEVERITY_COLOR, SEVERITY_ORDER } from '../lib/severity'

/*
 * Severity is the console's primary reading, so it gets a calibrated scale
 * rather than a coloured chip: four ticks filled to the level, which stays
 * legible when hue alone does not (colour-vision deficiency, a projector, a
 * printed export). Position carries the magnitude; colour reinforces it.
 */

/**
 * The four-tick scale. `level` is one of SEVERITY_ORDER; anything else
 * renders an empty rail, which reads correctly as "not rated".
 */
export function SeverityRail({ level, showLabel = true }) {
  const index = SEVERITY_ORDER.indexOf(level)
  const color = SEVERITY_COLOR[level] || 'var(--color-bone-mute)'

  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <span
        className="inline-flex items-end gap-[2px]"
        role="img"
        aria-label={
          index === -1
            ? 'Severity not rated'
            : `Severity ${index + 1} of 4, ${level}`
        }
      >
        {SEVERITY_ORDER.map((step, i) => (
          <span
            key={step}
            className="w-[3px] rounded-[1px]"
            style={{
              // Ticks grow with the scale, so the rail reads as a ramp even
              // before colour is perceived.
              height: `${5 + i * 2}px`,
              background: i <= index ? color : 'var(--color-rule)',
            }}
          />
        ))}
      </span>
      {showLabel && (
        <span
          className="font-display text-[13px] font-medium capitalize leading-none"
          style={{ color: index === -1 ? 'var(--color-bone-mute)' : color }}
        >
          {level || 'unrated'}
        </span>
      )}
    </span>
  )
}

/** Category label with its own dot. Never coloured like severity. */
export function CategoryTag({ category }) {
  const color = (category && CATEGORY_COLOR[category]) || 'var(--color-bone-mute)'

  return (
    <span className="tag" style={{ color }}>
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: color }}
        aria-hidden="true"
      />
      <span style={{ color: 'var(--color-bone)' }}>
        {CATEGORY_LABEL[category] || CATEGORY_LABEL.unknown}
      </span>
    </span>
  )
}
