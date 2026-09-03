/*
 * Threat vocabulary.
 *
 * Severity and category share one cool-to-hot ramp, because they answer the
 * same question at different resolutions: how bad is this. Nothing else in
 * the interface is allowed a saturated colour, so a hue on screen always
 * means threat level and never decoration.
 *
 * Kept free of JSX so any module can import the scale, and so fast refresh
 * keeps working for the components that render it.
 */

/** Ascending. Index here is the magnitude the rail draws. */
export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']

export const SEVERITY_COLOR = {
  low: 'var(--color-s1)',
  medium: 'var(--color-s2)',
  high: 'var(--color-s3)',
  critical: 'var(--color-s4)',
}

/** Categories map onto the same ramp, ordered benign → exfiltration. */
export const CATEGORY_COLOR = {
  benign: 'var(--color-s1)',
  reconnaissance: 'var(--color-s2)',
  exploitation: 'var(--color-s3)',
  exfiltration: 'var(--color-s4)',
  unknown: 'var(--color-paper-3)',
}

export const CATEGORY_LABEL = {
  benign: 'Benign',
  reconnaissance: 'Reconnaissance',
  exploitation: 'Exploitation',
  exfiltration: 'Exfiltration',
  unknown: 'Unclassified',
}

/** Hot first: the proportion bar leads with what matters most. */
export const CATEGORY_ORDER = [
  'exfiltration',
  'exploitation',
  'reconnaissance',
  'benign',
  'unknown',
]

export const PROFILE_LABEL = {
  automated_bot: 'Automated bot',
  script_kiddie: 'Script kiddie',
  skilled_attacker: 'Skilled attacker',
  apt: 'Advanced persistent threat',
  unknown: 'Unknown',
}

export const PROFILE_LABEL_SHORT = {
  automated_bot: 'Bot',
  script_kiddie: 'Script kiddie',
  skilled_attacker: 'Skilled',
  apt: 'APT',
  unknown: 'Unknown',
}

/**
 * Whether a profile implies a person at a keyboard rather than a script.
 * This is the distinction a tier-1 analyst is actually triaging for, so the
 * feed marks it explicitly.
 */
export const HANDS_ON_PROFILES = new Set(['skilled_attacker', 'apt'])

/** Compact relative time. Sessions are read in the minutes after they land. */
export function timeAgo(iso) {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}
