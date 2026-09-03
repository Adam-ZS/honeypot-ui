/*
 * Severity and category vocabulary.
 *
 * Kept apart from the components that render it so a module can import the
 * scale without importing JSX — and so fast refresh keeps working, which it
 * does not for a file mixing components with plain exports.
 */

/** Ascending. Index in this array is the magnitude the rail draws. */
export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']

export const SEVERITY_COLOR = {
  low: 'var(--color-sev-low)',
  medium: 'var(--color-sev-medium)',
  high: 'var(--color-sev-high)',
  critical: 'var(--color-sev-critical)',
}

/** Attack category is a kind, not a magnitude — labels, not a scale. */
export const CATEGORY_COLOR = {
  benign: 'var(--color-cat-benign)',
  reconnaissance: 'var(--color-cat-recon)',
  exploitation: 'var(--color-cat-exploit)',
  exfiltration: 'var(--color-cat-exfil)',
}

export const CATEGORY_LABEL = {
  benign: 'Benign',
  reconnaissance: 'Reconnaissance',
  exploitation: 'Exploitation',
  exfiltration: 'Exfiltration',
  unknown: 'Unclassified',
}

/** Order the proportion bar by threat rather than count, so it reads consistently. */
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

/** Short forms for the sessions table, where the column is narrow. */
export const PROFILE_LABEL_SHORT = {
  automated_bot: 'Bot',
  script_kiddie: 'Script kiddie',
  skilled_attacker: 'Skilled',
  apt: 'APT',
  unknown: 'Unknown',
}
