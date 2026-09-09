import { useEffect, useState } from 'react'

/**
 * Delay propagating a rapidly-changing value.
 *
 * The session search box fired one API request per keystroke; typing an IP
 * address issued a dozen queries and the responses could arrive out of order.
 */
export function useDebounced(value, delayMs = 350) {
  const [debounced, setDebounced] = useState(value)

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(timer)
  }, [value, delayMs])

  return debounced
}
