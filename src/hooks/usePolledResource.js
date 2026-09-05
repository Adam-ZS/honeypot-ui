import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Load data on mount, optionally re-loading on an interval.
 *
 * Centralises the fetch/loading/error/cleanup handling that each page used to
 * repeat, and guarantees a response that arrives after unmount (or after a
 * newer request started) is discarded instead of overwriting fresher state.
 *
 * @param {() => Promise<any>} loader resolves to the data
 * @param {{intervalMs?: number, deps?: any[]}} options
 */
export function usePolledResource(loader, { intervalMs = 0, deps = [] } = {}) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const loaderRef = useRef(loader)
  useEffect(() => {
    loaderRef.current = loader
  })

  // Monotonically increasing token: only the newest in-flight request is
  // allowed to commit its result.
  const requestId = useRef(0)
  const mounted = useRef(true)

  const refresh = useCallback(async () => {
    const id = ++requestId.current
    try {
      const result = await loaderRef.current()
      if (!mounted.current || id !== requestId.current) return
      setData(result)
      setError(null)
    } catch (err) {
      if (!mounted.current || id !== requestId.current) return
      setError(err.message || 'Request failed')
    } finally {
      if (mounted.current && id === requestId.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    mounted.current = true
    // Kicked off asynchronously so no state update happens synchronously in
    // the effect body (react-hooks/set-state-in-effect).
    const timer = setTimeout(refresh, 0)
    const interval = intervalMs > 0 ? setInterval(refresh, intervalMs) : null

    return () => {
      mounted.current = false
      // This is a request counter, not a DOM ref; invalidate pending work.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      requestId.current++
      clearTimeout(timer)
      if (interval) clearInterval(interval)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh, intervalMs, ...deps])

  return { data, error, loading, refresh, setData }
}
