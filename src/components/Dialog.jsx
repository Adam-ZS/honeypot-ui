import { useEffect, useRef } from 'react'

/** Native modal semantics include focus containment, Escape, and focus restoration. */
export default function Dialog({ label, onClose, className = '', children }) {
  const ref = useRef(null)
  useEffect(() => {
    const dialog = ref.current
    const previous = document.activeElement
    dialog.showModal()
    return () => {
      dialog.close()
      previous?.focus()
    }
  }, [])
  return (
    <dialog ref={ref} aria-label={label} onCancel={(event) => { event.preventDefault(); onClose() }}
      onClick={(event) => { if (event.target === event.currentTarget) onClose() }}
      className={`m-auto max-h-[90dvh] w-[calc(100%-2rem)] max-w-3xl border-0 bg-transparent p-0 text-paper backdrop:bg-black/80 ${className}`}>
      <div className="panel max-h-[85dvh] overflow-y-auto">{children}</div>
    </dialog>
  )
}
