import { Inbox } from 'lucide-react'

export default function EmptyState({ title, hint, icon: Icon = Inbox }) {
  return (
    <div className="text-center py-8">
      <Icon className="w-8 h-8 text-gray-600 mx-auto mb-3" />
      <p className="font-mono text-sm text-gray-500">{title}</p>
      {hint && <p className="font-mono text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}
