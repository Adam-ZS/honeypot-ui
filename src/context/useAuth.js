import { useContext } from 'react'
import { AuthContext } from './authContext.js'

/** Access the authenticated user and auth actions. */
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
