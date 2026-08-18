import { createContext } from 'react'

/**
 * Auth state shared across the app.
 *
 * Lives in its own module so AuthContext.jsx can export only the provider
 * component, which is what React Fast Refresh requires.
 */
export const AuthContext = createContext(null)
