import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { apiGet, apiPost, getApiKey, setApiKey as persistApiKey } from './api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [apiKey, setApiKeyState] = useState(() => getApiKey())
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function restoreSession() {
      const key = getApiKey()
      if (!key) {
        setLoading(false)
        return
      }
      try {
        const data = await apiGet('/auth/me')
        if (!cancelled) {
          setUser(data.user)
          setApiKeyState(key)
        }
      } catch {
        // Stored key is invalid/expired - clear it and log out.
        persistApiKey(null)
        if (!cancelled) {
          setUser(null)
          setApiKeyState(null)
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    restoreSession()
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email, password) => {
    const data = await apiPost('/auth/login', { email, password })
    persistApiKey(data.api_key)
    setApiKeyState(data.api_key)
    setUser(data.user)
    return data.user
  }, [])

  const register = useCallback(async (email, password) => {
    const data = await apiPost('/auth/register', { email, password })
    persistApiKey(data.api_key)
    setApiKeyState(data.api_key)
    setUser(data.user)
    return data.user
  }, [])

  const logout = useCallback(() => {
    persistApiKey(null)
    setApiKeyState(null)
    setUser(null)
  }, [])

  const value = {
    user,
    apiKey,
    isAuthenticated: !!user,
    isAdmin: !!(user && user.is_admin),
    loading,
    login,
    register,
    logout,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components -- context + provider + hook live together intentionally
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return ctx
}
