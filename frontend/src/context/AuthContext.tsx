import { createContext, useEffect, useState, type ReactNode } from 'react'
import api from '../services/api'

type AuthContextType = {
  token: string | null
  user: any | null
  setToken: (t: string | null) => void
  logout: () => void
  setUser: (u: any) => void
}

export const AuthContext = createContext<AuthContextType>({
  token: null,
  user: null,
  setToken: () => {},
  logout: () => {},
  setUser: () => {},
})

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [token, setTokenState] = useState<string | null>(localStorage.getItem('token'))
  const [user, setUser] = useState<any>(null)

  useEffect(() => {
    if (token) {
      localStorage.setItem('token', token)
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`
    } else {
      localStorage.removeItem('token')
      delete api.defaults.headers.common['Authorization']
    }
  }, [token])

  // If we have a token but no `user` in memory (e.g. after a reload), fetch
  // the current user from the server so components can rely on `user.id`.
  useEffect(() => {
    let mounted = true
    async function fetchMe() {
      if (!token || user) return
      try {
        const res = await api.get('/auth/me')
        if (!mounted) return
        if (res?.data?.user) setUser(res.data.user)
      } catch (err) {
        // ignore; user remains null and app will behave as unauthenticated
      }
    }
    fetchMe()
    return () => {
      mounted = false
    }
  }, [token])

  const setToken = (t: string | null) => {
    // update state
    setTokenState(t)
    // also apply immediately to axios defaults and localStorage so requests made
    // immediately after setToken have the Authorization header available
    try {
      if (t) {
        localStorage.setItem('token', t)
        api.defaults.headers.common['Authorization'] = `Bearer ${t}`
      } else {
        localStorage.removeItem('token')
        delete api.defaults.headers.common['Authorization']
      }
    } catch (err) {
      // ignore storage errors
    }
  }

  const logout = () => {
    setTokenState(null)
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ token, user, setToken, logout, setUser }}>
      {children}
    </AuthContext.Provider>
  )
}
