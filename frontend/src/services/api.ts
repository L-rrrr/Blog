import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_BASE_URL

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
})

function setAuthHeaderFromStorage() {
  try {
    const token = localStorage.getItem('token')
    if (token) api.defaults.headers.common['Authorization'] = `Bearer ${token}`
    else delete api.defaults.headers.common['Authorization']
  } catch (err) {
    // localStorage may be unavailable in some environments
  }
}

// initialize header on startup
setAuthHeaderFromStorage()

// request interceptor: always ensure the latest token from storage is attached
api.interceptors.request.use((config) => {
  try {
    const token = localStorage.getItem('token')
    if (token) {
      if (!config.headers) config.headers = {} as any
      config.headers['Authorization'] = `Bearer ${token}`
    }
  } catch (err) {
    // ignore
  }
  return config
})

// cross-tab token sync: update defaults when storage changes
if (typeof window !== 'undefined' && window.addEventListener) {
  window.addEventListener('storage', (e) => {
    if (e.key === 'token') setAuthHeaderFromStorage()
  })
}

export default api
