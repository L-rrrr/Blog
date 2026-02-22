import api from './api'

interface RegisterProps { name: string; email: string; password: string }

export async function register(payload: RegisterProps) {
  const res = await api.post('/auth/register', payload)
  return res.data
}

interface LoginProps { email: string; password: string }
export async function login(payload: LoginProps) {
  const res = await api.post('/auth/login', payload)
  return res.data
}
