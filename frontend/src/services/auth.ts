import api from './api'

interface RegisterProps { name: string; email: string; password: string }

export async function register(payload: RegisterProps) {
  const res = await api.post('/auth/register', payload)
  return res.data
}
