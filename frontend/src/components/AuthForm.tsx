import { type SyntheticEvent, useState } from 'react'

type Props = {
  mode?: 'register' | 'login'
  onSubmit: (values: { name?: string; email: string; password: string }) => Promise<void>
}

export default function AuthForm({ mode = 'register', onSubmit }: Props) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await onSubmit({ name: name || undefined, email, password })
    } catch (err: any) {
      const resp = err?.response?.data
      setError(resp?.error || resp?.message || err?.message || 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ maxWidth: 420 }}>
      {mode === 'register' && (
        <div style={{ marginBottom: 8 }}>
          <label style={{ display: 'block', marginBottom: 4 }}>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
      )}

      <div style={{ marginBottom: 8 }}>
        <label style={{ display: 'block', marginBottom: 4 }}>Email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={{ display: 'block', marginBottom: 4 }}>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </div>

      <button type="submit" disabled={loading}>
        {loading ? 'Please wait…' : mode === 'register' ? 'Create account' : 'Sign in'}
      </button>

      {error && <div style={{ color: 'crimson', marginTop: 8 }}>{error}</div>}
    </form>
  )
}
