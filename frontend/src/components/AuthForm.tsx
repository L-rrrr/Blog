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
    <form onSubmit={handleSubmit} className="card stack" style={{ maxWidth: 460 }}>
      {mode === 'register' && (
        <div>
          <label className="form-label" htmlFor="name-input">Name</label>
          <input id="name-input" className="form-control" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
      )}

      <div>
        <label className="form-label" htmlFor="email-input">Email</label>
        <input id="email-input" className="form-control" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </div>

      <div>
        <label className="form-label" htmlFor="password-input">Password</label>
        <input id="password-input" className="form-control" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </div>

      <button className="btn btn-primary" type="submit" disabled={loading}>
        {loading ? 'Please wait…' : mode === 'register' ? 'Create account' : 'Sign in'}
      </button>

      {error && <div style={{ color: 'var(--danger)' }}>{error}</div>}
    </form>
  )
}
