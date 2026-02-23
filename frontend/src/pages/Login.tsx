import { useContext, useEffect } from 'react'
import AuthForm from '../components/AuthForm'
import { login } from '../services/auth'
import { AuthContext } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'

export default function LoginPage() {
  const { token, setToken, setUser } = useContext(AuthContext)
  const navigate = useNavigate()
  
  useEffect(() => {
    if (token) navigate('/', { replace: true })
  }, [token, navigate])

  async function handleLogin(values: { name?: string; email: string; password: string }) {
    const data = await login({ email: values.email, password: values.password })

    if (data.token) setToken(data.token)
    if (data.user) setUser(data.user)

    navigate('/', { replace: true })
  }

  return (
    <section className="stack" style={{ gap: 14 }}>
      <h2>Sign in</h2>
      <AuthForm mode="login" onSubmit={handleLogin} />
    </section>
  )
}
