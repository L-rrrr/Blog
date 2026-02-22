import { useContext } from 'react'
import AuthForm from '../components/AuthForm'
import { register } from '../services/auth'
import { AuthContext } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'

export default function RegisterPage() {
  const { setToken, setUser } = useContext(AuthContext)
  const navigate = useNavigate()

  async function handleRegister(values: { name?: string; email: string; password: string }) {
    const data = await register({
      name: values.name || '',
      email: values.email,
      password: values.password,
    })

    // Expect backend to return a token and user
    if (data.token) {
      setToken(data.token)
    }
    if (data.user) {
      setUser(data.user)
    }

    navigate('/')
  }

  return (
    <div style={{ padding: 20 }}>
      <h2>Create an account</h2>
      <AuthForm mode="register" onSubmit={handleRegister} />
    </div>
  )
}
