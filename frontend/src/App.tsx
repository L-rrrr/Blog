import { Link, Route, Routes } from 'react-router-dom'
import './App.css'
import RegisterPage from './pages/Register'
import LoginPage from './pages/Login'

export default function App() {
  return (
    <div style={{ padding: 20 }}>
      <nav style={{ marginBottom: 12 }}>
        <Link to="/">Home</Link> | <Link to="/register">Register</Link> | <Link to="/login">Login</Link>
      </nav>

      <Routes>
        <Route path="/" element={<div>Home — posts will be listed here.</div>} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/login" element={<LoginPage />} />
      </Routes>
    </div>
  )
}
