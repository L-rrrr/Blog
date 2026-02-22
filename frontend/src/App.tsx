import { Link, Route, Routes, useNavigate } from 'react-router-dom'
import './App.css'
import { useContext } from 'react'
import { AuthContext } from './context/AuthContext'
import RegisterPage from './pages/Register'
import LoginPage from './pages/Login'
import Home from './pages/Home'
import PostDetail from './pages/PostDetail'
import NewPost from './pages/NewPost'
import EditPost from './pages/EditPost'

export default function App() {
  const { token, logout } = useContext(AuthContext)
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/', { replace: true })
  }

  return (
    <div style={{ padding: 20 }}>
      <nav style={{ marginBottom: 12 }}>
        <Link to="/">Home</Link>
        {token ? (
          <> | <Link to="/posts/new">New Post</Link> | <button onClick={handleLogout}>Logout</button></>
        ) : (
          <> | <Link to="/register">Register</Link> | <Link to="/login">Login</Link></>
        )}
      </nav>

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/posts/:id" element={<PostDetail />} />
        <Route path="/posts/new" element={<NewPost />} />
        <Route path="/posts/:id/edit" element={<EditPost />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/login" element={<LoginPage />} />
      </Routes>
    </div>
  )
}
