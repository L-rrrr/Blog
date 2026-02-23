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
  const { token, user, logout } = useContext(AuthContext)
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/', { replace: true })
  }

  return (
    <div className="app-wrap">
      <div className="container">
        <header className="site-header">
          <div className="site-brand">
            <span className="logo-mark" aria-hidden="true" />
            <div className="stack" style={{ gap: 2 }}>
              <span>Simple Blog CMS</span>
              <span className="muted" style={{ fontSize: 12 }}>
                Publish, discuss, and manage posts
              </span>
            </div>
          </div>

          <nav className="site-nav" aria-label="Main navigation">
            <Link className="nav-link" to="/">
              Home
            </Link>

            {token ? (
              <>
                <Link className="nav-link" to="/posts/new">
                  New Post
                </Link>
                <span className="muted" style={{ fontSize: 13 }}>
                  Signed in{user?.name ? ` as ${user.name}` : ''}
                </span>
                <button type="button" className="btn btn-ghost" onClick={handleLogout}>
                  Logout
                </button>
              </>
            ) : (
              <>
                <Link className="nav-link" to="/register">
                  Register
                </Link>
                <Link className="nav-link" to="/login">
                  Login
                </Link>
              </>
            )}
          </nav>
        </header>

        <main className="site-main">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/posts/:id" element={<PostDetail />} />
            <Route path="/posts/new" element={<NewPost />} />
            <Route path="/posts/:id/edit" element={<EditPost />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/login" element={<LoginPage />} />
          </Routes>
        </main>

        <footer className="footer">Simple Blog CMS</footer>
      </div>
    </div>
  )
}
