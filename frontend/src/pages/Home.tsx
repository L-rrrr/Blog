import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getPosts } from '../services/posts'

export default function Home() {
  const [posts, setPosts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true
    setLoading(true)
    getPosts()
      .then((data) => {
        if (!mounted) return
        setPosts(data || [])
      })
      .catch((err) => setError(err?.response?.data?.error || err.message || 'Failed to load posts'))
      .finally(() => setLoading(false))

    return () => {
      mounted = false
    }
  }, [])

  if (loading) return <div>Loading posts…</div>
  if (error) return <div style={{ color: 'crimson' }}>{error}</div>

  return (
    <div>
      <h2>Recent posts</h2>
      {posts.length === 0 && <div>No posts yet.</div>}
      <ul>
        {posts.map((p) => (
          <li key={p.id} style={{ marginBottom: 12 }}>
            <Link to={`/posts/${p.id}`}>
              <strong>{p.title}</strong>
            </Link>
            <div style={{ fontSize: 12, color: '#666' }}>
              by {p.author_name || 'Unknown'} — {new Date(p.created_at).toLocaleString()}
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
