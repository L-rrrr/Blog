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

  if (loading) return <div className="card muted">Loading posts…</div>
  if (error) return <div className="card" style={{ color: 'var(--danger)' }}>{error}</div>

  return (
    <section className="stack" style={{ gap: 20 }}>
      <div className="hero card">
        <div className="intro stack" style={{ gap: 8 }}>
          <h1>Recent Posts</h1>
          <p className="muted">Explore the latest updates from the community.</p>
        </div>
      </div>

      {posts.length === 0 ? (
        <div className="card list-empty">No posts yet.</div>
      ) : (
        <div className="posts-grid" aria-label="Recent posts">
          {posts.map((p) => (
            <article key={p.id} className="post-card stack" style={{ gap: 10 }}>
              <Link className="post-title" to={`/posts/${p.id}`}>
                {p.title}
              </Link>
              <p className="post-excerpt" style={{ whiteSpace: 'pre-wrap' }}>
                {(p.content || '').slice(0, 150)}{(p.content || '').length > 150 ? '…' : ''}
              </p>
              <div className="muted" style={{ fontSize: 12 }}>
                by {p.author_name || 'Unknown'} • {new Date(p.created_at).toLocaleString()}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  )
}
