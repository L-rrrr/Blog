import { useContext, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createPost } from '../services/posts'
import { AuthContext } from '../context/AuthContext'

export default function NewPost() {
  const { token } = useContext(AuthContext)
  const navigate = useNavigate()
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!token) return <div className="card muted">You must be signed in to create a post.</div>

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    e.preventDefault()
    setError(null)
    if (!title.trim() || !content.trim()) return setError('Title and content are required')
    setLoading(true)
    try {
      const post = await createPost(title.trim(), content.trim())
      // pass post in navigation state so the author can view their draft immediately
      navigate(`/posts/${post.id}`, { state: { post } })
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to create post')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="stack" style={{ gap: 14 }}>
      <h2>Create Post</h2>
      <form onSubmit={handleSubmit} className="card stack" style={{ gap: 12 }}>
        <div>
          <label className="form-label" htmlFor="new-title">Title</label>
          <input
            id="new-title"
            className="form-control"
            placeholder="Enter post title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            disabled={loading}
          />
        </div>
        <div>
          <label className="form-label" htmlFor="new-content">Content</label>
          <textarea
            id="new-content"
            className="form-control"
            rows={10}
            placeholder="Write your post..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            disabled={loading}
          />
        </div>
        <div className="form-actions">
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? 'Creating…' : 'Create Post'}
          </button>
          {error && <span style={{ color: 'var(--danger)' }}>{error}</span>}
        </div>
      </form>
    </section>
  )
}
