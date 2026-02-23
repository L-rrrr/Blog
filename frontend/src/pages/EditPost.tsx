import { useContext, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { getPost, updatePost } from '../services/posts'
import { AuthContext } from '../context/AuthContext'

export default function EditPost() {
  const { id } = useParams()
  const { token } = useContext(AuthContext)
  const navigate = useNavigate()
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true
    if (!id) return
    setLoading(true)
    getPost(id)
      .then((p) => {
        if (!mounted) return
        setTitle(p.title || '')
        setContent(p.content || '')
      })
      .catch((err) => setError(err?.response?.data?.error || err?.message || 'Failed to load post'))
      .finally(() => setLoading(false))

    return () => {
      mounted = false
    }
  }, [id])

  if (!token) return <div className="card muted">You must be signed in to edit posts.</div>
  if (loading) return <div className="card muted">Loading post…</div>

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    e.preventDefault()
    setError(null)
    if (!id) return setError('Invalid post id')
    if (!title.trim() || !content.trim()) return setError('Title and content are required')
    setSaving(true)
    try {
      const post = await updatePost(id, title.trim(), content.trim())
      navigate(`/posts/${post.id}`)
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to update post')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="stack" style={{ gap: 14 }}>
      <h2>Edit Post</h2>
      <form onSubmit={handleSubmit} className="card stack" style={{ gap: 12 }}>
        <div>
          <label className="form-label" htmlFor="edit-title">Title</label>
          <input
            id="edit-title"
            className="form-control"
            placeholder="Enter post title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            disabled={saving}
          />
        </div>
        <div>
          <label className="form-label" htmlFor="edit-content">Content</label>
          <textarea
            id="edit-content"
            className="form-control"
            rows={10}
            placeholder="Write your post..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            disabled={saving}
          />
        </div>
        <div className="form-actions">
          <button className="btn btn-primary" type="submit" disabled={saving}>
            {saving ? 'Saving…' : 'Save Changes'}
          </button>
          {error && <span style={{ color: 'var(--danger)' }}>{error}</span>}
        </div>
      </form>
    </section>
  )
}
