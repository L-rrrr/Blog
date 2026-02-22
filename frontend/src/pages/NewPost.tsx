import React, { useContext, useState } from 'react'
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

  if (!token) return <div>You must be signed in to create a post.</div>

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
    <div>
      <h2>Create Post</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <input
            placeholder="Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            style={{ width: '100%', padding: 8 }}
            disabled={loading}
          />
        </div>
        <div style={{ marginTop: 8 }}>
          <textarea
            rows={10}
            placeholder="Write your post..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            style={{ width: '100%', padding: 8 }}
            disabled={loading}
          />
        </div>
        <div style={{ marginTop: 8 }}>
          <button type="submit" disabled={loading}>{loading ? 'Creating…' : 'Create Post'}</button>
          {error && <span style={{ color: 'crimson', marginLeft: 12 }}>{error}</span>}
        </div>
      </form>
    </div>
  )
}
