import { useContext, useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { getPost, getComments, addComment, deleteComment, deletePost } from '../services/posts'
import { AuthContext } from '../context/AuthContext'

export default function PostDetail() {
  const { id } = useParams()
  const { token, user } = useContext(AuthContext)
  const [post, setPost] = useState<any | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [comments, setComments] = useState<any[]>([])
  const [commentsLoading, setCommentsLoading] = useState(true)
  const [commentText, setCommentText] = useState('')
  const [adding, setAdding] = useState(false)
  const [commentError, setCommentError] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true
    if (!id) return
    setLoading(true)
    getPost(id)
      .then((data) => {
        if (!mounted) return
        setPost(data)
      })
      .catch((err) => setError(err?.response?.data?.error || err.message || 'Failed to load post'))
      .finally(() => setLoading(false))

    // load comments separately
    setCommentsLoading(true)
    getComments(id)
      .then((list) => {
        if (!mounted) return
        setComments(list || [])
      })
      .catch(() => {
        if (!mounted) return
        setCommentError('Failed to load comments')
      })
      .finally(() => setCommentsLoading(false))

    return () => {
      mounted = false
    }
  }, [id])

  async function handleAddComment(e: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    e.preventDefault()
    setCommentError(null)
    if (!commentText.trim()) return setCommentError('Comment cannot be empty')
    if (!token) return setCommentError('You must be signed in to comment')

    const tempId = `temp-${Date.now()}`
    const optimistic = {
      id: tempId,
      content: commentText,
      author_name: user?.name || 'You',
      created_at: new Date().toISOString(),
    }
    setComments((c) => [...c, optimistic])
    setCommentText('')
    setAdding(true)

    try {
      if (!id) return
      const saved = await addComment(id, optimistic.content)
      // replace temp with saved
      setComments((c) => c.map((it) => (it.id === tempId ? saved : it)))
    } catch (err: any) {
      // remove optimistic
      setComments((c) => c.filter((it) => it.id !== tempId))
      setCommentError(err?.response?.data?.error || err?.message || 'Failed to add comment')
    } finally {
      setAdding(false)
    }
  }

  async function handleDeleteComment(commentId: number | string) {
    if (!commentId) return
    if (!confirm('Delete this comment?')) return

    // optimistic remove
    const prev = comments
    setComments((c) => c.filter((it) => it.id !== commentId))
    try {
      await deleteComment(commentId)
    } catch (err: any) {
      setComments(prev)
      setCommentError(err?.response?.data?.error || err?.message || 'Failed to delete comment')
    }
  }

  const navigate = useNavigate()

  async function handleDeletePost() {
    if (!post?.id) return
    if (!confirm('Delete this post? This cannot be undone.')) return
    try {
      await deletePost(post.id)
      navigate('/')
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to delete post')
    }
  }

  if (loading) return <div className="card muted">Loading post…</div>
  if (error) return <div className="card" style={{ color: 'var(--danger)' }}>{error}</div>
  if (!post) return <div className="card muted">Post not found.</div>

  return (
    <article className="stack" style={{ gap: 20 }}>
      <section className="card stack" style={{ gap: 12 }}>
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap' }}>
          <h1>{post.title}</h1>
          {(user?.role === 'ADMIN' || String(user?.id) === String(post.author_id)) && (
            <div className="form-actions">
              <button type="button" className="btn btn-ghost" onClick={() => navigate(`/posts/${post.id}/edit`)}>
                Edit
              </button>
              <button type="button" className="btn btn-ghost" onClick={handleDeletePost}>
                Delete Post
              </button>
            </div>
          )}
        </div>

        <div className="muted" style={{ fontSize: 13 }}>
          by {post.author_name || 'Unknown'} • {new Date(post.created_at).toLocaleString()}
        </div>

        <div style={{ whiteSpace: 'pre-wrap' }}>{post.content}</div>
      </section>

      <section className="card stack" style={{ gap: 14 }}>
        <h2>Comments</h2>

        {commentsLoading ? (
          <div className="muted">Loading comments…</div>
        ) : comments.length === 0 ? (
          <div className="list-empty">No comments yet.</div>
        ) : (
          <ul className="stack" style={{ gap: 10, listStyle: 'none', padding: 0, margin: 0 }}>
            {comments.map((c) => (
              <li key={c.id} className="post-card stack" style={{ gap: 8 }}>
                <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ whiteSpace: 'pre-wrap', flex: 1 }}>{c.content}</div>
                  {(user?.role === 'ADMIN' || String(user?.id) === String(c.author_id) || String(c.id).startsWith('temp-')) && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => handleDeleteComment(c.id)}
                    >
                      Delete
                    </button>
                  )}
                </div>
                <div className="muted" style={{ fontSize: 12 }}>
                  {c.author_name || 'Unknown'} • {new Date(c.created_at).toLocaleString()}
                </div>
              </li>
            ))}
          </ul>
        )}

        <form onSubmit={handleAddComment} className="stack" style={{ gap: 10 }}>
          <label className="form-label" htmlFor="comment-content">
            Add a comment
          </label>
          <textarea
            id="comment-content"
            className="form-control"
            rows={4}
            value={commentText}
            onChange={(e) => setCommentText(e.target.value)}
            placeholder={token ? 'Write a comment…' : 'Sign in to write a comment'}
            disabled={!token || adding}
          />
          <div className="form-actions">
            <button className="btn btn-primary" type="submit" disabled={!token || adding}>
              {adding ? 'Posting…' : 'Post Comment'}
            </button>
            {commentError && <span style={{ color: 'var(--danger)' }}>{commentError}</span>}
          </div>
        </form>
      </section>
    </article>
  )
}
