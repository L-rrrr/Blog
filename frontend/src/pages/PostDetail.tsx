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
      const saved = await addComment(id!, optimistic.content)
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

  if (loading) return <div>Loading post…</div>
  if (error) return <div style={{ color: 'crimson' }}>{error}</div>
  if (!post) return <div>Post not found.</div>

  return (
    <article>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h1 style={{ margin: 0 }}>{post.title}</h1>
        {(user?.role === 'ADMIN' || String(user?.id) === String(post.author_id)) && (
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => navigate(`/posts/${post.id}/edit`)} style={{ marginLeft: 12 }}>
              Edit
            </button>
            <button onClick={handleDeletePost} style={{ marginLeft: 12 }}>
              Delete Post
            </button>
          </div>
        )}
      </div>
      <div style={{ fontSize: 13, color: '#666' }}>
        by {post.author_name || 'Unknown'} — {new Date(post.created_at).toLocaleString()}
      </div>
      <div style={{ marginTop: 12, whiteSpace: 'pre-wrap' }}>{post.content}</div>

      <section style={{ marginTop: 24 }}>
        <h3>Comments</h3>

        {commentsLoading ? (
          <div>Loading comments…</div>
        ) : (
          <div>
            {comments.length === 0 && <div>No comments yet.</div>}
            <ul style={{ paddingLeft: 0, listStyle: 'none' }}>
              {comments.map((c) => (
                <li key={c.id} style={{ padding: 8, borderBottom: '1px solid #eee' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: 13, color: '#333' }}>{c.content}</div>
                    <div>
                      {(user?.role === 'ADMIN' || String(user?.id) === String(c.author_id) || String(c.id).startsWith('temp-')) && (
                        <button
                          onClick={() => handleDeleteComment(c.id)}
                          style={{ marginLeft: 8 }}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: '#666' }}>
                    {c.author_name || 'Unknown'} — {new Date(c.created_at).toLocaleString()}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}

        <form onSubmit={handleAddComment} style={{ marginTop: 12 }}>
          <textarea
            rows={3}
            value={commentText}
            onChange={(e) => setCommentText(e.target.value)}
            placeholder={token ? 'Write a comment…' : 'Sign in to write a comment'}
            style={{ width: '100%', padding: 8 }}
            disabled={!token || adding}
          />
          <div style={{ marginTop: 8 }}>
            <button type="submit" disabled={!token || adding}>
              {adding ? 'Posting…' : 'Post comment'}
            </button>
            {commentError && <span style={{ color: 'crimson', marginLeft: 12 }}>{commentError}</span>}
          </div>
        </form>
      </section>
    </article>
  )
}
