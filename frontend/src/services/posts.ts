import api from './api'

export async function getPosts() {
  const res = await api.get('/posts')
  return res.data.posts
}

export async function getPost(id: number | string) {
  const res = await api.get(`/posts/${id}`)
  return res.data.post
}

export async function getComments(postId: number | string) {
  const res = await api.get(`/posts/${postId}/comments`)
  return res.data.comments
}

export async function addComment(postId: number | string, content: string) {
  const res = await api.post('/comments', { postId, content })
  return res.data.comment
}

export async function createPost(title: string, content: string) {
  const res = await api.post('/posts', { title, content })
  return res.data.post
}

export async function updatePost(id: number | string, title: string, content: string) {
  const res = await api.put(`/posts/${id}`, { title, content })
  return res.data.post
}

export async function deletePost(id: number | string) {
  const res = await api.delete(`/posts/${id}`)
  return res.data
}

export async function deleteComment(id: number | string) {
  const res = await api.delete(`/comments/${id}`)
  return res.data
}
export default { getPosts, getPost, getComments, addComment, createPost, updatePost, deletePost, deleteComment }
