function getUserId(user) {
  return user && (user.id ?? user.userId)
}

function isAdmin(user) {
  return Boolean(user && user.role === 'ADMIN')
}

function isOwner(user, ownerId) {
  return getUserId(user) === ownerId
}

function isOwnerOrAdmin(user, ownerId) {
  return isOwner(user, ownerId) || isAdmin(user)
}

module.exports = { getUserId, isAdmin, isOwner, isOwnerOrAdmin }
