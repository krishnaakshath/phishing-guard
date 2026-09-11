import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../AuthContext'

// Backend also enforces admin-only access (403 for non-admins) - this is
// just UX so non-admins never see the console shell flash in.
export default function AdminRoute({ children }) {
  const { isAuthenticated, isAdmin, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return <div className="page-loading">Loading...</div>
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (!isAdmin) {
    return <Navigate to="/" state={{ flash: 'Admin access required.' }} replace />
  }

  return children
}
