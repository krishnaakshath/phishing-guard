import { useEffect } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import './App.css'
import { AuthProvider, useAuth } from './AuthContext'
import { apiGet } from './api'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import AdminRoute from './components/AdminRoute'

import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import HistoryPage from './pages/HistoryPage'
import WhitelistPage from './pages/WhitelistPage'
import BlacklistPage from './pages/BlacklistPage'
import SettingsPage from './pages/SettingsPage'
import SiteScannerPage from './pages/SiteScannerPage'
import PasswordCheckerPage from './pages/PasswordCheckerPage'
import AdminPage from './pages/AdminPage'

// Applies the user's saved dark_mode preference to the document once
// they're logged in. Defaults to dark (the app's primary look) otherwise.
function ThemeSync() {
  const { isAuthenticated } = useAuth()

  useEffect(() => {
    let cancelled = false

    async function applyTheme() {
      if (!isAuthenticated) {
        document.body.classList.remove('theme-light')
        return
      }
      try {
        const data = await apiGet('/settings')
        if (!cancelled) {
          document.body.classList.toggle('theme-light', data.settings.preferences.dark_mode === false)
        }
      } catch {
        // keep current theme
      }
    }

    applyTheme()
    return () => {
      cancelled = true
    }
  }, [isAuthenticated])

  return null
}

function App() {
  return (
    <AuthProvider>
      <ThemeSync />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        <Route element={<Layout />}>
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <DashboardPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/history"
            element={
              <ProtectedRoute>
                <HistoryPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/whitelist"
            element={
              <ProtectedRoute>
                <WhitelistPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/blacklist"
            element={
              <ProtectedRoute>
                <BlacklistPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <SettingsPage />
              </ProtectedRoute>
            }
          />
          <Route path="/tools/site-scanner" element={<SiteScannerPage />} />
          <Route path="/tools/password-checker" element={<PasswordCheckerPage />} />
        </Route>

        <Route
          path="/admin"
          element={
            <AdminRoute>
              <AdminPage />
            </AdminRoute>
          }
        />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}

export default App
