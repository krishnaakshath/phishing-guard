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
import PrivacyPolicyPage from './pages/PrivacyPolicyPage'
import { isDaytimeNow } from './sunTheme'

// Resolves and applies the active theme. 'auto' (the default, and the only
// option for logged-out visitors, who have no settings) follows real
// sunrise/sunset at the user's location - not a fixed clock time. A
// logged-in user can still force 'light' or 'dark' explicitly in Settings.
function ThemeSync() {
  const { isAuthenticated } = useAuth()

  useEffect(() => {
    let cancelled = false

    async function applyTheme() {
      let mode = 'auto'

      if (isAuthenticated) {
        try {
          const data = await apiGet('/settings')
          mode = data.settings.preferences.theme_mode || 'auto'
        } catch {
          mode = 'auto'
        }
      }

      if (cancelled) return

      if (mode === 'light') {
        document.body.classList.add('theme-light')
        return
      }
      if (mode === 'dark') {
        document.body.classList.remove('theme-light')
        return
      }

      // 'auto'
      try {
        const daytime = await isDaytimeNow()
        if (!cancelled) document.body.classList.toggle('theme-light', daytime)
      } catch {
        // Sun calculation failed for some reason - keep the current theme
        // rather than flipping unexpectedly.
      }
    }

    applyTheme()
    // Re-check roughly hourly so the theme actually flips around sunrise/
    // sunset for someone who leaves the tab open, not just on page load.
    const interval = setInterval(applyTheme, 60 * 60 * 1000)

    return () => {
      cancelled = true
      clearInterval(interval)
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
          <Route path="/privacy" element={<PrivacyPolicyPage />} />
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
