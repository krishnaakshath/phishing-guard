import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../AuthContext'
import {
  ShieldIcon,
  DashboardIcon,
  SettingsIcon,
  HistoryIcon,
  ListIcon,
  BlockIcon,
  GlobeIcon,
  KeyIcon,
  LogOutIcon,
  AdminIcon,
} from '../icons'

function NavItem({ to, icon, label, end, extraClass = '' }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) => `nav-item ${extraClass} ${isActive ? 'active' : ''}`}
    >
      {icon}
      <span>{label}</span>
    </NavLink>
  )
}

export default function Layout() {
  const { user, isAuthenticated, isAdmin, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const initials = user?.email ? user.email.slice(0, 2) : '??'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="logo-mark">
              <ShieldIcon />
            </div>
            <div className="logo-text">
              <span className="logo-name">Phishing Guard</span>
              <span className="logo-sub">dashboard v2.1</span>
            </div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">Main</div>
            <NavItem to="/" end icon={<DashboardIcon />} label="Dashboard" />
            <NavItem to="/history" icon={<HistoryIcon />} label="Scan History" />
          </div>

          <div className="nav-section">
            <div className="nav-section-title">Protection</div>
            <NavItem to="/whitelist" icon={<ListIcon />} label="Whitelist" />
            <NavItem to="/blacklist" icon={<BlockIcon />} label="Blacklist" />
            <NavItem to="/settings" icon={<SettingsIcon />} label="Settings" />
          </div>

          <div className="nav-section">
            <div className="nav-section-title">Tools</div>
            <NavItem to="/tools/site-scanner" icon={<GlobeIcon />} label="Site Scanner" />
            <NavItem to="/tools/password-checker" icon={<KeyIcon />} label="Password Checker" />
          </div>

          {isAdmin && (
            <div className="nav-section">
              <div className="nav-section-title">Operator</div>
              <NavItem
                to="/admin"
                icon={<AdminIcon />}
                label="Admin Console"
                extraClass="admin-nav-item"
              />
            </div>
          )}
        </nav>

        <div className="sidebar-footer">
          {isAuthenticated ? (
            <div className="user-card">
              <div className="user-avatar">{initials}</div>
              <div className="user-info">
                <div className="user-email" title={user.email}>{user.email}</div>
                <div className="user-role-row">
                  {isAdmin && <span className="admin-chip">Admin</span>}
                </div>
              </div>
              <button className="logout-btn" onClick={handleLogout} title="Log out">
                <LogOutIcon />
              </button>
            </div>
          ) : (
            <NavLink to="/login" className="btn btn-primary btn-block">
              Log In
            </NavLink>
          )}
        </div>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}
