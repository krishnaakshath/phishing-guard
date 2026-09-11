import { useEffect, useState } from 'react'
import { apiGet, apiPut } from '../api'
import { ShieldIcon, LockIcon, CardIcon, LinkIcon, BellIcon, BlockIcon, SpeakerIcon, MoonIcon } from '../icons'

const LEVELS = ['low', 'medium', 'high']

export default function SettingsPage() {
  const [settings, setSettings] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [savedAt, setSavedAt] = useState(null)

  useEffect(() => {
    let cancelled = false
    apiGet('/settings')
      .then((data) => {
        if (!cancelled) setSettings(data.settings)
      })
      .catch((e) => {
        if (!cancelled) setError(e.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const save = async (next) => {
    setSettings(next)
    setSaving(true)
    setError(null)
    try {
      await apiPut('/settings', next)
      setSavedAt(Date.now())
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const toggleModule = (key) => {
    if (!settings) return
    save({ ...settings, modules: { ...settings.modules, [key]: !settings.modules[key] } })
  }

  const togglePreference = (key) => {
    if (!settings) return
    save({ ...settings, preferences: { ...settings.preferences, [key]: !settings.preferences[key] } })
  }

  const setLevel = (level) => {
    if (!settings) return
    save({ ...settings, protection_level: level })
  }

  if (loading) {
    return (
      <>
        <header className="page-header">
          <div>
            <h1 className="page-title">Settings</h1>
            <p className="page-subtitle">Configure your protection preferences</p>
          </div>
        </header>
        <div className="loading-state">Loading settings…</div>
      </>
    )
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Configure your protection preferences</p>
        </div>
        <div className="text-muted" style={{ fontSize: '12px', alignSelf: 'center' }}>
          {saving ? 'Saving…' : savedAt ? 'Saved' : ''}
        </div>
      </header>

      {error && <div className="flash-banner danger">{error}</div>}

      {settings && (
        <>
          <div className="settings-section">
            <h3 className="settings-title">Protection Level</h3>
            <div className="protection-level-row">
              {LEVELS.map((level) => (
                <div
                  key={level}
                  className={`level-option ${settings.protection_level === level ? 'active' : ''}`}
                  onClick={() => setLevel(level)}
                >
                  {level.charAt(0).toUpperCase() + level.slice(1)}
                </div>
              ))}
            </div>
          </div>

          <div className="settings-section">
            <h3 className="settings-title">Protection Modules</h3>
            <div className="settings-card">
              <SettingsToggle
                icon={<ShieldIcon />}
                title="Phishing Protection"
                desc="Detect and block phishing websites"
                checked={settings.modules.phishing_protection}
                onChange={() => toggleModule('phishing_protection')}
              />
              <SettingsToggle
                icon={<LockIcon />}
                title="Password Guard"
                desc="Protect password entry on untrusted sites"
                checked={settings.modules.password_guard}
                onChange={() => toggleModule('password_guard')}
              />
              <SettingsToggle
                icon={<CardIcon />}
                title="Payment Protection"
                desc="Enhanced security for payment forms"
                checked={settings.modules.payment_protection}
                onChange={() => toggleModule('payment_protection')}
              />
              <SettingsToggle
                icon={<LinkIcon />}
                title="Link Scanner"
                desc="Scan links before you click them"
                checked={settings.modules.link_scanner}
                onChange={() => toggleModule('link_scanner')}
              />
            </div>
          </div>

          <div className="settings-section">
            <h3 className="settings-title">Preferences</h3>
            <div className="settings-card">
              <SettingsToggle
                icon={<BellIcon />}
                title="Real-time Alerts"
                desc="Show notifications when threats are detected"
                checked={settings.preferences.real_time_alerts}
                onChange={() => togglePreference('real_time_alerts')}
              />
              <SettingsToggle
                icon={<BlockIcon />}
                title="Auto-block Dangerous Sites"
                desc="Automatically block sites with high risk scores"
                checked={settings.preferences.auto_block_dangerous}
                onChange={() => togglePreference('auto_block_dangerous')}
              />
              <SettingsToggle
                icon={<SpeakerIcon />}
                title="Notification Sound"
                desc="Play sound when threats are blocked"
                checked={settings.preferences.notification_sound}
                onChange={() => togglePreference('notification_sound')}
              />
              <SettingsToggle
                icon={<MoonIcon />}
                title="Dark Mode"
                desc="Use the dark theme across the dashboard"
                checked={settings.preferences.dark_mode}
                onChange={() => togglePreference('dark_mode')}
              />
            </div>
          </div>
        </>
      )}
    </>
  )
}

function SettingsToggle({ icon, title, desc, checked, onChange }) {
  return (
    <div className="settings-item">
      <div className="settings-item-info">
        <div className="settings-item-icon">{icon}</div>
        <div className="settings-item-text">
          <h4>{title}</h4>
          <p>{desc}</p>
        </div>
      </div>
      <label className="toggle">
        <input type="checkbox" checked={checked} onChange={onChange} />
        <span className="toggle-slider"></span>
      </label>
    </div>
  )
}
