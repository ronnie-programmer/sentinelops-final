import { useState, useEffect } from 'react'
import api from '../api'

function StatusBadge({ status }) {
  const map = {
    sent: 'bg-green-900/40 text-green-400 border-green-700/40',
    skipped: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
    error: 'bg-red-900/40 text-red-400 border-red-700/40',
    pending: 'bg-gray-800 text-gray-400 border-gray-700',
  }
  return (
    <span className={`severity-badge border ${map[status] || map.pending}`}>{status}</span>
  )
}

export default function NotificationSettings() {
  const [settings, setSettings] = useState({
    slack_enabled: false,
    slack_webhook_url: '',
    pagerduty_enabled: false,
    pagerduty_integration_key: '',
    pagerduty_severity_threshold: 'HIGH',
  })
  const [notifications, setNotifications] = useState([])
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    api.get('/notifications/settings').then((r) => setSettings(r.data))
    api.get('/notifications/').then((r) => setNotifications(r.data))
  }, [])

  async function save() {
    setSaving(true)
    try {
      await api.post('/notifications/settings', settings)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } finally {
      setSaving(false)
    }
  }

  async function test(channel) {
    setTesting(channel)
    try {
      await api.post('/notifications/test', { channel })
      const r = await api.get('/notifications/')
      setNotifications(r.data)
    } finally {
      setTesting('')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Notification Settings</h1>
        <p className="text-sm text-[#8b949e] mt-1">
          Route critical alerts to Slack and PagerDuty automatically.
        </p>
      </div>

      {/* Slack */}
      <div className="card p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-[#4A154B]/30 border border-[#4A154B]/50 rounded-lg flex items-center justify-center text-sm">
              S
            </div>
            <div>
              <div className="font-semibold text-white text-sm">Slack</div>
              <div className="text-xs text-[#8b949e]">Incoming Webhook</div>
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={settings.slack_enabled}
              onChange={(e) => setSettings({ ...settings, slack_enabled: e.target.checked })}
              className="w-4 h-4 accent-[#58a6ff]"
            />
            <span className="text-sm text-gray-200">Enabled</span>
          </label>
        </div>
        <div>
          <label className="block text-xs text-[#8b949e] mb-1">Webhook URL</label>
          <input
            type="text"
            className="input w-full font-mono text-xs"
            placeholder="https://hooks.slack.com/services/T00000000/B00000000/XXXX"
            value={settings.slack_webhook_url}
            onChange={(e) => setSettings({ ...settings, slack_webhook_url: e.target.value })}
          />
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => test('slack')}
            disabled={!!testing}
            className="btn-secondary text-xs disabled:opacity-50"
          >
            {testing === 'slack' ? 'Sending...' : 'Send Test Alert'}
          </button>
        </div>
      </div>

      {/* PagerDuty */}
      <div className="card p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-green-900/30 border border-green-700/50 rounded-lg flex items-center justify-center text-sm text-green-400">
              PD
            </div>
            <div>
              <div className="font-semibold text-white text-sm">PagerDuty</div>
              <div className="text-xs text-[#8b949e]">Events API v2</div>
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={settings.pagerduty_enabled}
              onChange={(e) => setSettings({ ...settings, pagerduty_enabled: e.target.checked })}
              className="w-4 h-4 accent-[#58a6ff]"
            />
            <span className="text-sm text-gray-200">Enabled</span>
          </label>
        </div>
        <div>
          <label className="block text-xs text-[#8b949e] mb-1">Integration Key</label>
          <input
            type="password"
            className="input w-full font-mono text-xs"
            placeholder="your-32-char-integration-key"
            value={settings.pagerduty_integration_key}
            onChange={(e) => setSettings({ ...settings, pagerduty_integration_key: e.target.value })}
          />
        </div>
        <div>
          <label className="block text-xs text-[#8b949e] mb-1">Minimum Severity to Alert</label>
          <select
            className="input text-sm"
            value={settings.pagerduty_severity_threshold}
            onChange={(e) => setSettings({ ...settings, pagerduty_severity_threshold: e.target.value })}
          >
            {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <button
          onClick={() => test('pagerduty')}
          disabled={!!testing}
          className="btn-secondary text-xs disabled:opacity-50"
        >
          {testing === 'pagerduty' ? 'Sending...' : 'Send Test Alert'}
        </button>
      </div>

      {/* Save */}
      <div className="flex justify-end">
        <button onClick={save} disabled={saving} className="btn-primary disabled:opacity-50">
          {saved ? 'Saved!' : saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>

      {/* Recent notifications */}
      <div className="card">
        <div className="px-4 py-3 border-b border-[#30363d]">
          <h2 className="text-sm font-semibold text-white">Recent Notifications</h2>
        </div>
        {notifications.length === 0 ? (
          <div className="py-8 text-center text-[#8b949e] text-sm">No notifications sent yet</div>
        ) : (
          <div className="divide-y divide-[#21262d]">
            {notifications.slice(0, 20).map((n) => (
              <div key={n.id} className="px-4 py-3 flex items-center gap-4">
                <span className="text-xs font-mono text-[#8b949e] w-16 uppercase">{n.channel}</span>
                <StatusBadge status={n.status} />
                {n.threat_id && (
                  <span className="text-xs text-[#8b949e]">Threat #{n.threat_id}</span>
                )}
                <span className="text-xs text-[#8b949e] ml-auto">
                  {new Date(n.attempted_at).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
