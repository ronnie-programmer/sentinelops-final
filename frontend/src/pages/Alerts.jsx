import { useState, useEffect, useCallback } from 'react'
import { alertsApi } from '../api'

function StatusBadge({ s }) {
  const map = {
    Pending: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
    Sent: 'bg-blue-900/40 text-blue-400 border-blue-700/40',
    Acknowledged: 'bg-green-900/40 text-green-400 border-green-700/40',
  }
  return <span className={`severity-badge border ${map[s] || 'bg-gray-800 text-gray-400 border-gray-700'}`}>{s}</span>
}

function SeverityBadge({ s }) {
  const cls = { CRITICAL: 'severity-critical', HIGH: 'severity-high', MEDIUM: 'severity-medium', LOW: 'severity-low' }
  return <span className={`severity-badge ${cls[s] || ''}`}>{s}</span>
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [ackingAll, setAckingAll] = useState(false)

  const load = useCallback(() => {
    const params = statusFilter ? { status: statusFilter } : {}
    alertsApi.getAll(params).then((r) => {
      setAlerts(r.data)
      setLoading(false)
    })
  }, [statusFilter])

  useEffect(() => { load() }, [load])

  async function acknowledge(id) {
    await alertsApi.acknowledge(id)
    load()
  }

  async function acknowledgeAll() {
    setAckingAll(true)
    try {
      await alertsApi.acknowledgeAll()
      load()
    } finally {
      setAckingAll(false)
    }
  }

  const unread = alerts.filter((a) => a.status !== 'Acknowledged').length

  return (
    <div className="space-y-4">
      {/* Summary row */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total Alerts', value: alerts.length, color: 'text-white' },
          { label: 'Unread', value: unread, color: 'text-red-400' },
          { label: 'Acknowledged', value: alerts.length - unread, color: 'text-green-400' },
        ].map((c) => (
          <div key={c.label} className="card p-4">
            <div className="text-xs text-[#8b949e] uppercase tracking-wide mb-1">{c.label}</div>
            <div className={`text-2xl font-bold ${c.color}`}>{c.value}</div>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex gap-2">
          {['', 'Pending', 'Sent', 'Acknowledged'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                statusFilter === s
                  ? 'bg-[#58a6ff]/20 text-[#58a6ff] border border-[#58a6ff]/40'
                  : 'bg-[#21262d] text-[#8b949e] border border-[#30363d] hover:text-gray-200'
              }`}
            >
              {s || 'All'}
            </button>
          ))}
        </div>
        {unread > 0 && (
          <button onClick={acknowledgeAll} disabled={ackingAll} className="btn-secondary text-xs disabled:opacity-50">
            {ackingAll ? 'Acknowledging...' : `Acknowledge All (${unread})`}
          </button>
        )}
      </div>

      {/* Alerts list */}
      <div className="card divide-y divide-[#21262d]">
        {loading ? (
          <div className="py-12 text-center text-[#8b949e]">Loading alerts...</div>
        ) : alerts.length === 0 ? (
          <div className="py-12 text-center">
            <div className="text-[#8b949e] mb-1">No alerts found</div>
            <div className="text-xs text-[#8b949e]/60">Alerts are triggered when HIGH or CRITICAL threats are created</div>
          </div>
        ) : alerts.map((alert) => (
          <div key={alert.id} className={`p-4 transition-colors ${alert.status === 'Acknowledged' ? 'opacity-60' : 'hover:bg-[#1c2128]'}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <SeverityBadge s={alert.severity} />
                  <StatusBadge s={alert.status} />
                  <span className="text-[10px] text-[#8b949e]">Threat #{alert.threat_id}</span>
                </div>
                <p className="text-sm text-gray-300 leading-snug">{alert.message}</p>
                {alert.summary && (
                  <p className="text-xs text-[#8b949e] mt-1 leading-snug line-clamp-2">
                    {alert.summary}
                  </p>
                )}
                <div className="mt-2 flex items-center gap-4 text-[10px] text-[#8b949e]">
                  <span>
                    <span className="text-[#8b949e]/60">Recipient:</span>{' '}
                    <span className="text-[#8b949e]">{alert.recipient || 'soc-team@sentinelops.internal'}</span>
                  </span>
                  <span>
                    <span className="text-[#8b949e]/60">Triggered:</span>{' '}
                    {new Date(alert.created_at).toLocaleString()}
                  </span>
                  {alert.acknowledged_at && (
                    <span>
                      <span className="text-[#8b949e]/60">Acked:</span>{' '}
                      {new Date(alert.acknowledged_at).toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
              {alert.status !== 'Acknowledged' && (
                <button
                  onClick={() => acknowledge(alert.id)}
                  className="flex-shrink-0 text-xs px-3 py-1.5 bg-green-900/20 hover:bg-green-900/40 text-green-400 border border-green-700/30 rounded-md transition-colors"
                >
                  Acknowledge
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      <p className="text-xs text-[#8b949e]">
        Alerts are automatically triggered for <strong className="text-white">HIGH</strong> and{' '}
        <strong className="text-red-400">CRITICAL</strong> threats. Email delivery is simulated — check the log above to manage notifications.
      </p>
    </div>
  )
}
