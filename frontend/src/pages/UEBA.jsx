import { useState, useEffect } from 'react'
import { uebaApi } from '../api'

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-900/40 text-red-400 border-red-700/40',
  HIGH: 'bg-orange-900/40 text-orange-400 border-orange-700/40',
  MEDIUM: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
  LOW: 'bg-blue-900/40 text-blue-400 border-blue-700/40',
}

const STATUS_OPTIONS = ['Open', 'Investigating', 'Resolved', 'False Positive']

function SeverityBadge({ severity }) {
  return (
    <span className={`severity-badge border ${SEVERITY_COLORS[severity] || SEVERITY_COLORS.LOW}`}>
      {severity}
    </span>
  )
}

function StatCard({ label, value, hint }) {
  return (
    <div className="card p-4">
      <div className="text-xs uppercase tracking-wide text-[#8b949e]">{label}</div>
      <div className="text-2xl font-bold text-white mt-1">{value}</div>
      {hint && <div className="text-[11px] text-[#6e7681] mt-1">{hint}</div>}
    </div>
  )
}

function ContributionBar({ score }) {
  const pct = Math.min(100, Math.max(0, score))
  const color = pct >= 80 ? 'bg-red-500' : pct >= 60 ? 'bg-orange-500' : pct >= 40 ? 'bg-yellow-500' : 'bg-blue-500'
  return (
    <div className="w-24 bg-[#0d1117] border border-[#30363d] rounded-sm h-2 overflow-hidden">
      <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  )
}

function UserDetailDrawer({ userId, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!userId) return
    setLoading(true)
    uebaApi.getUser(userId).then((r) => {
      setData(r.data)
      setLoading(false)
    })
  }, [userId])

  if (!userId) return null

  return (
    <div className="fixed inset-0 z-40 flex">
      <div className="flex-1 bg-black/50" onClick={onClose} />
      <div className="w-[640px] bg-[#161b22] border-l border-[#30363d] overflow-y-auto p-6 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">{data?.username || 'Loading…'}</h2>
            <p className="text-xs text-[#8b949e]">
              {data?.role} · {data?.department} {data?.is_privileged && '· Privileged'}
            </p>
          </div>
          <button onClick={onClose} className="btn-secondary text-xs">Close</button>
        </div>

        {loading || !data ? (
          <div className="text-[#8b949e] text-sm">Loading user profile…</div>
        ) : (
          <>
            <div>
              <h3 className="text-xs uppercase tracking-wide text-[#8b949e] mb-2">Behavioral Baseline</h3>
              {data.baseline ? (
                <div className="card p-3 text-xs">
                  <div className="text-[11px] text-[#8b949e] mb-2">
                    Refreshed {data.baseline_updated_at && new Date(data.baseline_updated_at).toLocaleString()} · {data.recent_event_count} events in last 7 days
                  </div>
                  <table className="w-full">
                    <thead className="text-[#8b949e]">
                      <tr><th className="text-left">Feature</th><th className="text-right">Mean</th><th className="text-right">Std</th><th className="text-right">Days</th></tr>
                    </thead>
                    <tbody className="font-mono text-gray-200">
                      {Object.entries(data.baseline).map(([feat, b]) => (
                        <tr key={feat} className="border-t border-[#30363d]">
                          <td className="py-1">{feat}</td>
                          <td className="text-right">{b.mean}</td>
                          <td className="text-right">{b.std}</td>
                          <td className="text-right">{b.n}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {Object.values(data.baseline).some((b) => b.low_confidence) && (
                    <div className="mt-2 text-[11px] text-yellow-400">
                      Low confidence — fewer than 5 days of history.
                    </div>
                  )}
                </div>
              ) : (
                <div className="card p-3 text-xs text-[#8b949e]">No baseline yet — recompute to bootstrap.</div>
              )}
            </div>

            <div>
              <h3 className="text-xs uppercase tracking-wide text-[#8b949e] mb-2">Recent Anomalies</h3>
              {data.recent_anomalies?.length ? (
                <div className="space-y-2">
                  {data.recent_anomalies.map((a) => (
                    <div key={a.id} className="card p-3">
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <SeverityBadge severity={a.severity} />
                        <span className="text-[11px] text-[#8b949e]">
                          {new Date(a.detected_at).toLocaleString()} · score {a.score}
                        </span>
                      </div>
                      <div className="text-xs text-gray-300">{a.summary}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="card p-3 text-xs text-[#8b949e]">No anomalies on file.</div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default function UEBA() {
  const [stats, setStats] = useState(null)
  const [anomalies, setAnomalies] = useState([])
  const [users, setUsers] = useState([])
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterStatus, setFilterStatus] = useState('Open')
  const [openUserId, setOpenUserId] = useState(null)
  const [busy, setBusy] = useState(false)
  const [expandedRow, setExpandedRow] = useState(null)

  function load() {
    Promise.all([
      uebaApi.getStats(),
      uebaApi.getUsers(),
      uebaApi.getAnomalies({
        ...(filterSeverity ? { severity: filterSeverity } : {}),
        ...(filterStatus ? { status: filterStatus } : {}),
      }),
    ]).then(([s, u, a]) => {
      setStats(s.data)
      setUsers(u.data)
      setAnomalies(a.data)
    })
  }

  useEffect(load, [filterSeverity, filterStatus])

  async function recompute() {
    setBusy(true)
    try {
      await uebaApi.recompute()
      load()
    } finally {
      setBusy(false)
    }
  }

  async function setAnomalyStatus(id, status) {
    await uebaApi.setAnomalyStatus(id, status)
    load()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">User & Entity Behavior Analytics</h1>
          <p className="text-sm text-[#8b949e] mt-1">
            Per-user behavioral baselines (statistical, not ML) flag deviations across login volume, failed auth, after-hours activity, source-IP diversity, privileged commands, and resource access.
          </p>
        </div>
        <button onClick={recompute} disabled={busy} className="btn-primary text-xs disabled:opacity-50">
          {busy ? 'Recomputing…' : 'Recompute Baselines'}
        </button>
      </div>

      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatCard label="Monitored Users" value={stats.user_count} />
          <StatCard label="Events Indexed" value={stats.event_count.toLocaleString()} />
          <StatCard label="Open Anomalies" value={stats.open_anomalies} />
          <StatCard
            label="Last Baseline"
            value={stats.last_baseline_at ? new Date(stats.last_baseline_at).toLocaleDateString() : '—'}
            hint={stats.last_baseline_at ? new Date(stats.last_baseline_at).toLocaleTimeString() : 'never run'}
          />
        </div>
      )}

      {stats && Object.keys(stats.by_severity || {}).length > 0 && (
        <div className="card p-4">
          <div className="text-xs uppercase tracking-wide text-[#8b949e] mb-2">Open Anomalies by Severity</div>
          <div className="flex gap-2 flex-wrap">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <div key={sev} className={`px-3 py-1 rounded-md border ${SEVERITY_COLORS[sev]}`}>
                <span className="text-xs font-semibold mr-2">{sev}</span>
                <span className="font-mono">{stats.by_severity[sev] || 0}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d] flex items-center justify-between">
          <div className="text-sm font-semibold text-white">Anomaly Events</div>
          <div className="flex gap-2">
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="text-xs bg-[#0d1117] border border-[#30363d] text-gray-200 rounded px-2 py-1"
            >
              <option value="">All severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="text-xs bg-[#0d1117] border border-[#30363d] text-gray-200 rounded px-2 py-1"
            >
              <option value="">All statuses</option>
              {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
        <table className="w-full text-sm">
          <thead className="bg-[#0d1117] text-[#8b949e]">
            <tr>
              <th className="text-left px-4 py-2">User</th>
              <th className="text-left px-4 py-2">Detected</th>
              <th className="text-left px-4 py-2">Severity</th>
              <th className="text-left px-4 py-2">Score</th>
              <th className="text-left px-4 py-2">Summary</th>
              <th className="text-left px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {anomalies.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-[#8b949e]">No anomalies match the current filters.</td></tr>
            ) : anomalies.map((a) => (
              <Row
                key={a.id}
                a={a}
                expanded={expandedRow === a.id}
                onToggle={() => setExpandedRow(expandedRow === a.id ? null : a.id)}
                onUserClick={() => setOpenUserId(a.user_id)}
                onStatusChange={(s) => setAnomalyStatus(a.id, s)}
              />
            ))}
          </tbody>
        </table>
      </div>

      <div className="card overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d] text-sm font-semibold text-white">Monitored Users</div>
        <table className="w-full text-sm">
          <thead className="bg-[#0d1117] text-[#8b949e]">
            <tr>
              <th className="text-left px-4 py-2">User</th>
              <th className="text-left px-4 py-2">Role / Dept</th>
              <th className="text-left px-4 py-2">Privileged</th>
              <th className="text-left px-4 py-2">Open Anomalies</th>
              <th className="text-left px-4 py-2">Max Score (7d)</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-t border-[#30363d] hover:bg-[#161b22] cursor-pointer" onClick={() => setOpenUserId(u.id)}>
                <td className="px-4 py-2 font-mono text-gray-200">{u.username}</td>
                <td className="px-4 py-2 text-[#8b949e]">{u.role} · {u.department}</td>
                <td className="px-4 py-2">{u.is_privileged ? <span className="severity-badge bg-purple-900/40 text-purple-400 border border-purple-700/40">YES</span> : <span className="text-[#6e7681]">no</span>}</td>
                <td className="px-4 py-2">{u.open_anomaly_count}</td>
                <td className="px-4 py-2"><div className="flex items-center gap-2"><span className="font-mono text-gray-200">{u.max_recent_score}</span><ContributionBar score={u.max_recent_score} /></div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <UserDetailDrawer userId={openUserId} onClose={() => setOpenUserId(null)} />
    </div>
  )
}

function Row({ a, expanded, onToggle, onUserClick, onStatusChange }) {
  return (
    <>
      <tr className="border-t border-[#30363d] hover:bg-[#161b22]">
        <td className="px-4 py-2">
          <button className="font-mono text-[#58a6ff] hover:underline" onClick={onUserClick}>{a.username}</button>
        </td>
        <td className="px-4 py-2 text-xs text-[#8b949e]">{new Date(a.detected_at).toLocaleString()}</td>
        <td className="px-4 py-2"><SeverityBadge severity={a.severity} /></td>
        <td className="px-4 py-2"><div className="flex items-center gap-2"><span className="font-mono text-gray-200">{a.score}</span><ContributionBar score={a.score} /></div></td>
        <td className="px-4 py-2 text-xs">
          <button className="text-left text-gray-200 hover:text-[#58a6ff]" onClick={onToggle}>
            {a.summary}
          </button>
        </td>
        <td className="px-4 py-2">
          <select
            value={a.status}
            onChange={(e) => onStatusChange(e.target.value)}
            className="text-xs bg-[#0d1117] border border-[#30363d] text-gray-200 rounded px-2 py-1"
          >
            {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </td>
      </tr>
      {expanded && a.contributing_features && (
        <tr className="bg-[#0d1117]">
          <td colSpan={6} className="px-4 py-3">
            <div className="text-[11px] uppercase tracking-wide text-[#8b949e] mb-2">Feature Contributions</div>
            <table className="w-full text-xs font-mono">
              <thead className="text-[#8b949e]">
                <tr>
                  <th className="text-left">Feature</th>
                  <th className="text-right">Observed</th>
                  <th className="text-right">Mean</th>
                  <th className="text-right">Std</th>
                  <th className="text-right">Z</th>
                  <th className="text-right">Score</th>
                </tr>
              </thead>
              <tbody className="text-gray-200">
                {a.contributing_features.map((c) => (
                  <tr key={c.feature} className="border-t border-[#30363d]">
                    <td className="py-1">{c.feature}</td>
                    <td className="text-right">{c.observed}</td>
                    <td className="text-right">{c.mean}</td>
                    <td className="text-right">{c.std}</td>
                    <td className="text-right">{c.z}</td>
                    <td className="text-right">{c.score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </td>
        </tr>
      )}
    </>
  )
}
