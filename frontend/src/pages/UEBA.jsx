import { useState, useEffect, useCallback } from 'react'
import { uebaApi } from '../api'

const SCORE_COLOR = (score) => {
  if (score >= 70) return 'text-red-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

const SCORE_BG = (score) => {
  if (score >= 70) return 'bg-red-500'
  if (score >= 40) return 'bg-yellow-500'
  return 'bg-green-500'
}

const SCORE_BADGE_BG = (score) => {
  if (score >= 70) return 'bg-red-500/20 text-red-400 border border-red-500/30'
  if (score >= 40) return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
  return 'bg-green-500/20 text-green-400 border border-green-500/30'
}

function AnomalyBadge({ isAnomaly }) {
  return isAnomaly ? (
    <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
      Anomaly
    </span>
  ) : (
    <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/30">
      Normal
    </span>
  )
}

function ScoreBar({ score }) {
  const pct = score ?? 0
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-2 bg-[#21262d] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${SCORE_BG(pct)}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={`text-xs font-mono font-semibold ${SCORE_COLOR(pct)}`}>{pct}</span>
    </div>
  )
}

function UserProfileModal({ username, onClose }) {
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    uebaApi.getUserProfile(username)
      .then((r) => setProfile(r.data))
      .catch(() => setError('Failed to load profile'))
      .finally(() => setLoading(false))
  }, [username])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-lg font-semibold text-white">{username}</h3>
            <p className="text-sm text-[#8b949e]">User behavior profile</p>
          </div>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {loading && <p className="text-[#8b949e] text-sm">Loading profile...</p>}
        {error && <p className="text-red-400 text-sm">{error}</p>}

        {profile && (
          <>
            {/* Baseline info */}
            <div className="grid grid-cols-3 gap-3 mb-5">
              <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-3 text-center">
                <div className="text-xl font-bold text-white">{profile.stats.total_events}</div>
                <div className="text-xs text-[#8b949e] mt-0.5">Total Events</div>
              </div>
              <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-3 text-center">
                <div className="text-xl font-bold text-red-400">{profile.stats.anomaly_count}</div>
                <div className="text-xs text-[#8b949e] mt-0.5">Anomalies</div>
              </div>
              <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-3 text-center">
                <div className={`text-xl font-bold ${SCORE_COLOR(profile.stats.avg_anomaly_score ?? 0)}`}>
                  {profile.stats.avg_anomaly_score ?? 'N/A'}
                </div>
                <div className="text-xs text-[#8b949e] mt-0.5">Avg Score</div>
              </div>
            </div>

            {/* Baseline metadata */}
            <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-3 mb-5">
              <div className="text-xs font-medium text-[#8b949e] uppercase tracking-wider mb-2">Baseline</div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  <span className="text-[#8b949e]">Entity type: </span>
                  <span className="text-white capitalize">{profile.baseline.entity_type}</span>
                </div>
                <div>
                  <span className="text-[#8b949e]">Training events: </span>
                  <span className="text-white">{profile.baseline.event_count}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-[#8b949e]">Last trained: </span>
                  <span className="text-white">
                    {profile.baseline.last_trained_at
                      ? new Date(profile.baseline.last_trained_at).toLocaleString()
                      : 'Never'}
                  </span>
                </div>
              </div>
            </div>

            {/* Recent events */}
            <div>
              <div className="text-xs font-medium text-[#8b949e] uppercase tracking-wider mb-2">Recent Events</div>
              {profile.recent_events.length === 0 ? (
                <p className="text-sm text-[#8b949e]">No events recorded.</p>
              ) : (
                <div className="space-y-1.5">
                  {profile.recent_events.map((ev) => (
                    <div key={ev.id} className="flex items-center justify-between bg-[#0d1117] border border-[#30363d] rounded px-3 py-2">
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-[#8b949e] font-mono capitalize">{ev.event_type.replace(/_/g, ' ')}</span>
                        <AnomalyBadge isAnomaly={ev.is_anomaly} />
                      </div>
                      <div className="flex items-center gap-3">
                        <ScoreBar score={ev.anomaly_score} />
                        <span className="text-xs text-[#8b949e]">{new Date(ev.detected_at).toLocaleString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default function UEBA() {
  const [topEvents, setTopEvents] = useState([])
  const [allEvents, setAllEvents] = useState([])
  const [users, setUsers] = useState([])
  const [selectedUser, setSelectedUser] = useState(null)
  const [filterAnomaly, setFilterAnomaly] = useState(null)
  const [retrainStatus, setRetrainStatus] = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    try {
      const [topRes, eventsRes, usersRes] = await Promise.all([
        uebaApi.getTopEvents(),
        uebaApi.getEvents({ limit: 100, ...(filterAnomaly !== null ? { is_anomaly: filterAnomaly } : {}) }),
        uebaApi.getUsers(),
      ])
      setTopEvents(topRes.data)
      setAllEvents(eventsRes.data)
      setUsers(usersRes.data)
    } catch (_) {
      // silently fail; table stays empty
    } finally {
      setLoading(false)
    }
  }, [filterAnomaly])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleRetrain = async () => {
    setRetrainStatus('starting')
    try {
      await uebaApi.retrain()
      setRetrainStatus('started')
      setTimeout(() => setRetrainStatus(null), 4000)
    } catch (_) {
      setRetrainStatus('error')
      setTimeout(() => setRetrainStatus(null), 4000)
    }
  }

  const todayEvents = allEvents.filter((e) => {
    const d = new Date(e.detected_at)
    const now = new Date()
    return d.toDateString() === now.toDateString()
  })
  const anomalyCount = allEvents.filter((e) => e.is_anomaly).length
  const highRiskUsers = [...new Set(
    allEvents.filter((e) => (e.anomaly_score ?? 0) >= 70).map((e) => e.username)
  )].length
  const baselinedUsers = users.filter((u) => u.last_trained_at).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">User &amp; Entity Behavior Analytics</h1>
          <p className="text-[#8b949e] text-sm mt-1">ML-based anomaly detection — deviations from established baselines</p>
        </div>
        <button
          onClick={handleRetrain}
          disabled={retrainStatus === 'starting'}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-[#58a6ff]/10 text-[#58a6ff] border border-[#58a6ff]/30 hover:bg-[#58a6ff]/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {retrainStatus === 'starting' ? 'Starting...' : retrainStatus === 'started' ? 'Retraining...' : 'Retrain Baselines'}
        </button>
      </div>

      {retrainStatus === 'error' && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2 text-red-400 text-sm">
          Retraining request failed. Check backend logs.
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Events Today', value: todayEvents.length, color: 'text-[#58a6ff]' },
          { label: 'Anomalies Detected', value: anomalyCount, color: 'text-red-400' },
          { label: 'High-Risk Users', value: highRiskUsers, color: 'text-orange-400' },
          { label: 'Users Baselined', value: baselinedUsers, color: 'text-green-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
            <div className={`text-3xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-sm text-[#8b949e] mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Anomaly Events Table */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[#30363d] flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Anomaly Events</h2>
          <div className="flex gap-2">
            {[
              { label: 'All', value: null },
              { label: 'Anomalies', value: 1 },
              { label: 'Normal', value: 0 },
            ].map((f) => (
              <button
                key={f.label}
                onClick={() => setFilterAnomaly(f.value)}
                className={`px-3 py-1 text-xs rounded-md transition-colors ${
                  filterAnomaly === f.value
                    ? 'bg-[#58a6ff]/20 text-[#58a6ff] border border-[#58a6ff]/30'
                    : 'text-[#8b949e] hover:text-white border border-transparent hover:border-[#30363d]'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="px-5 py-10 text-center text-[#8b949e] text-sm">Loading events...</div>
        ) : allEvents.length === 0 ? (
          <div className="px-5 py-10 text-center text-[#8b949e] text-sm">No events found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#30363d] text-[#8b949e] text-xs uppercase tracking-wide">
                  <th className="px-5 py-3 text-left font-medium">Username</th>
                  <th className="px-5 py-3 text-left font-medium">Event Type</th>
                  <th className="px-5 py-3 text-left font-medium">Anomaly Score</th>
                  <th className="px-5 py-3 text-left font-medium">Status</th>
                  <th className="px-5 py-3 text-left font-medium">Detected At</th>
                  <th className="px-5 py-3 text-left font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {allEvents.map((ev) => (
                  <tr key={ev.id} className="border-b border-[#30363d]/50 hover:bg-[#21262d] transition-colors">
                    <td className="px-5 py-3">
                      <button
                        onClick={() => setSelectedUser(ev.username)}
                        className="text-[#58a6ff] hover:text-[#79c0ff] font-medium transition-colors text-left"
                      >
                        {ev.username}
                      </button>
                    </td>
                    <td className="px-5 py-3 text-white capitalize">{ev.event_type.replace(/_/g, ' ')}</td>
                    <td className="px-5 py-3">
                      <ScoreBar score={ev.anomaly_score} />
                    </td>
                    <td className="px-5 py-3">
                      <AnomalyBadge isAnomaly={ev.is_anomaly} />
                    </td>
                    <td className="px-5 py-3 text-[#8b949e]">
                      {new Date(ev.detected_at).toLocaleString()}
                    </td>
                    <td className="px-5 py-3">
                      <button
                        onClick={() => setSelectedUser(ev.username)}
                        className="text-xs text-[#8b949e] hover:text-[#58a6ff] transition-colors"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* User Profiles */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[#30363d]">
          <h2 className="text-base font-semibold text-white">User Baselines</h2>
          <p className="text-xs text-[#8b949e] mt-0.5">Click a user to view their behavior profile</p>
        </div>
        {users.length === 0 ? (
          <div className="px-5 py-8 text-center text-[#8b949e] text-sm">No baselines found.</div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-0 divide-x divide-y divide-[#30363d]">
            {users.map((user) => {
              const userEvents = allEvents.filter((e) => e.username === user.username)
              const userAnomalies = userEvents.filter((e) => e.is_anomaly).length
              const scores = userEvents.map((e) => e.anomaly_score ?? 0)
              const maxScore = scores.length ? Math.max(...scores) : 0
              return (
                <button
                  key={user.id}
                  onClick={() => setSelectedUser(user.username)}
                  className="p-4 text-left hover:bg-[#21262d] transition-colors"
                >
                  <div className="text-sm font-medium text-white truncate">{user.username}</div>
                  <div className="text-xs text-[#8b949e] mt-1 capitalize">{user.entity_type}</div>
                  <div className="mt-3 flex items-center justify-between">
                    <span className="text-xs text-[#8b949e]">{userAnomalies} anomalies</span>
                    <span className={`text-xs font-semibold ${SCORE_COLOR(maxScore)}`}>
                      peak {maxScore}
                    </span>
                  </div>
                  <div className="mt-1.5 w-full h-1 bg-[#21262d] rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${SCORE_BG(maxScore)}`}
                      style={{ width: `${maxScore}%` }}
                    />
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </div>

      {/* User Profile Modal */}
      {selectedUser && (
        <UserProfileModal username={selectedUser} onClose={() => setSelectedUser(null)} />
      )}
    </div>
  )
}
