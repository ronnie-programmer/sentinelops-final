import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { dashboardApi } from '../api'

const SEV_COLORS = {
  CRITICAL: '#f85149',
  HIGH: '#d29922',
  MEDIUM: '#e3b341',
  LOW: '#58a6ff',
}

const STAT_CARDS = (stats) => [
  { label: 'Total Threats', value: stats.total_threats, color: 'text-white', bg: 'bg-[#161b22]' },
  { label: 'Critical', value: stats.critical_threats, color: 'text-red-400', bg: 'bg-red-900/10 border-red-800/30' },
  { label: 'High', value: stats.high_threats, color: 'text-orange-400', bg: 'bg-orange-900/10 border-orange-800/30' },
  { label: 'Open', value: stats.open_threats, color: 'text-yellow-400', bg: 'bg-yellow-900/10 border-yellow-800/30' },
  { label: 'Resolved', value: stats.resolved_threats, color: 'text-green-400', bg: 'bg-green-900/10 border-green-800/30' },
  { label: 'Total Assets', value: stats.total_assets, color: 'text-blue-400', bg: 'bg-blue-900/10 border-blue-800/30' },
  { label: 'Vulnerable Assets', value: stats.vulnerable_assets, color: 'text-orange-400', bg: 'bg-orange-900/10 border-orange-800/30' },
  { label: 'Unread Alerts', value: stats.unread_alerts, color: 'text-red-400', bg: 'bg-red-900/10 border-red-800/30' },
]

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    dashboardApi.getStats().then((r) => {
      setStats(r.data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) return <div className="flex items-center justify-center h-64 text-[#8b949e]">Loading dashboard...</div>
  if (!stats) return <div className="text-red-400">Failed to load dashboard data.</div>

  const pieData = Object.entries(stats.threats_by_type || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6)

  const PIE_COLORS = ['#58a6ff', '#f85149', '#d29922', '#3fb950', '#bc8cff', '#8b949e']

  const cards = STAT_CARDS(stats)

  return (
    <div className="space-y-6">
      {/* Stat grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {cards.map((card) => (
          <div key={card.label} className={`card border ${card.bg} p-4`}>
            <div className="text-xs text-[#8b949e] uppercase tracking-wide mb-1">{card.label}</div>
            <div className={`text-3xl font-bold ${card.color}`}>{card.value}</div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Threat trend */}
        <div className="card p-4">
          <h3 className="text-sm font-semibold text-white mb-4">Threats — Last 7 Days</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={stats.threats_by_day}>
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#8b949e' }} tickFormatter={(v) => v.slice(5)} />
              <YAxis tick={{ fontSize: 10, fill: '#8b949e' }} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6, fontSize: 12 }}
                labelStyle={{ color: '#8b949e' }}
                itemStyle={{ color: '#58a6ff' }}
              />
              <Bar dataKey="count" fill="#58a6ff" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Threat types pie */}
        <div className="card p-4">
          <h3 className="text-sm font-semibold text-white mb-4">Threats by Type</h3>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={false} fontSize={9}>
                {pieData.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent threats */}
      <div className="card">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#30363d]">
          <h3 className="text-sm font-semibold text-white">Recent Threats</h3>
          <button onClick={() => navigate('/threats')} className="text-xs text-[#58a6ff] hover:underline">View all</button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase text-[#8b949e] border-b border-[#21262d]">
              <th className="text-left px-4 py-2">Title</th>
              <th className="text-left px-4 py-2 hidden md:table-cell">Type</th>
              <th className="text-left px-4 py-2">Severity</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2 hidden lg:table-cell">Time</th>
            </tr>
          </thead>
          <tbody>
            {(stats.recent_threats || []).map((t) => (
              <tr key={t.id} className="table-row" onClick={() => navigate('/threats')}>
                <td className="px-4 py-2.5 text-gray-300 max-w-xs truncate">{t.title}</td>
                <td className="px-4 py-2.5 text-[#8b949e] hidden md:table-cell">{t.threat_type}</td>
                <td className="px-4 py-2.5">
                  <span className={`severity-badge severity-${t.severity.toLowerCase()}`}>{t.severity}</span>
                </td>
                <td className="px-4 py-2.5">
                  <span className={`severity-badge status-${t.status.toLowerCase().replace(' ', '-')}`}>{t.status}</span>
                </td>
                <td className="px-4 py-2.5 text-[#8b949e] text-xs hidden lg:table-cell">
                  {new Date(t.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
