import { useState, useEffect } from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { complianceApi } from '../api'

const STATUS_COLORS = {
  Passing: '#3fb950',
  Failing: '#f85149',
  'In Review': '#d29922',
}

const STATUS_BADGE = {
  Passing: 'bg-green-900/40 text-green-400 border border-green-700/40',
  Failing: 'bg-red-900/40 text-red-400 border border-red-700/40',
  'In Review': 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
}

function ControlRow({ control }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <>
      <tr
        className="border-b border-[#21262d] hover:bg-[#1c2128] transition-colors cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3 font-mono text-xs text-[#58a6ff]">{control.id}</td>
        <td className="px-4 py-3 text-gray-300 text-sm">{control.name}</td>
        <td className="px-4 py-3 text-[#8b949e] text-xs hidden md:table-cell">{control.category}</td>
        <td className="px-4 py-3">
          <span className={`severity-badge ${STATUS_BADGE[control.status] || ''}`}>{control.status}</span>
        </td>
        <td className="px-4 py-3 text-[#8b949e] text-xs hidden lg:table-cell">{control.owner}</td>
        <td className="px-4 py-3 text-[#8b949e] text-xs hidden xl:table-cell">{control.last_assessed}</td>
        <td className="px-4 py-3 text-[#8b949e] text-xs">
          <svg className={`w-4 h-4 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </td>
      </tr>
      {expanded && (
        <tr className="bg-[#0d1117]">
          <td colSpan={7} className="px-4 py-3 text-xs text-[#8b949e] leading-relaxed">
            {control.description}
          </td>
        </tr>
      )}
    </>
  )
}

export default function Compliance() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeFramework, setActiveFramework] = useState('all')
  const [statusFilter, setStatusFilter] = useState('')
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    complianceApi.getOverview().then((r) => {
      setData(r.data)
      setLoading(false)
    })
  }, [])

  async function exportCSV() {
    setExporting(true)
    try {
      const res = await complianceApi.exportCSV()
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = 'compliance_export.csv'
      a.click()
      window.URL.revokeObjectURL(url)
    } finally {
      setExporting(false)
    }
  }

  if (loading) return <div className="flex items-center justify-center h-64 text-[#8b949e]">Loading compliance data...</div>
  if (!data) return <div className="text-red-400">Failed to load compliance data.</div>

  const allControls = data.frameworks.flatMap((f) => f.controls)

  const filtered = allControls.filter((c) => {
    if (activeFramework !== 'all' && c.framework !== activeFramework) return false
    if (statusFilter && c.status !== statusFilter) return false
    return true
  })

  return (
    <div className="space-y-5">
      {/* Overall Score */}
      <div className="card p-5 flex flex-col sm:flex-row items-center gap-6">
        <div className="text-center">
          <div className="text-5xl font-bold text-white">{data.overall_score}%</div>
          <div className="text-xs text-[#8b949e] mt-1 uppercase tracking-wide">Overall Compliance Score</div>
        </div>
        <div className="flex gap-4 flex-wrap justify-center">
          {data.frameworks.map((fw) => (
            <div key={fw.framework} className="text-center">
              <div className="text-2xl font-bold text-white">{fw.score}%</div>
              <div className="text-xs text-[#8b949e]">{fw.framework}</div>
              <div className="text-[10px] text-green-400 mt-0.5">{fw.passing}/{fw.total} passing</div>
            </div>
          ))}
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {data.frameworks.map((fw) => {
          const pieData = [
            { name: 'Passing', value: fw.passing },
            { name: 'Failing', value: fw.failing },
            { name: 'In Review', value: fw.in_review },
          ].filter((d) => d.value > 0)

          return (
            <div key={fw.framework} className="card p-4">
              <h3 className="text-sm font-semibold text-white mb-1">{fw.framework}</h3>
              <div className="text-xs text-[#8b949e] mb-4">
                {fw.passing} passing · {fw.failing} failing · {fw.in_review} in review
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                  >
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={STATUS_COLORS[entry.name]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6, fontSize: 12 }} />
                  <Legend
                    iconSize={8}
                    wrapperStyle={{ fontSize: '11px', color: '#8b949e' }}
                    formatter={(value) => <span style={{ color: STATUS_COLORS[value] }}>{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )
        })}
      </div>

      {/* Controls table */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#30363d] flex-wrap gap-3">
          <h3 className="text-sm font-semibold text-white">Control Details</h3>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Framework tabs */}
            {['all', ...data.frameworks.map((f) => f.framework)].map((fw) => (
              <button
                key={fw}
                onClick={() => setActiveFramework(fw)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  activeFramework === fw
                    ? 'bg-[#58a6ff]/20 text-[#58a6ff] border border-[#58a6ff]/40'
                    : 'bg-[#21262d] text-[#8b949e] border border-[#30363d] hover:text-gray-200'
                }`}
              >
                {fw === 'all' ? 'All' : fw}
              </button>
            ))}
            <select
              className="input text-xs"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option>Passing</option>
              <option>Failing</option>
              <option>In Review</option>
            </select>
            <button
              onClick={exportCSV}
              disabled={exporting}
              className="btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
          </div>
        </div>

        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase text-[#8b949e] border-b border-[#30363d] bg-[#0d1117]">
              <th className="text-left px-4 py-3">Control ID</th>
              <th className="text-left px-4 py-3">Control Name</th>
              <th className="text-left px-4 py-3 hidden md:table-cell">Category</th>
              <th className="text-left px-4 py-3">Status</th>
              <th className="text-left px-4 py-3 hidden lg:table-cell">Owner</th>
              <th className="text-left px-4 py-3 hidden xl:table-cell">Last Assessed</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-8 text-[#8b949e]">No controls match your filters</td></tr>
            ) : filtered.map((c) => (
              <ControlRow key={`${c.framework}-${c.id}`} control={c} />
            ))}
          </tbody>
        </table>
        <div className="px-4 py-2 border-t border-[#21262d] text-xs text-[#8b949e]">
          {filtered.length} of {allControls.length} controls
        </div>
      </div>
    </div>
  )
}
