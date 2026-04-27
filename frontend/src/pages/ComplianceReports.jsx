import { useState, useEffect, useCallback } from 'react'
import { complianceReportsApi } from '../api'

const FRAMEWORKS = ['SOC2', 'HIPAA', 'NIST', 'CMMC']

const DATE_RANGE_OPTIONS = [
  { label: 'Last 30 days', days: 30 },
  { label: 'Last 90 days', days: 90 },
  { label: 'Last 6 months', days: 180 },
  { label: 'Last year', days: 365 },
  { label: 'Custom', days: null },
]

function computeDateRange(days) {
  const end = new Date()
  const start = new Date()
  start.setDate(start.getDate() - days)
  return { start: start.toISOString(), end: end.toISOString() }
}

function StatusBadge({ status }) {
  const map = {
    ready: 'bg-green-900/40 text-green-400 border border-green-700/40',
    generating: 'bg-blue-900/40 text-blue-400 border border-blue-700/40',
    error: 'bg-red-900/40 text-red-400 border border-red-700/40',
  }
  const cls = map[status] || 'bg-gray-800 text-gray-400 border border-gray-600'
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status === 'generating' && (
        <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
        </svg>
      )}
      {status}
    </span>
  )
}

function FrameworkBadge({ framework }) {
  const colors = {
    SOC2: 'text-purple-400 bg-purple-900/30 border-purple-700/40',
    HIPAA: 'text-cyan-400 bg-cyan-900/30 border-cyan-700/40',
    NIST: 'text-orange-400 bg-orange-900/30 border-orange-700/40',
    CMMC: 'text-yellow-400 bg-yellow-900/30 border-yellow-700/40',
  }
  const cls = colors[framework] || 'text-gray-400 bg-gray-800 border-gray-600'
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-mono font-medium border ${cls}`}>
      {framework}
    </span>
  )
}

export default function ComplianceReports() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState(null)
  const [genError, setGenError] = useState(null)

  const [framework, setFramework] = useState('SOC2')
  const [dateRangeOption, setDateRangeOption] = useState('Last 30 days')
  const [customStart, setCustomStart] = useState('')
  const [customEnd, setCustomEnd] = useState('')

  const [downloading, setDownloading] = useState({})
  const [deleting, setDeleting] = useState({})

  const fetchReports = useCallback(async () => {
    try {
      const res = await complianceReportsApi.getAll()
      setReports(res.data)
    } catch {
      setError('Failed to load reports.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchReports()
  }, [fetchReports])

  // Poll while any report is generating
  useEffect(() => {
    const hasGenerating = reports.some((r) => r.status === 'generating')
    if (!hasGenerating) return
    const interval = setInterval(fetchReports, 3000)
    return () => clearInterval(interval)
  }, [reports, fetchReports])

  async function handleGenerate() {
    setGenError(null)
    const option = DATE_RANGE_OPTIONS.find((o) => o.label === dateRangeOption)
    let start, end

    if (option?.days) {
      const range = computeDateRange(option.days)
      start = range.start
      end = range.end
    } else {
      if (!customStart || !customEnd) {
        setGenError('Please select a custom start and end date.')
        return
      }
      start = new Date(customStart).toISOString()
      end = new Date(customEnd).toISOString()
      if (new Date(start) >= new Date(end)) {
        setGenError('Start date must be before end date.')
        return
      }
    }

    setGenerating(true)
    try {
      await complianceReportsApi.generate({ framework, date_range_start: start, date_range_end: end })
      await fetchReports()
    } catch (err) {
      setGenError(err?.response?.data?.detail || 'Failed to generate report.')
    } finally {
      setGenerating(false)
    }
  }

  async function handleDownload(report) {
    setDownloading((prev) => ({ ...prev, [report.id]: true }))
    try {
      const res = await complianceReportsApi.download(report.id)
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `SentinelOps_${report.framework}_Report.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
    } catch {
      // silent — user sees status remains
    } finally {
      setDownloading((prev) => ({ ...prev, [report.id]: false }))
    }
  }

  async function handleDelete(report) {
    setDeleting((prev) => ({ ...prev, [report.id]: true }))
    try {
      await complianceReportsApi.delete(report.id)
      setReports((prev) => prev.filter((r) => r.id !== report.id))
    } catch {
      // silent
    } finally {
      setDeleting((prev) => ({ ...prev, [report.id]: false }))
    }
  }

  function formatDate(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
  }

  function formatDateTime(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white">Compliance Reports</h1>
        <p className="text-sm text-[#8b949e] mt-1">
          Generate audit-ready reports for SOC2, HIPAA, NIST 800-53, and CMMC
        </p>
      </div>

      {/* Generate Section */}
      <div className="card p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Generate New Report</h2>
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-[#8b949e]">Framework</label>
            <select
              className="input text-sm min-w-[140px]"
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
            >
              {FRAMEWORKS.map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs text-[#8b949e]">Date Range</label>
            <select
              className="input text-sm min-w-[160px]"
              value={dateRangeOption}
              onChange={(e) => setDateRangeOption(e.target.value)}
            >
              {DATE_RANGE_OPTIONS.map((o) => (
                <option key={o.label} value={o.label}>{o.label}</option>
              ))}
            </select>
          </div>

          {dateRangeOption === 'Custom' && (
            <>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#8b949e]">Start Date</label>
                <input
                  type="date"
                  className="input text-sm"
                  value={customStart}
                  onChange={(e) => setCustomStart(e.target.value)}
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#8b949e]">End Date</label>
                <input
                  type="date"
                  className="input text-sm"
                  value={customEnd}
                  onChange={(e) => setCustomEnd(e.target.value)}
                />
              </div>
            </>
          )}

          <button
            className="btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
            onClick={handleGenerate}
            disabled={generating}
          >
            {generating ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                </svg>
                Generating...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Generate Report
              </>
            )}
          </button>
        </div>

        {genError && (
          <div className="mt-3 text-xs text-red-400 bg-red-900/20 border border-red-700/40 rounded px-3 py-2">
            {genError}
          </div>
        )}
      </div>

      {/* Reports Table */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#30363d]">
          <h2 className="text-sm font-semibold text-white">Generated Reports</h2>
          <span className="text-xs text-[#8b949e]">{reports.length} report{reports.length !== 1 ? 's' : ''}</span>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12 text-[#8b949e] text-sm">
            Loading reports...
          </div>
        ) : error ? (
          <div className="py-8 text-center text-red-400 text-sm">{error}</div>
        ) : reports.length === 0 ? (
          <div className="py-12 text-center text-[#8b949e] text-sm">
            No reports yet. Generate your first compliance report above.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[10px] uppercase text-[#8b949e] border-b border-[#30363d] bg-[#0d1117]">
                  <th className="text-left px-4 py-3">Framework</th>
                  <th className="text-left px-4 py-3">Generated At</th>
                  <th className="text-left px-4 py-3 hidden md:table-cell">Date Range</th>
                  <th className="text-right px-4 py-3 hidden lg:table-cell">Alerts</th>
                  <th className="text-right px-4 py-3 hidden lg:table-cell">Threats</th>
                  <th className="text-left px-4 py-3">Status</th>
                  <th className="text-right px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((report) => (
                  <tr
                    key={report.id}
                    className="border-b border-[#21262d] hover:bg-[#1c2128] transition-colors"
                  >
                    <td className="px-4 py-3">
                      <FrameworkBadge framework={report.framework} />
                    </td>
                    <td className="px-4 py-3 text-gray-300 text-xs">
                      {formatDateTime(report.generated_at)}
                    </td>
                    <td className="px-4 py-3 text-[#8b949e] text-xs hidden md:table-cell">
                      {formatDate(report.date_range_start)} — {formatDate(report.date_range_end)}
                    </td>
                    <td className="px-4 py-3 text-right text-[#8b949e] text-xs hidden lg:table-cell">
                      {report.alert_count}
                    </td>
                    <td className="px-4 py-3 text-right text-[#8b949e] text-xs hidden lg:table-cell">
                      {report.threat_count}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={report.status} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleDownload(report)}
                          disabled={report.status !== 'ready' || downloading[report.id]}
                          title={report.status !== 'ready' ? 'Report not ready' : 'Download PDF'}
                          className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium bg-[#21262d] text-[#58a6ff] border border-[#30363d] hover:bg-[#30363d] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                        >
                          {downloading[report.id] ? (
                            <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                            </svg>
                          ) : (
                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                          )}
                          PDF
                        </button>

                        <button
                          onClick={() => handleDelete(report)}
                          disabled={deleting[report.id]}
                          title="Delete report"
                          className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium bg-[#21262d] text-red-400 border border-[#30363d] hover:bg-red-900/30 hover:border-red-700/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                        >
                          {deleting[report.id] ? (
                            <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                            </svg>
                          ) : (
                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          )}
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
