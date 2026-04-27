import { useState, useEffect, useCallback } from 'react'
import { iocApi } from '../api'

function scoreColor(score) {
  if (score === null || score === undefined) return 'text-[#8b949e]'
  if (score >= 75) return 'text-red-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

function scoreBg(score) {
  if (score === null || score === undefined) return 'bg-[#21262d] text-[#8b949e]'
  if (score >= 75) return 'bg-red-900/20 text-red-400 border border-red-800/30'
  if (score >= 40) return 'bg-yellow-900/20 text-yellow-400 border border-yellow-800/30'
  return 'bg-green-900/20 text-green-400 border border-green-800/30'
}

function vtLink(ioc) {
  const typeMap = { ip: 'ip-address', hash: 'file', domain: 'domain', url: 'url' }
  const vtType = typeMap[ioc.ioc_type] || ioc.ioc_type
  return `https://www.virustotal.com/gui/${vtType}/${encodeURIComponent(ioc.value)}`
}

function TopCard({ ioc }) {
  if (!ioc) {
    return (
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex items-center justify-center">
        <span className="text-[#8b949e] text-sm">No data</span>
      </div>
    )
  }
  const best = Math.max(
    ioc.vt_score ?? -1,
    ioc.abuseipdb_score ?? -1,
  )
  const displayScore = best >= 0 ? best : null

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide text-[#8b949e]">{ioc.ioc_type}</span>
        {displayScore !== null && (
          <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${scoreBg(displayScore)}`}>
            {displayScore}
          </span>
        )}
      </div>
      <a
        href={vtLink(ioc)}
        target="_blank"
        rel="noreferrer"
        className="block text-sm text-[#58a6ff] hover:underline truncate font-mono"
        title={ioc.value}
      >
        {ioc.value}
      </a>
      <div className="flex gap-3 text-xs text-[#8b949e]">
        {ioc.vt_score !== null && ioc.vt_score !== undefined && (
          <span>VT: <span className={scoreColor(ioc.vt_score)}>{ioc.vt_score}</span></span>
        )}
        {ioc.abuseipdb_score !== null && ioc.abuseipdb_score !== undefined && (
          <span>Abuse: <span className={scoreColor(ioc.abuseipdb_score)}>{ioc.abuseipdb_score}</span></span>
        )}
      </div>
    </div>
  )
}

export default function IOCs() {
  const [topIocs, setTopIocs] = useState([])
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [enrichingId, setEnrichingId] = useState(null)

  const fetchAll = useCallback(() => {
    const params = {}
    if (typeFilter) params.type = typeFilter
    if (search) params.search = search
    return iocApi.getAll(params).then((r) => setIocs(r.data)).catch(() => {})
  }, [typeFilter, search])

  useEffect(() => {
    setLoading(true)
    Promise.all([
      iocApi.getTop().then((r) => setTopIocs(r.data)).catch(() => {}),
      fetchAll(),
    ]).finally(() => setLoading(false))
  }, [fetchAll])

  const handleEnrich = async (id) => {
    setEnrichingId(id)
    try {
      await iocApi.enrich(id)
      await fetchAll()
      await iocApi.getTop().then((r) => setTopIocs(r.data)).catch(() => {})
    } catch (_) {
    } finally {
      setEnrichingId(null)
    }
  }

  const handleDelete = async (id) => {
    try {
      await iocApi.delete(id)
      setIocs((prev) => prev.filter((i) => i.id !== id))
      setTopIocs((prev) => prev.filter((i) => i.id !== id))
    } catch (_) {}
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">IOC Reputation</h1>
        <p className="text-sm text-[#8b949e] mt-1">
          Indicators of Compromise enriched via VirusTotal &amp; AbuseIPDB
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {[0, 1, 2].map((i) => (
          <TopCard key={i} ioc={topIocs[i]} />
        ))}
      </div>

      <div className="bg-[#161b22] border border-[#30363d] rounded-lg">
        <div className="flex flex-col sm:flex-row gap-3 p-4 border-b border-[#30363d]">
          <input
            type="text"
            placeholder="Search value..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-md px-3 py-1.5 text-sm text-white placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
          />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-[#0d1117] border border-[#30363d] rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#58a6ff]"
          >
            <option value="">All types</option>
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="hash">Hash</option>
            <option value="url">URL</option>
          </select>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-40 text-[#8b949e]">Loading...</div>
        ) : iocs.length === 0 ? (
          <div className="flex items-center justify-center h-40 text-[#8b949e]">
            No IOCs found. Enrich an alert to populate this table.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[10px] uppercase text-[#8b949e] border-b border-[#21262d]">
                  <th className="text-left px-4 py-2">Type</th>
                  <th className="text-left px-4 py-2">Value</th>
                  <th className="text-left px-4 py-2">VT Score</th>
                  <th className="text-left px-4 py-2">AbuseIPDB</th>
                  <th className="text-left px-4 py-2 hidden md:table-cell">Last Enriched</th>
                  <th className="text-left px-4 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => (
                  <tr
                    key={ioc.id}
                    className="border-b border-[#21262d] hover:bg-[#21262d] transition-colors"
                  >
                    <td className="px-4 py-2.5">
                      <span className="text-xs bg-[#21262d] border border-[#30363d] rounded px-2 py-0.5 text-[#8b949e] uppercase">
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 max-w-xs">
                      <a
                        href={vtLink(ioc)}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[#58a6ff] hover:underline font-mono text-xs truncate block"
                        title={ioc.value}
                      >
                        {ioc.value}
                      </a>
                    </td>
                    <td className="px-4 py-2.5">
                      {ioc.vt_score !== null && ioc.vt_score !== undefined ? (
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${scoreBg(ioc.vt_score)}`}>
                          {ioc.vt_score}
                          {ioc.vt_engines_total ? (
                            <span className="font-normal opacity-70"> /{ioc.vt_engines_total}</span>
                          ) : null}
                        </span>
                      ) : (
                        <span className="text-xs text-[#8b949e]">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {ioc.abuseipdb_score !== null && ioc.abuseipdb_score !== undefined ? (
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${scoreBg(ioc.abuseipdb_score)}`}>
                          {ioc.abuseipdb_score}
                        </span>
                      ) : (
                        <span className="text-xs text-[#8b949e]">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 hidden md:table-cell text-xs text-[#8b949e]">
                      {ioc.last_enriched_at
                        ? new Date(ioc.last_enriched_at).toLocaleString()
                        : '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleEnrich(ioc.id)}
                          disabled={enrichingId === ioc.id}
                          className="text-xs text-[#58a6ff] hover:text-white border border-[#30363d] hover:border-[#58a6ff] rounded px-2 py-1 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {enrichingId === ioc.id ? 'Enriching...' : 'Enrich'}
                        </button>
                        <button
                          onClick={() => handleDelete(ioc.id)}
                          className="text-xs text-[#8b949e] hover:text-red-400 transition-colors"
                          title="Delete"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
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
