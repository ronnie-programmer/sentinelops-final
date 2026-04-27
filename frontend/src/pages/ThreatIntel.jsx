import { useState, useEffect, useCallback } from 'react'
import { intelApi } from '../api'

const TYPE_BADGE = {
  'CVE': 'bg-red-900/40 text-red-400 border-red-700/40',
  'Threat Actor': 'bg-purple-900/40 text-purple-400 border-purple-700/40',
  'IOC-IP': 'bg-orange-900/40 text-orange-400 border-orange-700/40',
  'IOC-Hash': 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
  'IOC-Domain': 'bg-blue-900/40 text-blue-400 border-blue-700/40',
}

const SEV_CLS = {
  CRITICAL: 'severity-critical',
  HIGH: 'severity-high',
  MEDIUM: 'severity-medium',
  LOW: 'severity-low',
}

function TypeBadge({ t }) {
  return <span className={`severity-badge border ${TYPE_BADGE[t] || 'bg-gray-800 text-gray-400 border-gray-700'}`}>{t}</span>
}

function ConfidenceMeter({ value }) {
  const color = value >= 90 ? 'bg-green-500' : value >= 70 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-[#21262d] rounded-full h-1.5 w-16">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-[10px] text-[#8b949e]">{value}%</span>
    </div>
  )
}

function IntelDrawer({ item, onClose, onImported }) {
  const [importing, setImporting] = useState(false)

  if (!item) return null

  async function handleImport() {
    setImporting(true)
    try {
      const res = await intelApi.importAsThreat(item.id)
      onImported && onImported(res.data)
      onClose()
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || 'Import failed'
      alert(msg)
    } finally {
      setImporting(false)
    }
  }

  const tags = item.tags ? item.tags.split(',').map((t) => t.trim()).filter(Boolean) : []

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/50" onClick={onClose} />
      <div className="w-full max-w-lg bg-[#161b22] border-l border-[#30363d] flex flex-col overflow-hidden">
        <div className="flex items-start justify-between p-5 border-b border-[#30363d]">
          <div className="flex-1 pr-4">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <TypeBadge t={item.intel_type} />
              <span className={`severity-badge ${SEV_CLS[item.severity]}`}>{item.severity}</span>
              {item.is_imported === 1 && (
                <span className="text-[10px] bg-green-900/30 text-green-400 border border-green-700/30 px-1.5 py-0.5 rounded">Imported</span>
              )}
            </div>
            <h2 className="text-base font-semibold text-white leading-snug">{item.title}</h2>
          </div>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Indicator value */}
          <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
            <div className="text-xs text-[#8b949e] mb-1 uppercase tracking-wide">Indicator / Value</div>
            <div className="text-sm text-[#58a6ff] font-mono break-all">{item.value}</div>
          </div>

          {/* Meta grid */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            {[
              ['Source', item.source || '—'],
              ['Confidence', null],
              ['Type', item.intel_type],
              ['Added', new Date(item.created_at).toLocaleDateString()],
            ].map(([label, val]) => (
              <div key={label} className="bg-[#0d1117] rounded p-2.5">
                <div className="text-[#8b949e] mb-1">{label}</div>
                {label === 'Confidence'
                  ? <ConfidenceMeter value={item.confidence} />
                  : <div className="text-gray-200 font-medium">{val}</div>}
              </div>
            ))}
          </div>

          {/* Description */}
          <div>
            <h3 className="text-xs text-[#8b949e] uppercase tracking-wide mb-2">Description</h3>
            <p className="text-sm text-gray-300 leading-relaxed bg-[#0d1117] rounded p-3">{item.description}</p>
          </div>

          {/* Tags */}
          {tags.length > 0 && (
            <div>
              <h3 className="text-xs text-[#8b949e] uppercase tracking-wide mb-2">Tags</h3>
              <div className="flex flex-wrap gap-1.5">
                {tags.map((tag) => (
                  <span key={tag} className="text-[10px] bg-[#21262d] text-[#8b949e] border border-[#30363d] px-2 py-0.5 rounded-full">{tag}</span>
                ))}
              </div>
            </div>
          )}

          {/* Import button */}
          <div className="pt-2">
            {item.is_imported === 1 ? (
              <div className="text-center text-sm text-green-400 bg-green-900/20 border border-green-700/30 rounded-lg p-3">
                Already imported as a threat
              </div>
            ) : (
              <button
                onClick={handleImport}
                disabled={importing}
                className="w-full flex items-center justify-center gap-2 bg-[#58a6ff]/10 hover:bg-[#58a6ff]/20 border border-[#58a6ff]/30 text-[#58a6ff] font-medium py-2.5 rounded-md text-sm transition-colors disabled:opacity-50"
              >
                {importing ? (
                  <>
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                    </svg>
                    Importing...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4v16m8-8H4" />
                    </svg>
                    Import to Threats
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function ThreatIntel() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [selected, setSelected] = useState(null)
  const [importMsg, setImportMsg] = useState(null)

  const load = useCallback(() => {
    const params = {}
    if (search) params.search = search
    if (typeFilter) params.intel_type = typeFilter
    if (sevFilter) params.severity = sevFilter
    intelApi.getAll(params).then((r) => {
      setItems(r.data)
      setLoading(false)
    })
  }, [search, typeFilter, sevFilter])

  useEffect(() => {
    const t = setTimeout(load, search ? 300 : 0)
    return () => clearTimeout(t)
  }, [load])

  function handleImported(result) {
    setImportMsg(`Threat #${result.threat_id} created: "${result.threat_title}"`)
    setTimeout(() => setImportMsg(null), 5000)
    load()
  }

  const typeOptions = ['', 'CVE', 'Threat Actor', 'IOC-IP', 'IOC-Hash', 'IOC-Domain']

  return (
    <div className="space-y-4">
      {/* Import success toast */}
      {importMsg && (
        <div className="bg-green-900/30 border border-green-700/50 rounded-lg px-4 py-3 text-sm text-green-400 flex items-center justify-between">
          <span>{importMsg}</span>
          <button onClick={() => setImportMsg(null)} className="text-green-400/60 hover:text-green-400 ml-4">✕</button>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
        {[
          { label: 'Total', value: items.length, color: 'text-white' },
          { label: 'CVEs', value: items.filter((i) => i.intel_type === 'CVE').length, color: 'text-red-400' },
          { label: 'Actors', value: items.filter((i) => i.intel_type === 'Threat Actor').length, color: 'text-purple-400' },
          { label: 'IOC-IP', value: items.filter((i) => i.intel_type === 'IOC-IP').length, color: 'text-orange-400' },
          { label: 'IOC-Hash', value: items.filter((i) => i.intel_type === 'IOC-Hash').length, color: 'text-yellow-400' },
          { label: 'Imported', value: items.filter((i) => i.is_imported === 1).length, color: 'text-green-400' },
        ].map((c) => (
          <div key={c.label} className="card p-3">
            <div className="text-[10px] text-[#8b949e] uppercase tracking-wide mb-1">{c.label}</div>
            <div className={`text-xl font-bold ${c.color}`}>{c.value}</div>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          className="input text-xs w-56"
          placeholder="Search title, value, tags..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select className="input text-xs" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          {typeOptions.map((o) => <option key={o} value={o}>{o || 'All Types'}</option>)}
        </select>
        <select className="input text-xs" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
          {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((o) => <option key={o} value={o}>{o || 'All Severities'}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase text-[#8b949e] border-b border-[#30363d] bg-[#0d1117]">
              <th className="text-left px-4 py-3">Title</th>
              <th className="text-left px-4 py-3">Type</th>
              <th className="text-left px-4 py-3 hidden md:table-cell">Indicator / Value</th>
              <th className="text-left px-4 py-3">Severity</th>
              <th className="text-left px-4 py-3 hidden lg:table-cell">Confidence</th>
              <th className="text-left px-4 py-3 hidden xl:table-cell">Source</th>
              <th className="text-left px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center py-12 text-[#8b949e]">Loading threat intelligence...</td></tr>
            ) : items.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-12 text-[#8b949e]">No intel items found</td></tr>
            ) : items.map((item) => (
              <tr
                key={item.id}
                className="table-row"
                onClick={() => setSelected(item)}
              >
                <td className="px-4 py-3 text-gray-300 max-w-xs">
                  <div className="truncate">{item.title}</div>
                </td>
                <td className="px-4 py-3">
                  <TypeBadge t={item.intel_type} />
                </td>
                <td className="px-4 py-3 hidden md:table-cell">
                  <span className="font-mono text-[11px] text-[#8b949e] truncate block max-w-[180px]">{item.value}</span>
                </td>
                <td className="px-4 py-3">
                  <span className={`severity-badge ${SEV_CLS[item.severity]}`}>{item.severity}</span>
                </td>
                <td className="px-4 py-3 hidden lg:table-cell">
                  <ConfidenceMeter value={item.confidence} />
                </td>
                <td className="px-4 py-3 text-[#8b949e] text-xs hidden xl:table-cell truncate max-w-[120px]">
                  {item.source || '—'}
                </td>
                <td className="px-4 py-3">
                  {item.is_imported === 1
                    ? <span className="text-[10px] text-green-400 bg-green-900/20 border border-green-700/30 px-1.5 py-0.5 rounded">Imported</span>
                    : <span className="text-[10px] text-[#58a6ff] bg-[#58a6ff]/10 border border-[#58a6ff]/30 px-1.5 py-0.5 rounded cursor-pointer hover:bg-[#58a6ff]/20">Import</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-4 py-2 border-t border-[#21262d] text-xs text-[#8b949e]">
          {items.length} intel item{items.length !== 1 ? 's' : ''} · Click a row to view details and import
        </div>
      </div>

      {selected && (
        <IntelDrawer
          item={selected}
          onClose={() => setSelected(null)}
          onImported={handleImported}
        />
      )}
    </div>
  )
}
