import { useState, useEffect, useCallback } from 'react'
import { threatsApi } from '../api'

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

function SeverityBadge({ s }) {
  const cls = { CRITICAL: 'severity-critical', HIGH: 'severity-high', MEDIUM: 'severity-medium', LOW: 'severity-low' }
  return <span className={`severity-badge ${cls[s] || ''}`}>{s}</span>
}

function StatusBadge({ s }) {
  const cls = { Open: 'status-open', Investigating: 'status-investigating', Resolved: 'status-resolved', 'False Positive': 'status-resolved' }
  return <span className={`severity-badge ${cls[s] || 'bg-gray-800 text-gray-400'}`}>{s}</span>
}

// ── Threat Drawer ────────────────────────────────────────────────────────────

function ThreatDrawer({ threat, onClose, onUpdated }) {
  const [analyzing, setAnalyzing] = useState(false)
  const [analysis, setAnalysis] = useState(threat?.ai_analysis || null)
  const [analyzedAt, setAnalyzedAt] = useState(threat?.ai_analyzed_at || null)
  const [status, setStatus] = useState(threat?.status || '')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (threat) {
      setAnalysis(threat.ai_analysis)
      setAnalyzedAt(threat.ai_analyzed_at)
      setStatus(threat.status)
    }
  }, [threat])

  if (!threat) return null

  async function runAnalysis() {
    setAnalyzing(true)
    try {
      const res = await threatsApi.analyze(threat.id)
      setAnalysis(res.data.analysis)
      setAnalyzedAt(res.data.analyzed_at)
      onUpdated && onUpdated()
    } catch (e) {
      alert('Analysis failed: ' + (e.message || 'Unknown error'))
    } finally {
      setAnalyzing(false)
    }
  }

  async function saveStatus() {
    setSaving(true)
    try {
      await threatsApi.update(threat.id, { status })
      onUpdated && onUpdated()
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-black/50" onClick={onClose} />
      {/* Drawer */}
      <div className="w-full max-w-xl bg-[#161b22] border-l border-[#30363d] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-[#30363d]">
          <div className="flex-1 pr-4">
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge s={threat.severity} />
              <StatusBadge s={threat.status} />
            </div>
            <h2 className="text-base font-semibold text-white leading-snug">{threat.title}</h2>
          </div>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white mt-0.5">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Details grid */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            {[
              ['Threat Type', threat.threat_type],
              ['MITRE Tactic', threat.mitre_tactic || '—'],
              ['Technique', threat.mitre_technique || '—'],
              ['Source IP', threat.source_ip || '—'],
              ['Destination', threat.destination_ip || '—'],
              ['Affected System', threat.affected_system || '—'],
              ['Created', new Date(threat.created_at).toLocaleString()],
              ['Updated', new Date(threat.updated_at).toLocaleString()],
            ].map(([label, value]) => (
              <div key={label} className="bg-[#0d1117] rounded p-2.5">
                <div className="text-[#8b949e] mb-0.5">{label}</div>
                <div className="text-gray-200 font-medium break-all">{value}</div>
              </div>
            ))}
          </div>

          {/* Description */}
          <div>
            <h3 className="text-xs text-[#8b949e] uppercase tracking-wide mb-2">Description</h3>
            <p className="text-sm text-gray-300 leading-relaxed bg-[#0d1117] rounded p-3">{threat.description}</p>
          </div>

          {/* Status update */}
          <div>
            <h3 className="text-xs text-[#8b949e] uppercase tracking-wide mb-2">Update Status</h3>
            <div className="flex gap-2">
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="input flex-1"
              >
                <option>Open</option>
                <option>Investigating</option>
                <option>Resolved</option>
                <option>False Positive</option>
              </select>
              <button onClick={saveStatus} disabled={saving || status === threat.status} className="btn-secondary disabled:opacity-50">
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>

          {/* AI Analysis */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs text-[#8b949e] uppercase tracking-wide">AI Threat Analysis</h3>
              {analyzedAt && (
                <span className="text-[10px] text-[#8b949e]">
                  Last: {new Date(analyzedAt).toLocaleString()}
                </span>
              )}
            </div>
            <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-4">
              {analysis ? (
                <div className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
                  {analysis}
                </div>
              ) : (
                <div className="text-center py-4">
                  <div className="text-[#8b949e] text-sm mb-1">No AI analysis generated yet</div>
                  <div className="text-xs text-[#8b949e]/60">Run analysis to get an AI-powered threat assessment</div>
                </div>
              )}
            </div>
            <button
              onClick={runAnalysis}
              disabled={analyzing}
              className="mt-3 w-full flex items-center justify-center gap-2 bg-[#1f2937] hover:bg-[#374151] border border-[#4b5563] text-[#58a6ff] font-medium py-2 rounded-md text-sm transition-colors disabled:opacity-50"
            >
              {analyzing ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                  </svg>
                  Analyzing with SentinelAI...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                  {analysis ? 'Re-run AI Analysis' : 'Run AI Analysis'}
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Create Threat Modal ──────────────────────────────────────────────────────

function CreateModal({ onClose, onCreated }) {
  const [form, setForm] = useState({
    title: '', description: '', severity: 'MEDIUM', threat_type: 'Malware',
    mitre_tactic: '', mitre_technique: '', source_ip: '', destination_ip: '',
    affected_system: '',
  })
  const [saving, setSaving] = useState(false)

  const set = (k, v) => setForm((p) => ({ ...p, [k]: v }))

  async function handleSubmit(e) {
    e.preventDefault()
    setSaving(true)
    try {
      await threatsApi.create(form)
      onCreated()
      onClose()
    } catch {
      alert('Failed to create threat')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg w-full max-w-lg mx-4 overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-[#30363d]">
          <h2 className="font-semibold text-white">New Threat</h2>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-3 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="text-xs text-[#8b949e] block mb-1">Title *</label>
            <input className="input w-full" value={form.title} onChange={(e) => set('title', e.target.value)} required />
          </div>
          <div>
            <label className="text-xs text-[#8b949e] block mb-1">Description *</label>
            <textarea className="input w-full" rows={3} value={form.description} onChange={(e) => set('description', e.target.value)} required />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Severity</label>
              <select className="input w-full" value={form.severity} onChange={(e) => set('severity', e.target.value)}>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Threat Type</label>
              <select className="input w-full" value={form.threat_type} onChange={(e) => set('threat_type', e.target.value)}>
                {['Malware', 'Phishing', 'Ransomware', 'Brute Force', 'SQL Injection', 'DDoS', 'Lateral Movement', 'Data Exfiltration', 'Zero-Day Exploit', 'Insider Threat'].map((t) => <option key={t}>{t}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">MITRE Tactic</label>
              <input className="input w-full" value={form.mitre_tactic} onChange={(e) => set('mitre_tactic', e.target.value)} placeholder="e.g. Initial Access" />
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">MITRE Technique</label>
              <input className="input w-full" value={form.mitre_technique} onChange={(e) => set('mitre_technique', e.target.value)} placeholder="e.g. T1566.001" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Source IP</label>
              <input className="input w-full" value={form.source_ip} onChange={(e) => set('source_ip', e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Destination IP</label>
              <input className="input w-full" value={form.destination_ip} onChange={(e) => set('destination_ip', e.target.value)} />
            </div>
          </div>
          <div>
            <label className="text-xs text-[#8b949e] block mb-1">Affected System</label>
            <input className="input w-full" value={form.affected_system} onChange={(e) => set('affected_system', e.target.value)} />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={saving} className="btn-primary disabled:opacity-50">
              {saving ? 'Creating...' : 'Create Threat'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Threats Page ────────────────────────────────────────────────────────

export default function Threats() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)
  const [showCreate, setShowCreate] = useState(false)
  const [filters, setFilters] = useState({ severity: '', status: '', threat_type: '' })

  const load = useCallback(() => {
    const params = {}
    if (filters.severity) params.severity = filters.severity
    if (filters.status) params.status = filters.status
    if (filters.threat_type) params.threat_type = filters.threat_type
    threatsApi.getAll(params).then((r) => {
      setThreats(r.data.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]))
      setLoading(false)
    })
  }, [filters])

  useEffect(() => { load() }, [load])

  const setFilter = (k, v) => setFilters((p) => ({ ...p, [k]: v }))

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div className="flex gap-2 flex-wrap">
          {[
            { key: 'severity', opts: ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], placeholder: 'All Severities' },
            { key: 'status', opts: ['', 'Open', 'Investigating', 'Resolved', 'False Positive'], placeholder: 'All Statuses' },
            { key: 'threat_type', opts: ['', 'Malware', 'Phishing', 'Ransomware', 'Brute Force', 'SQL Injection', 'DDoS', 'Lateral Movement', 'Data Exfiltration', 'Zero-Day Exploit', 'Insider Threat'], placeholder: 'All Types' },
          ].map(({ key, opts, placeholder }) => (
            <select key={key} className="input text-xs" value={filters[key]} onChange={(e) => setFilter(key, e.target.value)}>
              {opts.map((o) => <option key={o} value={o}>{o || placeholder}</option>)}
            </select>
          ))}
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Threat
        </button>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase text-[#8b949e] border-b border-[#30363d] bg-[#0d1117]">
              <th className="text-left px-4 py-3">Title</th>
              <th className="text-left px-4 py-3 hidden md:table-cell">Type</th>
              <th className="text-left px-4 py-3 hidden lg:table-cell">MITRE Tactic</th>
              <th className="text-left px-4 py-3">Severity</th>
              <th className="text-left px-4 py-3">Status</th>
              <th className="text-left px-4 py-3 hidden xl:table-cell">AI</th>
              <th className="text-left px-4 py-3 hidden lg:table-cell">Date</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center py-12 text-[#8b949e]">Loading threats...</td></tr>
            ) : threats.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-12 text-[#8b949e]">No threats found</td></tr>
            ) : threats.map((t) => (
              <tr key={t.id} className="table-row" onClick={() => setSelected(t)}>
                <td className="px-4 py-3 text-gray-300 max-w-xs">
                  <div className="truncate">{t.title}</div>
                  {t.affected_system && <div className="text-[10px] text-[#8b949e] truncate mt-0.5">{t.affected_system}</div>}
                </td>
                <td className="px-4 py-3 text-[#8b949e] hidden md:table-cell text-xs">{t.threat_type}</td>
                <td className="px-4 py-3 text-[#8b949e] hidden lg:table-cell text-xs">{t.mitre_tactic || '—'}</td>
                <td className="px-4 py-3"><SeverityBadge s={t.severity} /></td>
                <td className="px-4 py-3"><StatusBadge s={t.status} /></td>
                <td className="px-4 py-3 hidden xl:table-cell">
                  {t.ai_analysis
                    ? <span className="text-[10px] text-purple-400 bg-purple-900/20 border border-purple-700/30 px-1.5 py-0.5 rounded">AI Ready</span>
                    : <span className="text-[10px] text-[#8b949e]">—</span>}
                </td>
                <td className="px-4 py-3 text-[#8b949e] text-xs hidden lg:table-cell">
                  {new Date(t.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-4 py-2 border-t border-[#21262d] text-xs text-[#8b949e]">
          {threats.length} threat{threats.length !== 1 ? 's' : ''}
        </div>
      </div>

      {selected && (
        <ThreatDrawer
          threat={selected}
          onClose={() => setSelected(null)}
          onUpdated={() => {
            load()
            // Refresh selected threat data
            threatsApi.getOne(selected.id).then((r) => setSelected(r.data))
          }}
        />
      )}
      {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreated={load} />}
    </div>
  )
}
