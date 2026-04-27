import { useState, useEffect, useCallback } from 'react'
import { assetsApi } from '../api'

function StatusDot({ s }) {
  const map = {
    Online: 'bg-green-400',
    Offline: 'bg-gray-500',
    Vulnerable: 'bg-orange-400',
  }
  return <span className={`inline-block w-2 h-2 rounded-full ${map[s] || 'bg-gray-500'} mr-1.5`} />
}

function TypeBadge({ t }) {
  const map = {
    Server: 'bg-blue-900/40 text-blue-400 border-blue-700/40',
    Endpoint: 'bg-purple-900/40 text-purple-400 border-purple-700/40',
    Network: 'bg-teal-900/40 text-teal-400 border-teal-700/40',
  }
  return <span className={`severity-badge border ${map[t] || 'bg-gray-800 text-gray-400 border-gray-700'}`}>{t}</span>
}

function CreateAssetModal({ onClose, onCreated }) {
  const [form, setForm] = useState({
    hostname: '', ip_address: '', os: '', asset_type: 'Server',
    status: 'Online', owner: '', location: '',
  })
  const [saving, setSaving] = useState(false)
  const set = (k, v) => setForm((p) => ({ ...p, [k]: v }))

  async function handleSubmit(e) {
    e.preventDefault()
    setSaving(true)
    try {
      await assetsApi.create(form)
      onCreated()
      onClose()
    } catch {
      alert('Failed to create asset')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg w-full max-w-md mx-4">
        <div className="flex items-center justify-between p-4 border-b border-[#30363d]">
          <h2 className="font-semibold text-white">New Asset</h2>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Hostname *</label>
              <input className="input w-full" value={form.hostname} onChange={(e) => set('hostname', e.target.value)} required />
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">IP Address *</label>
              <input className="input w-full" value={form.ip_address} onChange={(e) => set('ip_address', e.target.value)} required />
            </div>
          </div>
          <div>
            <label className="text-xs text-[#8b949e] block mb-1">Operating System *</label>
            <input className="input w-full" value={form.os} onChange={(e) => set('os', e.target.value)} required placeholder="e.g. Ubuntu 22.04 LTS" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Type</label>
              <select className="input w-full" value={form.asset_type} onChange={(e) => set('asset_type', e.target.value)}>
                <option>Server</option>
                <option>Endpoint</option>
                <option>Network</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Status</label>
              <select className="input w-full" value={form.status} onChange={(e) => set('status', e.target.value)}>
                <option>Online</option>
                <option>Offline</option>
                <option>Vulnerable</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Owner</label>
              <input className="input w-full" value={form.owner} onChange={(e) => set('owner', e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Location</label>
              <input className="input w-full" value={form.location} onChange={(e) => set('location', e.target.value)} />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={saving} className="btn-primary disabled:opacity-50">
              {saving ? 'Creating...' : 'Create Asset'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Assets() {
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [deleting, setDeleting] = useState(null)

  const load = useCallback(() => {
    const params = {}
    if (search) params.search = search
    if (typeFilter) params.asset_type = typeFilter
    if (statusFilter) params.status = statusFilter
    assetsApi.getAll(params).then((r) => {
      setAssets(r.data)
      setLoading(false)
    })
  }, [search, typeFilter, statusFilter])

  useEffect(() => {
    const t = setTimeout(load, search ? 300 : 0)
    return () => clearTimeout(t)
  }, [load])

  async function deleteAsset(id) {
    if (!window.confirm('Delete this asset?')) return
    setDeleting(id)
    await assetsApi.delete(id)
    setDeleting(null)
    load()
  }

  const stats = {
    total: assets.length,
    online: assets.filter((a) => a.status === 'Online').length,
    vulnerable: assets.filter((a) => a.status === 'Vulnerable').length,
    offline: assets.filter((a) => a.status === 'Offline').length,
  }

  return (
    <div className="space-y-4">
      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Assets', value: stats.total, color: 'text-white' },
          { label: 'Online', value: stats.online, color: 'text-green-400' },
          { label: 'Vulnerable', value: stats.vulnerable, color: 'text-orange-400' },
          { label: 'Offline', value: stats.offline, color: 'text-gray-400' },
        ].map((c) => (
          <div key={c.label} className="card p-4">
            <div className="text-xs text-[#8b949e] uppercase tracking-wide mb-1">{c.label}</div>
            <div className={`text-2xl font-bold ${c.color}`}>{c.value}</div>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div className="flex gap-2 flex-wrap">
          <input
            className="input text-xs w-48"
            placeholder="Search hostname, IP, OS..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select className="input text-xs" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            <option value="">All Types</option>
            <option>Server</option>
            <option>Endpoint</option>
            <option>Network</option>
          </select>
          <select className="input text-xs" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All Statuses</option>
            <option>Online</option>
            <option>Offline</option>
            <option>Vulnerable</option>
          </select>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2 text-sm">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Asset
        </button>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase text-[#8b949e] border-b border-[#30363d] bg-[#0d1117]">
              <th className="text-left px-4 py-3">Hostname</th>
              <th className="text-left px-4 py-3">IP Address</th>
              <th className="text-left px-4 py-3 hidden md:table-cell">OS</th>
              <th className="text-left px-4 py-3">Type</th>
              <th className="text-left px-4 py-3">Status</th>
              <th className="text-left px-4 py-3 hidden lg:table-cell">Owner</th>
              <th className="text-left px-4 py-3 hidden xl:table-cell">Location</th>
              <th className="text-left px-4 py-3">Vulns</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={9} className="text-center py-12 text-[#8b949e]">Loading assets...</td></tr>
            ) : assets.length === 0 ? (
              <tr><td colSpan={9} className="text-center py-12 text-[#8b949e]">No assets found</td></tr>
            ) : assets.map((a) => (
              <tr key={a.id} className="border-b border-[#21262d] hover:bg-[#1c2128] transition-colors">
                <td className="px-4 py-3 text-gray-200 font-medium">{a.hostname}</td>
                <td className="px-4 py-3 text-[#8b949e] font-mono text-xs">{a.ip_address}</td>
                <td className="px-4 py-3 text-[#8b949e] text-xs hidden md:table-cell">{a.os}</td>
                <td className="px-4 py-3"><TypeBadge t={a.asset_type} /></td>
                <td className="px-4 py-3 text-sm">
                  <StatusDot s={a.status} />
                  <span className={a.status === 'Vulnerable' ? 'text-orange-400' : a.status === 'Offline' ? 'text-gray-400' : 'text-green-400'}>
                    {a.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-[#8b949e] text-xs hidden lg:table-cell">{a.owner || '—'}</td>
                <td className="px-4 py-3 text-[#8b949e] text-xs hidden xl:table-cell">{a.location || '—'}</td>
                <td className="px-4 py-3">
                  {a.vulnerability_count > 0
                    ? <span className="text-xs text-orange-400 bg-orange-900/20 border border-orange-700/30 px-1.5 py-0.5 rounded">{a.vulnerability_count}</span>
                    : <span className="text-xs text-[#8b949e]">0</span>}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => deleteAsset(a.id)}
                    disabled={deleting === a.id}
                    className="text-[#8b949e] hover:text-red-400 transition-colors text-xs disabled:opacity-50"
                  >
                    {deleting === a.id ? '...' : 'Delete'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-4 py-2 border-t border-[#21262d] text-xs text-[#8b949e]">
          {assets.length} asset{assets.length !== 1 ? 's' : ''}
        </div>
      </div>

      {showCreate && <CreateAssetModal onClose={() => setShowCreate(false)} onCreated={load} />}
    </div>
  )
}
