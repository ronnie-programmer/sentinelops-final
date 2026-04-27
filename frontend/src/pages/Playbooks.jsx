import { useState, useEffect } from 'react'
import { playbooksApi } from '../api'

const DEFAULT_TRIGGER = `type: alert_severity_gte\nseverity: HIGH\n`
const DEFAULT_ACTIONS = `- action: notify_slack\n  message: "Alert triggered: {alert_title}"\n`

function StatusBadge({ status }) {
  const map = {
    success: 'bg-green-900/40 text-green-400 border-green-700/40',
    error: 'bg-red-900/40 text-red-400 border-red-700/40',
    running: 'bg-blue-900/40 text-[#58a6ff] border-blue-700/40',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${map[status] || 'bg-gray-800 text-gray-400 border-gray-700'}`}>
      {status}
    </span>
  )
}

function BuiltinBadge() {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-[#58a6ff]/10 text-[#58a6ff] border border-[#58a6ff]/30">
      Built-in
    </span>
  )
}

function Toggle({ enabled, onChange }) {
  return (
    <button
      onClick={onChange}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${enabled ? 'bg-[#58a6ff]' : 'bg-[#30363d]'}`}
    >
      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${enabled ? 'translate-x-4.5' : 'translate-x-0.5'}`} />
    </button>
  )
}

function CollapsibleOutput({ output }) {
  const [open, setOpen] = useState(false)
  if (!output) return <span className="text-[#8b949e] text-xs">—</span>
  let parsed
  try { parsed = JSON.parse(output) } catch { parsed = output }
  return (
    <div>
      <button
        onClick={() => setOpen(o => !o)}
        className="text-xs text-[#58a6ff] hover:underline focus:outline-none"
      >
        {open ? 'Hide' : 'Show'} output
      </button>
      {open && (
        <pre className="mt-1 text-xs bg-[#0d1117] border border-[#30363d] rounded p-2 max-h-32 overflow-auto text-[#8b949e] whitespace-pre-wrap">
          {typeof parsed === 'string' ? parsed : JSON.stringify(parsed, null, 2)}
        </pre>
      )}
    </div>
  )
}

function NewPlaybookForm({ onSave, onCancel }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [triggerYaml, setTriggerYaml] = useState(DEFAULT_TRIGGER)
  const [actionsYaml, setActionsYaml] = useState(DEFAULT_ACTIONS)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleSave() {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true)
    setError('')
    try {
      await playbooksApi.create({ name: name.trim(), description: description.trim(), trigger_yaml: triggerYaml, actions_yaml: actionsYaml })
      onSave()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Failed to create playbook')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-semibold text-white">New Playbook</h3>
      {error && <div className="text-red-400 text-xs">{error}</div>}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-[#8b949e] mb-1">Name *</label>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#58a6ff]"
            placeholder="e.g. Block Malicious IP"
          />
        </div>
        <div>
          <label className="block text-xs text-[#8b949e] mb-1">Description</label>
          <input
            value={description}
            onChange={e => setDescription(e.target.value)}
            className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#58a6ff]"
            placeholder="Optional description"
          />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-[#8b949e] mb-1">Trigger YAML</label>
          <textarea
            value={triggerYaml}
            onChange={e => setTriggerYaml(e.target.value)}
            rows={5}
            className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-[#58a6ff] resize-none"
          />
        </div>
        <div>
          <label className="block text-xs text-[#8b949e] mb-1">Actions YAML</label>
          <textarea
            value={actionsYaml}
            onChange={e => setActionsYaml(e.target.value)}
            rows={5}
            className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-[#58a6ff] resize-none"
          />
        </div>
      </div>
      <div className="flex gap-2 justify-end">
        <button onClick={onCancel} className="px-3 py-1.5 text-sm text-[#8b949e] hover:text-white transition-colors">
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-1.5 text-sm bg-[#58a6ff] text-[#0d1117] font-medium rounded hover:bg-[#79bcff] transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save Playbook'}
        </button>
      </div>
    </div>
  )
}

function EditPlaybookModal({ playbook, onSave, onCancel }) {
  const [name, setName] = useState(playbook.name)
  const [description, setDescription] = useState(playbook.description || '')
  const [triggerYaml, setTriggerYaml] = useState(playbook.trigger_yaml)
  const [actionsYaml, setActionsYaml] = useState(playbook.actions_yaml)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleSave() {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true)
    setError('')
    try {
      await playbooksApi.update(playbook.id, { name: name.trim(), description: description.trim(), trigger_yaml: triggerYaml, actions_yaml: actionsYaml })
      onSave()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Failed to update playbook')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-5 w-full max-w-2xl space-y-3">
        <h3 className="text-sm font-semibold text-white">Edit Playbook</h3>
        {error && <div className="text-red-400 text-xs">{error}</div>}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-[#8b949e] mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#58a6ff]"
            />
          </div>
          <div>
            <label className="block text-xs text-[#8b949e] mb-1">Description</label>
            <input
              value={description}
              onChange={e => setDescription(e.target.value)}
              className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#58a6ff]"
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-[#8b949e] mb-1">Trigger YAML</label>
            <textarea
              value={triggerYaml}
              onChange={e => setTriggerYaml(e.target.value)}
              rows={7}
              className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-[#58a6ff] resize-none"
            />
          </div>
          <div>
            <label className="block text-xs text-[#8b949e] mb-1">Actions YAML</label>
            <textarea
              value={actionsYaml}
              onChange={e => setActionsYaml(e.target.value)}
              rows={7}
              className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-[#58a6ff] resize-none"
            />
          </div>
        </div>
        <div className="flex gap-2 justify-end">
          <button onClick={onCancel} className="px-3 py-1.5 text-sm text-[#8b949e] hover:text-white transition-colors">
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-1.5 text-sm bg-[#58a6ff] text-[#0d1117] font-medium rounded hover:bg-[#79bcff] transition-colors disabled:opacity-50"
          >
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Playbooks() {
  const [playbooks, setPlaybooks] = useState([])
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [showNewForm, setShowNewForm] = useState(false)
  const [editingPlaybook, setEditingPlaybook] = useState(null)
  const [runningId, setRunningId] = useState(null)
  const [deletingId, setDeletingId] = useState(null)

  async function loadAll() {
    try {
      const [pbRes, runRes] = await Promise.all([
        playbooksApi.getAll(),
        playbooksApi.getAllRuns(),
      ])
      setPlaybooks(pbRes.data)
      setRuns(runRes.data)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadAll() }, [])

  async function handleToggle(id) {
    await playbooksApi.toggle(id)
    loadAll()
  }

  async function handleRun(id) {
    setRunningId(id)
    try {
      await playbooksApi.run(id)
      loadAll()
    } finally {
      setRunningId(null)
    }
  }

  async function handleDelete(pb) {
    if (!confirm(`Delete playbook "${pb.name}"?`)) return
    setDeletingId(pb.id)
    try {
      await playbooksApi.delete(pb.id)
      loadAll()
    } catch (e) {
      alert(e?.response?.data?.detail || 'Delete failed')
    } finally {
      setDeletingId(null)
    }
  }

  function getTriggerType(triggerYaml) {
    const m = triggerYaml.match(/type:\s*(\S+)/)
    return m ? m[1] : 'unknown'
  }

  function formatDate(dt) {
    if (!dt) return '—'
    return new Date(dt).toLocaleString()
  }

  const playbookMap = Object.fromEntries(playbooks.map(p => [p.id, p.name]))

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#8b949e] text-sm">Loading playbooks...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">SOAR Playbooks</h1>
          <p className="text-sm text-[#8b949e] mt-0.5">Automated response workflows that execute when trigger conditions are met</p>
        </div>
        <button
          onClick={() => setShowNewForm(s => !s)}
          className="flex items-center gap-2 px-4 py-2 bg-[#58a6ff] text-[#0d1117] text-sm font-medium rounded-md hover:bg-[#79bcff] transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Playbook
        </button>
      </div>

      {/* New playbook form */}
      {showNewForm && (
        <NewPlaybookForm
          onSave={() => { setShowNewForm(false); loadAll() }}
          onCancel={() => setShowNewForm(false)}
        />
      )}

      {/* Edit modal */}
      {editingPlaybook && (
        <EditPlaybookModal
          playbook={editingPlaybook}
          onSave={() => { setEditingPlaybook(null); loadAll() }}
          onCancel={() => setEditingPlaybook(null)}
        />
      )}

      {/* Playbooks table */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d]">
          <h2 className="text-sm font-semibold text-white">Playbooks</h2>
          <p className="text-xs text-[#8b949e] mt-0.5">{playbooks.length} playbook{playbooks.length !== 1 ? 's' : ''} configured</p>
        </div>
        {playbooks.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-[#8b949e]">No playbooks yet. Create one above.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#30363d]">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Name</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Trigger</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Enabled</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Runs</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Last Run</th>
                  <th className="text-right px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#30363d]">
                {playbooks.map(pb => (
                  <tr key={pb.id} className="hover:bg-[#1c2128] transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-white font-medium">{pb.name}</span>
                        {pb.is_builtin && <BuiltinBadge />}
                      </div>
                      {pb.description && (
                        <div className="text-xs text-[#8b949e] mt-0.5 max-w-xs truncate">{pb.description}</div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <code className="text-xs bg-[#0d1117] border border-[#30363d] rounded px-1.5 py-0.5 text-[#58a6ff]">
                        {getTriggerType(pb.trigger_yaml)}
                      </code>
                    </td>
                    <td className="px-4 py-3">
                      <Toggle enabled={pb.enabled} onChange={() => handleToggle(pb.id)} />
                    </td>
                    <td className="px-4 py-3 text-[#8b949e]">{pb.run_count}</td>
                    <td className="px-4 py-3 text-xs text-[#8b949e]">{formatDate(pb.last_run_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 justify-end">
                        <button
                          onClick={() => handleRun(pb.id)}
                          disabled={runningId === pb.id}
                          title="Run now"
                          className="p-1.5 text-[#8b949e] hover:text-green-400 transition-colors disabled:opacity-50"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => setEditingPlaybook(pb)}
                          title="Edit"
                          className="p-1.5 text-[#8b949e] hover:text-[#58a6ff] transition-colors"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        {!pb.is_builtin && (
                          <button
                            onClick={() => handleDelete(pb)}
                            disabled={deletingId === pb.id}
                            title="Delete"
                            className="p-1.5 text-[#8b949e] hover:text-red-400 transition-colors disabled:opacity-50"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Run History */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d]">
          <h2 className="text-sm font-semibold text-white">Run History</h2>
          <p className="text-xs text-[#8b949e] mt-0.5">{runs.length} run{runs.length !== 1 ? 's' : ''} recorded</p>
        </div>
        {runs.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-[#8b949e]">No runs yet. Trigger a playbook manually or wait for an alert to fire one.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#30363d]">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Playbook</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Triggered By</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Status</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Started</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-[#8b949e] uppercase tracking-wider">Output</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#30363d]">
                {runs.map(run => (
                  <tr key={run.id} className="hover:bg-[#1c2128] transition-colors">
                    <td className="px-4 py-3 text-white">{playbookMap[run.playbook_id] || `#${run.playbook_id}`}</td>
                    <td className="px-4 py-3 text-[#8b949e] text-xs">{run.triggered_by || '—'}</td>
                    <td className="px-4 py-3"><StatusBadge status={run.status} /></td>
                    <td className="px-4 py-3 text-xs text-[#8b949e]">{formatDate(run.started_at)}</td>
                    <td className="px-4 py-3"><CollapsibleOutput output={run.output} /></td>
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
