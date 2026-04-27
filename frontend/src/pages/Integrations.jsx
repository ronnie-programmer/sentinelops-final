import { useState, useEffect } from 'react'
import api from '../api'
import { edrApi } from '../api'

const PROVIDER_META = {
  crowdstrike: { label: 'CrowdStrike Falcon', color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/40', abbr: 'CS' },
  datadog: { label: 'Datadog Security', color: 'text-purple-400', bg: 'bg-purple-900/20 border-purple-700/40', abbr: 'DD' },
  splunk: { label: 'Splunk Enterprise Security', color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/40', abbr: 'SP' },
  crowdstrike_insight: { label: 'CrowdStrike Insight (EDR)', color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/40', abbr: 'CSI' },
  sentinelone: { label: 'SentinelOne Singularity', color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/40', abbr: 'S1' },
}

const EDR_PROVIDERS = new Set(['crowdstrike_insight', 'sentinelone'])

function StatusPill({ status, isMock }) {
  if (isMock) return <span className="severity-badge bg-yellow-900/30 text-yellow-400 border border-yellow-700/40">MOCK</span>
  const map = {
    connected: 'bg-green-900/40 text-green-400 border-green-700/40',
    error: 'bg-red-900/40 text-red-400 border-red-700/40',
    idle: 'bg-gray-800 text-gray-400 border-gray-700',
  }
  return <span className={`severity-badge border ${map[status] || map.idle}`}>{status}</span>
}

function IsolateHostModal({ provider, onClose }) {
  const [hostname, setHostname] = useState('')
  const [deviceId, setDeviceId] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    try {
      const r = await edrApi.isolateHost(provider, { hostname, device_id: deviceId })
      setResult(r.data)
    } catch (err) {
      setResult({ status: 'error', message: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="card p-6 w-full max-w-sm space-y-4" onClick={(e) => e.stopPropagation()}>
        <h3 className="font-semibold text-white">Isolate Host</h3>
        <form onSubmit={submit} className="space-y-3">
          <input
            className="w-full bg-[#161b22] border border-[#30363d] rounded px-3 py-2 text-sm text-white placeholder-[#8b949e]"
            placeholder="Hostname"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            required
          />
          <input
            className="w-full bg-[#161b22] border border-[#30363d] rounded px-3 py-2 text-sm text-white placeholder-[#8b949e]"
            placeholder="Device ID (optional)"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
          />
          <div className="flex gap-2">
            <button type="submit" disabled={busy} className="btn-primary text-xs flex-1 disabled:opacity-50">
              {busy ? 'Sending...' : 'Isolate'}
            </button>
            <button type="button" onClick={onClose} className="btn-secondary text-xs flex-1">Cancel</button>
          </div>
        </form>
        {result && (
          <div className={`p-2 rounded text-xs font-mono ${result.status === 'error' ? 'bg-red-900/20 text-red-400' : 'bg-green-900/20 text-green-400'}`}>
            {JSON.stringify(result)}
          </div>
        )}
      </div>
    </div>
  )
}

function KillProcessModal({ provider, onClose }) {
  const [agentId, setAgentId] = useState('')
  const [processId, setProcessId] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    try {
      const r = await edrApi.killProcess(provider, { agent_id: agentId, process_id: parseInt(processId, 10) })
      setResult(r.data)
    } catch (err) {
      setResult({ status: 'error', message: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="card p-6 w-full max-w-sm space-y-4" onClick={(e) => e.stopPropagation()}>
        <h3 className="font-semibold text-white">Kill Process</h3>
        <form onSubmit={submit} className="space-y-3">
          <input
            className="w-full bg-[#161b22] border border-[#30363d] rounded px-3 py-2 text-sm text-white placeholder-[#8b949e]"
            placeholder="Agent ID"
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            required
          />
          <input
            className="w-full bg-[#161b22] border border-[#30363d] rounded px-3 py-2 text-sm text-white placeholder-[#8b949e]"
            placeholder="Process ID (PID)"
            type="number"
            value={processId}
            onChange={(e) => setProcessId(e.target.value)}
            required
          />
          <div className="flex gap-2">
            <button type="submit" disabled={busy} className="btn-primary text-xs flex-1 disabled:opacity-50">
              {busy ? 'Sending...' : 'Kill Process'}
            </button>
            <button type="button" onClick={onClose} className="btn-secondary text-xs flex-1">Cancel</button>
          </div>
        </form>
        {result && (
          <div className={`p-2 rounded text-xs font-mono ${result.status === 'error' ? 'bg-red-900/20 text-red-400' : 'bg-green-900/20 text-green-400'}`}>
            {JSON.stringify(result)}
          </div>
        )}
      </div>
    </div>
  )
}

export default function Integrations() {
  const [integrations, setIntegrations] = useState([])
  const [loading, setLoading] = useState(true)
  const [polling, setPolling] = useState('')
  const [isolateModal, setIsolateModal] = useState(null)
  const [killModal, setKillModal] = useState(null)

  const load = () => {
    api.get('/integrations/').then((r) => {
      setIntegrations(r.data)
      setLoading(false)
    })
  }

  useEffect(() => { load() }, [])

  async function toggle(provider, current) {
    await api.post(`/integrations/${provider}/toggle`, { enabled: !current })
    load()
  }

  async function pollNow(provider) {
    setPolling(provider)
    try {
      await api.post(`/integrations/${provider}/poll`)
      setTimeout(load, 2000) // reload after 2s to show new state
    } finally {
      setPolling('')
    }
  }

  const coreIntegrations = integrations.filter((i) => !EDR_PROVIDERS.has(i.provider))
  const edrIntegrations = integrations.filter((i) => EDR_PROVIDERS.has(i.provider))

  function renderCard(integ) {
    const meta = PROVIDER_META[integ.provider] || { label: integ.provider, color: 'text-gray-400', bg: 'bg-gray-800 border-gray-700', abbr: '?' }
    return (
      <div key={integ.provider} className="card p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-10 h-10 rounded-lg border flex items-center justify-center text-sm font-bold ${meta.bg} ${meta.color}`}>
              {meta.abbr}
            </div>
            <div>
              <div className="font-semibold text-white">{meta.label}</div>
              <div className="flex items-center gap-2 mt-1">
                <StatusPill status={integ.status} isMock={integ.is_mock} />
                {integ.last_polled_at && (
                  <span className="text-xs text-[#8b949e]">
                    Last poll: {new Date(integ.last_polled_at).toLocaleString()}
                  </span>
                )}
                {integ.last_poll_count > 0 && (
                  <span className="text-xs text-[#8b949e]">
                    · {integ.last_poll_count} alerts ingested
                  </span>
                )}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            {integ.provider === 'crowdstrike_insight' && (
              <button
                onClick={() => setIsolateModal(integ.provider)}
                className="btn-secondary text-xs"
              >
                Isolate Host
              </button>
            )}
            {integ.provider === 'sentinelone' && (
              <button
                onClick={() => setKillModal(integ.provider)}
                className="btn-secondary text-xs"
              >
                Kill Process
              </button>
            )}
            <button
              onClick={() => pollNow(integ.provider)}
              disabled={!!polling}
              className="btn-secondary text-xs disabled:opacity-50"
            >
              {polling === integ.provider ? 'Polling...' : 'Poll Now'}
            </button>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={integ.enabled}
                onChange={() => toggle(integ.provider, integ.enabled)}
                className="w-4 h-4 accent-[#58a6ff]"
              />
              <span className="text-sm text-gray-200">Enabled</span>
            </label>
          </div>
        </div>

        {integ.is_mock && (
          <div className="mt-3 p-3 bg-yellow-900/10 border border-yellow-700/20 rounded-md">
            <p className="text-xs text-yellow-400/80">
              Running in <strong>mock mode</strong> — generating realistic sample alerts. Configure API credentials in <code className="font-mono">.env</code> to connect to the real API.
            </p>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Integrations</h1>
        <p className="text-sm text-[#8b949e] mt-1">
          Connect SentinelOps to your existing security tools. Alerts are normalized and surfaced here.
        </p>
      </div>

      {loading ? (
        <div className="py-20 text-center text-[#8b949e]">Loading integrations...</div>
      ) : (
        <>
          <div className="space-y-4">
            {coreIntegrations.map(renderCard)}
          </div>

          {edrIntegrations.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <h2 className="text-sm font-semibold text-white">EDR Adapters</h2>
                <div className="flex-1 h-px bg-[#30363d]" />
              </div>
              {edrIntegrations.map(renderCard)}
            </div>
          )}
        </>
      )}

      <div className="card p-4">
        <h2 className="text-sm font-semibold text-white mb-3">Environment Setup</h2>
        <div className="space-y-1 font-mono text-xs text-[#8b949e]">
          <div><span className="text-[#58a6ff]">CROWDSTRIKE_CLIENT_ID</span>=your-client-id</div>
          <div><span className="text-[#58a6ff]">CROWDSTRIKE_CLIENT_SECRET</span>=your-client-secret</div>
          <div><span className="text-[#58a6ff]">DATADOG_API_KEY</span>=your-api-key</div>
          <div><span className="text-[#58a6ff]">DATADOG_APP_KEY</span>=your-app-key</div>
          <div><span className="text-[#58a6ff]">SPLUNK_HOST</span>=splunk.your-company.com</div>
          <div><span className="text-[#58a6ff]">SPLUNK_TOKEN</span>=your-bearer-token</div>
          <div className="pt-1 border-t border-[#30363d] mt-1"><span className="text-[#58a6ff]">CROWDSTRIKE_INSIGHT_CLIENT_ID</span>=your-insight-client-id</div>
          <div><span className="text-[#58a6ff]">CROWDSTRIKE_INSIGHT_CLIENT_SECRET</span>=your-insight-client-secret</div>
          <div><span className="text-[#58a6ff]">SENTINELONE_API_KEY</span>=your-api-key</div>
          <div><span className="text-[#58a6ff]">SENTINELONE_MANAGEMENT_URL</span>=https://usea1.sentinelone.net</div>
        </div>
      </div>

      {isolateModal && (
        <IsolateHostModal provider={isolateModal} onClose={() => setIsolateModal(null)} />
      )}
      {killModal && (
        <KillProcessModal provider={killModal} onClose={() => setKillModal(null)} />
      )}
    </div>
  )
}
