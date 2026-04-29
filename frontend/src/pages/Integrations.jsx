import { useState, useEffect } from 'react'
import api from '../api'

const PROVIDER_META = {
  crowdstrike: { label: 'CrowdStrike Falcon', subtitle: 'Detection summaries', color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/40', abbr: 'CS', kind: 'siem' },
  datadog: { label: 'Datadog Security', subtitle: 'Cloud SIEM signals', color: 'text-purple-400', bg: 'bg-purple-900/20 border-purple-700/40', abbr: 'DD', kind: 'siem' },
  splunk: { label: 'Splunk Enterprise Security', subtitle: 'Correlation alerts', color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/40', abbr: 'SP', kind: 'siem' },
  crowdstrike_insight: { label: 'CrowdStrike Falcon Insight', subtitle: 'EDR — process telemetry, RTR', color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/40', abbr: 'CSI', kind: 'edr' },
  sentinelone: { label: 'SentinelOne Singularity', subtitle: 'EDR — behavioral AI, mitigation', color: 'text-cyan-400', bg: 'bg-cyan-900/20 border-cyan-700/40', abbr: 'S1', kind: 'edr' },
}

function StatusPill({ status, isMock }) {
  if (isMock) return <span className="severity-badge bg-yellow-900/30 text-yellow-400 border border-yellow-700/40">MOCK</span>
  const map = {
    connected: 'bg-green-900/40 text-green-400 border-green-700/40',
    error: 'bg-red-900/40 text-red-400 border-red-700/40',
    idle: 'bg-gray-800 text-gray-400 border-gray-700',
  }
  return <span className={`severity-badge border ${map[status] || map.idle}`}>{status}</span>
}

function EDRActionsPanel({ provider, onResult }) {
  const [hostId, setHostId] = useState('')
  const [pid, setPid] = useState('')
  const [busy, setBusy] = useState('')

  async function isolate() {
    if (!hostId) return
    setBusy('isolate')
    try {
      const r = await api.post(`/integrations/${provider}/isolate`, { host_id: hostId })
      onResult(`isolate: ${r.data.message}`, true)
    } catch (e) {
      onResult(`isolate failed: ${e.response?.data?.detail || e.message}`, false)
    } finally {
      setBusy('')
    }
  }

  async function kill() {
    if (!hostId || !pid) return
    setBusy('kill')
    try {
      const r = await api.post(`/integrations/${provider}/kill-process`, { host_id: hostId, process_id: pid })
      onResult(`kill: ${r.data.message}`, true)
    } catch (e) {
      onResult(`kill failed: ${e.response?.data?.detail || e.message}`, false)
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="mt-3 p-3 bg-[#0d1117] border border-[#30363d] rounded-md">
      <div className="text-xs font-semibold text-[#8b949e] uppercase tracking-wide mb-2">EDR Response Actions</div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mb-2">
        <input
          value={hostId}
          onChange={(e) => setHostId(e.target.value)}
          placeholder="agent / host id"
          className="px-2 py-1 text-xs bg-[#161b22] border border-[#30363d] rounded text-gray-200"
        />
        <input
          value={pid}
          onChange={(e) => setPid(e.target.value)}
          placeholder="process id (for kill)"
          className="px-2 py-1 text-xs bg-[#161b22] border border-[#30363d] rounded text-gray-200"
        />
        <div className="flex gap-2">
          <button
            onClick={isolate}
            disabled={!hostId || !!busy}
            className="btn-secondary text-xs flex-1 disabled:opacity-50"
          >
            {busy === 'isolate' ? '…' : 'Isolate Host'}
          </button>
          <button
            onClick={kill}
            disabled={!hostId || !pid || !!busy}
            className="btn-secondary text-xs flex-1 disabled:opacity-50"
          >
            {busy === 'kill' ? '…' : 'Kill Process'}
          </button>
        </div>
      </div>
      <p className="text-[11px] text-[#6e7681]">
        Quarantine an endpoint from the network or terminate a malicious process directly from SentinelOps.
      </p>
    </div>
  )
}

export default function Integrations() {
  const [integrations, setIntegrations] = useState([])
  const [loading, setLoading] = useState(true)
  const [polling, setPolling] = useState('')
  const [actionResult, setActionResult] = useState(null)

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
      setTimeout(load, 2000)
    } finally {
      setPolling('')
    }
  }

  function handleActionResult(message, ok) {
    setActionResult({ message, ok, ts: Date.now() })
    setTimeout(() => setActionResult(null), 6000)
  }

  const siemAdapters = integrations.filter((i) => PROVIDER_META[i.provider]?.kind === 'siem')
  const edrAdapters = integrations.filter((i) => PROVIDER_META[i.provider]?.kind === 'edr')

  function renderCard(integ) {
    const meta = PROVIDER_META[integ.provider] || { label: integ.provider, subtitle: '', color: 'text-gray-400', bg: 'bg-gray-800 border-gray-700', abbr: '?', kind: 'siem' }
    return (
      <div key={integ.provider} className="card p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-10 h-10 rounded-lg border flex items-center justify-center text-sm font-bold ${meta.bg} ${meta.color}`}>
              {meta.abbr}
            </div>
            <div>
              <div className="font-semibold text-white">{meta.label}</div>
              {meta.subtitle && <div className="text-[11px] text-[#8b949e] mt-0.5">{meta.subtitle}</div>}
              <div className="flex items-center gap-2 mt-1">
                <StatusPill status={integ.status} isMock={integ.is_mock} />
                {integ.last_polled_at && (
                  <span className="text-xs text-[#8b949e]">
                    Last poll: {new Date(integ.last_polled_at).toLocaleString()}
                  </span>
                )}
                {integ.last_poll_count > 0 && (
                  <span className="text-xs text-[#8b949e]">· {integ.last_poll_count} alerts ingested</span>
                )}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
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

        {meta.kind === 'edr' && integ.enabled && (
          <EDRActionsPanel provider={integ.provider} onResult={handleActionResult} />
        )}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Integrations</h1>
        <p className="text-sm text-[#8b949e] mt-1">
          Connect SentinelOps to your existing security tools. Alerts are normalized and surfaced here. EDR adapters add response actions (isolate host, kill process).
        </p>
      </div>

      {actionResult && (
        <div className={`px-3 py-2 rounded-md border text-sm ${actionResult.ok ? 'bg-green-900/20 border-green-700/40 text-green-400' : 'bg-red-900/20 border-red-700/40 text-red-400'}`}>
          {actionResult.message}
        </div>
      )}

      {loading ? (
        <div className="py-20 text-center text-[#8b949e]">Loading integrations...</div>
      ) : (
        <>
          <div>
            <h2 className="text-sm font-semibold text-[#8b949e] uppercase tracking-wide mb-2">SIEM &amp; Cloud Security</h2>
            <div className="space-y-4">{siemAdapters.map(renderCard)}</div>
          </div>
          <div>
            <h2 className="text-sm font-semibold text-[#8b949e] uppercase tracking-wide mb-2">Endpoint Detection &amp; Response (EDR)</h2>
            <div className="space-y-4">{edrAdapters.map(renderCard)}</div>
          </div>
        </>
      )}

      <div className="card p-4">
        <h2 className="text-sm font-semibold text-white mb-3">Environment Setup</h2>
        <div className="space-y-1 font-mono text-xs text-[#8b949e]">
          <div><span className="text-[#58a6ff]">CROWDSTRIKE_CLIENT_ID</span>=your-client-id</div>
          <div><span className="text-[#58a6ff]">CROWDSTRIKE_CLIENT_SECRET</span>=your-client-secret</div>
          <div><span className="text-[#58a6ff]">CROWDSTRIKE_INSIGHT_CLIENT_ID</span>=your-insight-client-id <span className="text-[#6e7681]"># falls back to CROWDSTRIKE_CLIENT_ID</span></div>
          <div><span className="text-[#58a6ff]">CROWDSTRIKE_INSIGHT_CLIENT_SECRET</span>=your-insight-secret</div>
          <div><span className="text-[#58a6ff]">SENTINELONE_API_KEY</span>=your-api-token</div>
          <div><span className="text-[#58a6ff]">SENTINELONE_MANAGEMENT_URL</span>=https://usea1.sentinelone.net</div>
          <div><span className="text-[#58a6ff]">DATADOG_API_KEY</span>=your-api-key</div>
          <div><span className="text-[#58a6ff]">DATADOG_APP_KEY</span>=your-app-key</div>
          <div><span className="text-[#58a6ff]">SPLUNK_HOST</span>=splunk.your-company.com</div>
          <div><span className="text-[#58a6ff]">SPLUNK_TOKEN</span>=your-bearer-token</div>
        </div>
      </div>
    </div>
  )
}
