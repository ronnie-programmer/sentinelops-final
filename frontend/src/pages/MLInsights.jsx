import { useState, useEffect } from 'react'
import {
  BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { mlApi } from '../api'

const SEVERITY_CLS = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  LOW: 'bg-green-500/15 text-green-400 border border-green-500/30',
}

const RISK_CLS = {
  High: 'bg-red-500/15 text-red-400 border border-red-500/30',
  Medium: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  Low: 'bg-green-500/15 text-green-400 border border-green-500/30',
  Unknown: 'bg-gray-500/15 text-[#8b949e] border border-gray-500/30',
}

const RISK_BAR_COLOR = { High: '#f85149', Medium: '#d29922', Low: '#3fb950', Anomalies: '#58a6ff' }

function Badge({ label, cls }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${cls}`}>{label}</span>
  )
}

function StatCard({ label, value, color }) {
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
      <div className="text-xs text-[#8b949e] mb-1">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  )
}

const TABS = [
  { id: 'all', label: 'All Threats' },
  { id: 'high', label: 'High Risk' },
  { id: 'anomalies', label: 'Anomalies' },
]

export default function MLInsights() {
  const [predictions, setPredictions] = useState([])
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [training, setTraining] = useState(false)
  const [trainResult, setTrainResult] = useState(null)
  const [activeTab, setActiveTab] = useState('all')

  const load = async () => {
    setLoading(true)
    try {
      const [predRes, statusRes] = await Promise.all([
        mlApi.getPredictions(),
        mlApi.getStatus(),
      ])
      setPredictions(predRes.data)
      setStatus(statusRes.data)
    } catch {
      // silently degrade — table will show empty state
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleTrain = async () => {
    setTraining(true)
    setTrainResult(null)
    try {
      const res = await mlApi.train()
      setTrainResult(res.data)
      await load()
    } catch {
      setTrainResult({ status: 'error' })
    } finally {
      setTraining(false)
    }
  }

  const counts = {
    High: predictions.filter((p) => p.risk_label === 'High').length,
    Medium: predictions.filter((p) => p.risk_label === 'Medium').length,
    Low: predictions.filter((p) => p.risk_label === 'Low').length,
    anomalies: predictions.filter((p) => p.is_anomaly).length,
  }

  const chartData = [
    { label: 'High Risk', count: counts.High, key: 'High' },
    { label: 'Medium Risk', count: counts.Medium, key: 'Medium' },
    { label: 'Low Risk', count: counts.Low, key: 'Low' },
    { label: 'Anomalies', count: counts.anomalies, key: 'Anomalies' },
  ]

  const displayed =
    activeTab === 'anomalies'
      ? predictions.filter((p) => p.is_anomaly)
      : activeTab === 'high'
      ? predictions.filter((p) => p.risk_label === 'High')
      : predictions

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">ML Insights</h1>
          <p className="text-sm text-[#8b949e] mt-0.5">
            AI-powered threat risk scoring and anomaly detection
          </p>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {status && (
            <div className="flex items-center gap-2">
              <div
                className={`w-2 h-2 rounded-full ${
                  status.ready ? 'bg-green-400' : 'bg-yellow-400'
                }`}
              />
              <span className="text-xs text-[#8b949e]">
                {status.ready
                  ? `Model ready · ${status.n_samples} samples`
                  : 'Model not trained'}
              </span>
            </div>
          )}
          <button
            onClick={handleTrain}
            disabled={training}
            className="px-4 py-2 bg-[#238636] hover:bg-[#2ea043] disabled:opacity-50 text-white text-sm rounded-md transition-colors font-medium"
          >
            {training ? 'Training…' : 'Retrain Model'}
          </button>
        </div>
      </div>

      {/* Train result banner */}
      {trainResult && (
        <div
          className={`p-3 rounded-md border text-sm ${
            trainResult.status === 'trained'
              ? 'bg-green-500/10 border-green-500/30 text-green-400'
              : trainResult.status === 'insufficient_data'
              ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
              : 'bg-red-500/10 border-red-500/30 text-red-400'
          }`}
        >
          {trainResult.status === 'trained'
            ? `Model retrained on ${trainResult.n_samples} threats · ${trainResult.n_high_risk} high-risk · trained at ${trainResult.trained_at?.slice(0, 19).replace('T', ' ')} UTC`
            : trainResult.status === 'insufficient_data'
            ? 'Not enough data to train (need ≥ 5 threats). Run seed.py first.'
            : 'Training failed — check backend logs.'}
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Scored" value={predictions.length} color="text-white" />
        <StatCard label="High Risk" value={counts.High} color="text-red-400" />
        <StatCard label="Medium Risk" value={counts.Medium} color="text-yellow-400" />
        <StatCard label="Anomalies" value={counts.anomalies} color="text-[#58a6ff]" />
      </div>

      {/* Chart + table */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Bar chart */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
          <div className="text-sm font-medium text-[#e6edf3] mb-4">Risk Distribution</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData} barSize={28}>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fill: '#8b949e', fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#8b949e', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  background: '#161b22',
                  border: '1px solid #30363d',
                  borderRadius: 6,
                  fontSize: 12,
                }}
                labelStyle={{ color: '#e6edf3' }}
                itemStyle={{ color: '#8b949e' }}
                cursor={{ fill: '#21262d' }}
              />
              <Bar dataKey="count" name="Count" radius={[4, 4, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell key={entry.key} fill={RISK_BAR_COLOR[entry.key]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Predictions table */}
        <div className="lg:col-span-2 bg-[#161b22] border border-[#30363d] rounded-lg flex flex-col">
          {/* Tabs */}
          <div className="flex border-b border-[#30363d] px-4 flex-shrink-0">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-3 px-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-[#58a6ff] text-[#58a6ff]'
                    : 'border-transparent text-[#8b949e] hover:text-[#e6edf3]'
                }`}
              >
                {tab.label}
                {tab.id === 'high' && counts.High > 0 && (
                  <span className="ml-1.5 text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded-full">
                    {counts.High}
                  </span>
                )}
                {tab.id === 'anomalies' && counts.anomalies > 0 && (
                  <span className="ml-1.5 text-xs bg-[#58a6ff]/20 text-[#58a6ff] px-1.5 py-0.5 rounded-full">
                    {counts.anomalies}
                  </span>
                )}
              </button>
            ))}
          </div>

          {loading ? (
            <div className="flex items-center justify-center flex-1 h-48 text-[#8b949e] text-sm">
              Loading predictions…
            </div>
          ) : displayed.length === 0 ? (
            <div className="flex items-center justify-center flex-1 h-48 text-[#8b949e] text-sm">
              No threats in this category.
            </div>
          ) : (
            <div className="overflow-x-auto overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-[#161b22]">
                  <tr className="text-left text-[#8b949e] text-xs uppercase tracking-wide">
                    <th className="px-4 py-3 font-medium">Threat</th>
                    <th className="px-4 py-3 font-medium">Type</th>
                    <th className="px-4 py-3 font-medium">Severity</th>
                    <th className="px-4 py-3 font-medium">AI Risk</th>
                    <th className="px-4 py-3 font-medium">Score</th>
                  </tr>
                </thead>
                <tbody>
                  {displayed.map((p) => (
                    <tr
                      key={p.id}
                      className={`border-t border-[#21262d] hover:bg-[#21262d]/60 transition-colors ${
                        p.is_anomaly ? 'bg-[#58a6ff]/[0.03]' : ''
                      }`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2 min-w-0">
                          {p.is_anomaly && (
                            <span className="text-[#58a6ff] flex-shrink-0" title="Anomaly">
                              ◆
                            </span>
                          )}
                          <span
                            className="text-[#e6edf3] truncate"
                            style={{ maxWidth: 180 }}
                            title={p.title}
                          >
                            {p.title}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-[#8b949e] whitespace-nowrap">{p.threat_type}</td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <Badge
                          label={p.severity}
                          cls={SEVERITY_CLS[p.severity] ?? SEVERITY_CLS.LOW}
                        />
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <Badge
                          label={p.risk_label}
                          cls={RISK_CLS[p.risk_label] ?? RISK_CLS.Unknown}
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-14 bg-[#21262d] rounded-full h-1.5 flex-shrink-0">
                            <div
                              className="h-1.5 rounded-full"
                              style={{
                                width: `${Math.round(p.risk_score * 100)}%`,
                                backgroundColor:
                                  p.risk_label === 'High'
                                    ? '#f85149'
                                    : p.risk_label === 'Medium'
                                    ? '#d29922'
                                    : '#3fb950',
                              }}
                            />
                          </div>
                          <span className="text-xs text-[#8b949e]">
                            {Math.round(p.risk_score * 100)}%
                          </span>
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

      {/* Anomaly callout */}
      {counts.anomalies > 0 && (
        <div className="bg-[#58a6ff]/5 border border-[#58a6ff]/20 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[#58a6ff] font-bold">◆</span>
            <span className="text-sm font-medium text-[#58a6ff]">Anomaly Detection Active</span>
          </div>
          <p className="text-xs text-[#8b949e] leading-relaxed">
            {counts.anomalies} threat{counts.anomalies !== 1 ? 's' : ''} flagged by Isolation
            Forest. Their feature combination (threat type, MITRE tactic, IP presence, time of
            day) is statistically unusual vs the rest of the dataset. Review these for
            misclassification or novel attack patterns not seen before.
          </p>
        </div>
      )}
    </div>
  )
}
