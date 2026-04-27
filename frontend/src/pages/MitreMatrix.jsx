import { useState, useEffect } from 'react'
import api from '../api'

const HEAT_COLORS = [
  'bg-[#21262d] text-[#8b949e]',      // 0 detections
  'bg-blue-900/40 text-blue-300',      // 1-2
  'bg-orange-900/50 text-orange-300',  // 3-5
  'bg-red-900/60 text-red-300',        // 6+
]

function heatClass(count) {
  if (count === 0) return HEAT_COLORS[0]
  if (count <= 2) return HEAT_COLORS[1]
  if (count <= 5) return HEAT_COLORS[2]
  return HEAT_COLORS[3]
}

export default function MitreMatrix() {
  const [matrix, setMatrix] = useState([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    api.get('/mitre/matrix').then((r) => {
      setMatrix(r.data)
      setLoading(false)
    })
  }, [])

  const totalDetections = matrix.reduce(
    (sum, tac) => sum + tac.techniques.reduce((s, t) => s + t.detection_count, 0),
    0
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">MITRE ATT&CK Matrix</h1>
          <p className="text-sm text-[#8b949e] mt-0.5">
            Enterprise technique detections — last 30 days &bull; {totalDetections} total
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs text-[#8b949e]">
          {[
            { label: 'No detections', cls: HEAT_COLORS[0] },
            { label: '1–2', cls: HEAT_COLORS[1] },
            { label: '3–5', cls: HEAT_COLORS[2] },
            { label: '6+', cls: HEAT_COLORS[3] },
          ].map((h) => (
            <div key={h.label} className="flex items-center gap-1.5">
              <span className={`w-3 h-3 rounded-sm inline-block ${h.cls}`} />
              {h.label}
            </div>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="py-20 text-center text-[#8b949e]">Loading matrix...</div>
      ) : (
        <div className="space-y-4 overflow-x-auto">
          {matrix.map((tactic) => (
            <div key={tactic.tactic_id} className="card p-4">
              <div className="text-xs font-semibold text-[#58a6ff] uppercase tracking-widest mb-3">
                {tactic.tactic_id} — {tactic.tactic}
              </div>
              <div className="flex flex-wrap gap-2">
                {tactic.techniques.map((tech) => (
                  <button
                    key={tech.id}
                    onClick={() => setSelected(selected?.id === tech.id ? null : tech)}
                    className={`px-2.5 py-1.5 rounded text-xs font-mono border border-[#30363d] transition-all hover:border-[#58a6ff]/50 ${heatClass(tech.detection_count)} ${selected?.id === tech.id ? 'ring-1 ring-[#58a6ff]' : ''}`}
                    title={`${tech.name} — ${tech.detection_count} detection(s)`}
                  >
                    <span className="opacity-60">{tech.id}</span>
                    <span className="ml-1 hidden sm:inline">{tech.name}</span>
                    {tech.detection_count > 0 && (
                      <span className="ml-1 font-bold">({tech.detection_count})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Side panel for selected technique */}
      {selected && (
        <div className="card p-5 border-[#58a6ff]/30">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-xs text-[#58a6ff] font-mono mb-1">{selected.id}</div>
              <h2 className="text-lg font-bold text-white">{selected.name}</h2>
              <div className="text-xs text-[#8b949e] mt-0.5">{selected.tactic}</div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold text-white">{selected.detection_count}</div>
              <div className="text-xs text-[#8b949e]">detections</div>
            </div>
          </div>
          <a
            href={selected.url}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-flex items-center gap-1 text-xs text-[#58a6ff] hover:underline"
          >
            View on MITRE ATT&CK ↗
          </a>
          <button
            onClick={() => setSelected(null)}
            className="mt-3 ml-4 btn-secondary text-xs"
          >
            Close
          </button>
        </div>
      )}
    </div>
  )
}
