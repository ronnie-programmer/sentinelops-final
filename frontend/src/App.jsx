import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'
import Dashboard from './pages/Dashboard'
import Threats from './pages/Threats'
import Alerts from './pages/Alerts'
import Assets from './pages/Assets'
import Compliance from './pages/Compliance'
import ThreatIntel from './pages/ThreatIntel'
import Integrations from './pages/Integrations'

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-[#0d1117]">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Navbar />
        <main className="flex-1 overflow-y-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/intel" element={<ThreatIntel />} />
            <Route path="/integrations" element={<Integrations />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
