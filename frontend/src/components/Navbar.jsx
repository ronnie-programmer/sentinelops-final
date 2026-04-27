import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { alertsApi } from '../api'

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/threats': 'Threat Management',
  '/alerts': 'Alert Log',
  '/assets': 'Asset Inventory',
  '/intel': 'Threat Intelligence Feed',
  '/compliance': 'Compliance Dashboard',
}

export default function Navbar() {
  const location = useLocation()
  const navigate = useNavigate()
  const [unreadCount, setUnreadCount] = useState(0)
  const [showDropdown, setShowDropdown] = useState(false)

  const title = PAGE_TITLES[location.pathname] || 'SentinelOps'

  useEffect(() => {
    fetchUnreadCount()
    const interval = setInterval(fetchUnreadCount, 30000)
    return () => clearInterval(interval)
  }, [])

  async function fetchUnreadCount() {
    try {
      const res = await alertsApi.getUnreadCount()
      setUnreadCount(res.data.count)
    } catch {
      // ignore
    }
  }

  const now = new Date().toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })

  return (
    <header className="h-14 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between px-6 flex-shrink-0">
      {/* Page title */}
      <div>
        <h1 className="text-sm font-semibold text-white">{title}</h1>
        <p className="text-[10px] text-[#8b949e]">{now}</p>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4">
        {/* Status indicator */}
        <div className="flex items-center gap-2 text-xs text-[#8b949e]">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span>SOC Live</span>
        </div>

        {/* Bell icon with badge */}
        <div className="relative">
          <button
            onClick={() => {
              setShowDropdown(!showDropdown)
              navigate('/alerts')
            }}
            className="relative p-2 rounded-md hover:bg-[#21262d] transition-colors"
            aria-label="Alerts"
          >
            <svg className="w-5 h-5 text-[#8b949e]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            {unreadCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center leading-none">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>
        </div>

        {/* Avatar */}
        <div className="w-7 h-7 rounded-full bg-[#58a6ff]/20 border border-[#58a6ff]/30 flex items-center justify-center text-xs font-semibold text-[#58a6ff]">
          SO
        </div>
      </div>
    </header>
  )
}
