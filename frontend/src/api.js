import axios from 'axios'

// In dev, VITE_API_URL is unset and Vite proxies /api → localhost:8000.
// In production (Vercel), set VITE_API_URL=https://your-backend.railway.app
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : '/api',
})

export const dashboardApi = {
  getStats: () => api.get('/dashboard/stats'),
}

export const threatsApi = {
  getAll: (params) => api.get('/threats/', { params }),
  getOne: (id) => api.get(`/threats/${id}`),
  create: (data) => api.post('/threats/', data),
  update: (id, data) => api.put(`/threats/${id}`, data),
  delete: (id) => api.delete(`/threats/${id}`),
  analyze: (id) => api.post(`/threats/${id}/analyze`),
}

export const alertsApi = {
  getAll: (params) => api.get('/alerts/', { params }),
  getUnreadCount: () => api.get('/alerts/unread-count'),
  acknowledge: (id) => api.post(`/alerts/${id}/acknowledge`),
  acknowledgeAll: () => api.post('/alerts/acknowledge-all'),
}

export const assetsApi = {
  getAll: (params) => api.get('/assets/', { params }),
  getOne: (id) => api.get(`/assets/${id}`),
  create: (data) => api.post('/assets/', data),
  update: (id, data) => api.put(`/assets/${id}`, data),
  delete: (id) => api.delete(`/assets/${id}`),
}

export const complianceApi = {
  getOverview: () => api.get('/compliance/'),
  getNIST: () => api.get('/compliance/nist'),
  getSOC2: () => api.get('/compliance/soc2'),
  exportCSV: () => api.get('/compliance/export/csv', { responseType: 'blob' }),
}

export const intelApi = {
  getAll: (params) => api.get('/intel/', { params }),
  getOne: (id) => api.get(`/intel/${id}`),
  create: (data) => api.post('/intel/', data),
  importAsThreat: (id) => api.post(`/intel/${id}/import`),
  delete: (id) => api.delete(`/intel/${id}`),
}

export const notificationsApi = {
  getAll: () => api.get('/notifications/'),
  getSettings: () => api.get('/notifications/settings'),
  saveSettings: (data) => api.post('/notifications/settings', data),
  test: (channel) => api.post('/notifications/test', { channel }),
}

export const mitreApi = {
  getTechniques: () => api.get('/mitre/techniques'),
  getTechnique: (id) => api.get(`/mitre/techniques/${id}`),
  getMatrix: () => api.get('/mitre/matrix'),
}

export const integrationsApi = {
  getAll: () => api.get('/integrations/'),
  toggle: (provider, enabled) => api.post(`/integrations/${provider}/toggle`, { enabled }),
  pollNow: (provider) => api.post(`/integrations/${provider}/poll`),
  getAlerts: (source) => api.get('/integrations/alerts', { params: source ? { source } : {} }),
}

export const iocApi = {
  getAll: (params) => api.get('/iocs/', { params }),
  getTop: () => api.get('/iocs/top'),
  getOne: (id) => api.get(`/iocs/${id}`),
  enrich: (id) => api.post(`/iocs/enrich/${id}`),
  delete: (id) => api.delete(`/iocs/${id}`),
}

export const complianceReportsApi = {
  getAll: () => api.get('/compliance/reports'),
  generate: (data) => api.post('/compliance/reports/generate', data),
  getOne: (id) => api.get(`/compliance/reports/${id}`),
  download: (id) => api.get(`/compliance/reports/${id}/download`, { responseType: 'blob' }),
  delete: (id) => api.delete(`/compliance/reports/${id}`),
}

export default api
