import axios from 'axios'

const api = axios.create({
  baseURL: `${import.meta.env.VITE_API_URL}/api`,
  timeout: 30000,
})

// ── Emails ─────────────────────────────────────────────────────────

export async function uploadEmail(file) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post('/emails/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function listEmails(skip = 0, limit = 50) {
  const { data } = await api.get('/emails', { params: { skip, limit } })
  return data
}

export async function getEmail(id) {
  const { data } = await api.get(`/emails/${id}`)
  return data
}

// ── Analysis ───────────────────────────────────────────────────────

export async function runFullAnalysis(emailId) {
  const { data } = await api.post(`/emails/${emailId}/analyze-full`)
  return data
}

export async function getFullAnalysis(emailId) {
  const { data } = await api.get(`/emails/${emailId}/analyze-full`)
  return data
}

// ── Classification ─────────────────────────────────────────────────

export async function classifyEmail(emailId) {
  const { data } = await api.post(`/emails/${emailId}/classify`)
  return data
}

// ── Risk Engine ────────────────────────────────────────────────────

export async function computeRisk(emailId) {
  const { data } = await api.post(`/emails/${emailId}/risk`)
  return data
}

export async function getRisk(emailId) {
  const { data } = await api.get(`/emails/${emailId}/risk`)
  return data
}

// ── Cases ───────────────────────────────────────────────────────────

export async function listCases() {
  const { data } = await api.get('/cases')
  return data
}

export async function getCase(id) {
  const { data } = await api.get(`/cases/${id}`)
  return data
}

export async function createCase(caseData) {
  const { data } = await api.post('/cases', caseData)
  return data
}

export async function updateCase(id, caseData) {
  const { data } = await api.put(`/cases/${id}`, caseData)
  return data
}

export async function assignEmailToCase(caseId, emailId) {
  const { data } = await api.post(`/cases/${caseId}/emails/${emailId}`)
  return data
}

export async function getCaseEmails(caseId) {
  const { data } = await api.get(`/cases/${caseId}/emails`)
  return data
}

// ── Evidence & Audit ────────────────────────────────────────────────

export async function verifyEvidence(emailId) {
  const { data } = await api.get(`/evidence/verify/${emailId}`)
  return data
}

export async function getAuditLogs(skip = 0, limit = 100) {
  const { data } = await api.get('/audit', { params: { skip, limit } })
  return data
}

export async function verifyAuditLog() {
  const { data } = await api.post('/audit/verify')
  return data
}

// ── Correlation & Reports ───────────────────────────────────────────

export async function getCorrelationGraph() {
  const { data } = await api.get('/graph')
  return data
}

export async function getSharedInfrastructure() {
  const { data } = await api.get('/graph/shared')
  return data
}

export async function addEmailToGraph(emailId) {
  const { data } = await api.post(`/graph/email/${emailId}`)
  return data
}

export function getReportUrl(emailId) {
  return `${import.meta.env.VITE_API_URL}/api/reports/${emailId}/pdf`
}

// ── Health ─────────────────────────────────────────────────────────

export async function checkHealth() {
  const { data } = await axios.get(
    `${import.meta.env.VITE_API_URL}/health`
  )
  return data
}
