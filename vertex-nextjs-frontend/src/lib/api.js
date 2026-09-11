import axios from 'axios'

const baseURL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: `${baseURL}/api`,
  timeout: 30000,
})

export async function uploadEmail(file) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post('/emails/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function listEmails(skip = 0, limit = 100) {
  const { data } = await api.get('/emails', { params: { skip, limit } })
  return data
}

export async function getEmail(id) {
  const { data } = await api.get(`/emails/${id}`)
  return data
}

export async function runFullAnalysis(emailId) {
  const { data } = await api.post(`/emails/${emailId}/analyze-full`)
  return data
}

export async function classifyEmail(emailId) {
  const { data } = await api.post(`/emails/${emailId}/classify`)
  return data
}

export async function computeRisk(emailId) {
  const { data } = await api.post(`/emails/${emailId}/risk`)
  return data
}

export async function listCases() {
  const { data } = await api.get('/cases')
  return data
}

export async function createCase(caseData) {
  const { data } = await api.post('/cases', caseData)
  return data
}

export async function assignEmailToCase(caseId, emailId) {
  const { data } = await api.post(`/cases/${caseId}/emails/${emailId}`)
  return data
}

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
  return `${baseURL}/api/reports/${emailId}/pdf`
}

export async function checkHealth() {
  const { data } = await axios.get(`${baseURL}/health`, { timeout: 6000 })
  return data
}

export function getApiBaseUrl() {
  return baseURL
}
