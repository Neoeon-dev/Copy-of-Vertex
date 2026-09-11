import axios, { AxiosError } from 'axios'
import type {
  AuditLog, AuditVerification, AuthenticationSummary, Case, CaseEmail, CorrelationGraph,
  EmailDetail, EmailSummary, EvidenceVerification, FullAnalysis, GraphNode, GraphEdge,
  MLClassification, RiskAssessment, SharedInfrastructure, IPAnalysis,
} from '../types/api'

const configuredApiUrl = process.env.NEXT_PUBLIC_API_URL?.trim()
const baseURL = (configuredApiUrl || (process.env.NODE_ENV === 'production'
  ? 'https://vertex-8ko3.onrender.com'
  : 'http://localhost:8000')).replace(/\/$/, '')

const api = axios.create({
  baseURL: `${baseURL}/api`,
  timeout: 30000,
})

export function apiError(error: unknown): string {
  if (error instanceof AxiosError) {
    return String(error.response?.data?.detail || error.message || 'Request failed')
  }
  return error instanceof Error ? error.message : 'Request failed'
}

export async function uploadEmail(file: File, onProgress?: (percent: number) => void): Promise<EmailDetail> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post<EmailDetail>('/emails/analyze', form, {
    onUploadProgress: (event) => onProgress?.(event.total ? Math.round((event.loaded / event.total) * 100) : 0),
  })
  return data
}

export async function listEmails(skip = 0, limit = 100): Promise<EmailSummary[]> {
  const { data } = await api.get<EmailSummary[]>('/emails', { params: { skip, limit } })
  return data
}

export async function getEmail(id: number | string): Promise<EmailDetail> {
  const { data } = await api.get<EmailDetail>(`/emails/${id}`)
  return data
}

export async function getAuthentication(id: number | string): Promise<AuthenticationSummary> {
  const { data } = await api.get<AuthenticationSummary>(`/emails/${id}/authentication`)
  return data
}

export async function runFullAnalysis(id: number | string): Promise<FullAnalysis> {
  const { data } = await api.post<FullAnalysis>(`/emails/${id}/analyze-full`)
  return data
}

export async function classifyEmail(id: number | string): Promise<MLClassification> {
  const { data } = await api.post<MLClassification>(`/emails/${id}/classify`)
  return data
}

export async function computeRisk(id: number | string): Promise<RiskAssessment> {
  const { data } = await api.post<RiskAssessment>(`/emails/${id}/risk`)
  return data
}

export async function getIpIntelligence(id: number | string): Promise<IPAnalysis> {
  const { data } = await api.get<IPAnalysis>(`/emails/${id}/ip-intel`)
  return data
}

export async function listCases(): Promise<Case[]> {
  const { data } = await api.get<Case[]>('/cases')
  return data
}

export async function createCase(payload: { title: string; description?: string | null }): Promise<Case> {
  const { data } = await api.post<Case>('/cases', payload)
  return data
}

export async function assignEmailToCase(caseId: number, emailId: number): Promise<{ status: string; email_id: number; case_id: number }> {
  const { data } = await api.post(`/cases/${caseId}/emails/${emailId}`)
  return data
}

export async function getCaseEmails(caseId: number): Promise<CaseEmail[]> {
  const { data } = await api.get<CaseEmail[]>(`/cases/${caseId}/emails`)
  return data
}

export async function verifyEvidence(emailId: number | string): Promise<EvidenceVerification> {
  const { data } = await api.get<EvidenceVerification>(`/evidence/verify/${emailId}`)
  return data
}

export async function getAuditLogs(skip = 0, limit = 100): Promise<AuditLog[]> {
  const { data } = await api.get<AuditLog[]>('/audit', { params: { skip, limit } })
  return data
}

export async function verifyAuditLog(): Promise<AuditVerification> {
  const { data } = await api.post<AuditVerification>('/audit/verify')
  return data
}

export async function getCorrelationGraph(): Promise<CorrelationGraph> {
  const { data } = await api.get<CorrelationGraph>('/graph')
  return data
}

export async function getSharedInfrastructure(): Promise<SharedInfrastructure> {
  const { data } = await api.get<SharedInfrastructure>('/graph/shared')
  return data
}

export async function addEmailToGraph(emailId: number | string): Promise<{ status: string; email_id: number }> {
  const { data } = await api.post(`/graph/email/${emailId}`)
  return data
}

export function getReportUrl(emailId: number | string): string {
  return `${baseURL}/api/reports/${emailId}/pdf`
}

export async function checkHealth(): Promise<{ status: string }> {
  const { data } = await axios.get<{ status: string }>(`${baseURL}/health`, { timeout: 7000 })
  return data
}

export function getApiBaseUrl(): string { return baseURL }
