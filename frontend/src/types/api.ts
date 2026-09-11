export type Recipient = { name: string | null; address: string | null }

export type HeaderOut = { name: string; value: string; position: number }
export type Attachment = { id: number; filename: string | null; content_type: string; size: number; sha256: string }

export type EmailSummary = {
  id: number
  case_id: number | null
  sha256: string
  filename: string | null
  size: number
  subject: string | null
  sender: string | null
  sender_name: string | null
  date: string | null
  created_at: string
}

export type AuthResult = {
  mechanism: 'SPF' | 'DKIM' | 'DMARC' | string
  result: string
  domain: string | null
  selector?: string | null
  aligned: boolean | null
  source: string
  details: string | null
  checked_at: string
}

export type AuthenticationSummary = {
  spf: AuthResult | null
  dkim: AuthResult | null
  dmarc: AuthResult | null
  all_results: AuthResult[]
}

export type EmailDetail = EmailSummary & {
  reply_to: string | null
  to: Recipient[]
  cc: Recipient[]
  message_id: string | null
  body_text: string | null
  body_html: string | null
  headers: HeaderOut[]
  attachments: Attachment[]
  authentication: AuthenticationSummary | null
}

export type AuthResultSimple = {
  mechanism: string
  result: string
  domain: string | null
  details: string | null
}


export type GeoInfo = {
  country_code: string | null
  country_name: string | null
  region: string | null
  city: string | null
  latitude: number | null
  longitude: number | null
  accuracy_radius_km: number | null
}

export type ASNInfo = {
  asn: number | null
  organization: string | null
  network: string | null
}

export type IPIntel = {
  ip: string
  is_public: boolean | null
  is_private: boolean | null
  is_reserved: boolean | null
  geo: GeoInfo | null
  asn: ASNInfo | null
  warnings: string[]
}

export type IPAnalysis = {
  email_id: number
  ips: IPIntel[]
  total_ips: number
  public_ips: number
  private_ips: number
}

export type FullAnalysis = {
  email_id: number
  subject: string | null
  sender: string | null
  spf: AuthResultSimple | null
  dkim: AuthResultSimple | null
  dmarc: AuthResultSimple | null
  total_hops: number
  public_ips: string[]
  private_ips: string[]
  received_anomalies: string[]
  ip_analysis: Record<string, unknown>[]
  domain_analysis: Record<string, unknown>[]
  urls: Record<string, unknown>[]
  total_urls: number
  attachment_analysis: Record<string, unknown>[]
  overall_risk_score: number
}

export type MLClassification = {
  email_id: number
  label: string
  confidence: number
  probabilities: Record<string, number>
  signals: Record<string, number>
  signal_details: Record<string, string>
  risk_score: number
}

export type RiskContribution = {
  category: string
  signal: string
  raw_value: number
  weight: number
  contribution: number
  description: string
  confidence: string
}

export type RiskAssessment = {
  email_id: number
  score: number
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string
  category_scores: Record<string, number>
  contributions: RiskContribution[]
  summary: string
  limitations: string[]
}

export type Case = { id: number; title: string; description: string | null; created_at: string; email_count: number }
export type CaseEmail = Pick<EmailSummary, 'id' | 'subject' | 'sender' | 'sha256' | 'created_at'>

export type AuditLog = {
  id: number
  timestamp: string
  action: string
  entity_type: string
  entity_id: number | null
  actor: string
  details: string | null
  entry_hash: string
}

export type AuditVerification = { valid: boolean; entry_count: number; errors: string[] }
export type EvidenceVerification = { email_id: number; evidence_id: string; valid: boolean; entry_count: number; errors: string[] }

export type GraphNode = {
  id: string
  label?: string
  nodeType?: string
  type?: string
  email_id?: number
  [key: string]: unknown
}
export type GraphEdge = { id?: string; source: string; target: string; edgeType?: string; [key: string]: unknown }
export type CorrelationGraph = {
  elements?: { nodes?: { data?: GraphNode }[]; edges?: { data?: GraphEdge }[] }
  nodes?: GraphNode[]
  links?: GraphEdge[]
  stats?: { total_nodes?: number; total_edges?: number }
}
export type SharedInfrastructure = { shared: Record<string, unknown> }
