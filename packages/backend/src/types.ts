type Priority = "HIGH" | "MEDIUM" | "LOW";
type Disposition = "ACTIVE" | "SUPPRESSED";
export type ReviewStatus =
  "NEEDS_REVIEW" | "REVIEWED" | "FALSE_POSITIVE" | "CONFIRMED";
export type ReferenceRole =
  "OBJECT" | "AUTH_CONTEXT" | "PAGINATION" | "TELEMETRY" | "UNKNOWN";

export type AnalyzerParameter = {
  name: string;
  value: string;
  location: string;
  structuralPath: string;
};

export type AnalyzerInput = {
  requestId?: string;
  responseId?: string;
  method: string;
  url: string;
  host: string;
  path: string;
  query: string;
  headers: Record<string, string[]>;
  parameters: AnalyzerParameter[];
  body: string;
  contentType: string;
  responseStatus: number;
  responseHeaders: Record<string, string[]>;
  responseBody: string;
  responseContentType: string;
};

export type DetectedReference = AnalyzerParameter & {
  source: "REQUEST" | "RESPONSE";
  shape: string;
  sensitivity: "NORMAL" | "SENSITIVE";
  role: ReferenceRole;
  evidence: string[];
};

export type ReferenceDTO = Omit<DetectedReference, "value"> & {
  maskedValue: string;
  valueHash: string;
};

export type DetectedAssessment = {
  fingerprint: string;
  score: number;
  priority: Priority;
  endpointTemplate: string;
  references: DetectedReference[];
  reasons: string[];
  disposition: Disposition;
  dispositionReason: string;
};

export type CandidateDTO = {
  projectId: string;
  fingerprint: string;
  requestId: string;
  responseId: string;
  url: string;
  host: string;
  method: string;
  responseStatus: number;
  endpointTemplate: string;
  score: number;
  priority: Priority;
  disposition: Disposition;
  dispositionReason: string;
  references: ReferenceDTO[];
  reasons: string[];
  reviewStatus: ReviewStatus;
  comparisonStatus: string;
  comparisonDetail: string;
  comparisonConfidence: string;
  similarity: number;
  baselineStability: number;
  ownerControlRequestId?: string;
  crossRequestId?: string;
  occurrenceCount: number;
  firstSeen: string;
  lastSeen: string;
  published: boolean;
};

export type ObservationDTO = {
  id: string;
  candidateFingerprint: string;
  requestId: string;
  responseId: string;
  observedAt: string;
  ownerProfileId?: string;
  referenceFingerprints: string[];
};

export type ProfileDTO = {
  id: string;
  name: string;
  role: string;
  fingerprint: string;
  headerNames: string[];
  substitutionNames: string[];
  capturedAt: string;
};

export type CandidateRuleDTO = {
  id: string;
  action: "IGNORE" | "ALLOW";
  scope: "HOST" | "ENDPOINT";
  host: string;
  method: string;
  endpointTemplate: string;
  referenceName: string;
  referenceLocation: string;
  structuralPath: string;
  reason: string;
  createdAt: string;
};

export type AssistantSettings = {
  scopeOnly: boolean;
  autoHistory: boolean;
  maxRequestBytes: number;
  maxResponseBytes: number;
  maxHistoryEntries: number;
  maxCandidates: number;
  requestBudget: number;
  delayMilliseconds: number;
  customAllowNames: string[];
  customDenyNames: string[];
  ignoredPathFragments: string[];
  volatileFields: string[];
};

export type ScanState = {
  phase: "IDLE" | "SCANNING" | "PAUSED" | "COMPARING";
  queued: number;
  active: number;
  scanned: number;
  dropped: number;
  comparisonsSent: number;
  message: string;
};

export type Snapshot = {
  candidates: CandidateDTO[];
  observations: ObservationDTO[];
  profiles: ProfileDTO[];
  rules: CandidateRuleDTO[];
  settings: AssistantSettings;
  state: ScanState;
};

export type MessageDetails = {
  requestId: string;
  request: string;
  response: string;
};

export type CaptureProfileInput = {
  requestId: string;
  name: string;
  role: string;
};

export type ComparisonInput = {
  candidateFingerprint: string;
  observationId: string;
  ownerProfileId: string;
  targetProfileId?: string;
  anonymous: boolean;
};

export type ComparisonResult = {
  candidateFingerprint: string;
  status: string;
  detail: string;
  confidence: string;
  similarity: number;
  baselineStability: number;
  ownershipEvidence: boolean;
  indicators: string[];
  ownerControlRequestId?: string;
  crossRequestId?: string;
};

export type PreparedMutation = {
  originalSessionId: string;
  crossSessionId: string;
};
