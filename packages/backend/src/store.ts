import { createHash } from "crypto";

import type { SDK } from "caido:plugin";
import type { Database } from "sqlite";

import { toReferenceDTO } from "./detector";
import type {
  AnalyzerInput,
  AssistantSettings,
  CandidateDTO,
  CandidateRuleDTO,
  ComparisonResult,
  DetectedAssessment,
  ObservationDTO,
  ReferenceDTO,
  ReviewStatus,
} from "./types";

const DEFAULT_SETTINGS: AssistantSettings = {
  scopeOnly: true,
  autoHistory: true,
  maxRequestBytes: 1024 * 1024,
  maxResponseBytes: 2 * 1024 * 1024,
  maxHistoryEntries: 5_000,
  maxCandidates: 2_000,
  requestBudget: 20,
  delayMilliseconds: 250,
  customAllowNames: [],
  customDenyNames: [],
  ignoredPathFragments: [],
  volatileFields: [
    "timestamp",
    "time",
    "date",
    "nonce",
    "request_id",
    "trace_id",
    "correlation_id",
  ],
};

type CandidateRow = {
  project_id: string;
  fingerprint: string;
  request_id: string;
  response_id: string;
  url: string;
  host: string;
  method: string;
  response_status: number;
  endpoint_template: string;
  score: number;
  priority: CandidateDTO["priority"];
  disposition: CandidateDTO["disposition"];
  disposition_reason: string;
  references_json: string;
  reasons_json: string;
  review_status: ReviewStatus;
  comparison_status: string;
  comparison_detail: string;
  comparison_confidence: string;
  similarity: number;
  baseline_stability: number;
  owner_control_request_id?: string;
  cross_request_id?: string;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  published: number;
};

type ObservationRow = {
  id: string;
  candidate_fingerprint: string;
  request_id: string;
  response_id: string;
  observed_at: string;
  owner_profile_id?: string;
  reference_fingerprints_json: string;
};

type RuleRow = {
  id: string;
  action: CandidateRuleDTO["action"];
  scope: CandidateRuleDTO["scope"];
  host: string;
  method: string;
  endpoint_template: string;
  reference_name: string;
  reference_location: string;
  structural_path: string;
  reason: string;
  created_at: string;
};

export class AssistantStore {
  private database?: Database;

  async initialize(sdk: SDK): Promise<void> {
    if (this.database !== undefined) return;
    this.database = await sdk.meta.db();
    await this.database.exec(`
      CREATE TABLE IF NOT EXISTS candidates (
        project_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        request_id TEXT NOT NULL,
        response_id TEXT NOT NULL,
        url TEXT NOT NULL,
        host TEXT NOT NULL,
        method TEXT NOT NULL,
        response_status INTEGER NOT NULL,
        endpoint_template TEXT NOT NULL,
        score INTEGER NOT NULL,
        priority TEXT NOT NULL,
        disposition TEXT NOT NULL,
        disposition_reason TEXT NOT NULL,
        references_json TEXT NOT NULL,
        reasons_json TEXT NOT NULL,
        review_status TEXT NOT NULL DEFAULT 'NEEDS_REVIEW',
        comparison_status TEXT NOT NULL DEFAULT 'NOT_TESTED',
        comparison_detail TEXT NOT NULL DEFAULT '',
        comparison_confidence TEXT NOT NULL DEFAULT '',
        similarity REAL NOT NULL DEFAULT 0,
        baseline_stability REAL NOT NULL DEFAULT 0,
        owner_control_request_id TEXT,
        cross_request_id TEXT,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS candidates_project_priority ON candidates(project_id, priority);
      CREATE INDEX IF NOT EXISTS candidates_project_disposition ON candidates(project_id, disposition);
      CREATE TABLE IF NOT EXISTS observations (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        candidate_fingerprint TEXT NOT NULL,
        request_id TEXT NOT NULL,
        response_id TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        owner_profile_id TEXT,
        reference_fingerprints_json TEXT NOT NULL,
        PRIMARY KEY(project_id, id)
      );
      CREATE INDEX IF NOT EXISTS observations_candidate ON observations(project_id, candidate_fingerprint, observed_at);
      CREATE TABLE IF NOT EXISTS review_states (
        project_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL,
        PRIMARY KEY(project_id, fingerprint)
      );
      CREATE TABLE IF NOT EXISTS candidate_rules (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        action TEXT NOT NULL,
        scope TEXT NOT NULL,
        host TEXT NOT NULL,
        method TEXT NOT NULL,
        endpoint_template TEXT NOT NULL,
        reference_name TEXT NOT NULL,
        reference_location TEXT NOT NULL,
        structural_path TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(project_id, id)
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }

  async getSettings(): Promise<AssistantSettings> {
    const statement = await this.requireDatabase().prepare(
      "SELECT value FROM settings WHERE key = ?",
    );
    const row = await statement.get<{ value: string }>("idor-assistant");
    if (row === undefined) return cloneSettings(DEFAULT_SETTINGS);
    try {
      return normalizeSettings({
        ...DEFAULT_SETTINGS,
        ...(JSON.parse(row.value) as Partial<AssistantSettings>),
      });
    } catch {
      return cloneSettings(DEFAULT_SETTINGS);
    }
  }

  async saveSettings(settings: AssistantSettings): Promise<AssistantSettings> {
    const normalized = normalizeSettings(settings);
    const statement = await this.requireDatabase().prepare(
      "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    );
    await statement.run("idor-assistant", JSON.stringify(normalized));
    return normalized;
  }

  async candidates(projectId: string): Promise<CandidateDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM candidates WHERE project_id = ? ORDER BY score DESC, last_seen DESC",
    );
    return (await statement.all<CandidateRow>(projectId)).map(toCandidate);
  }

  async observations(projectId: string): Promise<ObservationDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM observations WHERE project_id = ? ORDER BY observed_at DESC",
    );
    return (await statement.all<ObservationRow>(projectId)).map(toObservation);
  }

  async rules(projectId: string): Promise<CandidateRuleDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM candidate_rules WHERE project_id = ? ORDER BY created_at DESC",
    );
    return (await statement.all<RuleRow>(projectId)).map(toRule);
  }

  async add(
    projectId: string,
    input: AnalyzerInput,
    assessment: DetectedAssessment,
    ownerProfileId: string | undefined,
    maximum: number,
  ): Promise<void> {
    const database = this.requireDatabase();
    const existingStatement = await database.prepare(
      "SELECT * FROM candidates WHERE project_id = ? AND fingerprint = ?",
    );
    const existing = await existingStatement.get<CandidateRow>(
      projectId,
      assessment.fingerprint,
    );
    const observationId = observationKey(input, assessment);
    const observationExists = await database
      .prepare(
        "SELECT 1 AS found FROM observations WHERE project_id = ? AND id = ?",
      )
      .then((statement) =>
        statement.get<{ found: number }>(projectId, observationId),
      );
    const occurrenceIncrement = observationExists === undefined ? 1 : 0;
    const now = new Date().toISOString();
    const references = assessment.references.map(toReferenceDTO);
    const review = await database
      .prepare(
        "SELECT status FROM review_states WHERE project_id = ? AND fingerprint = ?",
      )
      .then((statement) =>
        statement.get<{ status: ReviewStatus }>(
          projectId,
          assessment.fingerprint,
        ),
      );
    if (existing === undefined) {
      const count = await database
        .prepare(
          "SELECT COUNT(*) AS count FROM candidates WHERE project_id = ?",
        )
        .then((statement) => statement.get<{ count: number }>(projectId));
      if ((count?.count ?? 0) >= maximum) return;
      const insert = await database.prepare(`
        INSERT INTO candidates(
          project_id, fingerprint, request_id, response_id, url, host, method, response_status,
          endpoint_template, score, priority, disposition, disposition_reason, references_json,
          reasons_json, review_status, first_seen, last_seen
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      await insert.run(
        projectId,
        assessment.fingerprint,
        input.requestId ?? "",
        input.responseId ?? "",
        redactURL(input.url, assessment),
        input.host,
        input.method,
        input.responseStatus,
        assessment.endpointTemplate,
        assessment.score,
        assessment.priority,
        assessment.disposition,
        assessment.dispositionReason,
        JSON.stringify(references),
        JSON.stringify(assessment.reasons),
        review?.status ?? "NEEDS_REVIEW",
        now,
        now,
      );
    } else if (
      existing.review_status !== "CONFIRMED" &&
      assessment.score >= existing.score
    ) {
      const update = await database.prepare(`
        UPDATE candidates SET request_id = ?, response_id = ?, url = ?, host = ?, method = ?,
          response_status = ?, endpoint_template = ?, score = MAX(score, ?),
          priority = CASE WHEN priority = 'HIGH' OR ? = 'HIGH' THEN 'HIGH'
            WHEN priority = 'MEDIUM' OR ? = 'MEDIUM' THEN 'MEDIUM' ELSE 'LOW' END,
          disposition = CASE WHEN disposition = 'ACTIVE' OR ? = 'ACTIVE' THEN 'ACTIVE' ELSE 'SUPPRESSED' END,
          disposition_reason = ?, references_json = ?, reasons_json = ?,
          occurrence_count = occurrence_count + ?, last_seen = ?
        WHERE project_id = ? AND fingerprint = ?
      `);
      await update.run(
        input.requestId ?? "",
        input.responseId ?? "",
        redactURL(input.url, assessment),
        input.host,
        input.method,
        input.responseStatus,
        assessment.endpointTemplate,
        assessment.score,
        assessment.priority,
        assessment.priority,
        assessment.disposition,
        assessment.dispositionReason,
        JSON.stringify(references),
        JSON.stringify(assessment.reasons),
        occurrenceIncrement,
        now,
        projectId,
        assessment.fingerprint,
      );
    } else {
      const update = await database.prepare(`
        UPDATE candidates SET occurrence_count = occurrence_count + ?, last_seen = ?
        WHERE project_id = ? AND fingerprint = ?
      `);
      await update.run(
        occurrenceIncrement,
        now,
        projectId,
        assessment.fingerprint,
      );
    }
    await this.addObservation(
      projectId,
      input,
      assessment,
      ownerProfileId,
      now,
    );
    await this.promoteRepeatedSuppressed(projectId, assessment.fingerprint);
  }

  async getCandidate(
    projectId: string,
    fingerprint: string,
  ): Promise<CandidateDTO | undefined> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM candidates WHERE project_id = ? AND fingerprint = ?",
    );
    const row = await statement.get<CandidateRow>(projectId, fingerprint);
    return row === undefined ? undefined : toCandidate(row);
  }

  async getObservation(
    projectId: string,
    id: string,
  ): Promise<ObservationDTO | undefined> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM observations WHERE project_id = ? AND id = ?",
    );
    const row = await statement.get<ObservationRow>(projectId, id);
    return row === undefined ? undefined : toObservation(row);
  }

  async setObservationOwner(
    projectId: string,
    observationId: string,
    profileId: string,
  ): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "UPDATE observations SET owner_profile_id = ? WHERE project_id = ? AND id = ?",
    );
    await statement.run(profileId, projectId, observationId);
  }

  async clearObservationOwnerProfile(
    projectId: string,
    profileId: string,
  ): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "UPDATE observations SET owner_profile_id = '' WHERE project_id = ? AND owner_profile_id = ?",
    );
    await statement.run(projectId, profileId);
  }

  async setStatus(
    projectId: string,
    fingerprint: string,
    status: ReviewStatus,
  ): Promise<void> {
    if (
      !(
        [
          "NEEDS_REVIEW",
          "REVIEWED",
          "FALSE_POSITIVE",
          "CONFIRMED",
        ] as ReviewStatus[]
      ).includes(status)
    )
      throw new Error("Invalid candidate review status");
    const database = this.requireDatabase();
    await database
      .prepare(
        "INSERT INTO review_states(project_id, fingerprint, status) VALUES(?, ?, ?) ON CONFLICT(project_id, fingerprint) DO UPDATE SET status = excluded.status",
      )
      .then((statement) => statement.run(projectId, fingerprint, status));
    await database
      .prepare(
        "UPDATE candidates SET review_status = ? WHERE project_id = ? AND fingerprint = ?",
      )
      .then((statement) => statement.run(status, projectId, fingerprint));
  }

  async saveComparison(
    projectId: string,
    value: ComparisonResult,
  ): Promise<void> {
    const statement = await this.requireDatabase().prepare(`
      UPDATE candidates SET comparison_status = ?, comparison_detail = ?, comparison_confidence = ?,
        similarity = ?, baseline_stability = ?, owner_control_request_id = ?, cross_request_id = ?,
        last_seen = ? WHERE project_id = ? AND fingerprint = ?
    `);
    await statement.run(
      value.status,
      value.detail.slice(0, 1_500),
      value.confidence,
      value.similarity,
      value.baselineStability,
      value.ownerControlRequestId ?? "",
      value.crossRequestId ?? "",
      new Date().toISOString(),
      projectId,
      value.candidateFingerprint,
    );
  }

  async addRule(projectId: string, rule: CandidateRuleDTO): Promise<void> {
    const statement = await this.requireDatabase().prepare(`
      INSERT OR REPLACE INTO candidate_rules(
        project_id, id, action, scope, host, method, endpoint_template, reference_name,
        reference_location, structural_path, reason, created_at
      ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await statement.run(
      projectId,
      rule.id,
      rule.action,
      rule.scope,
      rule.host,
      rule.method,
      rule.endpointTemplate,
      rule.referenceName,
      rule.referenceLocation,
      rule.structuralPath,
      rule.reason.slice(0, 200),
      rule.createdAt,
    );
  }

  async removeRule(projectId: string, id: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "DELETE FROM candidate_rules WHERE project_id = ? AND id = ?",
    );
    await statement.run(projectId, id);
  }

  async clearUnconfirmed(projectId: string): Promise<void> {
    const database = this.requireDatabase();
    await database
      .prepare(
        "DELETE FROM observations WHERE project_id = ? AND candidate_fingerprint IN (SELECT fingerprint FROM candidates WHERE project_id = ? AND review_status != 'CONFIRMED')",
      )
      .then((statement) => statement.run(projectId, projectId));
    await database
      .prepare(
        "DELETE FROM candidates WHERE project_id = ? AND review_status != 'CONFIRMED'",
      )
      .then((statement) => statement.run(projectId));
  }

  async markPublished(projectId: string, fingerprint: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "UPDATE candidates SET published = 1 WHERE project_id = ? AND fingerprint = ?",
    );
    await statement.run(projectId, fingerprint);
  }

  private async addObservation(
    projectId: string,
    input: AnalyzerInput,
    assessment: DetectedAssessment,
    ownerProfileId: string | undefined,
    now: string,
  ): Promise<void> {
    const database = this.requireDatabase();
    const observationId = observationKey(input, assessment);
    const fingerprints = assessment.references
      .filter(
        (reference) =>
          reference.source === "REQUEST" && reference.role === "OBJECT",
      )
      .map((reference) => sha256(reference.value).slice(0, 16));
    const insert = await database.prepare(`
      INSERT OR IGNORE INTO observations(
        project_id, id, candidate_fingerprint, request_id, response_id, observed_at,
        owner_profile_id, reference_fingerprints_json
      ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await insert.run(
      projectId,
      observationId,
      assessment.fingerprint,
      input.requestId ?? "",
      input.responseId ?? "",
      now,
      ownerProfileId ?? "",
      JSON.stringify(fingerprints),
    );
    const trim = await database.prepare(`
      DELETE FROM observations WHERE project_id = ? AND candidate_fingerprint = ? AND id NOT IN (
        SELECT id FROM observations WHERE project_id = ? AND candidate_fingerprint = ?
        ORDER BY observed_at DESC LIMIT 20
      )
    `);
    await trim.run(
      projectId,
      assessment.fingerprint,
      projectId,
      assessment.fingerprint,
    );
  }

  private async promoteRepeatedSuppressed(
    projectId: string,
    fingerprint: string,
  ): Promise<void> {
    const database = this.requireDatabase();
    const rows = await database
      .prepare(
        "SELECT reference_fingerprints_json FROM observations WHERE project_id = ? AND candidate_fingerprint = ?",
      )
      .then((statement) =>
        statement.all<{ reference_fingerprints_json: string }>(
          projectId,
          fingerprint,
        ),
      );
    const distinct = new Set<string>();
    for (const row of rows) {
      for (const value of parseStringArray(row.reference_fingerprints_json))
        distinct.add(value);
    }
    if (distinct.size < 3) return;
    const candidate = await this.getCandidate(projectId, fingerprint);
    if (candidate === undefined || candidate.disposition !== "SUPPRESSED")
      return;
    const reasons = new Set(candidate.reasons);
    reasons.add("promoted after three distinct observed object IDs");
    const statement = await database.prepare(`
      UPDATE candidates SET disposition = 'ACTIVE', disposition_reason = '', score = MAX(score, 55),
        priority = CASE WHEN priority = 'LOW' THEN 'MEDIUM' ELSE priority END, reasons_json = ?
      WHERE project_id = ? AND fingerprint = ?
    `);
    await statement.run(JSON.stringify([...reasons]), projectId, fingerprint);
  }

  private requireDatabase(): Database {
    if (this.database === undefined)
      throw new Error("Plugin database is not initialized");
    return this.database;
  }
}

function toCandidate(row: CandidateRow): CandidateDTO {
  return {
    projectId: row.project_id,
    fingerprint: row.fingerprint,
    requestId: row.request_id,
    responseId: row.response_id,
    url: row.url,
    host: row.host,
    method: row.method,
    responseStatus: row.response_status,
    endpointTemplate: row.endpoint_template,
    score: row.score,
    priority: row.priority,
    disposition: row.disposition,
    dispositionReason: row.disposition_reason,
    references: parseReferences(row.references_json),
    reasons: parseStringArray(row.reasons_json),
    reviewStatus: row.review_status,
    comparisonStatus: row.comparison_status,
    comparisonDetail: row.comparison_detail,
    comparisonConfidence: row.comparison_confidence,
    similarity: row.similarity,
    baselineStability: row.baseline_stability,
    ownerControlRequestId:
      row.owner_control_request_id === ""
        ? undefined
        : row.owner_control_request_id,
    crossRequestId:
      row.cross_request_id === "" ? undefined : row.cross_request_id,
    occurrenceCount: row.occurrence_count,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    published: row.published === 1,
  };
}

function toObservation(row: ObservationRow): ObservationDTO {
  return {
    id: row.id,
    candidateFingerprint: row.candidate_fingerprint,
    requestId: row.request_id,
    responseId: row.response_id,
    observedAt: row.observed_at,
    ownerProfileId:
      row.owner_profile_id === "" ? undefined : row.owner_profile_id,
    referenceFingerprints: parseStringArray(row.reference_fingerprints_json),
  };
}

function toRule(row: RuleRow): CandidateRuleDTO {
  return {
    id: row.id,
    action: row.action,
    scope: row.scope,
    host: row.host,
    method: row.method,
    endpointTemplate: row.endpoint_template,
    referenceName: row.reference_name,
    referenceLocation: row.reference_location,
    structuralPath: row.structural_path,
    reason: row.reason,
    createdAt: row.created_at,
  };
}

function parseReferences(value: string): ReferenceDTO[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? (parsed as ReferenceDTO[]) : [];
  } catch {
    return [];
  }
}

function parseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === "string")
      : [];
  } catch {
    return [];
  }
}

function redactURL(url: string, assessment: DetectedAssessment): string {
  const fragmentAt = url.indexOf("#");
  const withoutFragment = fragmentAt < 0 ? url : url.slice(0, fragmentAt);
  const queryAt = withoutFragment.indexOf("?");
  let output =
    queryAt < 0 ? withoutFragment : withoutFragment.slice(0, queryAt);
  output = output.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/i, "$1");
  for (const reference of assessment.references) {
    if (
      reference.source === "REQUEST" &&
      reference.location === "PATH" &&
      reference.value !== ""
    )
      for (const value of [
        reference.value,
        encodeURIComponent(reference.value),
      ])
        output = output.replace(
          `/${value}`,
          `/object-${sha256(reference.value).slice(0, 12)}`,
        );
  }
  if (queryAt >= 0) {
    const names = [
      ...new Set(
        assessment.references
          .filter(
            (reference) =>
              reference.source === "REQUEST" && reference.location === "QUERY",
          )
          .map((reference) => encodeURIComponent(reference.name)),
      ),
    ];
    output +=
      names.length === 0
        ? ""
        : `?${names.map((name) => `${name}=<redacted>`).join("&")}`;
  }
  return output;
}

export function normalizeSettings(
  settings: AssistantSettings,
): AssistantSettings {
  return {
    scopeOnly: settings.scopeOnly !== false,
    autoHistory: settings.autoHistory === true,
    maxRequestBytes: bounded(
      settings.maxRequestBytes,
      16_384,
      10 * 1024 * 1024,
    ),
    maxResponseBytes: bounded(
      settings.maxResponseBytes,
      16_384,
      20 * 1024 * 1024,
    ),
    maxHistoryEntries: bounded(settings.maxHistoryEntries, 100, 50_000),
    maxCandidates: bounded(settings.maxCandidates, 100, 20_000),
    requestBudget: bounded(settings.requestBudget, 2, 100),
    delayMilliseconds: bounded(settings.delayMilliseconds, 0, 5_000),
    customAllowNames: normalizeList(settings.customAllowNames),
    customDenyNames: normalizeList(settings.customDenyNames),
    ignoredPathFragments: normalizeList(settings.ignoredPathFragments),
    volatileFields: normalizeList(settings.volatileFields),
  };
}

function normalizeList(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  return [
    ...new Set(
      values
        .filter((value): value is string => typeof value === "string")
        .map((value) => value.trim().slice(0, 160))
        .filter(Boolean),
    ),
  ].slice(0, 500);
}

function bounded(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.max(minimum, Math.min(Math.round(value), maximum));
}

function cloneSettings(settings: AssistantSettings): AssistantSettings {
  return {
    ...settings,
    customAllowNames: [...settings.customAllowNames],
    customDenyNames: [...settings.customDenyNames],
    ignoredPathFragments: [...settings.ignoredPathFragments],
    volatileFields: [...settings.volatileFields],
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function observationKey(
  input: AnalyzerInput,
  assessment: DetectedAssessment,
): string {
  return sha256(`${input.requestId ?? ""}\n${assessment.fingerprint}`).slice(
    0,
    24,
  );
}
