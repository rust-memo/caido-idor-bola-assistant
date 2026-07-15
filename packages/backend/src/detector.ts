import { createHash } from "crypto";

import type {
  AnalyzerInput,
  AnalyzerParameter,
  AssistantSettings,
  CandidateRuleDTO,
  DetectedAssessment,
  DetectedReference,
  ReferenceDTO,
  ReferenceRole,
} from "./types";

const EXACT = new Set([
  "id",
  "uid",
  "uuid",
  "guid",
  "object_id",
  "record_id",
  "resource_id",
  "reference_id",
  "user_id",
  "member_id",
  "customer_id",
  "profile_id",
  "owner_id",
  "account_id",
  "tenant_id",
  "organization_id",
  "org_id",
  "company_id",
  "team_id",
  "group_id",
  "workspace_id",
  "project_id",
  "order_id",
  "invoice_id",
  "transaction_id",
  "payment_id",
  "payment_method_id",
  "subscription_id",
  "ticket_id",
  "case_id",
  "issue_id",
  "message_id",
  "thread_id",
  "conversation_id",
  "comment_id",
  "file_id",
  "folder_id",
  "document_id",
  "document",
  "attachment_id",
  "download_id",
  "report_id",
  "export_id",
  "address_id",
  "booking_id",
  "reservation_id",
  "appointment_id",
  "patient_id",
  "medical_record_id",
  "prescription_id",
  "claim_id",
  "api_key_id",
  "credential_id",
  "role_id",
  "permission_id",
  "admin_id",
  "employee_id",
  "device_id",
  "webhook_id",
  "job_id",
  "task_id",
]);
const GENERIC = new Set(["id", "uid", "uuid", "guid", "key", "ref"]);
const IGNORED = new Set([
  "session_id",
  "request_id",
  "trace_id",
  "correlation_id",
  "span_id",
  "analytics_id",
  "csrf_token",
  "xsrf_token",
  "captcha_id",
  "page_id",
  "sort_id",
  "filter_id",
  "locale_id",
  "language_id",
  "timestamp_id",
  "time_id",
  "version_id",
  "build_id",
  "event_id",
  "visitor_id",
  "cursor_id",
  "offset_id",
  "limit_id",
]);
const IDENTITY_HEADERS = new Set([
  "x-user-id",
  "x-account-id",
  "x-customer-id",
  "x-member-id",
  "x-tenant-id",
  "x-organization-id",
  "x-org-id",
  "x-owner-id",
  "x-profile-id",
  "x-client-id",
]);
const OBJECT_HEADERS = new Set(["x-resource-id", "x-object-id"]);
const PAGINATION = new Set([
  "page",
  "page_id",
  "page_size",
  "limit",
  "offset",
  "cursor",
  "after",
  "before",
  "sort",
  "sort_id",
  "filter",
  "filter_id",
  "cursor_id",
  "offset_id",
  "limit_id",
  "start",
  "end",
  "from",
  "to",
]);
const TELEMETRY = new Set([
  "request_id",
  "trace_id",
  "correlation_id",
  "span_id",
  "analytics_id",
  "event_id",
  "visitor_id",
  "build_id",
  "version_id",
  "revision_id",
  "timestamp_id",
  "time_id",
  "device_id",
]);
const FEATURES = new Set([
  "user",
  "profile",
  "account",
  "member",
  "customer",
  "order",
  "invoice",
  "payment",
  "card",
  "subscription",
  "transaction",
  "refund",
  "ticket",
  "case",
  "issue",
  "message",
  "conversation",
  "comment",
  "file",
  "folder",
  "document",
  "attachment",
  "download",
  "upload",
  "export",
  "report",
  "address",
  "booking",
  "reservation",
  "appointment",
  "patient",
  "medical",
  "prescription",
  "claim",
  "credential",
  "admin",
  "role",
  "permission",
  "project",
  "workspace",
  "organization",
  "tenant",
  "webhook",
  "notification",
  "resource",
  "object",
  "record",
  "employee",
  "team",
  "group",
  "company",
]);
const OWNERS = new Set([
  "user",
  "account",
  "member",
  "customer",
  "client",
  "owner",
  "tenant",
  "org",
  "organization",
  "company",
  "team",
  "group",
  "workspace",
  "patient",
  "employee",
  "admin",
  "role",
  "permission",
]);
const NON_RESOURCES = new Set([
  "api",
  "rest",
  "graphql",
  "rpc",
  "status",
  "health",
  "metrics",
  "search",
  "query",
  "list",
  "lists",
  "page",
  "pages",
  "limit",
  "offset",
  "sort",
  "filter",
  "events",
  "analytics",
  "static",
  "assets",
  "public",
  "callback",
  "oauth",
  "login",
  "logout",
  "auth",
  "token",
  "refresh",
  "version",
  "build",
  "year",
  "month",
  "day",
  "hour",
  "minute",
  "download",
  "upload",
  "preview",
  "count",
  "summary",
]);
const LIST_ENDPOINTS = new Set([
  "search",
  "query",
  "list",
  "all",
  "feed",
  "index",
]);
const STATIC_EXTENSIONS = new Set([
  "js",
  "css",
  "map",
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "ico",
  "woff",
  "woff2",
  "ttf",
  "mp4",
  "mp3",
  "pdf",
]);
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]{16,64}$/i;
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
const NUMBER = /^[0-9]{1,20}$/;
const OPAQUE = /^[A-Za-z0-9_-]{12,160}$/;
const IDENTIFIER_SUFFIXES = ["_id", "_ids", "_uuid", "_guid", "_key", "_ref"];

type ScoredReference = {
  reference: DetectedReference;
  score: number;
  ignored: boolean;
  allowed: boolean;
  reasons: string[];
};

export function analyzeMessage(
  input: AnalyzerInput,
  settings: AssistantSettings,
  rules: CandidateRuleDTO[] = [],
): DetectedAssessment | undefined {
  const lowerPath = input.path.toLowerCase();
  if (
    settings.ignoredPathFragments.some((fragment) =>
      lowerPath.includes(fragment.trim().toLowerCase()),
    )
  )
    return undefined;
  const extension = lowerPath.split(".").at(-1) ?? "";
  if (STATIC_EXTENSIONS.has(extension)) return undefined;

  const allowNames = new Set(settings.customAllowNames.map(normalizeName));
  const denyNames = new Set(settings.customDenyNames.map(normalizeName));
  let references: DetectedReference[] = [];
  for (const parameter of input.parameters) {
    if (!isIdentifierName(parameter.name, allowNames, denyNames)) continue;
    references.push(enrich(parameter, "REQUEST", input.path));
  }
  for (const [headerName, values] of Object.entries(input.headers)) {
    const lower = headerName.toLowerCase();
    if (!IDENTITY_HEADERS.has(lower) && !OBJECT_HEADERS.has(lower)) continue;
    for (const value of values.slice(0, 5)) {
      const role: ReferenceRole = IDENTITY_HEADERS.has(lower)
        ? "AUTH_CONTEXT"
        : "OBJECT";
      references.push({
        name: headerName,
        value,
        location: "HEADER",
        structuralPath: `header.${headerName}`,
        source: "REQUEST",
        shape: identifierShape(value),
        sensitivity: sensitivity(headerName),
        role,
        evidence: [
          role === "AUTH_CONTEXT" ? "identity header" : "object header",
        ],
      });
    }
  }
  references.push(...pathReferences(input.path));
  references.push(
    ...bodyReferences(
      input.body,
      input.contentType,
      input.path,
      allowNames,
      denyNames,
    ),
  );
  references = deduplicate(references);
  if (references.length === 0) return undefined;

  references.push(
    ...responseReferences(
      input.responseBody,
      input.path,
      allowNames,
      denyNames,
    ),
  );
  references = deduplicate(references);
  const endpoint = endpointTemplate(input.path);
  const requestReferences = references.filter(
    (reference) => reference.source === "REQUEST",
  );
  const responseReferenceList = references.filter(
    (reference) => reference.source === "RESPONSE",
  );
  const scored = requestReferences.map((reference) =>
    scoreReference(
      reference,
      input.host,
      input.method,
      endpoint,
      input.path,
      allowNames,
      rules,
    ),
  );
  let scoredIndex = 0;
  const assessedReferences = references.map((reference) => {
    if (reference.source !== "REQUEST") return reference;
    const scoredReference = scored[scoredIndex]?.reference ?? reference;
    scoredIndex += 1;
    return scoredReference;
  });
  const eligible = scored.filter(
    (value) =>
      !value.ignored &&
      (value.allowed ||
        !(
          ["AUTH_CONTEXT", "PAGINATION", "TELEMETRY"] as ReferenceRole[]
        ).includes(value.reference.role)),
  );
  if (eligible.length === 0) {
    if (!scored.some((value) => value.ignored)) return undefined;
    return buildAssessment(
      input,
      endpoint,
      30,
      "LOW",
      assessedReferences,
      ["matched a scoped false-positive rule"],
      "SUPPRESSED",
      "Suppressed by a user rule",
    );
  }

  const firstEligible = eligible[0];
  if (firstEligible === undefined) return undefined;
  let best = firstEligible;
  for (const value of eligible.slice(1)) {
    if (value.score > best.score) best = value;
  }
  let score = best.score;
  const reasons = new Set(best.reasons);
  if (eligible.length > 1) {
    score += 5;
    reasons.add("multiple object-reference signals");
  }
  const method = input.method.toUpperCase();
  if (["PUT", "PATCH", "DELETE"].includes(method)) {
    score += 10;
    reasons.add("state-changing method");
  } else if (method === "POST") {
    score += 5;
    reasons.add("request body/action method");
  }
  if (
    correlated(
      eligible.map((value) => value.reference),
      responseReferenceList,
    )
  ) {
    score += 10;
    reasons.add("request reference correlated with response");
  }
  if (isListEndpoint(input.path) && best.score < 55) {
    score -= 15;
    reasons.add("list/search endpoint penalty");
  }
  score = Math.max(0, Math.min(score, 100));
  const explicitlyAllowed = eligible.some((value) => value.allowed);
  const disposition =
    explicitlyAllowed || score >= 55 ? "ACTIVE" : "SUPPRESSED";
  if (score < 30 && !explicitlyAllowed) return undefined;
  const priority = score >= 75 ? "HIGH" : score >= 55 ? "MEDIUM" : "LOW";
  return buildAssessment(
    input,
    endpoint,
    score,
    priority,
    assessedReferences,
    [...reasons],
    disposition,
    disposition === "SUPPRESSED"
      ? "Insufficient independent object-reference evidence"
      : "",
  );
}

export function parseRequestParameters(
  query: string,
  body: string,
  contentType: string,
  cookieHeaders: string[],
): AnalyzerParameter[] {
  const output = parseEncoded(query, "QUERY", "query");
  const lowerType = contentType.toLowerCase();
  if (lowerType.includes("application/x-www-form-urlencoded"))
    output.push(...parseEncoded(body, "FORM", "form"));
  if (lowerType.includes("multipart/form-data"))
    output.push(...parseMultipart(body));
  for (const header of cookieHeaders) {
    output.push(
      ...parseEncoded(header.replace(/;\s*/g, "&"), "COOKIE", "cookie"),
    );
  }
  return output.slice(0, 2_000);
}

export function endpointTemplate(path: string): string {
  return (path.split("?", 1)[0] ?? "/")
    .split("/")
    .map((segment) => (identifierShape(segment) === "" ? segment : "{id}"))
    .join("/");
}

export function identifierShape(value: string): string {
  if (value.length === 0 || value.length > 256 || value.startsWith("$"))
    return "";
  if (UUID.test(value)) return "UUID";
  if (ULID.test(value)) return "ULID";
  if (NUMBER.test(value))
    return value.length >= 16 ? "Snowflake/numeric ID" : "numeric ID";
  if (HEX.test(value)) return "hex/object ID";
  if (OPAQUE.test(value) && /[0-9]/.test(value)) return "opaque/base64-like ID";
  return "";
}

export function toReferenceDTO(reference: DetectedReference): ReferenceDTO {
  return {
    name: reference.name,
    location: reference.location,
    structuralPath: reference.structuralPath,
    source: reference.source,
    shape: reference.shape,
    sensitivity: reference.sensitivity,
    role: reference.role,
    evidence: reference.evidence,
    maskedValue: mask(reference.value),
    valueHash: sha256(reference.value),
  };
}

function buildAssessment(
  input: AnalyzerInput,
  endpoint: string,
  score: number,
  priority: "HIGH" | "MEDIUM" | "LOW",
  references: DetectedReference[],
  reasons: string[],
  disposition: "ACTIVE" | "SUPPRESSED",
  dispositionReason: string,
): DetectedAssessment {
  const selectors = references
    .filter(
      (reference) =>
        reference.source === "REQUEST" &&
        !(
          ["AUTH_CONTEXT", "PAGINATION", "TELEMETRY"] as ReferenceRole[]
        ).includes(reference.role),
    )
    .map(
      (reference) =>
        `${normalizeName(reference.name)}@${reference.location}:${reference.structuralPath}`,
    )
    .sort()
    .join(",");
  return {
    fingerprint: sha256(
      `${input.method.toUpperCase()}\n${input.host.toLowerCase()}\n${endpoint}\n${selectors}`,
    ),
    score,
    priority,
    endpointTemplate: endpoint,
    references,
    reasons,
    disposition,
    dispositionReason,
  };
}

function scoreReference(
  reference: DetectedReference,
  host: string,
  method: string,
  endpoint: string,
  path: string,
  allowNames: Set<string>,
  rules: CandidateRuleDTO[],
): ScoredReference {
  const name = normalizeName(reference.name);
  const allow = matchingRule("ALLOW", rules, host, method, endpoint, reference);
  const ignore = matchingRule(
    "IGNORE",
    rules,
    host,
    method,
    endpoint,
    reference,
  );
  if (allow !== undefined)
    return {
      reference: { ...reference, evidence: ["scoped allow rule"] },
      score: 100,
      ignored: false,
      allowed: true,
      reasons: ["explicit scoped allow rule"],
    };
  if (ignore !== undefined)
    return {
      reference: { ...reference, evidence: ["scoped ignore rule"] },
      score: 0,
      ignored: true,
      allowed: false,
      reasons: [ignore.reason],
    };
  if (
    !allowNames.has(name) &&
    (["AUTH_CONTEXT", "PAGINATION", "TELEMETRY"] as ReferenceRole[]).includes(
      reference.role,
    )
  )
    return {
      reference,
      score: 0,
      ignored: false,
      allowed: false,
      reasons: [reference.role.toLowerCase()],
    };

  let score = 0;
  const reasons: string[] = [];
  const customAllowed = allowNames.has(name);
  if (customAllowed) {
    score += 70;
    reasons.push("custom identifier allowlist");
  } else if (reference.location === "PATH") {
    if (isKnownResource(name)) {
      score += 30;
      reasons.push("known resource path segment");
    } else if (isPlausibleResource(name)) {
      score += 20;
      reasons.push("resource-like path segment");
    }
  } else if (OBJECT_HEADERS.has(reference.name.toLowerCase())) {
    score += 30;
    reasons.push("explicit object header");
  } else if (GENERIC.has(name)) {
    score += 10;
    reasons.push("generic identifier name");
  } else if (EXACT.has(name)) {
    score += 30;
    reasons.push("known object field");
  } else if (hasIdentifierSuffix(name)) {
    score += 25;
    reasons.push("object identifier suffix");
  }
  if (reference.shape !== "") {
    score += 25;
    reasons.push("identifier-shaped value");
  }
  if (hasResourceContext(path, name)) {
    score += 20;
    reasons.push("object/resource endpoint context");
  }
  if (reference.sensitivity === "SENSITIVE") {
    score += 10;
    reasons.push("sensitive object reference");
  }
  if ([...OWNERS].some((owner) => tokenMatches(name, owner))) {
    score += 10;
    reasons.push("owner/account field");
  }
  if (reference.location === "COOKIE") {
    score -= 15;
    reasons.push("cookie context penalty");
  }
  return {
    reference: { ...reference, evidence: reasons },
    score: Math.max(score, 0),
    ignored: false,
    allowed: customAllowed,
    reasons,
  };
}

function pathReferences(path: string): DetectedReference[] {
  const output: DetectedReference[] = [];
  const parts = (path.split("?", 1)[0] ?? "/").split("/");
  for (let index = 0; index < parts.length; index += 1) {
    const value = parts[index] ?? "";
    const shape = identifierShape(value);
    if (shape === "") continue;
    if (value.length === 4 && NUMBER.test(value)) {
      const year = Number(value);
      if (year >= 1900 && year <= 2100) continue;
    }
    const name = index > 0 ? (parts[index - 1] ?? "path") : "path";
    const detectedRole = role(name, "PATH");
    if (["AUTH_CONTEXT", "PAGINATION", "TELEMETRY"].includes(detectedRole))
      continue;
    output.push({
      name,
      value,
      location: "PATH",
      structuralPath: `path[${index}]`,
      source: "REQUEST",
      shape,
      sensitivity: sensitivity(name),
      role: detectedRole,
      evidence: [],
    });
  }
  return output;
}

function bodyReferences(
  body: string,
  contentType: string,
  path: string,
  allowNames: Set<string>,
  denyNames: Set<string>,
): DetectedReference[] {
  if (body.length === 0) return [];
  const output = jsonReferences(body, "REQUEST", allowNames, denyNames).map(
    (reference) => enrich(reference, "REQUEST", path),
  );
  if (output.length === 0) {
    const pattern =
      /["']([A-Za-z][A-Za-z0-9_.-]*(?:id|uuid|guid|key|ref))["']\s*:\s*["']?([A-Za-z0-9_:.@/=-]{1,160})/gi;
    for (const match of body.matchAll(pattern)) {
      const name = match[1] ?? "";
      if (!isIdentifierName(name, allowNames, denyNames)) continue;
      output.push(
        enrich(
          {
            name,
            value: match[2] ?? "",
            location: "JSON_BODY",
            structuralPath: name,
          },
          "REQUEST",
          path,
        ),
      );
      if (output.length >= 2_000) break;
    }
  }
  const graphql =
    /\b([A-Za-z][A-Za-z0-9_]*(?:Id|ID|Uuid|UUID|Guid|GUID|Key|Ref))\s*:\s*(?:"([^"]+)"|([0-9]+)|\$([A-Za-z][A-Za-z0-9_]*))/g;
  for (const match of body.matchAll(graphql)) {
    if (match[4] !== undefined) continue;
    const name = match[1] ?? "";
    const value = match[2] ?? match[3] ?? "";
    output.push(
      enrich(
        {
          name,
          value,
          location: "GRAPHQL",
          structuralPath: `graphql.${name}`,
        },
        "REQUEST",
        path,
      ),
    );
  }
  if (
    contentType.toLowerCase().includes("xml") ||
    body.trimStart().startsWith("<")
  )
    output.push(...xmlReferences(body, path, allowNames, denyNames));
  return output.slice(0, 2_000);
}

function xmlReferences(
  body: string,
  path: string,
  allowNames: Set<string>,
  denyNames: Set<string>,
): DetectedReference[] {
  const output: DetectedReference[] = [];
  const attribute = /\b([A-Za-z_:][\w:.-]*)\s*=\s*["']([^"']{1,256})["']/g;
  for (const match of body.matchAll(attribute)) {
    const name = match[1] ?? "";
    if (!isIdentifierName(name, allowNames, denyNames)) continue;
    output.push(
      enrich(
        {
          name,
          value: match[2] ?? "",
          location: "XML_ATTRIBUTE",
          structuralPath: `xml.@${name}`,
        },
        "REQUEST",
        path,
      ),
    );
  }
  const element = /<([A-Za-z_:][\w:.-]*)\b[^>]*>\s*([^<]{1,256})\s*<\/\1\s*>/g;
  for (const match of body.matchAll(element)) {
    const name = match[1] ?? "";
    if (!isIdentifierName(name, allowNames, denyNames)) continue;
    output.push(
      enrich(
        {
          name,
          value: (match[2] ?? "").trim(),
          location: "XML",
          structuralPath: `xml.${name}`,
        },
        "REQUEST",
        path,
      ),
    );
  }
  return output.slice(0, 2_000);
}

function responseReferences(
  body: string,
  path: string,
  allowNames: Set<string>,
  denyNames: Set<string>,
): DetectedReference[] {
  return jsonReferences(body, "RESPONSE", allowNames, denyNames)
    .slice(0, 50)
    .map((reference) => enrich(reference, "RESPONSE", path));
}

function jsonReferences(
  body: string,
  source: "REQUEST" | "RESPONSE",
  allowNames: Set<string>,
  denyNames: Set<string>,
): DetectedReference[] {
  if (body.length === 0) return [];
  let root: unknown;
  try {
    root = JSON.parse(body) as unknown;
  } catch {
    return [];
  }
  const output: DetectedReference[] = [];
  const walk = (
    value: unknown,
    path: string,
    key: string,
    depth: number,
  ): void => {
    if (depth > 40 || output.length >= 2_000 || value === undefined) return;
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1)
        walk(value[index], `${path}[${index}]`, key, depth + 1);
      return;
    }
    if (value !== null && typeof value === "object") {
      for (const [name, child] of Object.entries(value))
        walk(child, `${path}.${name}`, name, depth + 1);
      return;
    }
    if (!isIdentifierName(key, allowNames, denyNames)) return;
    let text: string;
    if (value === null) text = "";
    else if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    )
      text = String(value);
    else return;
    if (text.length > 256) return;
    output.push({
      name: key,
      value: text,
      location: source === "RESPONSE" ? "RESPONSE_JSON" : "JSON_BODY",
      structuralPath: path,
      source,
      shape: identifierShape(text),
      sensitivity: sensitivity(key),
      role: role(key, source === "RESPONSE" ? "RESPONSE_JSON" : "JSON_BODY"),
      evidence: [],
    });
  };
  walk(root, "$", "", 0);
  return output;
}

function enrich(
  parameter: AnalyzerParameter,
  source: "REQUEST" | "RESPONSE",
  requestPath: string,
): DetectedReference {
  let detectedRole = role(parameter.name, parameter.location);
  if (
    detectedRole === "UNKNOWN" &&
    hasResourceContext(requestPath, normalizeName(parameter.name))
  )
    detectedRole = "OBJECT";
  return {
    ...parameter,
    source,
    shape: identifierShape(parameter.value),
    sensitivity: sensitivity(parameter.name),
    role: detectedRole,
    evidence: [],
  };
}

function parseEncoded(
  raw: string,
  location: string,
  pathPrefix: string,
): AnalyzerParameter[] {
  if (raw.length === 0) return [];
  return raw
    .split("&")
    .slice(0, 2_000)
    .map((pair, index) => {
      const separator = pair.indexOf("=");
      const rawName = separator < 0 ? pair : pair.slice(0, separator);
      const rawValue = separator < 0 ? "" : pair.slice(separator + 1);
      return {
        name: safeDecode(rawName.replace(/\+/g, " ")),
        value: safeDecode(rawValue.replace(/\+/g, " ")),
        location,
        structuralPath: `${pathPrefix}[${index}]`,
      };
    });
}

function parseMultipart(body: string): AnalyzerParameter[] {
  const output: AnalyzerParameter[] = [];
  const pattern =
    /content-disposition:[^\r\n]*\bname="([^"]+)"[^\r\n]*\r?\n(?:[^\r\n]*\r?\n)*\r?\n([^\r\n]{0,256})/gi;
  for (const match of body.matchAll(pattern)) {
    const name = match[1] ?? "";
    output.push({
      name,
      value: (match[2] ?? "").trim(),
      location: "MULTIPART",
      structuralPath: `multipart.${name}`,
    });
    if (output.length >= 2_000) break;
  }
  return output;
}

function matchingRule(
  action: "ALLOW" | "IGNORE",
  rules: CandidateRuleDTO[],
  host: string,
  method: string,
  endpoint: string,
  reference: DetectedReference,
): CandidateRuleDTO | undefined {
  return [...rules]
    .reverse()
    .find(
      (rule) =>
        rule.action === action &&
        rule.host.toLowerCase() === host.toLowerCase() &&
        (rule.scope === "HOST" ||
          (rule.method.toUpperCase() === method.toUpperCase() &&
            rule.endpointTemplate === endpoint &&
            normalizeName(rule.referenceName) ===
              normalizeName(reference.name) &&
            rule.referenceLocation === reference.location &&
            rule.structuralPath === reference.structuralPath)),
    );
}

function isIdentifierName(
  raw: string,
  allowNames: Set<string>,
  denyNames: Set<string>,
): boolean {
  const name = normalizeName(raw);
  if (name === "" || denyNames.has(name)) return false;
  if (allowNames.has(name)) return true;
  if (IGNORED.has(name)) return false;
  return EXACT.has(name) || hasIdentifierSuffix(name);
}

function role(nameInput: string, locationInput: string): ReferenceRole {
  const name = normalizeName(nameInput);
  const location = locationInput.toLowerCase();
  if (
    location.includes("header") &&
    IDENTITY_HEADERS.has(nameInput.toLowerCase())
  )
    return "AUTH_CONTEXT";
  if (
    location.includes("cookie") &&
    ([...OWNERS].some((owner) => tokenMatches(name, owner)) ||
      name.includes("session") ||
      name.includes("auth") ||
      name.includes("token"))
  )
    return "AUTH_CONTEXT";
  if (PAGINATION.has(name)) return "PAGINATION";
  if (TELEMETRY.has(name)) return "TELEMETRY";
  if (EXACT.has(name) || hasIdentifierSuffix(name) || isKnownResource(name))
    return "OBJECT";
  return "UNKNOWN";
}

function sensitivity(name: string): "NORMAL" | "SENSITIVE" {
  return /(patient|medical|payment|card|credential|admin|permission|tenant|account).*id/i.test(
    name,
  )
    ? "SENSITIVE"
    : "NORMAL";
}

function correlated(
  request: DetectedReference[],
  response: DetectedReference[],
): boolean {
  for (const left of request) {
    for (const right of response) {
      if (left.value !== "" && left.value === right.value) return true;
    }
  }
  return false;
}

function hasResourceContext(path: string, name: string): boolean {
  return isKnownResource(name) || pathTokens(path).some(isKnownResource);
}

function isListEndpoint(path: string): boolean {
  return pathTokens(path).some((token) => LIST_ENDPOINTS.has(token));
}

function pathTokens(path: string): string[] {
  return path
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function isKnownResource(input: string): boolean {
  const token = normalizeName(input);
  if (FEATURES.has(token)) return true;
  if (token.endsWith("ies") && FEATURES.has(`${token.slice(0, -3)}y`))
    return true;
  if (token.endsWith("es") && FEATURES.has(token.slice(0, -2))) return true;
  return (
    token.endsWith("s") && token.length > 3 && FEATURES.has(token.slice(0, -1))
  );
}

function isPlausibleResource(input: string): boolean {
  const token = normalizeName(input);
  return (
    /^[a-z][a-z0-9_-]{2,40}$/.test(token) &&
    !NON_RESOURCES.has(token) &&
    !/^v[0-9]+$/.test(token) &&
    !PAGINATION.has(token) &&
    !TELEMETRY.has(token)
  );
}

function tokenMatches(name: string, token: string): boolean {
  return (
    name === token ||
    name.startsWith(`${token}_`) ||
    name.endsWith(`_${token}`) ||
    name.includes(`_${token}_`)
  );
}

function hasIdentifierSuffix(name: string): boolean {
  return IDENTIFIER_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

function normalizeName(raw: string): string {
  return raw
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[-.]/g, "_")
    .replace(/\[[^\]]*\]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "");
}

function deduplicate(references: DetectedReference[]): DetectedReference[] {
  const unique = new Map<string, DetectedReference>();
  for (const reference of references) {
    const key = `${reference.source}\0${reference.location}\0${reference.structuralPath}\0${normalizeName(reference.name)}\0${reference.value}`;
    if (!unique.has(key)) unique.set(key, reference);
  }
  return [...unique.values()];
}

function mask(value: string): string {
  if (value.length <= 8) return "[REDACTED]";
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
