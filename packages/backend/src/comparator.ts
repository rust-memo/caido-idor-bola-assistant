import type { DetectedReference } from "./types";

export type ResponseSample = {
  status: number;
  contentType: string;
  body: string;
};

export type EvidenceResult = {
  status: string;
  detail: string;
  similarity: number;
  baselineStability: number;
  ownershipEvidence: boolean;
  indicators: string[];
  confidence: string;
  authenticationFailure: boolean;
};

const DENIED =
  /\b(unauthori[sz]ed|forbidden|access denied|permission denied|not allowed|login required)\b/i;
const SESSION =
  /\b(?:invalid|expired|missing|required|failed)\s+(?:csrf|xsrf|nonce|token|session)\b|\b(?:csrf|xsrf|nonce|token|session)(?:\s+token)?\s+(?:is\s+)?(?:invalid|expired|missing|required|failed)\b/i;
const LOGIN =
  /<form[^>]+(?:login|signin)|name=["']?(?:password|passwd)|\/login|sign[ -]?in/i;
const WAF =
  /\b(web application firewall|cloudflare|akamai|imperva|request blocked|security policy)\b/i;

export function compareEvidence(
  original: ResponseSample | undefined,
  owner: ResponseSample,
  cross: ResponseSample,
  expectedReferences: DetectedReference[],
  volatileFields: string[],
): EvidenceResult {
  const stability =
    original === undefined || original.status !== owner.status
      ? 0
      : dice(
          normalizeBody(original.body, original.contentType, volatileFields),
          normalizeBody(owner.body, owner.contentType, volatileFields),
        );
  const ownerBody = normalizeBody(
    owner.body,
    owner.contentType,
    volatileFields,
  );
  const crossBody = normalizeBody(
    cross.body,
    cross.contentType,
    volatileFields,
  );
  const similarity = dice(ownerBody, crossBody);
  const ownership = ownershipEvidence(
    owner.body,
    cross.body,
    expectedReferences,
  );
  const indicators: string[] = [];
  if (ownership) indicators.push("shared object identity");
  indicators.push(`content type: ${safeContentType(owner.contentType)}`);

  if (cross.status === 429)
    return result(
      "Inconclusive",
      "Other account was rate limited",
      similarity,
      stability,
      ownership,
      indicators,
      "LOW",
      false,
    );
  if (SESSION.test(cross.body))
    return result(
      "Inconclusive",
      "Other-account response indicates CSRF, token, or session failure",
      similarity,
      stability,
      ownership,
      indicators,
      "LOW",
      true,
    );
  if (LOGIN.test(cross.body))
    return result(
      "Inconclusive",
      "Other account received a login page or authentication redirect",
      similarity,
      stability,
      ownership,
      indicators,
      "LOW",
      true,
    );
  if (WAF.test(cross.body))
    return result(
      "Inconclusive",
      "A WAF or security gateway appears to have handled the request",
      similarity,
      stability,
      ownership,
      indicators,
      "LOW",
      false,
    );
  if (cross.status >= 300 && cross.status < 400)
    return result(
      "Inconclusive",
      "Redirect response needs manual authentication-flow review",
      similarity,
      stability,
      ownership,
      indicators,
      "LOW",
      true,
    );
  if (cross.status === 401 || cross.status === 403 || DENIED.test(cross.body))
    return result(
      "Likely protected",
      "Other-account request was explicitly denied",
      similarity,
      stability,
      ownership,
      indicators,
      "HIGH",
      false,
    );
  if (cross.status === 404 && successful(owner.status))
    return result(
      "Likely protected",
      "Object is hidden from the other account (404)",
      similarity,
      stability,
      ownership,
      indicators,
      "MEDIUM",
      false,
    );
  if (!compatibleContentTypes(owner.contentType, cross.contentType))
    return result(
      "Inconclusive",
      "Owner and other-account responses use different content types",
      similarity,
      stability,
      false,
      indicators,
      "LOW",
      false,
    );

  let status = "Inconclusive";
  let detail = "Response difference needs manual review";
  let confidence = "LOW";
  if (
    successful(owner.status) &&
    successful(cross.status) &&
    ownership &&
    similarity >= 0.85
  ) {
    status = "Suspicious access";
    detail =
      "Both accounts received highly similar successful responses containing the same object identity";
    confidence = "HIGH";
  } else if (successful(cross.status) && ownership && similarity >= 0.5) {
    status = "Suspicious access";
    detail =
      "Other account received a materially similar response with matching object identity";
    confidence = "MEDIUM";
  } else if (successful(cross.status) && similarity >= 0.85) {
    detail =
      "Responses are similar, but no object-ownership evidence was found";
  }
  if (stability > 0 && stability < 0.65 && status === "Suspicious access") {
    status = "Inconclusive";
    confidence = "LOW";
    detail =
      "The owner baseline changed materially; repeat after stabilizing the request";
    indicators.push("unstable owner baseline");
  } else if (stability === 0 && confidence === "HIGH") {
    confidence = "MEDIUM";
    indicators.push("no comparable original baseline");
  }
  return result(
    status,
    detail,
    similarity,
    stability,
    ownership,
    indicators,
    confidence,
    false,
  );
}

export function normalizeBody(
  body: string,
  contentType: string,
  volatileFields: string[],
): string {
  const lowerType = contentType.toLowerCase();
  if (
    lowerType.startsWith("image/") ||
    lowerType.includes("octet-stream") ||
    lowerType.includes("pdf")
  )
    return `binary:length=${body.length}`;
  if (lowerType.includes("html"))
    return body
      .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")
      .replace(/<form\b[^>]*>/gi, " <form> ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  if (lowerType.includes("xml"))
    return body
      .replace(/<\?xml[^>]*>/gi, "")
      .replace(/<!--[^]*?-->/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  try {
    const value = JSON.parse(body) as unknown;
    return canonicalJSON(
      value,
      new Set(volatileFields.map(normalizeName)),
    ).toLowerCase();
  } catch {
    return body
      .replace(
        /("(?:timestamp|time|date|nonce|request_?id|trace_?id)"\s*:\s*)"?[^",}]+"?/gi,
        "$1<volatile>",
      )
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  }
}

export function dice(left: string, right: string): number {
  if (left === right) return 1;
  if (left.length < 2 || right.length < 2) return 0;
  const grams = new Map<string, number>();
  for (let index = 0; index < left.length - 1; index += 1) {
    const gram = left.slice(index, index + 2);
    grams.set(gram, (grams.get(gram) ?? 0) + 1);
  }
  let overlap = 0;
  for (let index = 0; index < right.length - 1; index += 1) {
    const gram = right.slice(index, index + 2);
    const count = grams.get(gram) ?? 0;
    if (count > 0) {
      overlap += 1;
      grams.set(gram, count - 1);
    }
  }
  return (2 * overlap) / (left.length - 1 + (right.length - 1));
}

function ownershipEvidence(
  ownerBody: string,
  crossBody: string,
  references: DetectedReference[],
): boolean {
  const expected = references.filter(
    (reference) =>
      reference.source === "REQUEST" &&
      reference.role === "OBJECT" &&
      reference.value !== "" &&
      !reference.value.startsWith("$"),
  );
  for (const reference of expected) {
    if (
      contextualIdentity(ownerBody, reference.name, reference.value) &&
      contextualIdentity(crossBody, reference.name, reference.value)
    )
      return true;
  }
  const ownerIdentities = identityValues(ownerBody);
  const crossIdentities = identityValues(crossBody);
  const expectedValues = new Set(expected.map((reference) => reference.value));
  for (const [name, values] of ownerIdentities) {
    const other = crossIdentities.get(name) ?? new Set<string>();
    for (const value of values) {
      if (
        other.has(value) &&
        (expectedValues.size === 0 || expectedValues.has(value))
      )
        return true;
    }
  }
  return false;
}

function identityValues(body: string): Map<string, Set<string>> {
  const output = new Map<string, Set<string>>();
  let root: unknown;
  try {
    root = JSON.parse(body) as unknown;
  } catch {
    return output;
  }
  const walk = (value: unknown, depth: number): void => {
    if (depth > 40 || value === null) return;
    if (Array.isArray(value)) {
      for (const child of value) walk(child, depth + 1);
      return;
    }
    if (typeof value !== "object") return;
    for (const [rawName, child] of Object.entries(value)) {
      const name = normalizeName(rawName);
      if (
        (name === "id" || name.endsWith("_id")) &&
        (typeof child === "string" || typeof child === "number")
      ) {
        const values = output.get(name) ?? new Set<string>();
        values.add(String(child));
        output.set(name, values);
      }
      walk(child, depth + 1);
    }
  };
  walk(root, 0);
  return output;
}

function contextualIdentity(
  body: string,
  name: string,
  value: string,
): boolean {
  const escapedName = escapeRegex(name);
  const escapedValue = escapeRegex(value);
  return new RegExp(
    `(?:[<"']${escapedName}[>"']\\s*[:=]?\\s*["']?${escapedValue}(?:[<"'\\s,}])|${escapedName}\\s*=\\s*["']${escapedValue}["'])`,
    "is",
  ).test(body);
}

function canonicalJSON(value: unknown, volatileFields: Set<string>): string {
  if (value === null) return "null";
  if (Array.isArray(value))
    return `[${value.map((child) => canonicalJSON(child, volatileFields)).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([name]) => !volatileFields.has(normalizeName(name)))
      .sort(([left], [right]) =>
        left.toLowerCase().localeCompare(right.toLowerCase()),
      )
      .map(
        ([name, child]) =>
          `${JSON.stringify(name)}:${canonicalJSON(child, volatileFields)}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function compatibleContentTypes(left: string, right: string): boolean {
  const first = left.toLowerCase();
  const second = right.toLowerCase();
  return (
    first === second ||
    (first.includes("json") && second.includes("json")) ||
    (first.includes("html") && second.includes("html")) ||
    (first.includes("xml") && second.includes("xml"))
  );
}

function successful(status: number): boolean {
  return status >= 200 && status < 300;
}

function result(
  status: string,
  detail: string,
  similarity: number,
  baselineStability: number,
  ownershipEvidenceValue: boolean,
  indicators: string[],
  confidence: string,
  authenticationFailure: boolean,
): EvidenceResult {
  return {
    status,
    detail,
    similarity,
    baselineStability,
    ownershipEvidence: ownershipEvidenceValue,
    indicators,
    confidence,
    authenticationFailure,
  };
}

function normalizeName(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .replace(/-/g, "_");
}

function safeContentType(value: string): string {
  return value.trim() === "" ? "unknown" : (value.split(";", 1)[0] ?? value);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
