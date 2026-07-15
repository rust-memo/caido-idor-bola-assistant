import { createHash } from "crypto";

import type { Request, RequestSpec } from "caido:utils";

import type { ProfileDTO } from "./types";

const AUTH_HEADERS = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "x-api-key",
  "api-key",
  "x-auth-token",
  "x-access-token",
  "x-session-token",
  "x-jwt-token",
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
  "x-csrf-token",
  "x-xsrf-token",
  "x-request-verification-token",
]);
const SESSION_NAMES = new Set([
  "csrf",
  "csrf_token",
  "csrftoken",
  "xsrf",
  "xsrf_token",
  "_token",
  "authenticity_token",
  "requestverificationtoken",
  "__requestverificationtoken",
]);

type Substitution = {
  location: "QUERY" | "FORM" | "JSON";
  name: string;
  path: string[];
  occurrence: number;
  value: string;
};

type IdentityProfile = ProfileDTO & {
  headers: Record<string, string>;
  substitutions: Substitution[];
};

export class ProfileManager {
  private readonly profiles = new Map<string, IdentityProfile>();

  capture(request: Request, name: string, role: string): ProfileDTO {
    const headers: Record<string, string> = {};
    for (const [headerName, values] of Object.entries(request.getHeaders())) {
      if (!AUTH_HEADERS.has(headerName.toLowerCase())) continue;
      headers[headerName] = joinHeaderValues(headerName, values);
    }
    const substitutions = captureSubstitutions(request);
    if (Object.keys(headers).length === 0)
      throw new Error(
        "No supported authentication headers were found in this request",
      );
    const fingerprint = profileFingerprint(headers, substitutions);
    const duplicate = [...this.profiles.values()].find(
      (value) => value.fingerprint === fingerprint,
    );
    if (duplicate !== undefined)
      throw new Error(
        `This identity is already captured as '${duplicate.name}'`,
      );
    const profile: IdentityProfile = {
      id: uniqueId(fingerprint),
      name: name.trim() === "" ? "Profile" : name.trim().slice(0, 80),
      role: role.trim().slice(0, 80),
      fingerprint,
      headerNames: Object.keys(headers).sort((left, right) =>
        left.localeCompare(right),
      ),
      substitutionNames: substitutions.map((value) =>
        value.location === "JSON"
          ? `${value.location}:${formatPath(value.path)}`
          : `${value.location}:${value.name}${value.occurrence === 0 ? "" : ` #${value.occurrence + 1}`}`,
      ),
      capturedAt: new Date().toISOString(),
      headers,
      substitutions,
    };
    this.profiles.set(profile.id, profile);
    return toDTO(profile);
  }

  list(): ProfileDTO[] {
    return [...this.profiles.values()].map(toDTO);
  }

  remove(id: string): void {
    this.profiles.delete(id);
  }

  clear(): void {
    this.profiles.clear();
  }

  get(id: string): IdentityProfile | undefined {
    return this.profiles.get(id);
  }

  inferOwner(request: Request): string | undefined {
    const matches = [...this.profiles.values()].filter((profile) =>
      profileMatches(profile, request),
    );
    return matches.length === 1 ? matches[0]?.id : undefined;
  }

  apply(request: Request, profile: IdentityProfile): RequestSpec {
    const spec = request.toSpec();
    for (const headerName of Object.keys(spec.getHeaders())) {
      if (AUTH_HEADERS.has(headerName.toLowerCase()))
        spec.removeHeader(headerName);
    }
    for (const [headerName, value] of Object.entries(profile.headers))
      spec.setHeader(headerName, value);
    applySubstitutions(spec, profile.substitutions);
    return spec;
  }

  anonymous(request: Request): RequestSpec {
    const spec = request.toSpec();
    for (const headerName of Object.keys(spec.getHeaders())) {
      if (AUTH_HEADERS.has(headerName.toLowerCase()))
        spec.removeHeader(headerName);
    }
    return spec;
  }
}

function captureSubstitutions(request: Request): Substitution[] {
  const output: Substitution[] = [];
  for (const value of parseEncoded(request.getQuery())) {
    if (SESSION_NAMES.has(normalize(value.name)))
      output.push({ location: "QUERY", path: [], ...value });
  }
  const body = request.getBody()?.toText() ?? "";
  const contentType = (request.getHeader("Content-Type") ?? [])
    .join(" ")
    .toLowerCase();
  if (contentType.includes("application/x-www-form-urlencoded")) {
    for (const value of parseEncoded(body)) {
      if (SESSION_NAMES.has(normalize(value.name)))
        output.push({ location: "FORM", path: [], ...value });
    }
  }
  if (contentType.includes("json")) collectJSONSubstitutions(body, output);
  return output.slice(0, 50);
}

function collectJSONSubstitutions(body: string, output: Substitution[]): void {
  let root: unknown;
  try {
    root = JSON.parse(body) as unknown;
  } catch {
    return;
  }
  const walk = (value: unknown, path: string[], depth: number): void => {
    if (depth > 30 || output.length >= 50 || value === null) return;
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1)
        walk(value[index], [...path, String(index)], depth + 1);
      return;
    }
    if (typeof value !== "object") return;
    for (const [name, child] of Object.entries(value)) {
      const nextPath = [...path, name];
      if (
        SESSION_NAMES.has(normalize(name)) &&
        (typeof child === "string" || typeof child === "number")
      )
        output.push({
          location: "JSON",
          name,
          path: nextPath,
          occurrence: 0,
          value: String(child),
        });
      else walk(child, nextPath, depth + 1);
    }
  };
  walk(root, [], 0);
}

function applySubstitutions(
  spec: RequestSpec,
  substitutions: Substitution[],
): void {
  for (const substitution of substitutions) {
    if (substitution.location === "QUERY") {
      spec.setQuery(
        replaceEncoded(
          spec.getQuery(),
          substitution.name,
          substitution.value,
          substitution.occurrence,
        ),
      );
      continue;
    }
    const body = spec.getBody()?.toText() ?? "";
    if (substitution.location === "FORM")
      spec.setBody(
        replaceEncoded(
          body,
          substitution.name,
          substitution.value,
          substitution.occurrence,
        ),
        {
          updateContentLength: true,
        },
      );
    else
      spec.setBody(replaceJSON(body, substitution.path, substitution.value), {
        updateContentLength: true,
      });
  }
}

export function replaceEncoded(
  raw: string,
  name: string,
  value: string,
  occurrence = 0,
): string {
  let seen = 0;
  let replaced = false;
  const output = raw.split("&").map((pair) => {
    const separator = pair.indexOf("=");
    const rawName = separator < 0 ? pair : pair.slice(0, separator);
    if (!replaced && safeDecode(rawName.replace(/\+/g, " ")) === name) {
      if (seen === occurrence) {
        replaced = true;
        return `${rawName}=${encodeURIComponent(value)}`;
      }
      seen += 1;
    }
    return pair;
  });
  return replaced ? output.join("&") : raw;
}

export function replaceJSON(
  raw: string,
  path: string[],
  value: string,
): string {
  let document: unknown;
  try {
    document = JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
  if (document === null || typeof document !== "object") return raw;
  const segments = path.filter((segment) => segment !== "");
  let current = document as Record<string, unknown>;
  for (const segment of segments.slice(0, -1)) {
    const next = current[segment];
    if (next === null || typeof next !== "object") return raw;
    current = next as Record<string, unknown>;
  }
  const last = segments.at(-1);
  if (last === undefined || !(last in current)) return raw;
  current[last] = value;
  return JSON.stringify(document);
}

function parseEncoded(
  raw: string,
): Array<{ name: string; value: string; occurrence: number }> {
  if (raw === "") return [];
  const occurrences = new Map<string, number>();
  return raw.split("&").map((pair) => {
    const separator = pair.indexOf("=");
    const name = safeDecode(
      (separator < 0 ? pair : pair.slice(0, separator)).replace(/\+/g, " "),
    );
    const occurrence = occurrences.get(name) ?? 0;
    occurrences.set(name, occurrence + 1);
    return {
      name,
      value: safeDecode(
        (separator < 0 ? "" : pair.slice(separator + 1)).replace(/\+/g, " "),
      ),
      occurrence,
    };
  });
}

function profileMatches(profile: IdentityProfile, request: Request): boolean {
  if (Object.keys(profile.headers).length === 0) return false;
  for (const [headerName, expected] of Object.entries(profile.headers)) {
    const actual = joinHeaderValues(
      headerName,
      request.getHeader(headerName) ?? [],
    );
    if (actual !== expected) return false;
  }
  return true;
}

function profileFingerprint(
  headers: Record<string, string>,
  substitutions: Substitution[],
): string {
  const material = Object.entries(headers)
    .sort(([left], [right]) =>
      left.toLowerCase().localeCompare(right.toLowerCase()),
    )
    .map(([name, value]) => `${name.toLowerCase()}:${value}`)
    .concat(
      substitutions
        .map(
          (value) =>
            `${value.location}:${normalize(value.name)}:${JSON.stringify(value.path)}:${value.occurrence}:${value.value}`,
        )
        .sort(),
    )
    .join("\n");
  return createHash("sha256").update(material).digest("hex");
}

function uniqueId(fingerprint: string): string {
  return createHash("sha256")
    .update(`${fingerprint}:${Date.now()}:${Math.random()}`)
    .digest("hex")
    .slice(0, 24);
}

function toDTO(profile: IdentityProfile): ProfileDTO {
  return {
    id: profile.id,
    name: profile.name,
    role: profile.role,
    fingerprint: profile.fingerprint,
    headerNames: [...profile.headerNames],
    substitutionNames: [...profile.substitutionNames],
    capturedAt: profile.capturedAt,
  };
}

function normalize(value: string): string {
  return value.trim().toLowerCase().replace(/-/g, "_");
}

export function joinHeaderValues(name: string, values: string[]): string {
  return values.join(name.toLowerCase() === "cookie" ? "; " : ", ");
}

function formatPath(path: string[]): string {
  return path
    .map((segment) => (/^[0-9]+$/.test(segment) ? `[${segment}]` : segment))
    .join(".")
    .replace(/\.\[/g, "[");
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
