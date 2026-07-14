import { describe, expect, it } from "vitest";

import {
  analyzeMessage,
  endpointTemplate,
  identifierShape,
  parseRequestParameters,
  toReferenceDTO,
} from "./detector";
import type {
  AnalyzerInput,
  AssistantSettings,
  CandidateRuleDTO,
} from "./types";

const settings: AssistantSettings = {
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
  volatileFields: ["timestamp", "request_id", "trace_id"],
};

function message(overrides: Partial<AnalyzerInput> = {}): AnalyzerInput {
  return {
    method: "GET",
    url: "https://app.test/api/users/12345",
    host: "app.test",
    path: "/api/users/12345",
    query: "",
    headers: {},
    parameters: [],
    body: "",
    contentType: "",
    responseStatus: 200,
    responseHeaders: { "Content-Type": ["application/json"] },
    responseBody: '{"user_id":12345,"name":"Alice"}',
    responseContentType: "application/json",
    ...overrides,
  };
}

describe("IDOR candidate detector", () => {
  it("creates high-evidence path candidates and templates object IDs", () => {
    const result = analyzeMessage(message(), settings);
    expect(result?.priority).toBe("HIGH");
    expect(result?.disposition).toBe("ACTIVE");
    expect(result?.endpointTemplate).toBe("/api/users/{id}");
    expect(
      endpointTemplate("/orders/550e8400-e29b-41d4-a716-446655440000"),
    ).toBe("/orders/{id}");
  });

  it("correlates a named request reference with the response", () => {
    const parameters = parseRequestParameters("user_id=12345", "", "", []);
    const result = analyzeMessage(
      message({
        path: "/api/profile",
        query: "user_id=12345",
        parameters,
      }),
      settings,
    );
    expect(result?.reasons).toContain(
      "request reference correlated with response",
    );
    expect(result?.score).toBeGreaterThanOrEqual(75);
  });

  it("suppresses a lone generic ID without resource context", () => {
    const parameters = parseRequestParameters("id=opaque123456", "", "", []);
    const result = analyzeMessage(
      message({
        path: "/api/lookup",
        query: "id=opaque123456",
        parameters,
        responseBody: "{}",
      }),
      settings,
    );
    expect(result?.disposition).toBe("SUPPRESSED");
  });

  it("does not turn telemetry, pagination, or identity headers into candidates", () => {
    const parameters = parseRequestParameters(
      "trace_id=abcdef1234567890&page_id=22",
      "",
      "",
      [],
    );
    expect(
      analyzeMessage(
        message({
          path: "/api/search",
          query: "trace_id=abcdef1234567890&page_id=22",
          parameters,
          headers: { "X-User-Id": ["12345"] },
          responseBody: "{}",
        }),
        settings,
      ),
    ).toBeUndefined();
  });

  it("parses form, cookie, JSON, GraphQL, and XML references with provenance", () => {
    const parameters = parseRequestParameters(
      "account_id=42",
      "order_id=12345",
      "application/x-www-form-urlencoded",
      ["session_id=secret; customer_id=88"],
    );
    expect(
      parameters.map((value) => `${value.location}:${value.name}`),
    ).toEqual(
      expect.arrayContaining([
        "QUERY:account_id",
        "FORM:order_id",
        "COOKIE:customer_id",
      ]),
    );
    const jsonResult = analyzeMessage(
      message({
        method: "POST",
        path: "/api/orders",
        body: '{"variables":{"orderId":"12345"}}',
        contentType: "application/json",
      }),
      settings,
    );
    expect(
      jsonResult?.references.some((value) => value.location === "JSON_BODY"),
    ).toBe(true);
    const xmlResult = analyzeMessage(
      message({
        method: "POST",
        path: "/api/orders",
        body: '<request account_id="42"><order_id>12345</order_id></request>',
        contentType: "application/xml",
      }),
      settings,
    );
    expect(
      xmlResult?.references.some((value) => value.location === "XML"),
    ).toBe(true);
  });

  it("ignores symbolic GraphQL arguments when no concrete variable exists", () => {
    const result = analyzeMessage(
      message({
        method: "POST",
        path: "/graphql",
        body: "query($userId: ID!){ user(userId: $userId){ name } }",
        contentType: "application/json",
        responseBody: "{}",
      }),
      settings,
    );
    expect(result).toBeUndefined();
  });

  it("applies scoped ignore rules without storing raw object values", () => {
    const rule: CandidateRuleDTO = {
      id: "rule-1",
      action: "IGNORE",
      scope: "ENDPOINT",
      host: "app.test",
      method: "GET",
      endpointTemplate: "/api/users/{id}",
      referenceName: "users",
      referenceLocation: "PATH",
      structuralPath: "path[3]",
      reason: "known public object",
      createdAt: new Date(0).toISOString(),
    };
    const result = analyzeMessage(message(), settings, [rule]);
    expect(result?.disposition).toBe("SUPPRESSED");
    const dto = toReferenceDTO(
      result?.references[0] as NonNullable<typeof result>["references"][0],
    );
    expect(JSON.stringify(dto)).not.toContain("12345");
    expect(dto.valueHash).toHaveLength(64);
  });

  it("rejects static assets and calendar years", () => {
    expect(
      analyzeMessage(message({ path: "/files/12345.pdf" }), settings),
    ).toBeUndefined();
    expect(
      analyzeMessage(
        message({ path: "/reports/2026", responseBody: "{}" }),
        settings,
      ),
    ).toBeUndefined();
  });

  it("recognizes bounded identifier shapes", () => {
    expect(identifierShape("550e8400-e29b-41d4-a716-446655440000")).toBe(
      "UUID",
    );
    expect(identifierShape("01ARZ3NDEKTSV4RRFFQ69G5FAV")).toBe("ULID");
    expect(identifierShape("/not-an-id")).toBe("");
  });
});
