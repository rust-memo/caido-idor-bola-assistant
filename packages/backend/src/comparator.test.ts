import { describe, expect, it } from "vitest";

import {
  classifyOwnerControl,
  compareEvidence,
  dice,
  normalizeBody,
} from "./comparator";
import type { DetectedReference } from "./types";

const reference: DetectedReference = {
  name: "user_id",
  value: "12345",
  location: "QUERY",
  structuralPath: "query[0]",
  source: "REQUEST",
  shape: "numeric ID",
  sensitivity: "NORMAL",
  role: "OBJECT",
  evidence: [],
};

describe("identity response comparison", () => {
  it("requires shared object identity for suspicious similar responses", () => {
    const suspicious = compareEvidence(
      {
        status: 200,
        contentType: "application/json",
        body: '{"user_id":12345,"name":"A"}',
      },
      {
        status: 200,
        contentType: "application/json",
        body: '{"user_id":12345,"name":"A"}',
      },
      {
        status: 200,
        contentType: "application/json",
        body: '{"user_id":12345,"name":"A"}',
      },
      [reference],
      ["timestamp"],
    );
    expect(suspicious.status).toBe("Suspicious access");
    expect(suspicious.ownershipEvidence).toBe(true);

    const generic = compareEvidence(
      undefined,
      { status: 200, contentType: "application/json", body: '{"ok":true}' },
      { status: 200, contentType: "application/json", body: '{"ok":true}' },
      [reference],
      [],
    );
    expect(generic.status).toBe("Inconclusive");
  });

  it("recognizes explicit protection and authentication failures", () => {
    const protectedResult = compareEvidence(
      undefined,
      { status: 200, contentType: "application/json", body: "{}" },
      {
        status: 403,
        contentType: "application/json",
        body: '{"error":"forbidden"}',
      },
      [reference],
      [],
    );
    expect(protectedResult.status).toBe("Likely protected");

    const sessionFailure = compareEvidence(
      undefined,
      { status: 200, contentType: "application/json", body: "{}" },
      {
        status: 400,
        contentType: "application/json",
        body: "csrf token invalid",
      },
      [reference],
      [],
    );
    expect(sessionFailure.authenticationFailure).toBe(true);

    const unauthorized = compareEvidence(
      undefined,
      { status: 200, contentType: "application/json", body: "{}" },
      {
        status: 401,
        contentType: "application/json",
        body: '{"error":"unauthorized"}',
      },
      [reference],
      [],
    );
    expect(unauthorized.authenticationFailure).toBe(true);
  });

  it("blocks a cross request when the owner control is not usable", () => {
    expect(
      classifyOwnerControl({
        status: 302,
        contentType: "text/html",
        body: "",
      }),
    ).toMatchObject({ authenticationFailure: true });
    expect(
      classifyOwnerControl({
        status: 200,
        contentType: "text/html",
        body: '<form action="/login"><input name="password"></form>',
      })?.detail,
    ).toContain("login page");
    expect(
      classifyOwnerControl({
        status: 200,
        contentType: "application/json",
        body: '{"error":"access denied"}',
      })?.detail,
    ).toContain("Owner control was denied");
    expect(
      classifyOwnerControl({
        status: 200,
        contentType: "application/json",
        body: '{"ok":true}',
      }),
    ).toBeUndefined();
  });

  it("downgrades suspicious access when the owner baseline is unstable", () => {
    const result = compareEvidence(
      {
        status: 200,
        contentType: "application/json",
        body: '{"user_id":12345,"value":"old"}',
      },
      {
        status: 200,
        contentType: "application/json",
        body: '{"user_id":12345,"different":"completely changed payload"}',
      },
      {
        status: 200,
        contentType: "application/json",
        body: '{"user_id":12345,"different":"completely changed payload"}',
      },
      [reference],
      [],
    );
    expect(result.status).toBe("Inconclusive");
    expect(result.indicators).toContain("unstable owner baseline");
  });

  it("normalizes volatile JSON fields and bounded HTML text", () => {
    expect(
      normalizeBody('{"timestamp":1,"id":2}', "application/json", [
        "timestamp",
      ]),
    ).toBe('{"id":2}');
    expect(normalizeBody("<h1>Hello</h1>", "text/html", [])).toBe("hello");
    expect(dice("abcdef", "abcdef")).toBe(1);
  });
});
