import { describe, expect, it } from "vitest";

import { joinHeaderValues, replaceEncoded, replaceJSON } from "./profiles";

describe("identity profile substitutions", () => {
  it("replaces the exact repeated query or form occurrence", () => {
    expect(replaceEncoded("csrf=one&csrf=two", "csrf", "target", 1)).toBe(
      "csrf=one&csrf=target",
    );
    expect(replaceEncoded("csrf=one", "missing", "target")).toBe("csrf=one");
  });

  it("replaces exact JSON paths including arrays and dotted keys", () => {
    expect(
      replaceJSON(
        '{"items":[{"csrf.token":"old"}]}',
        ["items", "0", "csrf.token"],
        "new",
      ),
    ).toBe('{"items":[{"csrf.token":"new"}]}');
  });

  it("preserves cookie header semantics when values are combined", () => {
    expect(joinHeaderValues("Cookie", ["a=1", "b=2"])).toBe("a=1; b=2");
    expect(joinHeaderValues("Authorization", ["A", "B"])).toBe("A, B");
  });
});
