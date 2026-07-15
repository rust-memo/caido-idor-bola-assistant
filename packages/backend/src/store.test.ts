import { describe, expect, it } from "vitest";

import { normalizeSettings } from "./store";
import type { AssistantSettings } from "./types";

describe("settings validation", () => {
  it("bounds numeric settings and rejects malformed list entries", () => {
    const malformed = {
      scopeOnly: "yes",
      autoHistory: true,
      maxRequestBytes: Number.POSITIVE_INFINITY,
      maxResponseBytes: -1,
      maxHistoryEntries: 1_000_000,
      maxCandidates: 0,
      requestBudget: 500,
      delayMilliseconds: -20,
      customAllowNames: [" order_id ", 42, "order_id"],
      customDenyNames: null,
      ignoredPathFragments: ["/assets/"],
      volatileFields: ["timestamp"],
    } as unknown as AssistantSettings;

    const value = normalizeSettings(malformed);
    expect(value.scopeOnly).toBe(true);
    expect(value.maxRequestBytes).toBe(16_384);
    expect(value.maxResponseBytes).toBe(16_384);
    expect(value.maxHistoryEntries).toBe(50_000);
    expect(value.requestBudget).toBe(100);
    expect(value.delayMilliseconds).toBe(0);
    expect(value.customAllowNames).toEqual(["order_id"]);
    expect(value.customDenyNames).toEqual([]);
  });
});
