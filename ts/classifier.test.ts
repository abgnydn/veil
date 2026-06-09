// SPDX-License-Identifier: Apache-2.0

// Credential detection — regression guard. A live demo caught that inline
// `KEY=value` credentials (e.g. `deploy with AWS_SECRET_ACCESS_KEY=…`) were
// classified `internal` and sailed through, because ENV_STYLE_RE was anchored
// to line-start and the value was under the generic key-length threshold.

import { describe, expect, test } from "bun:test";
import { classifyTierHeuristic, classifyTierArgmax } from "./classifier";

describe("classifier — credentials flag as secret", () => {
  test("inline KEY=value credential, not at line start", () => {
    expect(classifyTierArgmax("deploy prod with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY")).toBe("secret");
  });

  test("env/export assignment", () => {
    expect(classifyTierArgmax("export DATABASE_URL=postgres://user:pw@host/db")).toBe("secret");
    expect(classifyTierArgmax("set GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa now")).toBe("secret");
  });

  test("vendor-prefixed keys", () => {
    expect(classifyTierArgmax("here is my key sk-abcdefghijklmnopqrstuvwxyz0123")).toBe("secret");
  });

  test("scores sum to ~1 and secret dominates for a credential", () => {
    const s = classifyTierHeuristic("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY");
    expect(s.public + s.internal + s.private + s.secret).toBeCloseTo(1, 5);
    expect(s.secret).toBeGreaterThan(0.5);
  });

  test("does NOT over-flag a bare UUID or ordinary prose as secret", () => {
    // {40,} generic fallback stays, so a 36-char UUID is not a false secret.
    expect(classifyTierArgmax("trace request 550e8400-e29b-41d4-a716-446655440000")).not.toBe("secret");
    expect(classifyTierArgmax("the meeting starts at three tomorrow afternoon")).not.toBe("secret");
  });
});
