// SPDX-License-Identifier: Apache-2.0

import { describe, expect, test } from "bun:test";

import { applyPseudonymMap, scrambleCohort } from "./cohort-scramble";

describe("scrambleCohort — pool-range fingerprint defense", () => {
  test("preserves kind-shape, randomizes numbers, keeps them distinct", () => {
    const cohort = [
      "remind EMAIL_1 re PATH_1", // real (low session numbers)
      "remind EMAIL_10001 re PATH_10001", // sibling (high pool numbers)
      "remind EMAIL_10002 re PATH_10002",
    ];
    const { prompts } = scrambleCohort(cohort, 0);

    // Every prompt keeps the same template — only numbers change.
    for (const p of prompts) expect(p).toMatch(/^remind EMAIL_\d+ re PATH_\d+$/);

    // The tell-tale "low number = real" signal is gone: the real prompt no
    // longer trivially carries EMAIL_1 (overwhelmingly — 1e6 space).
    // And all k EMAIL slots stay distinct, so entropy is still log2(k).
    const emails = prompts.map((p) => /EMAIL_\d+/.exec(p)![0]);
    expect(new Set(emails).size).toBe(3);
    const paths = prompts.map((p) => /PATH_\d+/.exec(p)![0]);
    expect(new Set(paths).size).toBe(3);
  });

  test("realDemap inverts exactly the real prompt's pseudonyms", () => {
    const cohort = ["to EMAIL_1 at PATH_1", "to EMAIL_10001 at PATH_10001"];
    const { prompts, realDemap } = scrambleCohort(cohort, 0);
    // Un-scrambling the (scrambled) real prompt restores the session pseudonyms.
    expect(applyPseudonymMap(prompts[0]!, realDemap)).toBe("to EMAIL_1 at PATH_1");
    // A sibling's scrambled pseudonym is not in realDemap (would be dropped).
    const siblingEmail = /EMAIL_\d+/.exec(prompts[1]!)![0];
    expect(realDemap.has(siblingEmail)).toBe(false);
  });

  test("un-scrambling a real reply restores session pseudonyms for reverse-map", () => {
    const cohort = ["ping EMAIL_1", "ping EMAIL_10001", "ping EMAIL_10002", "ping EMAIL_10003"];
    const { prompts, realDemap } = scrambleCohort(cohort, 0);
    const scrambledReal = /EMAIL_\d+/.exec(prompts[0]!)![0];
    // The model replies referencing the scrambled pseudonym it was shown.
    const reply = `Reminded ${scrambledReal}.`;
    expect(applyPseudonymMap(reply, realDemap)).toBe("Reminded EMAIL_1.");
  });

  test("applyPseudonymMap leaves unmapped tokens untouched", () => {
    const map = new Map([["EMAIL_5", "EMAIL_1"]]);
    expect(applyPseudonymMap("EMAIL_5 and EMAIL_9", map)).toBe("EMAIL_1 and EMAIL_9");
  });
});
