// SPDX-License-Identifier: Apache-2.0

// kvkk-sar.test.ts — Themis acceptance suite for KVKK Madde 11(b)(c) SAR.
//
// The SAR engine is dependency-injected: every spec passes a mock
// `SARContext` and asserts the engine's contract:
//
//   1. A successful SAR returns docs + consents + processing purposes
//      + sha256.
//   2. An empty match still appends an audit row (KVKK Madde 13).
//   3. Raw TC kimlik must not appear in audit message_preview /
//      reply_preview / args_hash plaintext.
//   4. The forensic sha256 is deterministic for fixed inputs.
//   5. The forensic sha256 changes when subject_id, requested_at, or
//      doc list changes.
//   6. Excerpt truncation is codepoint-safe (emoji boundary survives).
//   7. The `format` knob propagates onto record.request.
//   8. The audit row's `args_hash` covers ALL request fields (not just
//      subject_id) — proven by changing `format` and watching the
//      hash change.

import { describe, expect, test } from "bun:test";

import {
  executeKVKKSAR,
  truncateExcerpt,
  computeSARArgsHash,
  canonicalizeSARRecord,
  KVKK_SAR_PREVIEW,
  KVKK_SAR_TOOL,
  type AuditRow,
  type SARContext,
  type SARConsentRecord,
  type SARRequest,
} from "./kvkk-sar";

// ---- Mock context factory --------------------------------------------------

interface MockOpts {
  matches?: {
    id: string;
    title: string;
    content: string;
    matched_via: "tc_hash" | "matter_id" | "frontmatter_party";
  }[];
  consents?: SARConsentRecord[];
  auditId?: string;
}

interface MockContext extends SARContext {
  callLog: { method: string; args: unknown[] }[];
  appendedRows: AuditRow[];
}

function makeMockContext(opts: MockOpts = {}): MockContext {
  const callLog: { method: string; args: unknown[] }[] = [];
  const appendedRows: AuditRow[] = [];
  return {
    callLog,
    appendedRows,
    async findDocsBySubject(id, kind) {
      callLog.push({ method: "findDocsBySubject", args: [id, kind] });
      return opts.matches ?? [];
    },
    async findConsentRecords(id) {
      callLog.push({ method: "findConsentRecords", args: [id] });
      return opts.consents ?? [];
    },
    async appendAuditRow(row) {
      callLog.push({ method: "appendAuditRow", args: [row] });
      appendedRows.push(row);
      return opts.auditId ?? "audit-sar-1";
    },
  };
}

// ---- Fixtures --------------------------------------------------------------

const TC_FIXTURE = "12345678901";
const REQUESTED_AT = 1735300000000;

function makeRequest(over: Partial<SARRequest> = {}): SARRequest {
  return {
    subject_id: TC_FIXTURE,
    subject_kind: "tc",
    requested_by: "Av. Test Lawyer",
    requested_at: REQUESTED_AT,
    format: "pdf",
    language: "tr",
    ...over,
  };
}

// ---- Specs -----------------------------------------------------------------

describe("executeKVKKSAR — happy path", () => {
  test("1. successful SAR returns docs + consents + processing purposes + sha256", async () => {
    const ctx = makeMockContext({
      matches: [
        {
          id: "doc-A",
          title: "Vekalet 2026/001",
          content: "Tam metin / full content...",
          matched_via: "tc_hash",
        },
        {
          id: "doc-B",
          title: "Dilekce",
          content: "...",
          matched_via: "frontmatter_party",
        },
      ],
      consents: [
        { ts: 1735200000000, purpose: "case_preparation", granted: true },
        { ts: 1735250000000, purpose: "billing", granted: true },
      ],
      auditId: "audit-happy",
    });
    const req = makeRequest();
    const record = await executeKVKKSAR(req, ctx);

    expect(record.audit_row_id).toBe("audit-happy");
    expect(record.documents.length).toBe(2);
    expect(record.documents[0]?.id).toBe("doc-A");
    expect(record.documents[0]?.title).toBe("Vekalet 2026/001");
    expect(record.documents[0]?.matched_via).toBe("tc_hash");
    expect(record.consent_records.length).toBe(2);
    expect(record.processing_purposes.length).toBeGreaterThan(0);
    // Madde 5 references baked into legal_basis strings.
    expect(record.processing_purposes[0]?.legal_basis).toContain("Madde 5");
    expect(record.data_categories.length).toBeGreaterThan(0);
    expect(record.third_party_recipients.length).toBeGreaterThan(0);
    expect(record.retention_period.length).toBeGreaterThan(0);
    expect(record.controller_contact.email).toContain("@");
    expect(record.sha256).toMatch(/^[0-9a-f]{64}$/);

    // Audit row appended with `decision: "allowed"` and SAR tool.
    expect(ctx.appendedRows.length).toBe(1);
    const row = ctx.appendedRows[0];
    expect(row?.tool).toBe(KVKK_SAR_TOOL);
    expect(row?.decision).toBe("allowed");
    expect(row?.tier).toBe("internal");
    expect(row?.documents_count).toBe(2);
    expect(row?.client_id).toBe("Av. Test Lawyer");
  });
});

describe("executeKVKKSAR — empty match", () => {
  test("2. no docs match — record returns documents: [], audit row still appended", async () => {
    const ctx = makeMockContext({
      matches: [],
      consents: [],
      auditId: "audit-empty",
    });
    const req = makeRequest({ subject_id: "11111111110" });
    const record = await executeKVKKSAR(req, ctx);

    expect(record.documents).toEqual([]);
    expect(record.consent_records).toEqual([]);
    expect(ctx.appendedRows.length).toBe(1);
    expect(ctx.appendedRows[0]?.documents_count).toBe(0);
    expect(ctx.appendedRows[0]?.decision).toBe("allowed");
    // Even with empty docs, the controller-level declarations are
    // present (Madde 11(c) is independent of whether anything is held).
    expect(record.processing_purposes.length).toBeGreaterThan(0);
    expect(record.third_party_recipients.length).toBeGreaterThan(0);
  });
});

describe("PII-not-in-audit invariant", () => {
  test("3. raw TC does NOT appear in message_preview / reply_preview / args_hash plaintext / reason", async () => {
    const ctx = makeMockContext({ matches: [], auditId: "audit-pii" });
    const req = makeRequest({ subject_id: TC_FIXTURE });
    await executeKVKKSAR(req, ctx);

    const row = ctx.appendedRows[0];
    expect(row).toBeDefined();
    expect(row?.message_preview).toBe(KVKK_SAR_PREVIEW);
    expect(row?.reply_preview).toBe(KVKK_SAR_PREVIEW);
    expect(row?.message_preview).not.toContain(TC_FIXTURE);
    expect(row?.reply_preview).not.toContain(TC_FIXTURE);
    expect(row?.reason).not.toContain(TC_FIXTURE);
    expect(row?.args_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(row?.args_hash).not.toContain(TC_FIXTURE);
  });
});

describe("forensic sha256 — determinism + sensitivity", () => {
  test("4. sha256 deterministic across same inputs", async () => {
    const matches = [
      {
        id: "doc-A",
        title: "T",
        content: "...",
        matched_via: "tc_hash" as const,
      },
    ];
    const r1 = await executeKVKKSAR(
      makeRequest(),
      makeMockContext({ matches, auditId: "fixed" }),
    );
    const r2 = await executeKVKKSAR(
      makeRequest(),
      makeMockContext({ matches, auditId: "fixed" }),
    );
    expect(r1.sha256).toBe(r2.sha256);
    expect(r1.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  test("5. sha256 changes when subject_id, requested_at, or doc list changes", async () => {
    const baseMatches = [
      {
        id: "doc-A",
        title: "T",
        content: "...",
        matched_via: "tc_hash" as const,
      },
    ];
    const base = await executeKVKKSAR(
      makeRequest(),
      makeMockContext({ matches: baseMatches, auditId: "id-1" }),
    );

    const altSubject = await executeKVKKSAR(
      makeRequest({ subject_id: "98765432109" }),
      makeMockContext({ matches: baseMatches, auditId: "id-1" }),
    );
    expect(altSubject.sha256).not.toBe(base.sha256);

    const altTime = await executeKVKKSAR(
      makeRequest({ requested_at: REQUESTED_AT + 1 }),
      makeMockContext({ matches: baseMatches, auditId: "id-1" }),
    );
    expect(altTime.sha256).not.toBe(base.sha256);

    const altDocs = await executeKVKKSAR(
      makeRequest(),
      makeMockContext({
        matches: [
          ...baseMatches,
          {
            id: "doc-B",
            title: "T2",
            content: "...",
            matched_via: "matter_id" as const,
          },
        ],
        auditId: "id-1",
      }),
    );
    expect(altDocs.sha256).not.toBe(base.sha256);
  });

  test("5b. canonicalizeSARRecord sorts doc ids — order-independent within the doc set", () => {
    const a = canonicalizeSARRecord({
      subject_id: "x",
      requested_at: 1,
      audit_row_id: "audit-1",
      document_ids: ["d-1", "d-2"],
    });
    const b = canonicalizeSARRecord({
      subject_id: "x",
      requested_at: 1,
      audit_row_id: "audit-1",
      document_ids: ["d-2", "d-1"],
    });
    // Unlike deletion, SAR sorts — the doc set, not its surfacing
    // order, is what matters.
    expect(a).toBe(b);
  });
});

describe("excerpt truncation — codepoint-safe", () => {
  test("6. excerpt truncation is codepoint-safe across emoji boundary", async () => {
    // 498 ASCII chars + 1 emoji (codepoint 1) + 1 emoji (codepoint 2)
    // The 500th codepoint is the first emoji, the 501st is the second.
    // A naïve `.slice(0, 500)` would slice mid-surrogate; codepoint-safe
    // slicing keeps the first emoji whole and drops the second cleanly.
    const filler = "a".repeat(498);
    const emoji1 = "\u{1F4DD}"; // 📝
    const emoji2 = "\u{1F4C2}"; // 📂
    const content = filler + emoji1 + emoji2 + "trailing-tail";

    const out = truncateExcerpt(content, 500);
    // First emoji is intact (codepoint 499 in 0-indexed terms).
    // We expect 500 codepoints: 498 'a's + 2 emoji = 500. Wait — the
    // doc says first 500 codepoints. So both emoji should fit IF
    // 498 + 2 = 500. Let's be precise.
    const codepoints = Array.from(out);
    expect(codepoints.length).toBe(500);
    expect(codepoints[498]).toBe(emoji1);
    expect(codepoints[499]).toBe(emoji2);
    // Trailing tail dropped.
    expect(out).not.toContain("trailing-tail");
    // No mojibake — the emoji round-trips through.
    expect(out).toContain(emoji1);
    expect(out).toContain(emoji2);

    // And confirm the engine wires this through.
    const ctx = makeMockContext({
      matches: [
        {
          id: "doc-emoji",
          title: "T",
          content,
          matched_via: "tc_hash",
        },
      ],
      auditId: "id",
    });
    const record = await executeKVKKSAR(makeRequest(), ctx);
    const ex = record.documents[0]?.excerpt ?? "";
    const exCodepoints = Array.from(ex);
    expect(exCodepoints.length).toBe(500);
    expect(exCodepoints[498]).toBe(emoji1);
    expect(exCodepoints[499]).toBe(emoji2);
  });

  test("6b. shorter content is returned untouched", async () => {
    const shortContent = "kisa metin / short text";
    const ctx = makeMockContext({
      matches: [
        {
          id: "doc-short",
          title: "T",
          content: shortContent,
          matched_via: "matter_id",
        },
      ],
      auditId: "id",
    });
    const record = await executeKVKKSAR(makeRequest(), ctx);
    expect(record.documents[0]?.excerpt).toBe(shortContent);
  });
});

describe("format propagation", () => {
  test("7. format propagates through to record.request.format", async () => {
    const ctxPdf = makeMockContext({ matches: [], auditId: "id" });
    const ctxJson = makeMockContext({ matches: [], auditId: "id" });
    const recPdf = await executeKVKKSAR(makeRequest({ format: "pdf" }), ctxPdf);
    const recJson = await executeKVKKSAR(
      makeRequest({ format: "json" }),
      ctxJson,
    );
    expect(recPdf.request.format).toBe("pdf");
    expect(recJson.request.format).toBe("json");
    // Audit row reason carries the format too.
    expect(ctxPdf.appendedRows[0]?.reason).toContain("format=pdf");
    expect(ctxJson.appendedRows[0]?.reason).toContain("format=json");
  });
});

describe("args_hash covers ALL request fields", () => {
  test("8. args_hash differs when format flips (proves all fields are hashed, not just subject_id)", async () => {
    const reqPdf = makeRequest({ format: "pdf" });
    const reqJson = makeRequest({ format: "json" });
    const hPdf = await computeSARArgsHash(reqPdf);
    const hJson = await computeSARArgsHash(reqJson);
    expect(hPdf).not.toBe(hJson);

    // Same for language.
    const reqTr = makeRequest({ language: "tr" });
    const reqEn = makeRequest({ language: "en" });
    const hTr = await computeSARArgsHash(reqTr);
    const hEn = await computeSARArgsHash(reqEn);
    expect(hTr).not.toBe(hEn);

    // Same for requested_by (lawyer name).
    const reqA = makeRequest({ requested_by: "Av. A" });
    const reqB = makeRequest({ requested_by: "Av. B" });
    expect(await computeSARArgsHash(reqA)).not.toBe(
      await computeSARArgsHash(reqB),
    );

    // Sanity: identical requests produce identical hashes.
    expect(await computeSARArgsHash(reqPdf)).toBe(
      await computeSARArgsHash(makeRequest({ format: "pdf" })),
    );
  });
});

describe("subject-kind routing", () => {
  test("9. matter-id calls findDocsBySubject(id, 'matter')", async () => {
    const ctx = makeMockContext({ matches: [], auditId: "id" });
    const req = makeRequest({
      subject_id: "matter-2026-001",
      subject_kind: "matter",
    });
    await executeKVKKSAR(req, ctx);
    const findCall = ctx.callLog.find((c) => c.method === "findDocsBySubject");
    expect(findCall?.args).toEqual(["matter-2026-001", "matter"]);
  });
});
