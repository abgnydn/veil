// SPDX-License-Identifier: Apache-2.0

// kvkk-deletion.test.ts — Themis acceptance suite for KVKK Madde 11 erasure.
//
// The deletion engine is dependency-injected: every spec passes a mock
// `DeletionContext` and asserts the engine's contract. The contract is:
//
//   1. Every matched doc is tombstoned exactly once, in the order
//      surfaced by `findDocsBySubject`.
//   2. Embedding rows are removed for the tombstoned set.
//   3. An audit row is appended even on empty match (KVKK Madde 13:
//      record the demand even if there's nothing to erase).
//   4. The audit row's `message_preview` and `reply_preview` are
//      fixed PII-safe constants — the raw TC kimlik must not appear
//      in those fields.
//   5. A tombstone failure halts further deletions, records an
//      `error` audit row that names the failing doc, and surfaces
//      the partial-state record on the thrown error.
//   6. The forensic sha256 is deterministic for fixed inputs and
//      changes when any field of the canonical record changes.

import { describe, expect, test } from "bun:test";

import {
  executeKVKKDeletion,
  KVKK_DELETE_PREVIEW,
  KVKK_DELETE_TOOL,
  computeArgsHash,
  canonicalizeRecord,
  type AuditRow,
  type DeletionCandidate,
  type DeletionContext,
  type DeletionRecord,
  type DeletionRequest,
} from "./kvkk-deletion";

// ---- Mock context factory --------------------------------------------------

interface MockContextOpts {
  /** Docs returned by `findDocsBySubject`. Defaults to empty. */
  docs?: DeletionCandidate[];
  /**
   * If set, `tombstoneDoc` throws on the doc whose id matches this
   * value. Used by the failure-path spec.
   */
  failOnTombstone?: string;
  /** Number of rows `removeEmbeddings` claims to have removed. */
  embeddingsRemoved?: number;
  /** Audit row id to return from `appendAuditRow`. */
  auditId?: string;
}

interface MockContext extends DeletionContext {
  callLog: { method: string; args: unknown[] }[];
  appendedRows: AuditRow[];
  tombstoned: string[];
}

function makeMockContext(opts: MockContextOpts = {}): MockContext {
  const callLog: { method: string; args: unknown[] }[] = [];
  const appendedRows: AuditRow[] = [];
  const tombstoned: string[] = [];
  const ctx: MockContext = {
    callLog,
    appendedRows,
    tombstoned,
    async findDocsBySubject(id, kind) {
      callLog.push({ method: "findDocsBySubject", args: [id, kind] });
      return opts.docs ?? [];
    },
    async tombstoneDoc(docId) {
      callLog.push({ method: "tombstoneDoc", args: [docId] });
      if (opts.failOnTombstone === docId) {
        throw new Error(`mock-tombstone-error:${docId}`);
      }
      tombstoned.push(docId);
    },
    async removeEmbeddings(docIds) {
      callLog.push({ method: "removeEmbeddings", args: [docIds] });
      return opts.embeddingsRemoved ?? docIds.length;
    },
    async appendAuditRow(row) {
      callLog.push({ method: "appendAuditRow", args: [row] });
      appendedRows.push(row);
      return opts.auditId ?? "audit-row-id-1";
    },
  };
  return ctx;
}

// ---- Fixture helpers -------------------------------------------------------

const TC_FIXTURE = "12345678901"; // 11-digit, format-only fixture
const REQUESTED_AT = 1735300000000; // fixed unix ms

function makeRequest(over: Partial<DeletionRequest> = {}): DeletionRequest {
  return {
    subject_id: TC_FIXTURE,
    subject_kind: "tc",
    grounds: "madde_11_d_amac_disi",
    requested_by: "Av. Test Lawyer",
    requested_at: REQUESTED_AT,
    ...over,
  };
}

// ---- Specs -----------------------------------------------------------------

describe("executeKVKKDeletion — happy paths", () => {
  test("1. successful deletion of 3 matched docs tombstones each, removes embeddings, appends an allowed audit row", async () => {
    const docs: DeletionCandidate[] = [
      { id: "doc-A", content: "...content with TC..." },
      { id: "doc-B", content: "..." },
      { id: "doc-C", content: "..." },
    ];
    const ctx = makeMockContext({
      docs,
      embeddingsRemoved: 5,
      auditId: "audit-1",
    });
    const req = makeRequest();
    const record = await executeKVKKDeletion(req, ctx);

    // Tombstoned all three, in order.
    expect(ctx.tombstoned).toEqual(["doc-A", "doc-B", "doc-C"]);
    // Embeddings removed for the tombstoned set.
    const embeddingsCall = ctx.callLog.find(
      (c) => c.method === "removeEmbeddings",
    );
    expect(embeddingsCall).toBeDefined();
    expect(embeddingsCall?.args[0]).toEqual(["doc-A", "doc-B", "doc-C"]);
    // Exactly one audit row appended, with `decision: "allowed"`.
    expect(ctx.appendedRows.length).toBe(1);
    const row = ctx.appendedRows[0];
    expect(row).toBeDefined();
    expect(row?.decision).toBe("allowed");
    expect(row?.tool).toBe(KVKK_DELETE_TOOL);
    expect(row?.tier).toBe("internal");
    expect(row?.documents_deleted_count).toBe(3);
    // Returned record reflects the run.
    expect(record.audit_row_id).toBe("audit-1");
    expect(record.documents_deleted).toEqual(["doc-A", "doc-B", "doc-C"]);
    expect(record.yjs_tombstones_emitted).toBe(3);
    expect(record.embedding_rows_removed).toBe(5);
    expect(record.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  test("2. empty-match still appends an audit row with documents_deleted: []", async () => {
    const ctx = makeMockContext({ docs: [], auditId: "audit-empty" });
    const req = makeRequest({ subject_id: "no-match-tc" });
    const record = await executeKVKKDeletion(req, ctx);

    expect(ctx.tombstoned).toEqual([]);
    expect(ctx.appendedRows.length).toBe(1);
    expect(ctx.appendedRows[0]?.decision).toBe("allowed");
    expect(ctx.appendedRows[0]?.documents_deleted_count).toBe(0);
    expect(record.documents_deleted).toEqual([]);
    expect(record.yjs_tombstones_emitted).toBe(0);
    expect(record.embedding_rows_removed).toBe(0);
    // No removeEmbeddings call for an empty set — saves an IO round-trip
    // and is meaningful: there are no rows to point at.
    const removeCall = ctx.callLog.find(
      (c) => c.method === "removeEmbeddings",
    );
    expect(removeCall).toBeUndefined();
  });
});

describe("executeKVKKDeletion — failure path", () => {
  test("3. tombstoneDoc throws on doc 2 of 3 — no further docs tombstoned, audit row records error + names the failing doc", async () => {
    const docs: DeletionCandidate[] = [
      { id: "doc-A", content: "..." },
      { id: "doc-B-fails", content: "..." },
      { id: "doc-C", content: "..." }, // should NOT be tombstoned
    ];
    const ctx = makeMockContext({
      docs,
      failOnTombstone: "doc-B-fails",
      auditId: "audit-err",
    });
    const req = makeRequest();

    let caught: Error | null = null;
    try {
      await executeKVKKDeletion(req, ctx);
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).not.toBeNull();
    expect(caught?.message).toContain("doc-B-fails");

    // Doc A was tombstoned; doc B failed; doc C was NEVER attempted.
    expect(ctx.tombstoned).toEqual(["doc-A"]);
    const tombstoneCalls = ctx.callLog.filter(
      (c) => c.method === "tombstoneDoc",
    );
    expect(tombstoneCalls.map((c) => c.args[0])).toEqual([
      "doc-A",
      "doc-B-fails",
    ]);

    // Audit row appended with `decision: "error"` + names the failed doc.
    expect(ctx.appendedRows.length).toBe(1);
    const row = ctx.appendedRows[0];
    expect(row?.decision).toBe("error");
    expect(row?.reason).toContain("error:tombstone_failed:doc-B-fails");
    expect(row?.documents_deleted_count).toBe(1); // only doc-A

    // The thrown error carries the partial-state record so the UI can
    // show the lawyer the audit row id even on failure.
    const partial = (caught as Error & { record?: DeletionRecord }).record;
    expect(partial).toBeDefined();
    expect(partial?.audit_row_id).toBe("audit-err");
    expect(partial?.documents_deleted).toEqual(["doc-A"]);
  });
});

describe("PII-not-in-audit invariant", () => {
  test("4. raw TC number does NOT appear in message_preview / reply_preview / args_hash plaintext", async () => {
    const docs: DeletionCandidate[] = [{ id: "doc-with-tc", content: "..." }];
    const ctx = makeMockContext({ docs, auditId: "audit-pii" });
    const req = makeRequest({ subject_id: TC_FIXTURE });
    await executeKVKKDeletion(req, ctx);

    const row = ctx.appendedRows[0];
    expect(row).toBeDefined();
    // The fixed previews are constants — by construction they cannot
    // carry PII. We assert the constant identity AND the absence of
    // the TC fixture.
    expect(row?.message_preview).toBe(KVKK_DELETE_PREVIEW);
    expect(row?.reply_preview).toBe(KVKK_DELETE_PREVIEW);
    expect(row?.message_preview).not.toContain(TC_FIXTURE);
    expect(row?.reply_preview).not.toContain(TC_FIXTURE);
    // The reason field carries grounds id, not the TC.
    expect(row?.reason).not.toContain(TC_FIXTURE);
    // args_hash is `sha256:<hex>` — no plaintext TC.
    expect(row?.args_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(row?.args_hash).not.toContain(TC_FIXTURE);
  });
});

describe("forensic sha256 — determinism + sensitivity", () => {
  test("5. same inputs -> same hash", async () => {
    const docs: DeletionCandidate[] = [
      { id: "doc-A", content: "..." },
      { id: "doc-B", content: "..." },
    ];
    const req = makeRequest();
    const ctx1 = makeMockContext({ docs, auditId: "fixed-id" });
    const ctx2 = makeMockContext({ docs, auditId: "fixed-id" });
    const r1 = await executeKVKKDeletion(req, ctx1);
    const r2 = await executeKVKKDeletion(req, ctx2);
    expect(r1.sha256).toBe(r2.sha256);
    expect(r1.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  test("6. sha256 changes if subject_id, requested_at, or doc list changes", async () => {
    const baseDocs: DeletionCandidate[] = [
      { id: "doc-A", content: "..." },
    ];

    const req = makeRequest();
    const baseRecord = await executeKVKKDeletion(
      req,
      makeMockContext({ docs: baseDocs, auditId: "id-1" }),
    );

    // Change subject_id.
    const altSubject = await executeKVKKDeletion(
      makeRequest({ subject_id: "different-tc" }),
      makeMockContext({ docs: baseDocs, auditId: "id-1" }),
    );
    expect(altSubject.sha256).not.toBe(baseRecord.sha256);

    // Change requested_at.
    const altTime = await executeKVKKDeletion(
      makeRequest({ requested_at: REQUESTED_AT + 1 }),
      makeMockContext({ docs: baseDocs, auditId: "id-1" }),
    );
    expect(altTime.sha256).not.toBe(baseRecord.sha256);

    // Change doc list.
    const altDocs = await executeKVKKDeletion(
      req,
      makeMockContext({
        docs: [...baseDocs, { id: "doc-B", content: "..." }],
        auditId: "id-1",
      }),
    );
    expect(altDocs.sha256).not.toBe(baseRecord.sha256);

    // Change audit row id (different DB sequence).
    const altAudit = await executeKVKKDeletion(
      req,
      makeMockContext({ docs: baseDocs, auditId: "id-2" }),
    );
    expect(altAudit.sha256).not.toBe(baseRecord.sha256);
  });

  test("6b. canonicalizeRecord is purely a function of its inputs", () => {
    const a = canonicalizeRecord({
      subject_id: "x",
      grounds: "madde_11_d_amac_disi",
      requested_at: 1,
      audit_row_id: "audit-1",
      documents_deleted: ["d-1", "d-2"],
    });
    const b = canonicalizeRecord({
      subject_id: "x",
      grounds: "madde_11_d_amac_disi",
      requested_at: 1,
      audit_row_id: "audit-1",
      documents_deleted: ["d-1", "d-2"],
    });
    expect(a).toBe(b);
    // Doc-list reordering must produce a different canonical form
    // (Themis rule: input order is part of the forensic record).
    const reordered = canonicalizeRecord({
      subject_id: "x",
      grounds: "madde_11_d_amac_disi",
      requested_at: 1,
      audit_row_id: "audit-1",
      documents_deleted: ["d-2", "d-1"],
    });
    expect(reordered).not.toBe(a);
  });
});

describe("subject-kind routing", () => {
  test("7. matter-id calls findDocsBySubject(id, 'matter') not 'tc'", async () => {
    const ctx = makeMockContext({ docs: [], auditId: "id" });
    const req = makeRequest({
      subject_id: "matter-2026-001",
      subject_kind: "matter",
    });
    await executeKVKKDeletion(req, ctx);
    const findCall = ctx.callLog.find(
      (c) => c.method === "findDocsBySubject",
    );
    expect(findCall).toBeDefined();
    expect(findCall?.args).toEqual(["matter-2026-001", "matter"]);
  });

  test("7b. tc-kind calls findDocsBySubject(id, 'tc')", async () => {
    const ctx = makeMockContext({ docs: [], auditId: "id" });
    const req = makeRequest({
      subject_id: TC_FIXTURE,
      subject_kind: "tc",
    });
    await executeKVKKDeletion(req, ctx);
    const findCall = ctx.callLog.find(
      (c) => c.method === "findDocsBySubject",
    );
    expect(findCall?.args).toEqual([TC_FIXTURE, "tc"]);
  });
});

describe("free-text propagation + clamping", () => {
  test("8. free_text propagates into the audit row's reason, truncated to 200 chars", async () => {
    const longText = "a".repeat(500); // 500 chars
    const ctx = makeMockContext({ docs: [], auditId: "id" });
    const req = makeRequest({
      grounds: "diger",
      free_text: longText,
    });
    await executeKVKKDeletion(req, ctx);
    const row = ctx.appendedRows[0];
    expect(row).toBeDefined();
    // grounds id + " | " + first 200 chars of the free text.
    expect(row?.reason).toContain("diger");
    expect(row?.reason).toContain("a".repeat(200));
    expect(row?.reason).not.toContain("a".repeat(201));
    // Total length of the appended `aaaa...` portion is exactly 200.
    const aRun = row?.reason.match(/a+/)?.[0] ?? "";
    expect(aRun.length).toBe(200);
  });

  test("8b. omitted free_text leaves the reason as just the grounds id", async () => {
    const ctx = makeMockContext({ docs: [], auditId: "id" });
    const req = makeRequest({ grounds: "madde_11_e_suresi_dolmus" });
    await executeKVKKDeletion(req, ctx);
    expect(ctx.appendedRows[0]?.reason).toBe("madde_11_e_suresi_dolmus");
  });
});

describe("computeArgsHash helper", () => {
  test("computeArgsHash is sha256:<hex>, deterministic per request", async () => {
    const req = makeRequest();
    const h1 = await computeArgsHash(req);
    const h2 = await computeArgsHash(req);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("computeArgsHash differs when subject_id differs", async () => {
    const a = await computeArgsHash(makeRequest({ subject_id: "X" }));
    const b = await computeArgsHash(makeRequest({ subject_id: "Y" }));
    expect(a).not.toBe(b);
  });
});
