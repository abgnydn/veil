// SPDX-License-Identifier: Apache-2.0

// kvkk-deletion — Themis's KVKK Madde 11 right-to-be-forgotten engine.
//
// What this is
// ============
//
// KVKK Madde 11 grants the data subject the right to demand erasure of
// their personal data (the right to be forgotten, equivalent in scope
// to GDPR Article 17). When a Turkish data subject files this demand,
// the data controller — here, the lawyer running Example — has 30
// days (KVKK Madde 13) to respond and, if the demand is grounded, to
// actually erase the data.
//
// This module is the engine the lawyer's UI calls to execute that
// erasure. It is intentionally PURE in the sense that all I/O (Dexie,
// Yjs, embedding store, audit log) is dependency-injected via
// `DeletionContext`. The engine orchestrates the steps, builds the
// forensic record, and returns it. The UI is responsible for confirming
// with the lawyer (two-stage modal + typed `SİL` token) before invoking
// this function — there is no soft-delete path back from here.
//
// PII-not-in-audit invariant
// ==========================
//
// The data subject's TC kimlik number (or matter id) is the input to
// the deletion request, but it is NOT permitted to appear in plaintext
// in the audit row's `message_preview` or `reply_preview` fields. KVKK
// Madde 6 classifies TC numbers as özel nitelikli kişisel veri
// (special-category personal data) and Madde 12 obligates the data
// controller to take all necessary technical and organizational
// measures to prevent unlawful access. An audit log that quotes the TC
// in plaintext defeats the purpose: it leaks the very identifier the
// subject demanded erasure of.
//
// Instead, the audit row stores `args_hash = sha256(JSON.stringify(req))`
// as the only forensic link. A regulator with the original deletion
// request can recompute the same hash and confirm the audit row
// corresponds to that request; nobody without the request can recover
// the TC from the hash.
//
// Hard delete + Yjs tombstone
// ===========================
//
// KVKK Madde 11 requires actual erasure within 30 days; "soft delete
// with restore" is not legally compliant. This module's contract:
//
//   1. `tombstoneDoc` MUST hard-delete the doc row from Dexie AND
//      emit a Yjs tombstone marker into the CRDT (so any peer that
//      syncs after the deletion sees the absence as intentional, not
//      as a corruption to merge-recover).
//   2. `removeEmbeddings` MUST physically remove the embedding rows.
//   3. The audit row stays. The audit is the legal proof of erasure;
//      KVKK Madde 11(g) explicitly requires the controller to inform
//      the subject of the erasure on demand, which requires us to
//      remember that we erased.

// ---- Public types ---------------------------------------------------------

/**
 * Madde 11 grounds enum. The strings are stable identifiers; the UI
 * renders them as Turkish labels. Bilingual labels live in the SPA so
 * the engine has zero locale knowledge.
 */
export type KVKKGrounds =
  | "madde_11_d_amac_disi"
  | "madde_11_e_suresi_dolmus"
  | "madde_11_f_mesru_olmayan"
  | "diger";

/**
 * The set of `tool` strings the audit row is allowed to carry for
 * deletion events. Single value today; exported as a const for callers
 * that want to filter the audit log to "deletion only".
 */
export const KVKK_DELETE_TOOL = "kvkk_delete" as const;

/**
 * Fixed previews used in the audit row. Constants (not template
 * strings) so the PII-not-in-audit invariant is statically auditable
 * — no codepath builds these from user input.
 */
export const KVKK_DELETE_PREVIEW =
  "[KVKK Madde 11 — kişisel veri silme talebi yürütüldü]";

/** A deletion request as submitted from the UI. */
export interface DeletionRequest {
  /** TC kimlik number OR client matter id, depending on `subject_kind`. */
  subject_id: string;
  /** Which identifier kind `subject_id` carries. */
  subject_kind: "tc" | "matter";
  /** Madde 11 ground cited by the subject (or "diger" for free-text). */
  grounds: KVKKGrounds;
  /** Free-text override / addendum. Capped to 200 chars by the UI. */
  free_text?: string;
  /** Lawyer name, read from the Example settings panel. */
  requested_by: string;
  /** Unix ms at which the lawyer hit "Talebi yürüt". */
  requested_at: number;
}

/** A tombstone-eligible doc surfaced by `findDocsBySubject`. */
export interface DeletionCandidate {
  id: string;
  content: string;
}

/**
 * Audit row shape this module appends. The `decision` field is
 * deliberately wider than kvkk-pdf's `KVKKAuditRow.decision` (which is
 * `"allow" | "deny"`) — deletion events have a third state, `"error"`,
 * for partial-failure rows. The audit subsystem stores deletion rows
 * under their own `tool: "kvkk_delete"` namespace so the wider
 * decision domain doesn't leak into other audit consumers.
 */
export interface AuditRow {
  /** ISO 8601 timestamp (UTC). */
  ts: string;
  /** Always `"kvkk_delete"` for rows this module appends. */
  tool: typeof KVKK_DELETE_TOOL;
  /**
   * `sha256:<hex>` of `JSON.stringify(request)`. The only forensic
   * link to the subject's identifier — see PII invariant above.
   */
  args_hash: string;
  /**
   * Wider than the read-tool audit's enum: `"allowed"` for a
   * successful (or empty-match) deletion, `"error"` for a partial
   * failure that named which doc id failed in the `reason`.
   */
  decision: "allowed" | "error";
  /**
   * Forensic reason. Format is
   *   `<grounds-id> | <free-text-clamped>`
   * for success, or
   *   `error:tombstone_failed:<docId> | <grounds-id> | <free-text>`
   * for partial-failure rows.
   */
  reason: string;
  /** Audit visibility tier. Always `"internal"` for deletion rows. */
  tier: "internal";
  /** Fixed PII-safe preview — the request message. */
  message_preview: typeof KVKK_DELETE_PREVIEW;
  /** Fixed PII-safe preview — the reply / acknowledgement. */
  reply_preview: typeof KVKK_DELETE_PREVIEW;
  /** Lawyer name from settings, the `requested_by` of the request. */
  client_id: string;
  /** Number of docs this row's request matched + tombstoned. */
  documents_deleted_count: number;
}

/**
 * The dependency-injected I/O surface. The engine never touches Dexie
 * or Yjs directly — the SPA wires this up; tests pass mocks.
 */
export interface DeletionContext {
  /**
   * Find every doc whose content / metadata matches the subject id.
   * - `kind === "tc"` -> case-INSENSITIVE substring match (TC numbers
   *   may be embedded in document body or in YAML frontmatter; the
   *   lawyer's threat model is "we don't know exactly where the
   *   identifier was filed").
   * - `kind === "matter"` -> EXACT match (matter ids are filing slugs;
   *   substring match would over-delete sibling matters that share a
   *   prefix).
   */
  findDocsBySubject(
    id: string,
    kind: "tc" | "matter",
  ): Promise<DeletionCandidate[]>;
  /**
   * Hard-delete the doc row from Dexie AND emit a Yjs tombstone
   * marker into the CRDT. Irreversible. Called once per matched doc;
   * if it throws, the engine stops processing further docs and
   * records the failure in the audit row.
   */
  tombstoneDoc(docId: string): Promise<void>;
  /**
   * Remove every embedding row whose `doc_id` is in the supplied
   * list. Returns the number of rows actually removed (some matched
   * docs may not have been embedded yet).
   */
  removeEmbeddings(docIds: string[]): Promise<number>;
  /**
   * Append a row to the audit log. Returns the row's id (the audit
   * subsystem assigns ids; the engine treats them as opaque tokens).
   */
  appendAuditRow(row: AuditRow): Promise<string>;
}

/**
 * The forensic record returned to the UI on success. The UI displays
 * `audit_row_id` + `sha256` to the lawyer (with copy-to-clipboard) so
 * the lawyer can give them to the data subject as the acknowledgement
 * the bar association requires for the case file.
 */
export interface DeletionRecord {
  request: DeletionRequest;
  audit_row_id: string;
  documents_deleted: string[];
  yjs_tombstones_emitted: number;
  embedding_rows_removed: number;
  /**
   * sha256 of the canonical record (see `canonicalizeRecord`). Hex,
   * lowercase, no `sha256:` prefix.
   */
  sha256: string;
  completed_at: number;
}

// ---- Helpers --------------------------------------------------------------

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Compute the args-hash that links the audit row back to the request.
 * Hex, lowercase, with the `sha256:` prefix (matching the audit-log
 * convention used elsewhere — see `KVKKAuditRow.args_hash`). The
 * payload is `JSON.stringify(req)` exactly; the regulator who is
 * handed the original request can reproduce this identically.
 */
export async function computeArgsHash(req: DeletionRequest): Promise<string> {
  const payload = JSON.stringify(req);
  return `sha256:${await sha256Hex(payload)}`;
}

/**
 * Canonicalize the deletion record into the byte-string we hash for
 * the forensic `sha256`. Order matters and is fixed:
 *
 *     subject_id || RS || grounds || RS || requested_at || RS ||
 *     audit_row_id || RS || documents_deleted.join("|")
 *
 * RS (0x1e) is the row-separator borrowed from kvkk-pdf's
 * canonicalization — it cannot appear in any of the fields.
 */
export function canonicalizeRecord(parts: {
  subject_id: string;
  grounds: KVKKGrounds;
  requested_at: number;
  audit_row_id: string;
  documents_deleted: readonly string[];
}): string {
  const RS = "\x1e";
  return [
    parts.subject_id,
    parts.grounds,
    String(parts.requested_at),
    parts.audit_row_id,
    parts.documents_deleted.join("|"),
  ].join(RS);
}

/**
 * Truncate the free-text reason to 200 chars. The UI also caps it,
 * but the engine re-applies the cap defensively — a buggy / malicious
 * caller cannot stuff a 10 KB blob into the audit log.
 */
function clampFreeText(text: string | undefined): string {
  if (!text) return "";
  return text.length > 200 ? text.slice(0, 200) : text;
}

/**
 * Compose the audit-row `reason` field. Format:
 *   `<grounds-id> | <free-text-or-empty>`
 *
 * The PDF formatter (kvkk-pdf.ts) renders the audit row's reason
 * verbatim, prefixed by "sebep / reason:". Bilingual labels live in
 * the SPA, not here — the audit log is forensic, not human-readable.
 */
function composeReason(grounds: KVKKGrounds, freeText: string): string {
  const clamped = clampFreeText(freeText);
  return clamped.length > 0 ? `${grounds} | ${clamped}` : grounds;
}

// ---- The engine -----------------------------------------------------------

/**
 * Execute a KVKK Madde 11 deletion request.
 *
 * Order of operations (each step is awaited; partial failures are
 * captured in the audit row, not retried):
 *
 *   1. `findDocsBySubject` — case-insensitive substring match on TC,
 *      exact match on matter id. Empty match is allowed (the audit
 *      row is still appended — KVKK Madde 13 requires the controller
 *      to record the demand even if there's nothing to erase).
 *   2. For each doc, `tombstoneDoc(docId)`. If any throws, we stop
 *      processing further docs and append an `error` audit row that
 *      names which doc id failed. Already-tombstoned docs stay
 *      tombstoned — there is no rollback (KVKK doesn't permit
 *      "un-deleting" a partially-erased subject's data).
 *   3. `removeEmbeddings(matchedIds)` — bulk-remove embedding rows.
 *   4. Build + append the audit row. `args_hash` is sha256 of the
 *      JSON-stringified request; `message_preview` and `reply_preview`
 *      are fixed constants (see `KVKK_DELETE_PREVIEW`).
 *   5. Compute the forensic `sha256` over the canonical record.
 *   6. Return the full `DeletionRecord` to the UI.
 */
export async function executeKVKKDeletion(
  req: DeletionRequest,
  ctx: DeletionContext,
): Promise<DeletionRecord> {
  const argsHash = await computeArgsHash(req);
  const reason = composeReason(req.grounds, req.free_text ?? "");

  // 1. Find candidates.
  const candidates = await ctx.findDocsBySubject(
    req.subject_id,
    req.subject_kind,
  );

  // 2. Tombstone each. If any throws, record + halt.
  const tombstoned: string[] = [];
  let tombstoneError: { docId: string; message: string } | null = null;
  for (const cand of candidates) {
    try {
      await ctx.tombstoneDoc(cand.id);
      tombstoned.push(cand.id);
    } catch (err) {
      tombstoneError = {
        docId: cand.id,
        message: err instanceof Error ? err.message : String(err),
      };
      break;
    }
  }

  // 3. Remove embeddings — only for docs we actually tombstoned. If we
  //    halted on a tombstone error, we still attempt cleanup for the
  //    docs that were tombstoned (they are erased; their embeddings
  //    must not survive).
  let embeddingsRemoved = 0;
  if (tombstoned.length > 0) {
    embeddingsRemoved = await ctx.removeEmbeddings(tombstoned);
  }

  // 4. Append audit row.
  const auditReason = tombstoneError
    ? `error:tombstone_failed:${tombstoneError.docId} | ${reason}`
    : reason;
  const auditRow: AuditRow = {
    ts: new Date(req.requested_at).toISOString(),
    tool: KVKK_DELETE_TOOL,
    args_hash: argsHash,
    decision: tombstoneError ? "error" : "allowed",
    reason: auditReason,
    tier: "internal",
    message_preview: KVKK_DELETE_PREVIEW,
    reply_preview: KVKK_DELETE_PREVIEW,
    client_id: req.requested_by,
    documents_deleted_count: tombstoned.length,
  };
  const auditRowId = await ctx.appendAuditRow(auditRow);

  // 5. Forensic sha256.
  const canonical = canonicalizeRecord({
    subject_id: req.subject_id,
    grounds: req.grounds,
    requested_at: req.requested_at,
    audit_row_id: auditRowId,
    documents_deleted: tombstoned,
  });
  const recordHash = await sha256Hex(canonical);

  // 6. Build + return record.
  const record: DeletionRecord = {
    request: req,
    audit_row_id: auditRowId,
    documents_deleted: tombstoned,
    yjs_tombstones_emitted: tombstoned.length,
    embedding_rows_removed: embeddingsRemoved,
    sha256: recordHash,
    completed_at: Date.now(),
  };

  if (tombstoneError) {
    // Surface the failure to the UI by throwing AFTER the audit row
    // is safely persisted. The UI catches and shows the lawyer the
    // partial-state warning + the audit row id.
    const e = new Error(
      `tombstone_failed:${tombstoneError.docId}:${tombstoneError.message}`,
    );
    (e as Error & { record?: DeletionRecord }).record = record;
    throw e;
  }

  return record;
}
