// SPDX-License-Identifier: Apache-2.0

// kvkk-sar — Themis's KVKK Madde 11(b)(c) Subject Access Request engine.
//
// What this is
// ============
//
// KVKK Madde 11 grants the data subject more than the right to demand
// erasure (b/c/d covered by `kvkk-deletion.ts`). It also grants:
//
//   - Madde 11(b): the right to LEARN whether their personal data is
//                  being processed.
//   - Madde 11(c): the right to OBTAIN INFORMATION about the
//                  processing — purposes, categories, third-party
//                  recipients, retention period, controller contact.
//
// Today the lawyer has a "Sil" (delete) button. They have no "Show me
// what we have on this subject" button. This module is the engine
// behind that button. It produces a forensic SARRecord — a snapshot of
// what's held + how it's processed — that the lawyer hands to the
// data subject (and, on demand, to the bar association or the KVKK
// Kurumu).
//
// Read-only by design
// ===================
//
// SAR is read-only. There is NO two-stage `SİL`-token confirmation
// upstream — the UI calls this engine on a single button press. The
// engine never mutates docs or embeddings; it only:
//
//   1. Looks up matching docs (same hashing rules as deletion: TC =
//      `tc_hash` exact match; matter = `matter_id` exact match).
//   2. Looks up consent history.
//   3. Inlines the controller-level declarations from
//      `kvkk-controller-config.ts`.
//   4. Appends an audit row of `tool: "kvkk_sar"`.
//   5. Computes a forensic sha256 over the canonical record.
//   6. Returns the full SARRecord to the UI.
//
// PII-not-in-audit invariant
// ==========================
//
// SAME discipline as kvkk-deletion: the audit row's `message_preview`
// and `reply_preview` are FIXED CONSTANTS — `KVKK_SAR_PREVIEW`. The
// only forensic link to the subject is `args_hash =
// sha256(JSON.stringify(req))`. KVKK Madde 6 still classifies TC
// kimlik as özel nitelikli kişisel veri; Madde 12 still obligates the
// controller to prevent unlawful access. A SAR audit row that quoted
// the TC in plaintext would itself be a Madde 12 violation.
//
// Decision-domain widening
// ========================
//
// Mirrors the `kvkk-deletion` move: this module's audit row uses a
// LOCAL `decision: "allowed" | "error"` typed widening. The shared
// `KVKKAuditRow` (kvkk-pdf.ts) keeps its narrower `"allow" | "deny"`
// for read-tool consumers; SAR rows live under `tool: "kvkk_sar"` and
// don't leak into other audit consumers.

import {
  EXAMPLE_CONTROLLER_CONFIG,
  type KVKKControllerConfig,
} from "./kvkk-controller-config";

// ---- Public types ---------------------------------------------------------

/** The set of `tool` strings the audit row carries for SAR events. */
export const KVKK_SAR_TOOL = "kvkk_sar" as const;

/**
 * Fixed audit-row preview. Constant (not template) so the
 * PII-not-in-audit invariant is statically auditable — no codepath
 * builds this from user input.
 */
export const KVKK_SAR_PREVIEW =
  "[KVKK Madde 11(b)(c) — özne erişim talebi yürütüldü]";

/**
 * What the lawyer's UI submits. Same DI shape as DeletionRequest +
 * `format` and `language` knobs the PDF formatter and JSON exporter
 * read.
 */
export interface SARRequest {
  /** TC kimlik number OR matter id (depending on `subject_kind`). */
  subject_id: string;
  /** Which identifier kind `subject_id` carries. */
  subject_kind: "tc" | "matter";
  /** Lawyer name, read from settings. */
  requested_by: string;
  /** Unix ms at which the lawyer hit "Yürüt". */
  requested_at: number;
  /**
   * Output format the SPA will materialize the record into. The bar
   * association prefers PDF; data-portability scenarios prefer JSON.
   * The engine returns a SARRecord either way; the choice is recorded
   * on `record.request.format` so the audit row covers it.
   */
  format: "pdf" | "json";
  /**
   * Cover-sheet language for the PDF. JSON labels are always EN. KVKK
   * applies even to non-TR data subjects whose data is processed in
   * TR (Madde 2 — applicability), hence the EN option.
   */
  language: "tr" | "en";
}

/**
 * A single processing purpose entry. Shape mirrors KVKK Madde 11(c)'s
 * three-part demand: WHY (purpose), ON WHAT BASIS (legal_basis,
 * citing Madde 5), and FOR HOW LONG (retention).
 */
export interface ProcessingPurpose {
  purpose: string;
  legal_basis: string;
  retention: string;
}

/** A doc that matched the subject id, surfaced by `findDocsBySubject`. */
export interface SARDocMatch {
  id: string;
  title: string;
  /** First 500 codepoints of content, codepoint-safe. */
  excerpt: string;
  /** How the match was made — fed back to the lawyer in the PDF/JSON. */
  matched_via: "tc_hash" | "matter_id" | "frontmatter_party";
}

/** A consent moment in the subject's history. */
export interface SARConsentRecord {
  ts: number;
  purpose: string;
  granted: boolean;
}

/**
 * Audit row this module appends. Decision domain widened to
 * `"allowed" | "error"` (mirroring kvkk-deletion). Stays under
 * `tool: "kvkk_sar"` so it doesn't smear into other audit consumers.
 */
export interface AuditRow {
  ts: string;
  tool: typeof KVKK_SAR_TOOL;
  /** `sha256:<hex>` of `JSON.stringify(request)`. */
  args_hash: string;
  decision: "allowed" | "error";
  /**
   * Forensic reason. Format:
   *   `<subject_kind> | format=<pdf|json> | docs=<count>`
   * No raw subject id, no free text from the user.
   */
  reason: string;
  tier: "internal";
  message_preview: typeof KVKK_SAR_PREVIEW;
  reply_preview: typeof KVKK_SAR_PREVIEW;
  /** Lawyer name from `request.requested_by`. */
  client_id: string;
  /** Number of docs matched + included in the record. */
  documents_count: number;
}

/**
 * The forensic record returned to the UI. The PDF formatter and the
 * JSON exporter both consume this shape.
 */
export interface SARRecord {
  request: SARRequest;
  audit_row_id: string;
  documents: SARDocMatch[];
  consent_records: SARConsentRecord[];
  /** Madde 11(c) requires the CONTROLLER's purposes. NOT per-subject. */
  processing_purposes: ProcessingPurpose[];
  /** Categories of personal data the controller processes. */
  data_categories: string[];
  /** Third-party recipients (statically declared, not discovered). */
  third_party_recipients: string[];
  retention_period: string;
  controller_contact: { name: string; email: string; address: string };
  /**
   * sha256 of the canonical record. Hex, lowercase, no `sha256:`
   * prefix.
   */
  sha256: string;
  completed_at: number;
}

/**
 * Dependency-injected I/O surface. The engine never touches Dexie or
 * Yjs directly — the SPA wires this; tests pass mocks. Same shape
 * discipline as `DeletionContext`.
 */
export interface SARContext {
  /**
   * Find every doc whose content / metadata identifies the subject.
   * - `kind === "tc"` -> match via tc_hash (the lawyer's vault stores
   *   `tc_hash` in frontmatter, NOT the raw TC; matching is done by
   *   hashing the input and comparing).
   * - `kind === "matter"` -> exact match against `matter_id`.
   *
   * Returns `{ id, title, content, matched_via }`. The engine
   * truncates the content to 500 codepoints and produces the final
   * `SARDocMatch`.
   */
  findDocsBySubject(
    id: string,
    kind: "tc" | "matter",
  ): Promise<{
    id: string;
    title: string;
    content: string;
    matched_via: SARDocMatch["matched_via"];
  }[]>;
  /**
   * Look up the subject's consent history (granted / denied moments,
   * with timestamps and purpose labels).
   */
  findConsentRecords(subject_id: string): Promise<SARConsentRecord[]>;
  /** Append an audit row; returns the row id. */
  appendAuditRow(row: AuditRow): Promise<string>;
  /**
   * Caller-supplied controller config. Tests pass a fixture; the SPA
   * passes the canonical `EXAMPLE_CONTROLLER_CONFIG`. Optional —
   * defaults to the canonical config if omitted.
   */
  controllerConfig?: KVKKControllerConfig;
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
 * `sha256:<hex>` of the JSON-stringified request. The audit row's
 * only forensic link to the subject's identifier — see the PII
 * invariant doc at the top of the file.
 */
export async function computeSARArgsHash(req: SARRequest): Promise<string> {
  return `sha256:${await sha256Hex(JSON.stringify(req))}`;
}

/**
 * Codepoint-safe truncation: `Array.from(s).slice(0, n).join("")`.
 * Naïve `s.slice(0, 500)` would clip an emoji at a UTF-16 surrogate
 * boundary and produce mojibake; spreading via `Array.from` iterates
 * codepoints.
 */
export function truncateExcerpt(content: string, n = 500): string {
  return Array.from(content).slice(0, n).join("");
}

/**
 * Canonicalize a SARRecord for the forensic sha256. Order is fixed:
 *
 *     subject_id || RS || requested_at || RS || audit_row_id || RS ||
 *     sorted-doc-ids.join("|")
 *
 * Doc ids are sorted lexicographically — unlike deletion (where input
 * order is part of the record), SAR is read-only and the doc set is
 * what matters. Sorting also makes the hash robust to whatever order
 * the storage layer happened to surface them in. RS (0x1e) cannot
 * appear in any field.
 */
export function canonicalizeSARRecord(parts: {
  subject_id: string;
  requested_at: number;
  audit_row_id: string;
  document_ids: readonly string[];
}): string {
  const RS = "\x1e";
  const sorted = [...parts.document_ids].sort();
  return [
    parts.subject_id,
    String(parts.requested_at),
    parts.audit_row_id,
    sorted.join("|"),
  ].join(RS);
}

// ---- The engine -----------------------------------------------------------

/**
 * Execute a KVKK Madde 11(b)+(c) Subject Access Request.
 *
 * Order of operations:
 *
 *   1. `findDocsBySubject` — same matching rules as deletion. Empty
 *      match is allowed (the audit row is still appended; KVKK Madde
 *      13 requires the controller to record the demand even if there's
 *      nothing held).
 *   2. `findConsentRecords` — pull the subject's consent history.
 *   3. Inline controller-level declarations (purposes, categories,
 *      recipients, retention, contact) from the supplied config or
 *      `EXAMPLE_CONTROLLER_CONFIG`.
 *   4. Truncate each doc's content to 500 codepoints (codepoint-safe).
 *   5. Append the audit row. `args_hash = sha256(JSON.stringify(req))`
 *      so ALL request fields (including `format` and `language`) are
 *      covered, not just `subject_id`.
 *   6. Compute the forensic `sha256` over the canonical record.
 *   7. Return the SARRecord.
 *
 * Read-only: never mutates docs, embeddings, or consent history.
 */
export async function executeKVKKSAR(
  req: SARRequest,
  ctx: SARContext,
): Promise<SARRecord> {
  const argsHash = await computeSARArgsHash(req);
  const config = ctx.controllerConfig ?? EXAMPLE_CONTROLLER_CONFIG;

  // 1 + 2. Lookups in parallel — they're independent.
  const [matches, consentRows] = await Promise.all([
    ctx.findDocsBySubject(req.subject_id, req.subject_kind),
    ctx.findConsentRecords(req.subject_id),
  ]);

  // 4. Truncate each match's content to 500 codepoints.
  const documents: SARDocMatch[] = matches.map((m) => ({
    id: m.id,
    title: m.title,
    excerpt: truncateExcerpt(m.content, 500),
    matched_via: m.matched_via,
  }));

  // 5. Append the audit row. Reason carries SHAPE only — never raw subject id.
  const reason =
    `${req.subject_kind} | format=${req.format} | docs=${documents.length}`;
  const auditRow: AuditRow = {
    ts: new Date(req.requested_at).toISOString(),
    tool: KVKK_SAR_TOOL,
    args_hash: argsHash,
    decision: "allowed",
    reason,
    tier: "internal",
    message_preview: KVKK_SAR_PREVIEW,
    reply_preview: KVKK_SAR_PREVIEW,
    client_id: req.requested_by,
    documents_count: documents.length,
  };
  const auditRowId = await ctx.appendAuditRow(auditRow);

  // 6. Forensic sha256.
  const canonical = canonicalizeSARRecord({
    subject_id: req.subject_id,
    requested_at: req.requested_at,
    audit_row_id: auditRowId,
    document_ids: documents.map((d) => d.id),
  });
  const recordHash = await sha256Hex(canonical);

  // 7. Build + return record.
  return {
    request: req,
    audit_row_id: auditRowId,
    documents,
    consent_records: consentRows,
    processing_purposes: config.processing_purposes,
    data_categories: config.data_categories,
    third_party_recipients: config.third_party_recipients,
    retention_period: config.retention_period,
    controller_contact: config.controller_contact,
    sha256: recordHash,
    completed_at: Date.now(),
  };
}
