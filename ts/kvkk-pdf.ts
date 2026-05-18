// SPDX-License-Identifier: Apache-2.0

// kvkk-pdf — Themis's bar-association-grade consent-log PDF formatter.
//
// What this is and is not
// =======================
//
// The Example audit log writes JSONL — one row per consent moment to
// `~/.the host/audit.log`. JSONL is forensically perfect (every byte
// hashable, append-only, machine-readable) but the bar association reads
// PDFs. This module is the bridge: take a date-range slice of audit rows,
// produce a legal-document-shaped PDF the lawyer can print, sign, and
// hand to a regulator on 24-hour notice.
//
// `formatConsentLog` is intentionally PURE and SYNCHRONOUS — it takes the
// rows and a precomputed integrity hash (rows are hashed asynchronously by
// the caller via `computeRowsHash` because Web Crypto's digest API is async
// and we don't want to colour the formatter function async). All layout
// happens here; no I/O, no fetch, no globals other than `jsPDF`. The
// caller (KVKKConsentExport.tsx in the SPA) is responsible for fetching
// rows from `/api/audit`, hashing them, and triggering the download.
//
// Integrity-hash strategy
// =======================
//
// JSON object key order is not guaranteed across runtimes (V8 preserves
// insertion order for string keys but the spec doesn't require it, and the
// audit-log writer is free to reorder fields). To make the PDF's cover-sheet
// hash stable and reproducible, we canonicalize each row as
//
//     `<ts><tool><args_hash><decision><reason ?? "">`
//
// (the five fields KVKK forensics actually cares about; ASCII US 0x1f is
// the field separator, picked because it cannot appear in any of the
// fields' content) and then join all rows with `` (ASCII RS 0x1e) in
// the SAME ORDER the rows are surfaced in the PDF — i.e. the
// chronological order the caller passed in. The sha256 of that string is
// written on the cover sheet and on the footer of every page.
//
// Tamper detection from the bar-association reviewer's perspective:
//   1. They open the PDF and read the cover-sheet hash + the per-page footer
//      hash suffix.
//   2. They request the source `audit.log` JSONL slice from the lawyer
//      (or from Example's read-only audit endpoint).
//   3. They re-canonicalize the rows the same way (the algorithm is
//      documented at the top of the cover sheet) and recompute the sha256.
//   4. If the hashes match, the PDF was generated from those exact rows.
//      If they don't, either the PDF was edited after export or the audit
//      file was modified — both are findings the regulator will pursue.
//
// We deliberately do NOT hash the formatted PDF text (that would couple
// integrity to layout decisions; a font change or a new article citation
// would invalidate every prior PDF). We hash the SOURCE ROWS, which is
// what KVKK Madde 12 defines as the consent record.

import type { jsPDF } from "jspdf";

// ---- Types -----------------------------------------------------------------

/** A single audit row as returned by `GET /api/audit`. */
export interface KVKKAuditRow {
  /** ISO 8601 timestamp (UTC). The PDF re-renders in `Europe/Istanbul`. */
  ts: string;
  /** Tool name, e.g. `get_document`, `share_document`, `brain_chat`. */
  tool: string;
  /** sha256:<hex> of the args object — opaque correlation token. */
  args_hash: string;
  /** Approval verdict for this dispatch. */
  decision: "allow" | "deny";
  /** Free-text reason. `'kvkk-locked-tool'` deny rows render in red. */
  reason: string | null;
  /** Wall-clock duration of the dispatch in milliseconds. */
  duration_ms: number;
  /** How the call entered the gate. */
  transport?: "stdio" | "ws" | "sse-internal";
  /** Caller identifier (MCP client id or session anchor). */
  client_id?: string;
  /** Permalink the user typed to confirm — only present on KVKKApprovalModal allows. */
  approval_id?: string | null;
  /** POST-Veil-routing message preview for chat turns. */
  message_preview?: string;
  /** Concatenated agent reply preview. */
  reply_preview?: string;
  /** sha256:<hex> of file content BEFORE a write. */
  before_hash?: string | null;
  /** sha256:<hex> of file content AFTER a write. */
  after_hash?: string | null;
}

/** Caller-supplied options for `formatConsentLog`. */
export interface KVKKPdfOptions {
  /**
   * The lawyer's name as registered in the Example settings panel. If
   * blank/undefined the cover sheet renders the bilingual placeholder
   * `[avukat adı belirtilmedi / lawyer name not specified]` and the export
   * still proceeds (Themis's rule: don't block, but flag).
   */
  lawyerName?: string;
  /** Optional bar-association registration (e.g. "Bolu Barosu — 1234"). */
  barRegistration?: string;
  /**
   * Date range covered by the export. Both bounds are INCLUSIVE; the cover
   * sheet renders them in `tr-TR` long-form ("26 Nisan 2026"). Pass ISO
   * strings like `2026-04-19T00:00:00.000Z` so the formatter can parse
   * them deterministically.
   */
  fromIso: string;
  toIso: string;
  /**
   * Pre-computed sha256 of the canonicalized source rows (see top-of-file
   * doc on canonicalization). Hex, lowercase, no `sha256:` prefix.
   */
  rowsHash: string;
  /**
   * `Date.now()`-style timestamp at which the PDF was generated. Made
   * injectable so tests don't have to mock the clock.
   */
  generatedAtMs: number;
  /**
   * Optional caller-supplied jsPDF constructor override — tests pass a mock
   * here. Production callers omit this and the formatter falls back to the
   * dynamic import of `jspdf`.
   */
  jsPDFCtor?: new (...args: unknown[]) => jsPDF;
}

// ---- Canonicalization + hashing -------------------------------------------

const FIELD_SEP = ""; // ASCII US — never appears in any audit field
const ROW_SEP = "";   // ASCII RS — boundary between rows

/**
 * Canonicalize a single audit row to a fixed-shape string that survives
 * JSON-key reordering. Only the 5 forensically-load-bearing fields are
 * used — see the file header for why.
 */
export function canonicalizeRow(row: KVKKAuditRow): string {
  return [
    row.ts,
    row.tool,
    row.args_hash,
    row.decision,
    row.reason ?? "",
  ].join(FIELD_SEP);
}

/**
 * Canonicalize every row in the array (preserving the input order — the
 * caller is responsible for chronological ordering) and return the joined
 * canonical string. This is what gets sha256'd to produce the cover-sheet
 * hash.
 */
export function canonicalizeRows(rows: readonly KVKKAuditRow[]): string {
  return rows.map(canonicalizeRow).join(ROW_SEP);
}

/**
 * Compute the sha256 hex digest of the canonicalized rows. Uses Web
 * Crypto (`crypto.subtle.digest`) which is available in browsers, Node 19+,
 * and Bun. Returns lowercase hex without the `sha256:` prefix.
 */
export async function computeRowsHash(
  rows: readonly KVKKAuditRow[],
): Promise<string> {
  const canonical = canonicalizeRows(rows);
  const enc = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

// ---- Layout constants ------------------------------------------------------

// A4 portrait: 595 x 842 pt in jsPDF's default unit. Conservative margins
// so the PDF prints legibly on any home-office printer.
const PAGE_WIDTH = 595;
const PAGE_HEIGHT = 842;
const MARGIN_X = 56;
const MARGIN_TOP = 72;
const MARGIN_BOTTOM = 72;
const FOOTER_Y = PAGE_HEIGHT - 36;
const ROW_HEIGHT_PT = 56; // each consent row block is multi-line — see writeRow
const HEADER_BAND_HEIGHT = 24;

const KVKK_ARTICLES = "KVKK Madde 6 / 9-10";

function formatTrDate(ms: number): string {
  // tr-TR long form, with `Europe/Istanbul` to match the regulator.
  return new Date(ms).toLocaleString("tr-TR", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatTrDateOnly(iso: string): string {
  // ISO `YYYY-MM-DD` -> tr-TR long-form date (no time).
  const parsed = Date.parse(iso);
  const ms = Number.isFinite(parsed) ? parsed : Date.now();
  return new Date(ms).toLocaleDateString("tr-TR", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

function formatRowTs(iso: string): string {
  const parsed = Date.parse(iso);
  if (!Number.isFinite(parsed)) return iso;
  return new Date(parsed).toLocaleString("tr-TR", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/**
 * Permalink heuristic: many tool dispatches store the document permalink in
 * the approval flow; if not, we fall back to displaying the args-hash short
 * suffix. The bar-association reviewer cross-references either against the
 * source JSONL.
 */
function rowPermalink(row: KVKKAuditRow): string {
  if (row.approval_id && row.approval_id.length > 0) return row.approval_id;
  const ah = row.args_hash || "";
  const colon = ah.indexOf(":");
  const tail = colon >= 0 ? ah.slice(colon + 1) : ah;
  return tail ? `args:${tail.slice(0, 12)}` : "—";
}

/**
 * Whether a deny row is a KVKK-policy-saved moment (locked-tool block).
 * These render in red — they are the export's most defendable content.
 */
function isKvkkPolicyDeny(row: KVKKAuditRow): boolean {
  return row.decision === "deny" && row.reason === "kvkk-locked-tool";
}

// ---- Default jsPDF loader --------------------------------------------------

/**
 * Lazy default constructor: only invoked if the caller didn't pass
 * `opts.jsPDFCtor`. Production callers want this; tests pass a mock and
 * never hit the real `jspdf` import.
 */
async function loadDefaultJsPDF(): Promise<new (...args: unknown[]) => jsPDF> {
  // Dynamic import so the kvkk-pdf module itself doesn't pull jspdf into
  // bundles that never call formatConsentLog (e.g. the Veil router).
  const mod = (await import("jspdf")) as unknown as {
    jsPDF?: new (...args: unknown[]) => jsPDF;
    default?: new (...args: unknown[]) => jsPDF;
  };
  const ctor = mod.jsPDF ?? mod.default;
  if (!ctor) {
    throw new Error("kvkk-pdf: jspdf module has no jsPDF or default export");
  }
  return ctor;
}

// ---- The formatter ---------------------------------------------------------

/**
 * Produce a jsPDF document containing the bar-association-grade consent
 * record for the given rows + options. Call `.save(filename)` on the
 * returned doc to trigger a download from the browser.
 *
 * If `opts.jsPDFCtor` is supplied, the formatter is fully synchronous
 * (this is what the test suite uses). Otherwise it `await`s the default
 * jsPDF import. Production callers should use the async path.
 */
export async function formatConsentLog(
  rows: readonly KVKKAuditRow[],
  opts: KVKKPdfOptions,
): Promise<jsPDF> {
  const Ctor = opts.jsPDFCtor ?? (await loadDefaultJsPDF());
  const doc = new Ctor({
    unit: "pt",
    format: "a4",
    orientation: "portrait",
  });

  drawCoverSheet(doc, rows, opts);

  if (rows.length === 0) {
    drawEmptyRangePage(doc, opts);
  } else {
    drawConsentRows(doc, rows, opts);
  }

  // Final pass: write footers on every page now that the page count is known.
  applyFootersToAllPages(doc, opts);

  return doc;
}

// ---- Cover sheet -----------------------------------------------------------

function drawCoverSheet(
  doc: jsPDF,
  rows: readonly KVKKAuditRow[],
  opts: KVKKPdfOptions,
): void {
  let y = MARGIN_TOP;

  // Title (TR primary, EN secondary — matched pair)
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.text("KVKK Onay Kaydi", MARGIN_X, y);
  y += 24;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(14);
  doc.text("KVKK Consent Record", MARGIN_X, y);
  y += 28;

  // Subtitle / regulator-facing context
  doc.setFontSize(10);
  doc.text(
    "Example - Avukat-musteri gizli icerigi icin onay kayitlari",
    MARGIN_X,
    y,
  );
  y += 12;
  doc.text(
    "Example - consent records for attorney-client privileged content",
    MARGIN_X,
    y,
  );
  y += 24;

  // Lawyer block
  const lawyerName = (opts.lawyerName ?? "").trim();
  const lawyerLine = lawyerName.length > 0
    ? lawyerName
    : "[avukat adi belirtilmedi / lawyer name not specified]";
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("Avukat / Lawyer:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.text(lawyerLine, MARGIN_X + 110, y);
  y += 16;
  if (opts.barRegistration && opts.barRegistration.trim().length > 0) {
    doc.setFont("helvetica", "bold");
    doc.text("Baro / Bar:", MARGIN_X, y);
    doc.setFont("helvetica", "normal");
    doc.text(opts.barRegistration.trim(), MARGIN_X + 110, y);
    y += 16;
  }

  // Date range
  doc.setFont("helvetica", "bold");
  doc.text("Tarih araligi / Date range:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  const range = `${formatTrDateOnly(opts.fromIso)} - ${formatTrDateOnly(opts.toIso)}`;
  doc.text(range, MARGIN_X + 170, y);
  y += 16;

  // Generated-at timestamp
  doc.setFont("helvetica", "bold");
  doc.text("Olusturulma / Generated at:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.text(formatTrDate(opts.generatedAtMs), MARGIN_X + 170, y);
  y += 16;

  // Row count
  doc.setFont("helvetica", "bold");
  doc.text("Onay sayisi / Consent count:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.text(String(rows.length), MARGIN_X + 170, y);
  y += 28;

  // Integrity hash block — surface BOTH the algorithm and the digest.
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("Butunluk hash / Integrity hash:", MARGIN_X, y);
  y += 14;
  doc.setFont("courier", "normal");
  doc.setFontSize(9);
  // sha256 is 64 hex chars — fits on one line at 9pt courier.
  doc.text(`sha256: ${opts.rowsHash}`, MARGIN_X, y);
  y += 14;
  doc.setFont("helvetica", "italic");
  doc.setFontSize(8);
  doc.text(
    "Algoritma: ts US tool US args_hash US decision US (reason||\"\"), satirlar arasi RS, sha256 hex.",
    MARGIN_X,
    y,
  );
  y += 10;
  doc.text(
    "Algorithm: ts US tool US args_hash US decision US (reason||\"\"), rows joined by RS, sha256 hex.",
    MARGIN_X,
    y,
  );
  y += 24;

  // KVKK reference block — bilingual matched pair
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("KVKK referanslari / KVKK references:", MARGIN_X, y);
  y += 14;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  const articles = [
    ["Madde 6", "ozel nitelikli kisisel veri / special-category personal data"],
    ["Madde 9", "yurt disina aktarim / cross-border transfer"],
    ["Madde 10", "aydinlatma yukumlulugu / notification obligation"],
  ];
  for (const [art, desc] of articles) {
    doc.setFont("helvetica", "bold");
    doc.text(art ?? "", MARGIN_X, y);
    doc.setFont("helvetica", "normal");
    doc.text(desc ?? "", MARGIN_X + 70, y);
    y += 14;
  }
  y += 12;

  // Lawyer-name not-specified flag (Themis's rule: flag, don't block)
  if (lawyerName.length === 0) {
    doc.setFont("helvetica", "bold");
    doc.setTextColor(180, 80, 0);
    doc.setFontSize(9);
    doc.text(
      "UYARI / WARNING: Avukat adi ayarlardan girilmemis. Bu PDF gecerli ama eksiktir.",
      MARGIN_X,
      y,
    );
    y += 12;
    doc.text(
      "WARNING: Lawyer name not set in settings. This PDF is valid but incomplete.",
      MARGIN_X,
      y,
    );
    doc.setTextColor(0, 0, 0);
    y += 16;
  }

  // Cover-sheet seal
  doc.setFont("helvetica", "italic");
  doc.setFontSize(9);
  doc.text(
    "Bu belge, asagidaki onay anlarinin forensik kaydidir.",
    MARGIN_X,
    PAGE_HEIGHT - 96,
  );
  doc.text(
    "This document is a forensic record of the consent moments listed below.",
    MARGIN_X,
    PAGE_HEIGHT - 84,
  );
}

// ---- Empty-range page ------------------------------------------------------

function drawEmptyRangePage(doc: jsPDF, opts: KVKKPdfOptions): void {
  doc.addPage();
  let y = MARGIN_TOP + 40;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.text("Bu tarih araliginda onay kaydi yok.", MARGIN_X, y);
  y += 22;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(12);
  doc.text("No consents in range.", MARGIN_X, y);
  y += 28;
  doc.setFontSize(10);
  doc.text(
    `Aralik / Range: ${formatTrDateOnly(opts.fromIso)} - ${formatTrDateOnly(opts.toIso)}`,
    MARGIN_X,
    y,
  );
  y += 14;
  doc.text(
    "Example denetim defteri bu aralikta hicbir izin anini kaydetmedi.",
    MARGIN_X,
    y,
  );
  y += 14;
  doc.text(
    "The Example audit log recorded zero consent moments in this range.",
    MARGIN_X,
    y,
  );
}

// ---- Consent-rows pages ----------------------------------------------------

function drawConsentRows(
  doc: jsPDF,
  rows: readonly KVKKAuditRow[],
  _opts: KVKKPdfOptions,
): void {
  doc.addPage();
  drawRowsHeader(doc);
  let y = MARGIN_TOP + HEADER_BAND_HEIGHT + 8;

  for (const row of rows) {
    if (y + ROW_HEIGHT_PT > FOOTER_Y - 24) {
      doc.addPage();
      drawRowsHeader(doc);
      y = MARGIN_TOP + HEADER_BAND_HEIGHT + 8;
    }
    writeRow(doc, row, y);
    y += ROW_HEIGHT_PT;
  }
}

function drawRowsHeader(doc: jsPDF): void {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("Onay anlari / Consent moments", MARGIN_X, MARGIN_TOP);
  doc.setLineWidth(0.5);
  doc.line(
    MARGIN_X,
    MARGIN_TOP + 6,
    PAGE_WIDTH - MARGIN_X,
    MARGIN_TOP + 6,
  );
}

function writeRow(doc: jsPDF, row: KVKKAuditRow, y: number): void {
  const policyDeny = isKvkkPolicyDeny(row);

  // Line 1: timestamp + decision + tool
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.setTextColor(0, 0, 0);
  doc.text(formatRowTs(row.ts), MARGIN_X, y);

  doc.setFont("helvetica", "bold");
  if (policyDeny) {
    doc.setTextColor(190, 30, 30);
  } else if (row.decision === "deny") {
    doc.setTextColor(140, 60, 60);
  } else {
    doc.setTextColor(20, 110, 50);
  }
  const verdict = row.decision === "allow" ? "APPROVED / ONAYLANDI" : "DENIED / REDDEDILDI";
  doc.text(verdict, MARGIN_X + 170, y);
  doc.setTextColor(0, 0, 0);

  doc.setFont("helvetica", "normal");
  doc.text(`tool: ${row.tool}`, MARGIN_X + 360, y);

  // Line 2: permalink + args hash
  doc.setFontSize(9);
  doc.setFont("courier", "normal");
  doc.text(`belge / doc: ${rowPermalink(row)}`, MARGIN_X, y + 12);

  // Line 3: KVKK article + reason
  doc.setFont("helvetica", "italic");
  doc.setFontSize(9);
  doc.setTextColor(60, 60, 60);
  doc.text(KVKK_ARTICLES, MARGIN_X, y + 24);
  if (row.reason && row.reason.length > 0) {
    const reasonLabel = `sebep / reason: ${row.reason}`;
    doc.text(reasonLabel.slice(0, 100), MARGIN_X + 130, y + 24);
  }
  doc.setTextColor(0, 0, 0);

  // Line 4: message preview if present (chat turns)
  if (row.message_preview && row.message_preview.length > 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    const preview = row.message_preview.slice(0, 140);
    doc.text(`mesaj / message: ${preview}`, MARGIN_X, y + 36);
  }

  // Light separator under the row
  doc.setDrawColor(220, 220, 220);
  doc.setLineWidth(0.3);
  doc.line(MARGIN_X, y + 44, PAGE_WIDTH - MARGIN_X, y + 44);
  doc.setDrawColor(0, 0, 0);
}

// ---- Footers ---------------------------------------------------------------

function applyFootersToAllPages(doc: jsPDF, opts: KVKKPdfOptions): void {
  // Use the doc's internal page count. jsPDF exposes
  // `getNumberOfPages()` on instances; we check defensively because tests
  // mock the surface.
  const total = typeof doc.getNumberOfPages === "function"
    ? doc.getNumberOfPages()
    : 1;
  const shortHash = opts.rowsHash.slice(0, 12);

  for (let p = 1; p <= total; p++) {
    if (typeof doc.setPage === "function") {
      doc.setPage(p);
    }
    drawFooter(doc, p, total, shortHash);
  }
}

function drawFooter(
  doc: jsPDF,
  page: number,
  total: number,
  shortHash: string,
): void {
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(100, 100, 100);

  // Left: page N of M (bilingual).
  doc.text(
    `Sayfa / Page ${page} / ${total}`,
    MARGIN_X,
    FOOTER_Y,
  );
  // Center: KVKK article band.
  doc.text(
    KVKK_ARTICLES,
    PAGE_WIDTH / 2,
    FOOTER_Y,
    { align: "center" },
  );
  // Right: source-rows hash short suffix.
  doc.text(
    `kaynak hash / source hash: ${shortHash}...`,
    PAGE_WIDTH - MARGIN_X,
    FOOTER_Y,
    { align: "right" },
  );

  doc.setTextColor(0, 0, 0);
}

// ---- Filename helper -------------------------------------------------------

/**
 * Canonical filename pattern:
 *   the host-kvkk-consents-YYYY-MM-DD.pdf
 * where the date is the `to` bound of the export, in `Europe/Istanbul`.
 * The bar association files by export-end-date; this matches their habit.
 */
export function consentLogFilename(toIso: string): string {
  const parsed = Date.parse(toIso);
  const ms = Number.isFinite(parsed) ? parsed : Date.now();
  // YYYY-MM-DD in Europe/Istanbul.
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(ms));
  return `the host-kvkk-consents-${parts}.pdf`;
}
