// SPDX-License-Identifier: Apache-2.0

// kvkk-sar-pdf — Themis's bar-association-grade SAR PDF formatter.
//
// What this is
// ============
//
// The companion to kvkk-pdf.ts (consent log) but for KVKK Madde
// 11(b)(c) Subject Access Requests. Takes a SARRecord (produced by
// kvkk-sar.ts) and renders a multi-page A4 PDF with six sections:
//
//   1. Tutulan veriler / Data held — table of matched docs.
//   2. Onay geçmişi / Consent history — chronological list.
//   3. İşleme amaçları / Processing purposes — Madde 5 references.
//   4. Üçüncü taraf alıcıları / Third-party recipients.
//   5. Saklama süresi / Retention.
//   6. Veri sorumlusu / Controller contact.
//
// Bilingual layout
// ================
//
// Cover sheet language is selectable: Turkish for domestic data
// subjects (the bar-association default), English for cross-border
// subjects (KVKK Madde 2 — the law applies even to non-TR subjects
// whose data is processed in TR). Section headings render bilingually
// (TR primary + EN secondary) so the PDF is single-source for both
// audiences regardless of which cover language was picked.
//
// Comment kept in sync with kvkk-pdf.ts: the layout helpers (page
// dims, margins, footer band) are intentional copies from kvkk-pdf.ts
// — extracting them into a shared file would be a few-line saving but
// would couple two PDF formatters that are owned by separate
// regulatory streams (consent vs. SAR) and may evolve independently.

import type { jsPDF } from "jspdf";
import type { SARRecord } from "./kvkk-sar";

// ---- Options ---------------------------------------------------------------

export interface KVKKSARPdfOptions {
  /**
   * Cover-sheet language. Section headings always render bilingually.
   * Defaults to `"tr"` if omitted (the bar-association default).
   */
  language?: "tr" | "en";
  /** Optional bar-registration line, e.g. "Bolu Barosu — 1234". */
  barRegistration?: string;
  /**
   * Test seam: caller-supplied jsPDF constructor override. Production
   * callers omit this; tests pass a mock.
   */
  jsPDFCtor?: new (...args: unknown[]) => jsPDF;
}

// ---- Layout constants (kept in sync with kvkk-pdf.ts) ---------------------

const PAGE_WIDTH = 595;
const PAGE_HEIGHT = 842;
const MARGIN_X = 56;
const MARGIN_TOP = 72;
const FOOTER_Y = PAGE_HEIGHT - 36;
const KVKK_FOOTER_BAND = "KVKK Madde 11(b)(c)";

// ---- TZ-aware date helpers ------------------------------------------------

function formatTrDateTime(ms: number): string {
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

function formatEnDateTime(ms: number): string {
  return new Date(ms).toLocaleString("en-GB", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatConsentTs(ms: number): string {
  return new Date(ms).toLocaleString("tr-TR", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---- Default jsPDF loader -------------------------------------------------

async function loadDefaultJsPDF(): Promise<new (...args: unknown[]) => jsPDF> {
  const mod = (await import("jspdf")) as unknown as {
    jsPDF?: new (...args: unknown[]) => jsPDF;
    default?: new (...args: unknown[]) => jsPDF;
  };
  const ctor = mod.jsPDF ?? mod.default;
  if (!ctor) {
    throw new Error("kvkk-sar-pdf: jspdf module has no jsPDF or default export");
  }
  return ctor;
}

// ---- Subject id surface (PII discipline) ----------------------------------

/**
 * The cover sheet displays the subject id verbatim if it's a matter
 * id (filing slugs are not PII). For TC kimlik (kind === "tc"), we
 * surface only the last 4 digits + the full sha256:<hex> hash, so a
 * leaked PDF doesn't surface the raw TC.
 */
async function subjectDisplay(
  id: string,
  kind: "tc" | "matter",
): Promise<string> {
  if (kind === "matter") return id;
  // TC: hash + last-4 trailer.
  const enc = new TextEncoder().encode(id);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  const tail = id.length >= 4 ? id.slice(-4) : id;
  return `tc_hash:${hex.slice(0, 16)}... (son 4 / last 4: ${tail})`;
}

// ---- Public formatter -----------------------------------------------------

/**
 * Format a SARRecord into a jsPDF document with all six sections.
 * Caller triggers `.save(filename)` to download.
 */
export async function formatSARPdf(
  record: SARRecord,
  opts: KVKKSARPdfOptions = {},
): Promise<jsPDF> {
  const Ctor = opts.jsPDFCtor ?? (await loadDefaultJsPDF());
  const doc = new Ctor({
    unit: "pt",
    format: "a4",
    orientation: "portrait",
  });

  const language = opts.language ?? record.request.language ?? "tr";
  const subjectLabel = await subjectDisplay(
    record.request.subject_id,
    record.request.subject_kind,
  );

  drawCoverSheet(doc, record, language, subjectLabel, opts);
  drawDocumentsSection(doc, record);
  drawConsentSection(doc, record);
  drawProcessingPurposesSection(doc, record);
  drawRecipientsSection(doc, record);
  drawRetentionSection(doc, record);
  drawControllerSection(doc, record);

  applyFootersToAllPages(doc, record);

  return doc;
}

// ---- Cover sheet ----------------------------------------------------------

function drawCoverSheet(
  doc: jsPDF,
  record: SARRecord,
  language: "tr" | "en",
  subjectLabel: string,
  opts: KVKKSARPdfOptions,
): void {
  let y = MARGIN_TOP;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  if (language === "tr") {
    doc.text("KVKK Madde 11(b)(c) - Erisim Talebi", MARGIN_X, y);
    y += 24;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(14);
    doc.text("Subject Access Request", MARGIN_X, y);
  } else {
    doc.text("Subject Access Request", MARGIN_X, y);
    y += 24;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(14);
    doc.text("KVKK Madde 11(b)(c) - Erisim Talebi", MARGIN_X, y);
  }
  y += 28;

  doc.setFontSize(10);
  doc.text(
    "Example - Veri sahibinin Madde 11(b) ve (c) kapsamindaki erisim hakki kayit ozeti",
    MARGIN_X,
    y,
  );
  y += 12;
  doc.text(
    "Example - record summary for the data subject's KVKK Article 11(b)+(c) access right",
    MARGIN_X,
    y,
  );
  y += 24;

  // Subject block (TC hashed; matter id verbatim)
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("Veri sahibi / Data subject:", MARGIN_X, y);
  doc.setFont("courier", "normal");
  doc.setFontSize(9);
  doc.text(subjectLabel, MARGIN_X + 170, y);
  y += 18;

  // Lawyer block
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("Avukat / Lawyer:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.text(record.request.requested_by, MARGIN_X + 170, y);
  y += 16;
  if (opts.barRegistration && opts.barRegistration.trim().length > 0) {
    doc.setFont("helvetica", "bold");
    doc.text("Baro / Bar:", MARGIN_X, y);
    doc.setFont("helvetica", "normal");
    doc.text(opts.barRegistration.trim(), MARGIN_X + 170, y);
    y += 16;
  }

  // Request date (TR + EN both in case the regulator pulls one or the other).
  doc.setFont("helvetica", "bold");
  doc.text("Talep tarihi / Requested at:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  const reqDate =
    language === "en"
      ? formatEnDateTime(record.request.requested_at)
      : formatTrDateTime(record.request.requested_at);
  doc.text(reqDate, MARGIN_X + 170, y);
  y += 16;

  // Format
  doc.setFont("helvetica", "bold");
  doc.text("Format:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.text(record.request.format.toUpperCase(), MARGIN_X + 170, y);
  y += 28;

  // sha256 + audit row id
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("Kayit hash / Record sha256:", MARGIN_X, y);
  y += 14;
  doc.setFont("courier", "normal");
  doc.setFontSize(9);
  doc.text(`sha256: ${record.sha256}`, MARGIN_X, y);
  y += 14;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("Audit row id:", MARGIN_X, y);
  doc.setFont("courier", "normal");
  doc.setFontSize(9);
  doc.text(record.audit_row_id, MARGIN_X + 170, y);
  y += 24;

  // KVKK Madde 11 citation
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("KVKK referansi / KVKK reference:", MARGIN_X, y);
  y += 14;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.text(
    "Madde 11(b) - Kisisel verilerin islenip islenmedigini ogrenme hakki",
    MARGIN_X,
    y,
  );
  y += 12;
  doc.text("Article 11(b) - Right to learn whether personal data is being processed", MARGIN_X, y);
  y += 16;
  doc.text(
    "Madde 11(c) - Isleme amaci ve kapsami hakkinda bilgi alma hakki",
    MARGIN_X,
    y,
  );
  y += 12;
  doc.text(
    "Article 11(c) - Right to obtain information about the processing",
    MARGIN_X,
    y,
  );
}

// ---- Section 1: Documents -------------------------------------------------

function drawDocumentsSection(doc: jsPDF, record: SARRecord): void {
  doc.addPage();
  let y = MARGIN_TOP;
  drawSectionHeader(
    doc,
    y,
    "1. Tutulan veriler",
    "Data held",
  );
  y += 32;

  if (record.documents.length === 0) {
    doc.setFont("helvetica", "italic");
    doc.setFontSize(10);
    doc.setTextColor(120, 120, 120);
    doc.text(
      "Bu veri sahibi icin Example vault'unda eslesen belge yoktur.",
      MARGIN_X,
      y,
    );
    y += 14;
    doc.text("No matching documents in the Example vault.", MARGIN_X, y);
    doc.setTextColor(0, 0, 0);
    return;
  }

  for (const m of record.documents) {
    if (y > FOOTER_Y - 80) {
      doc.addPage();
      y = MARGIN_TOP;
    }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.setTextColor(0, 0, 0);
    doc.text(m.title || m.id, MARGIN_X, y);
    y += 12;

    doc.setFont("helvetica", "italic");
    doc.setFontSize(8);
    doc.setTextColor(100, 100, 100);
    doc.text(
      `belge / doc id: ${m.id}  -  eslesme / matched via: ${m.matched_via}`,
      MARGIN_X,
      y,
    );
    y += 12;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(40, 40, 40);
    // Wrap excerpt at ~90 chars per line. jsPDF has splitTextToSize but
    // mocks may not implement it; fall back to manual wrap.
    const lines = wrapText(m.excerpt, 90);
    for (const line of lines) {
      if (y > FOOTER_Y - 24) {
        doc.addPage();
        y = MARGIN_TOP;
      }
      doc.text(line, MARGIN_X, y);
      y += 11;
    }
    doc.setTextColor(0, 0, 0);
    y += 8;
  }
}

// ---- Section 2: Consent ---------------------------------------------------

function drawConsentSection(doc: jsPDF, record: SARRecord): void {
  doc.addPage();
  let y = MARGIN_TOP;
  drawSectionHeader(doc, y, "2. Onay gecmisi", "Consent history");
  y += 32;

  if (record.consent_records.length === 0) {
    doc.setFont("helvetica", "italic");
    doc.setFontSize(10);
    doc.setTextColor(120, 120, 120);
    doc.text(
      "Bu veri sahibi icin kayitli onay ani yoktur.",
      MARGIN_X,
      y,
    );
    y += 14;
    doc.text("No consent moments recorded for this subject.", MARGIN_X, y);
    doc.setTextColor(0, 0, 0);
    return;
  }

  // Chronological — sort ascending.
  const sorted = [...record.consent_records].sort((a, b) => a.ts - b.ts);
  for (const c of sorted) {
    if (y > FOOTER_Y - 40) {
      doc.addPage();
      y = MARGIN_TOP;
    }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(0, 0, 0);
    doc.text(formatConsentTs(c.ts), MARGIN_X, y);

    doc.setFont("helvetica", "bold");
    if (c.granted) {
      doc.setTextColor(20, 110, 50);
      doc.text("ONAYLANDI / GRANTED", MARGIN_X + 130, y);
    } else {
      doc.setTextColor(140, 60, 60);
      doc.text("REDDEDILDI / DENIED", MARGIN_X + 130, y);
    }
    doc.setTextColor(0, 0, 0);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.text(`amac / purpose: ${c.purpose}`, MARGIN_X + 290, y);
    y += 16;
  }
}

// ---- Section 3: Processing purposes ---------------------------------------

function drawProcessingPurposesSection(doc: jsPDF, record: SARRecord): void {
  doc.addPage();
  let y = MARGIN_TOP;
  drawSectionHeader(doc, y, "3. Isleme amaclari", "Processing purposes");
  y += 32;

  doc.setFont("helvetica", "italic");
  doc.setFontSize(9);
  doc.setTextColor(100, 100, 100);
  doc.text(
    "Madde 11(c) - Veri sorumlusunun ilan ettigi isleme amaclari ve hukuki dayanaklari.",
    MARGIN_X,
    y,
  );
  y += 11;
  doc.text(
    "Article 11(c) - Controller-declared purposes and legal bases.",
    MARGIN_X,
    y,
  );
  y += 18;
  doc.setTextColor(0, 0, 0);

  for (const p of record.processing_purposes) {
    if (y > FOOTER_Y - 56) {
      doc.addPage();
      y = MARGIN_TOP;
    }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.text(p.purpose, MARGIN_X, y);
    y += 12;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.text(`hukuki dayanak / legal basis: ${p.legal_basis}`, MARGIN_X, y);
    y += 11;
    doc.text(`saklama / retention: ${p.retention}`, MARGIN_X, y);
    y += 18;
  }
}

// ---- Section 4: Recipients -------------------------------------------------

function drawRecipientsSection(doc: jsPDF, record: SARRecord): void {
  doc.addPage();
  let y = MARGIN_TOP;
  drawSectionHeader(doc, y, "4. Ucuncu taraf alicilari", "Third-party recipients");
  y += 32;

  for (const r of record.third_party_recipients) {
    if (y > FOOTER_Y - 24) {
      doc.addPage();
      y = MARGIN_TOP;
    }
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.text(`- ${r}`, MARGIN_X, y);
    y += 14;
  }
}

// ---- Section 5: Retention --------------------------------------------------

function drawRetentionSection(doc: jsPDF, record: SARRecord): void {
  doc.addPage();
  let y = MARGIN_TOP;
  drawSectionHeader(doc, y, "5. Saklama suresi", "Retention");
  y += 32;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  for (const line of record.retention_period.split("\n")) {
    doc.text(line, MARGIN_X, y);
    y += 14;
  }
}

// ---- Section 6: Controller -------------------------------------------------

function drawControllerSection(doc: jsPDF, record: SARRecord): void {
  doc.addPage();
  let y = MARGIN_TOP;
  drawSectionHeader(doc, y, "6. Veri sorumlusu", "Controller");
  y += 32;

  const c = record.controller_contact;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.text("Ad / Name:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.text(c.name, MARGIN_X + 110, y);
  y += 16;

  doc.setFont("helvetica", "bold");
  doc.text("E-posta / Email:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.text(c.email, MARGIN_X + 110, y);
  y += 16;

  doc.setFont("helvetica", "bold");
  doc.text("Adres / Address:", MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  for (const line of c.address.split("\n")) {
    doc.text(line, MARGIN_X + 110, y);
    y += 14;
  }
}

// ---- Section header helper ------------------------------------------------

function drawSectionHeader(
  doc: jsPDF,
  y: number,
  trTitle: string,
  enTitle: string,
): void {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(0, 0, 0);
  doc.text(trTitle, MARGIN_X, y);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(100, 100, 100);
  doc.text(`/ ${enTitle}`, MARGIN_X, y + 16);
  doc.setTextColor(0, 0, 0);
  doc.setLineWidth(0.5);
  doc.line(MARGIN_X, y + 22, PAGE_WIDTH - MARGIN_X, y + 22);
}

// ---- Wrap helper -----------------------------------------------------------

function wrapText(s: string, maxChars: number): string[] {
  const out: string[] = [];
  const words = s.split(/\s+/);
  let line = "";
  for (const w of words) {
    if (line.length === 0) {
      line = w;
    } else if (line.length + 1 + w.length <= maxChars) {
      line += " " + w;
    } else {
      out.push(line);
      line = w;
    }
  }
  if (line.length > 0) out.push(line);
  return out.length > 0 ? out : [""];
}

// ---- Footers --------------------------------------------------------------

function applyFootersToAllPages(doc: jsPDF, record: SARRecord): void {
  const total =
    typeof doc.getNumberOfPages === "function" ? doc.getNumberOfPages() : 1;
  const shortHash = record.sha256.slice(0, 12);
  for (let p = 1; p <= total; p++) {
    if (typeof doc.setPage === "function") doc.setPage(p);
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

  doc.text(`Sayfa / Page ${page} / ${total}`, MARGIN_X, FOOTER_Y);
  doc.text(KVKK_FOOTER_BAND, PAGE_WIDTH / 2, FOOTER_Y, { align: "center" });
  doc.text(
    `kayit / record: ${shortHash}...`,
    PAGE_WIDTH - MARGIN_X,
    FOOTER_Y,
    { align: "right" },
  );

  doc.setTextColor(0, 0, 0);
}

// ---- Filename helper ------------------------------------------------------

/**
 * Canonical filename pattern:
 *   the host-kvkk-sar-YYYY-MM-DD.pdf
 * where the date is the request date in Europe/Istanbul.
 */
export function sarPdfFilename(requestedAtMs: number): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(requestedAtMs));
  return `the host-kvkk-sar-${parts}.pdf`;
}

/** Filename for the JSON variant — same date stamp, .json suffix. */
export function sarJsonFilename(requestedAtMs: number): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Istanbul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(requestedAtMs));
  return `the host-kvkk-sar-${parts}.json`;
}
