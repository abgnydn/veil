// SPDX-License-Identifier: Apache-2.0

// kvkk-sar-pdf.test.ts — Themis acceptance suite for the SAR PDF formatter.
//
// We mock jsPDF entirely. Spec-by-spec we assert:
//   1. PDF rendered with all 6 sections.
//   2. Cover sheet contains lawyer name + sha256.
//   3. TR language renders Turkish headings.
//   4. EN language renders English headings.
//   5. Footer applied on every page (with page N/M and short hash).

import { describe, expect, test } from "bun:test";

import { formatSARPdf, sarPdfFilename, sarJsonFilename } from "./kvkk-sar-pdf";
import type { SARRecord } from "./kvkk-sar";

// ---- jsPDF mock ------------------------------------------------------------

interface RecordedCall {
  method: string;
  args: unknown[];
}

class FakeJsPDF {
  calls: RecordedCall[] = [];
  pages = 1;
  currentPage = 1;
  textCalls: { text: string; x: number; y: number; page: number }[] = [];

  constructor(public ctorArgs: unknown[]) {
    this.calls.push({ method: "ctor", args: ctorArgs });
  }

  addPage(): this {
    this.pages += 1;
    this.currentPage = this.pages;
    this.calls.push({ method: "addPage", args: [] });
    return this;
  }

  setPage(n: number): this {
    this.currentPage = n;
    this.calls.push({ method: "setPage", args: [n] });
    return this;
  }

  getNumberOfPages(): number {
    return this.pages;
  }

  setFont(family: string, style?: string): this {
    this.calls.push({ method: "setFont", args: [family, style] });
    return this;
  }

  setFontSize(sz: number): this {
    this.calls.push({ method: "setFontSize", args: [sz] });
    return this;
  }

  setTextColor(r: number, g: number, b: number): this {
    this.calls.push({ method: "setTextColor", args: [r, g, b] });
    return this;
  }

  setDrawColor(r: number, g: number, b: number): this {
    this.calls.push({ method: "setDrawColor", args: [r, g, b] });
    return this;
  }

  setLineWidth(w: number): this {
    this.calls.push({ method: "setLineWidth", args: [w] });
    return this;
  }

  text(text: string, x: number, y: number, _opts?: unknown): this {
    this.textCalls.push({ text, x, y, page: this.currentPage });
    this.calls.push({ method: "text", args: [text, x, y, _opts] });
    return this;
  }

  line(x1: number, y1: number, x2: number, y2: number): this {
    this.calls.push({ method: "line", args: [x1, y1, x2, y2] });
    return this;
  }

  save(filename: string): this {
    this.calls.push({ method: "save", args: [filename] });
    return this;
  }
}

function FakeCtor(...args: unknown[]): FakeJsPDF {
  return new FakeJsPDF(args);
}

const FakeCtorTyped = FakeCtor as unknown as new (...a: unknown[]) => never;

// ---- Fixture ---------------------------------------------------------------

function makeRecord(over: Partial<SARRecord> = {}): SARRecord {
  const base: SARRecord = {
    request: {
      subject_id: "matter-2026-001",
      subject_kind: "matter",
      requested_by: "Av. Ahmet Yilmaz",
      requested_at: Date.parse("2026-04-26T10:00:00.000Z"),
      format: "pdf",
      language: "tr",
    },
    audit_row_id: "audit-sar-fixture",
    documents: [
      {
        id: "doc-A",
        title: "Vekalet 2026/001",
        excerpt: "Tam metin / full content excerpt of the matter file...",
        matched_via: "matter_id",
      },
      {
        id: "doc-B",
        title: "Dilekce",
        excerpt: "Dilekce icerigi / petition body...",
        matched_via: "frontmatter_party",
      },
    ],
    consent_records: [
      { ts: 1735200000000, purpose: "case_preparation", granted: true },
      { ts: 1735250000000, purpose: "billing_and_invoicing", granted: true },
      { ts: 1735300000000, purpose: "marketing", granted: false },
    ],
    processing_purposes: [
      {
        purpose: "case_preparation",
        legal_basis: "KVKK Madde 5/2/e",
        retention: "5 yil",
      },
      {
        purpose: "billing_and_invoicing",
        legal_basis: "KVKK Madde 5/2/c",
        retention: "10 yil",
      },
    ],
    data_categories: [
      "Kimlik verileri / Identity",
      "Iletisim verileri / Contact",
    ],
    third_party_recipients: ["UYAP", "Bolu Barosu"],
    retention_period: "Vekalet + 5 yil / Representation + 5 years",
    controller_contact: {
      name: "Example - Av. Ahmet Yilmaz",
      email: "kvkk@example.com",
      address: "Bolu, TR",
    },
    sha256: "deadbeef".repeat(8), // 64 hex
    completed_at: Date.parse("2026-04-26T10:00:01.000Z"),
    ...over,
  };
  return base;
}

// ---- Specs -----------------------------------------------------------------

describe("formatSARPdf — sections", () => {
  test("1. PDF rendered with all 6 sections", async () => {
    const record = makeRecord();
    const doc = (await formatSARPdf(record, {
      jsPDFCtor: FakeCtorTyped,
    })) as unknown as FakeJsPDF;

    const allText = doc.textCalls.map((c) => c.text).join("\n");
    // 1. Documents section
    expect(allText).toContain("1. Tutulan veriler");
    // 2. Consent history
    expect(allText).toContain("2. Onay gecmisi");
    // 3. Processing purposes
    expect(allText).toContain("3. Isleme amaclari");
    // 4. Recipients
    expect(allText).toContain("4. Ucuncu taraf alicilari");
    // 5. Retention
    expect(allText).toContain("5. Saklama suresi");
    // 6. Controller
    expect(allText).toContain("6. Veri sorumlusu");

    // EN secondary headings present too.
    expect(allText).toContain("Data held");
    expect(allText).toContain("Consent history");
    expect(allText).toContain("Processing purposes");
    expect(allText).toContain("Third-party recipients");
    expect(allText).toContain("Retention");
    expect(allText).toContain("Controller");
  });
});

describe("formatSARPdf — cover sheet", () => {
  test("2. cover sheet contains lawyer name + sha256 + audit row id + Madde 11(b)+(c) citation", async () => {
    const record = makeRecord();
    const doc = (await formatSARPdf(record, {
      jsPDFCtor: FakeCtorTyped,
      barRegistration: "Bolu Barosu - 1234",
    })) as unknown as FakeJsPDF;

    const allText = doc.textCalls.map((c) => c.text).join("\n");
    expect(allText).toContain("Av. Ahmet Yilmaz");
    expect(allText).toContain(`sha256: ${record.sha256}`);
    expect(allText).toContain(record.audit_row_id);
    expect(allText).toContain("Bolu Barosu - 1234");
    // Madde 11 citation rendered explicitly.
    expect(allText).toContain("Madde 11(b)");
    expect(allText).toContain("Madde 11(c)");
    // Article 11 EN citation also present.
    expect(allText).toContain("Article 11(b)");
    expect(allText).toContain("Article 11(c)");
    // Format flag surfaced (PDF in this fixture).
    expect(allText).toContain("PDF");
  });

  test("2b. TC kimlik subject is hashed on the cover, NOT shown in plaintext", async () => {
    const record = makeRecord({
      request: {
        ...makeRecord().request,
        subject_id: "12345678901",
        subject_kind: "tc",
      },
    });
    const doc = (await formatSARPdf(record, {
      jsPDFCtor: FakeCtorTyped,
    })) as unknown as FakeJsPDF;
    const allText = doc.textCalls.map((c) => c.text).join("\n");
    // Raw TC must NOT appear.
    expect(allText).not.toContain("12345678901");
    // tc_hash prefix surfaced + last-4 trailer.
    expect(allText).toContain("tc_hash:");
    expect(allText).toContain("son 4 / last 4: 8901");
  });
});

describe("formatSARPdf — language toggle", () => {
  test("3. TR language renders Turkish headings (TR title above EN subtitle on cover)", async () => {
    const record = makeRecord();
    const doc = (await formatSARPdf(record, {
      jsPDFCtor: FakeCtorTyped,
      language: "tr",
    })) as unknown as FakeJsPDF;
    const trTitleCall = doc.textCalls.find((c) =>
      c.text.includes("KVKK Madde 11(b)(c) - Erisim Talebi"),
    );
    const enSubtitleCall = doc.textCalls.find(
      (c) => c.text === "Subject Access Request",
    );
    expect(trTitleCall).toBeDefined();
    expect(enSubtitleCall).toBeDefined();
    // TR title precedes EN subtitle on the cover (lower y wins because we
    // draw top-down; first text call is drawn first).
    if (trTitleCall && enSubtitleCall) {
      const trIdx = doc.textCalls.indexOf(trTitleCall);
      const enIdx = doc.textCalls.indexOf(enSubtitleCall);
      expect(trIdx).toBeLessThan(enIdx);
    }
  });

  test("4. EN language flips the cover order: EN primary, TR secondary", async () => {
    const record = makeRecord();
    const doc = (await formatSARPdf(record, {
      jsPDFCtor: FakeCtorTyped,
      language: "en",
    })) as unknown as FakeJsPDF;
    const trCall = doc.textCalls.find((c) =>
      c.text.includes("KVKK Madde 11(b)(c) - Erisim Talebi"),
    );
    const enCall = doc.textCalls.find(
      (c) => c.text === "Subject Access Request",
    );
    expect(trCall).toBeDefined();
    expect(enCall).toBeDefined();
    if (trCall && enCall) {
      const enIdx = doc.textCalls.indexOf(enCall);
      const trIdx = doc.textCalls.indexOf(trCall);
      // EN drawn first now.
      expect(enIdx).toBeLessThan(trIdx);
    }
  });
});

describe("formatSARPdf — footer", () => {
  test("5. footer applied on every page with page N/M + short hash", async () => {
    const record = makeRecord();
    const doc = (await formatSARPdf(record, {
      jsPDFCtor: FakeCtorTyped,
    })) as unknown as FakeJsPDF;
    const total = doc.pages;
    expect(total).toBeGreaterThanOrEqual(7); // cover + 6 sections, at minimum

    for (let p = 1; p <= total; p++) {
      const found = doc.textCalls.find(
        (c) => c.page === p && c.text === `Sayfa / Page ${p} / ${total}`,
      );
      expect(found).toBeTruthy();
    }
    // KVKK Madde 11(b)(c) band on every footer.
    const bandFooters = doc.textCalls.filter(
      (c) => c.text === "KVKK Madde 11(b)(c)",
    );
    expect(bandFooters.length).toBeGreaterThanOrEqual(total);

    // Short hash (12 chars) on every page footer.
    const hashFooters = doc.textCalls.filter((c) =>
      c.text.startsWith("kayit / record: "),
    );
    expect(hashFooters.length).toBe(total);
    expect(hashFooters[0]?.text).toContain(record.sha256.slice(0, 12));
  });
});

describe("formatSARPdf — empty docs", () => {
  test("6. empty matches still render section 1 with the bilingual placeholder", async () => {
    const record = makeRecord({ documents: [], consent_records: [] });
    const doc = (await formatSARPdf(record, {
      jsPDFCtor: FakeCtorTyped,
    })) as unknown as FakeJsPDF;
    const allText = doc.textCalls.map((c) => c.text).join("\n");
    expect(allText).toContain("eslesen belge yoktur");
    expect(allText).toContain("No matching documents");
    expect(allText).toContain("kayitli onay ani yoktur");
    expect(allText).toContain("No consent moments");
  });
});

describe("filename helpers", () => {
  test("sarPdfFilename matches the host-kvkk-sar-<date>.pdf", () => {
    const fn = sarPdfFilename(Date.parse("2026-04-26T10:00:00.000Z"));
    expect(fn).toMatch(/^the host-kvkk-sar-\d{4}-\d{2}-\d{2}\.pdf$/);
  });
  test("sarJsonFilename matches the host-kvkk-sar-<date>.json", () => {
    const fn = sarJsonFilename(Date.parse("2026-04-26T10:00:00.000Z"));
    expect(fn).toMatch(/^the host-kvkk-sar-\d{4}-\d{2}-\d{2}\.json$/);
  });
});
