// SPDX-License-Identifier: Apache-2.0

// kvkk-pdf.test.ts — Themis acceptance suite for the consent-log PDF formatter.
//
// We mock jsPDF entirely. The formatter is layout code; the test surface is
// (a) what calls it makes against jsPDF and (b) the canonicalization +
// hashing functions, which are deterministic and pure.
//
// Each spec asserts an invariant that a bar-association reviewer would
// check — the cover sheet says the right things, the hash is computed from
// the right rows in the right order, the empty range produces the right
// message, KVKK-policy-deny rows render in red.

import { describe, expect, test } from "bun:test";

import {
  formatConsentLog,
  computeRowsHash,
  canonicalizeRow,
  canonicalizeRows,
  consentLogFilename,
  type KVKKAuditRow,
  type KVKKPdfOptions,
} from "./kvkk-pdf";

// ---- jsPDF mock ------------------------------------------------------------

interface RecordedCall {
  method: string;
  args: unknown[];
}

class FakeJsPDF {
  calls: RecordedCall[] = [];
  pages = 1;
  currentPage = 1;
  textCalls: { text: string; x: number; y: number; page: number; color: [number, number, number] }[] = [];
  private color: [number, number, number] = [0, 0, 0];

  // jsPDF is invoked as `new jsPDF(opts)`. The signature is variadic in the
  // type defs; we accept anything.
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
    this.color = [r, g, b];
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
    this.textCalls.push({
      text,
      x,
      y,
      page: this.currentPage,
      color: [...this.color] as [number, number, number],
    });
    this.calls.push({ method: "text", args: [text, x, y, _opts] });
    return this;
  }

  line(x1: number, y1: number, x2: number, y2: number): this {
    this.calls.push({ method: "line", args: [x1, y1, x2, y2] });
    return this;
  }

  // jsPDF's save method on real instances triggers a download. We never
  // call it from the formatter; the caller does.
  save(filename: string): this {
    this.calls.push({ method: "save", args: [filename] });
    return this;
  }
}

function FakeCtor(...args: unknown[]): FakeJsPDF {
  return new FakeJsPDF(args);
}

// jsPDF generic constructor signature; cast through `unknown` so the
// formatter's strict type accepts the fake.
const FakeCtorTyped = FakeCtor as unknown as new (...a: unknown[]) => never;

// ---- Fixtures --------------------------------------------------------------

function row(partial: Partial<KVKKAuditRow>): KVKKAuditRow {
  return {
    ts: "2026-04-26T10:00:00.000Z",
    tool: "get_document",
    args_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    decision: "allow",
    reason: null,
    duration_ms: 12,
    transport: "ws",
    client_id: "client-test",
    ...partial,
  };
}

const ROW_ALLOW = row({});
const ROW_KVKK_DENY = row({
  ts: "2026-04-26T11:30:00.000Z",
  tool: "bash",
  decision: "deny",
  reason: "kvkk-locked-tool",
});
const ROW_REGULAR_DENY = row({
  ts: "2026-04-26T12:00:00.000Z",
  tool: "share_document",
  decision: "deny",
  reason: "user-clicked-deny",
});
const ROW_CHAT = row({
  ts: "2026-04-26T13:00:00.000Z",
  tool: "brain_chat",
  message_preview: "Mahkeme dosyasini ozetler misin? / Can you summarize the case file?",
  reply_preview: "Onayli ozet... / Approved summary...",
});

function baseOpts(extra: Partial<KVKKPdfOptions> = {}): KVKKPdfOptions {
  return {
    fromIso: "2026-04-19T00:00:00.000Z",
    toIso: "2026-04-26T23:59:59.999Z",
    rowsHash: "deadbeef".repeat(8), // 64 hex chars
    generatedAtMs: Date.parse("2026-04-26T18:00:00.000Z"),
    jsPDFCtor: FakeCtorTyped,
    ...extra,
  };
}

// ---- Specs -----------------------------------------------------------------

describe("canonicalizeRow + canonicalizeRows", () => {
  test("canonicalizeRow produces a stable string from the 5 forensic fields", () => {
    const r = row({ ts: "2026-04-26T00:00:00Z", tool: "x", args_hash: "h", decision: "allow", reason: null });
    const c = canonicalizeRow(r);
    // Field separator is 0x1f; reason null becomes empty string.
    expect(c).toBe("2026-04-26T00:00:00Z\x1fx\x1fh\x1fallow\x1f");
  });

  test("canonicalizeRows preserves caller-supplied order and ignores key reordering", () => {
    const a: KVKKAuditRow = row({ ts: "T1" });
    // Object with keys in DIFFERENT order — JSON.stringify would diverge,
    // canonicalize must NOT.
    const bRaw = {
      decision: "deny" as const,
      reason: "x",
      ts: "T2",
      args_hash: "h",
      tool: "y",
      duration_ms: 0,
    } satisfies KVKKAuditRow;
    const aThenB = canonicalizeRows([a, bRaw]);
    const bThenA = canonicalizeRows([bRaw, a]);
    expect(aThenB).not.toBe(bThenA); // order is preserved (it matters)
    // The b-canonical chunk is identical regardless of how its keys were
    // declared in the source object.
    expect(aThenB.includes(canonicalizeRow(bRaw))).toBe(true);
  });

  test("computeRowsHash returns 64-hex sha256 of the canonical string", async () => {
    const h = await computeRowsHash([ROW_ALLOW, ROW_KVKK_DENY]);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    // Idempotent: same input -> same hash.
    const h2 = await computeRowsHash([ROW_ALLOW, ROW_KVKK_DENY]);
    expect(h2).toBe(h);
    // Different order -> different hash.
    const hReversed = await computeRowsHash([ROW_KVKK_DENY, ROW_ALLOW]);
    expect(hReversed).not.toBe(h);
  });
});

describe("formatConsentLog — cover sheet", () => {
  test("cover sheet has bilingual title, lawyer, range, hash, KVKK articles", async () => {
    const opts = baseOpts({ lawyerName: "Av. Ahmet Yilmaz", barRegistration: "Bolu Barosu - 1234" });
    const doc = (await formatConsentLog([ROW_ALLOW], opts)) as unknown as FakeJsPDF;

    const allText = doc.textCalls.map((c) => c.text).join("\n");
    // Title (TR + EN matched pair)
    expect(allText).toContain("KVKK Onay Kaydi");
    expect(allText).toContain("KVKK Consent Record");
    // Lawyer info
    expect(allText).toContain("Avukat / Lawyer:");
    expect(allText).toContain("Av. Ahmet Yilmaz");
    expect(allText).toContain("Bolu Barosu - 1234");
    // Date range labels
    expect(allText).toContain("Tarih araligi / Date range:");
    // Generated at
    expect(allText).toContain("Olusturulma / Generated at:");
    // Hash present (full 64-hex)
    expect(allText).toContain(`sha256: ${opts.rowsHash}`);
    // KVKK articles
    expect(allText).toContain("Madde 6");
    expect(allText).toContain("Madde 9");
    expect(allText).toContain("Madde 10");
  });

  test("missing lawyer name renders the bilingual placeholder + warning, but does NOT block export", async () => {
    const opts = baseOpts(); // no lawyerName
    const doc = (await formatConsentLog([ROW_ALLOW], opts)) as unknown as FakeJsPDF;
    const allText = doc.textCalls.map((c) => c.text).join("\n");

    expect(allText).toContain("[avukat adi belirtilmedi / lawyer name not specified]");
    // The warning band is present
    expect(allText).toContain("UYARI");
    expect(allText).toContain("WARNING");
    // The PDF still got generated — the body pages exist.
    expect(doc.pages).toBeGreaterThanOrEqual(2);
  });
});

describe("formatConsentLog — empty range", () => {
  test("empty rows array produces a single 'no consents in range' page (plus cover)", async () => {
    const opts = baseOpts({ lawyerName: "Av. Test" });
    const doc = (await formatConsentLog([], opts)) as unknown as FakeJsPDF;
    const allText = doc.textCalls.map((c) => c.text).join("\n");

    expect(allText).toContain("Bu tarih araliginda onay kaydi yok.");
    expect(allText).toContain("No consents in range.");
    // Two pages exactly: cover + empty-range.
    expect(doc.pages).toBe(2);
    // Row count on cover sheet says 0.
    const countLine = doc.textCalls.find((c) => c.text === "0");
    expect(countLine).toBeTruthy();
  });
});

describe("formatConsentLog — consent-rows rendering", () => {
  test("each row renders timestamp, verdict, tool, KVKK article line", async () => {
    const opts = baseOpts({ lawyerName: "Av. Test" });
    const doc = (await formatConsentLog([ROW_ALLOW, ROW_CHAT], opts)) as unknown as FakeJsPDF;
    const allText = doc.textCalls.map((c) => c.text).join("\n");

    // Verdict labels (TR/EN).
    expect(allText).toContain("APPROVED / ONAYLANDI");
    // Tool labels.
    expect(allText).toContain("tool: get_document");
    expect(allText).toContain("tool: brain_chat");
    // KVKK Madde line on rows.
    expect(allText).toContain("KVKK Madde 6 / 9-10");
    // Chat row's message preview surfaced.
    expect(allText.includes("mesaj / message:")).toBe(true);
    expect(allText).toContain("Mahkeme dosyasini ozetler misin?");
  });

  test("kvkk-locked-tool deny rows render in red; regular denies render in muted red, allows render in green", async () => {
    const opts = baseOpts({ lawyerName: "Av. Test" });
    const doc = (await formatConsentLog(
      [ROW_ALLOW, ROW_KVKK_DENY, ROW_REGULAR_DENY],
      opts,
    )) as unknown as FakeJsPDF;

    // Find the verdict text calls — they're the ones matching APPROVED/DENIED.
    const verdictCalls = doc.textCalls.filter(
      (c) => c.text === "APPROVED / ONAYLANDI" || c.text === "DENIED / REDDEDILDI",
    );
    expect(verdictCalls.length).toBe(3);

    // Allow verdict: green-ish text color.
    const allowCall = verdictCalls.find((c) => c.text === "APPROVED / ONAYLANDI");
    expect(allowCall?.color[1]).toBeGreaterThan(80); // green channel high
    expect(allowCall?.color[0]).toBeLessThan(80); // red channel low

    // KVKK-locked deny: bright red (190, 30, 30) — by far the reddest.
    const denyVerdicts = verdictCalls.filter((c) => c.text === "DENIED / REDDEDILDI");
    expect(denyVerdicts.length).toBe(2);
    const reds = denyVerdicts.map((c) => c.color[0]).sort((a, b) => a - b);
    // Bright red has the highest red channel.
    expect(reds[reds.length - 1]).toBeGreaterThanOrEqual(180);
  });
});

describe("formatConsentLog — footers", () => {
  test("footer is applied on every page with page N / M and short hash", async () => {
    const opts = baseOpts({ lawyerName: "Av. Test", rowsHash: "abc123def456" + "0".repeat(52) });
    const doc = (await formatConsentLog([ROW_ALLOW, ROW_CHAT], opts)) as unknown as FakeJsPDF;
    const total = doc.pages;
    expect(total).toBeGreaterThanOrEqual(2);

    // For each page, there should be a "Sayfa / Page p / total" call.
    for (let p = 1; p <= total; p++) {
      const found = doc.textCalls.find(
        (c) => c.page === p && c.text === `Sayfa / Page ${p} / ${total}`,
      );
      expect(found).toBeTruthy();
    }
    // The KVKK article band on every page footer.
    const articleFooterCount = doc.textCalls.filter((c) => c.text === "KVKK Madde 6 / 9-10").length;
    // Each page has the footer; rows themselves also write the article line.
    expect(articleFooterCount).toBeGreaterThanOrEqual(total);

    // Short hash suffix on the right side of each footer.
    const hashLines = doc.textCalls.filter((c) =>
      c.text.startsWith("kaynak hash / source hash: "),
    );
    expect(hashLines.length).toBe(total);
    expect(hashLines[0]?.text).toContain("abc123def456"); // first 12 chars
  });
});

describe("consentLogFilename", () => {
  test("matches the the host-kvkk-consents-<ISO-date>.pdf pattern", () => {
    const fn = consentLogFilename("2026-04-26T23:59:59.999Z");
    expect(fn).toMatch(/^the host-kvkk-consents-\d{4}-\d{2}-\d{2}\.pdf$/);
    // The date portion uses the `to` bound; in Europe/Istanbul, 23:59 UTC
    // on 2026-04-26 is 02:59 on 2026-04-27. We assert the format only —
    // the exact date is TZ-dependent.
  });

  test("graceful when given an unparseable string (falls back to today)", () => {
    const fn = consentLogFilename("not-a-date");
    expect(fn).toMatch(/^the host-kvkk-consents-\d{4}-\d{2}-\d{2}\.pdf$/);
  });
});
