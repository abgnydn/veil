// SPDX-License-Identifier: Apache-2.0

// kvkk-profile.test.ts — Themis acceptance suite.
//
// The KVKK profile is a regulated-domain bundle: it MUST hold its shape, MUST
// reject the locked tools by name (with article citations in the error), and
// MUST refuse to be downgraded at runtime. These specs are the contract.

import { describe, expect, test } from "bun:test";

import {
  KVKK_PROFILE,
  KVKKLockedError,
  assertNotLocked,
  isLockedTool,
} from "./kvkk-profile";

describe("KVKK_PROFILE — shape invariants", () => {
  test("lockedTools contains exactly the six high-blast-radius tools", () => {
    // The contract from themis.md: bash + 3 session tools + 2 temple tools.
    // Read tools and write-vault tools must NOT be in this set.
    expect(KVKK_PROFILE.lockedTools.has("bash")).toBe(true);
    expect(KVKK_PROFILE.lockedTools.has("spawn_session")).toBe(true);
    expect(KVKK_PROFILE.lockedTools.has("kill_session")).toBe(true);
    expect(KVKK_PROFILE.lockedTools.has("send_to_session")).toBe(true);
    expect(KVKK_PROFILE.lockedTools.has("summon_temple")).toBe(true);
    expect(KVKK_PROFILE.lockedTools.has("dismiss_temple")).toBe(true);
    expect(KVKK_PROFILE.lockedTools.size).toBe(6);

    // Negative: read + write tools must NOT be locked.
    expect(KVKK_PROFILE.lockedTools.has("get_document")).toBe(false);
    expect(KVKK_PROFILE.lockedTools.has("list_documents")).toBe(false);
    expect(KVKK_PROFILE.lockedTools.has("update_document")).toBe(false);
    expect(KVKK_PROFILE.lockedTools.has("create_document")).toBe(false);
    expect(KVKK_PROFILE.lockedTools.has("save_to_vault")).toBe(false);
  });

  test("forcedTier locks override=false and perDocApproval=true", () => {
    // The contract: a lawyer cannot mark Müvekkil-Avukat-Gizli content as
    // `public` to dodge the modal, and every read fires a fresh prompt.
    expect(KVKK_PROFILE.forcedTier.override).toBe(false);
    expect(KVKK_PROFILE.forcedTier.perDocApproval).toBe(true);
  });

  test("locale is 'tr' and is non-overridable at the type level", () => {
    expect(KVKK_PROFILE.locale).toBe("tr");
    // The shape's locale field is typed `KVKKLocale = "tr"`. The runtime
    // value here is the only valid value — any attempt to assign 'en' would
    // fail compile-time. We assert the string identity at runtime.
    const allowedLocales = ["tr"] as const;
    expect(allowedLocales).toContain(KVKK_PROFILE.locale);
  });

  test("auditVisibility is 'home' — the audit log is the primary surface", () => {
    expect(KVKK_PROFILE.auditVisibility).toBe("home");
  });

  test("auditTopBanner is enabled — count + last-action timestamp shown persistently", () => {
    expect(KVKK_PROFILE.auditTopBanner).toBe(true);
  });

  test("the profile is frozen — runtime mutation throws (or no-ops in non-strict)", () => {
    // Object.freeze is shallow but the only mutable field a misbehaving
    // consumer could try is `auditTopBanner` / `auditVisibility` / `locale`.
    // Strict-mode mutation throws; non-strict silently no-ops. Either way,
    // the value MUST not change.
    expect(Object.isFrozen(KVKK_PROFILE)).toBe(true);
    expect(Object.isFrozen(KVKK_PROFILE.forcedTier)).toBe(true);
    try {
      // @ts-expect-error — runtime check that the field is read-only at runtime.
      KVKK_PROFILE.locale = "en";
    } catch {
      // strict-mode TypeError is fine.
    }
    expect(KVKK_PROFILE.locale).toBe("tr");
  });
});

describe("KVKKLockedError + assertNotLocked", () => {
  test("each locked tool throws KVKKLockedError with KVKK article citation", () => {
    // The contract: every locked-tool error cites Madde 6 (özel nitelikli
    // kişisel veri) and bilingually mentions the KVKK profile. The lawyer
    // needs the citation for their bar-association evidence.
    for (const tool of [
      "bash",
      "spawn_session",
      "kill_session",
      "send_to_session",
      "summon_temple",
      "dismiss_temple",
    ]) {
      let caught: unknown = null;
      try {
        assertNotLocked(tool);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(KVKKLockedError);
      const e = caught as KVKKLockedError;
      // KVKK article cited in message.
      expect(e.message).toContain("KVKK");
      expect(e.message).toContain("Madde 6");
      // Bilingual: TR primary, EN translation.
      expect(e.message).toContain("kilitli");
      expect(e.message).toContain("locked");
      // Tool name surfaced (so the audit row is unambiguous).
      expect(e.message).toContain(tool);
      // Article field surfaced for the audit row.
      expect(e.article).toContain("Madde 6");
    }
  });

  test("non-locked tools pass through assertNotLocked without throwing", () => {
    // Read + write-vault tools must NOT trip the locked-set check.
    for (const tool of [
      "get_document",
      "list_documents",
      "search_docs",
      "create_document",
      "update_document",
      "rename_document",
      "save_to_vault",
    ]) {
      expect(() => assertNotLocked(tool)).not.toThrow();
      expect(isLockedTool(tool)).toBe(false);
    }
  });

  test("KVKKLockedError carries the JSON-RPC error code -32003", () => {
    // -32001 is NoApprovalUI, -32002 is PermissionDenied. -32003 is the
    // KVKK policy denial. MCP transport adapters surface this code verbatim.
    const err = new KVKKLockedError("bash");
    expect(err.code).toBe(-32003);
    expect(err.name).toBe("KVKKLockedError");
  });
});

describe("per-doc approval — no cache semantics", () => {
  test("forcedTier.perDocApproval is the signal the gate checks; it is true and cannot be made false", () => {
    // The gate's KVKK branch reads this field. Its value MUST be the literal
    // `true`. A regression that flips it to `false` would silently re-enable
    // the 15m cache — a covert KVKK violation. We pin the type AND the value.
    const policy: typeof KVKK_PROFILE.forcedTier = KVKK_PROFILE.forcedTier;
    expect(policy.perDocApproval).toBe(true);
    // The literal-type lock: TS forbids `policy.perDocApproval = false`.
    // We assert the runtime invariant here as a belt-and-braces check.
    expect((policy as { perDocApproval: boolean }).perDocApproval).toBe(true);
  });

  test("forcedTier.override is the literal false — no path lets the lawyer downgrade a tier", () => {
    expect(KVKK_PROFILE.forcedTier.override).toBe(false);
    // Same belt-and-braces check.
    expect((KVKK_PROFILE.forcedTier as { override: boolean }).override).toBe(false);
  });
});
