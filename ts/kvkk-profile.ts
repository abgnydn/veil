// SPDX-License-Identifier: Apache-2.0

// KVKK profile — Themis's regulated-domain configuration bundle.
//
// Example is the sibling deployment for Turkish lawyers. Lawyers serving
// Turkish clients carry duties to those clients (KVKK — Kişisel Verilerin
// Korunması Kanunu, the Turkish counterpart to GDPR). This profile is what
// turns Example from a brand skin into a regulated-domain product:
//
//   - A LOCKED-DOWN tool surface: no Bash, no shell escape, no session
//     control, no temple. The only allowed surfaces are read tools and
//     write-vault tools. The lawyer cannot accidentally (or via prompt
//     injection) summon a process that exfiltrates client data.
//   - PER-DOCUMENT approval on every remote LLM call. No 15m cache.
//     Every read of a `private` (or higher) doc fires a fresh modal.
//   - Audit log AS the home page — primary surface, not buried in Settings.
//   - Locale locked to `tr` (the regulator reads Turkish).
//
// Themis owns this profile. She does NOT own the underlying mechanism (Veil
// router, PermissionGate, audit log — those belong to Talos / Hephaestus-
// Backend). She owns the *configuration*: a bundle the runtime can consume.
//
// KVKK references baked into the error / approval-modal copy:
//   - Madde 6 — özel nitelikli kişisel veri (special-category personal data)
//   - Madde 9 — yurt dışına aktarım (cross-border transfer)
//   - Madde 10 — aydınlatma yükümlülüğü (notification obligation)
// Attorney-client privileged content (`Müvekkil-Avukat-Gizli`) almost always
// hits Madde 6 because case files routinely contain health, criminal-record,
// religious-belief, or biometric data of the client.

// ---- Locked-tool error -----------------------------------------------------

/**
 * Thrown by the PermissionGate when a tool that's locked under the KVKK
 * profile is invoked. The error message is bilingual on purpose — the
 * lawyer's regulator (KVKK Kurumu) reads Turkish; the lawyer's defense
 * counsel and any cross-border audit reads English.
 */
export class KVKKLockedError extends Error {
  /** JSON-RPC error code surfaced to MCP callers. -32003 is reserved for
   *  policy denials; matches NoApprovalUI (-32001) / PermissionDenied (-32002)
   *  in the same numeric family. */
  code = -32003;
  /** The article block this denial cites. Always present so the audit row
   *  can record the citation alongside the deny decision. */
  article: string;
  constructor(toolName: string) {
    super(
      `Bu araç KVKK profilinde kilitli — Example avukat hizmeti için. ` +
        `/ This tool is locked in KVKK mode — Example legal-services profile. ` +
        `(tool="${toolName}", KVKK Madde 6 / Articles 9–10)`,
    );
    this.name = "KVKKLockedError";
    this.article = "KVKK Madde 6 / Articles 9–10";
  }
}

// ---- Profile shape ---------------------------------------------------------

/** Audit-log surface placement. KVKK requires it visible at the top level. */
export type AuditVisibility = "home" | "settings" | "hidden";

/** Locale lock — Example is Turkish-only by regulation. */
export type KVKKLocale = "tr";

/**
 * Forced-tier policy. The lawyer cannot mark a Müvekkil-Avukat-Gizli doc as
 * `public` to dodge the modal — `override: false` makes the storage layer
 * refuse the downgrade, and `perDocApproval: true` makes the gate prompt
 * fresh on every read.
 */
export interface ForcedTierPolicy {
  /**
   * Always `false` under KVKK. Storage-layer refuses any attempt to override
   * an inferred tier downward. (E.g. the classifier says `private`; the user
   * cannot set `frontmatter.tier = public`.)
   */
  override: false;
  /**
   * Always `true` under KVKK. Every read of a `private` (or higher) tier doc
   * fires a fresh approval modal — no 15m cache, no "trust this kind of
   * thing" override.
   */
  perDocApproval: true;
}

/**
 * The complete KVKK configuration bundle. Consumed by:
 *   - `apps/mcp/src/permission.ts` — checks `lockedTools`, skips cache.
 *   - `packages/veil/router.ts`     — refuses remote dispatch without approval.
 *   - `apps/web/src/routes/App.tsx` — locks locale, embeds audit.
 */
export interface KVKKProfile {
  /**
   * The OPPOSITE of an allowlist: tools BLOCKED under this profile. Read
   * tools and write-vault tools stay allowed (their absence from this set is
   * the signal). Everything that can shell-escape, control sessions, or
   * spawn arbitrary processes is in here.
   */
  lockedTools: Set<string>;
  /** Tier-routing override + per-doc approval policy. */
  forcedTier: ForcedTierPolicy;
  /** Where the audit log surfaces. KVKK requires `'home'`. */
  auditVisibility: AuditVisibility;
  /** Locale lock. Always `'tr'` under KVKK; not user-overridable. */
  locale: KVKKLocale;
  /** When true, the topbar shows audit-row count + last-action timestamp. */
  auditTopBanner: boolean;
}

// ---- The singleton ---------------------------------------------------------

/**
 * The locked tools, frozen at module load. Includes:
 *   - `bash` — arbitrary shell. Hard-blocked: a single Bash call could
 *     `cat ~/brain/...` and pipe to a remote endpoint.
 *   - `spawn_session`, `kill_session`, `send_to_session` — tmux-like session
 *     control. A spawned session is an unmonitored channel; KVKK forbids it.
 *   - `summon_temple`, `dismiss_temple` — sub-agent control. The temple can
 *     itself run tools; the lawyer cannot delegate consent.
 *
 * Read tools (list_documents, get_document, search_docs, …) and write-vault
 * tools (create_document, update_document, …) are NOT in this set. They go
 * through the standard PermissionGate, with the KVKK overrides applied
 * (per-doc approval, no cache).
 */
const LOCKED_TOOLS: ReadonlySet<string> = new Set([
  "bash",
  "spawn_session",
  "kill_session",
  "send_to_session",
  "summon_temple",
  "dismiss_temple",
]);

/**
 * The default KVKK profile. Frozen — callers MUST NOT mutate it. The Set is
 * also frozen-by-construction: tests verify the shape, but the runtime never
 * exposes a mutator.
 *
 * Re-exported from `packages/veil/index.ts`. Consume via:
 *
 *   import { KVKK_PROFILE } from "@abgnydn/veil";
 *   if (KVKK_PROFILE.lockedTools.has(toolName)) throw new KVKKLockedError(toolName);
 */
export const KVKK_PROFILE: Readonly<KVKKProfile> = Object.freeze({
  lockedTools: LOCKED_TOOLS as Set<string>,
  forcedTier: Object.freeze({
    override: false as const,
    perDocApproval: true as const,
  }),
  auditVisibility: "home" as const,
  locale: "tr" as const,
  auditTopBanner: true,
});

// ---- Helpers ---------------------------------------------------------------

/**
 * Returns true if the named tool is locked under the KVKK profile. Cheap;
 * the gate calls this on every dispatch.
 */
export function isLockedTool(toolName: string): boolean {
  return KVKK_PROFILE.lockedTools.has(toolName);
}

/**
 * Throws KVKKLockedError if the tool is locked. Convenience wrapper for the
 * gate's KVKKMode branch. Returns void on pass-through.
 */
export function assertNotLocked(toolName: string): void {
  if (isLockedTool(toolName)) {
    throw new KVKKLockedError(toolName);
  }
}
