// SPDX-License-Identifier: Apache-2.0

// kvkk-controller-config — Example canonical KVKK Madde 11(c) declarations.
//
// What this is
// ============
//
// KVKK Madde 11(c) gives the data subject the right to obtain
// information about the PURPOSES of processing, the DATA CATEGORIES,
// the THIRD-PARTY RECIPIENTS the controller transfers data to, and the
// retention period — i.e. the controller-LEVEL declarations the data
// controller (Example, operated by the lawyer) must publish.
//
// These values are NOT per-subject. They describe how Example, as
// the data controller, processes Turkish-lawyer-client data in
// general. They live in code because v1 ships them as a static config
// the SAR PDF formatter renders verbatim. A future settings stream
// (Hephaestus or Themis-2) will let the lawyer override per-firm fields
// — bar association code, registered office address, retention period
// (some bars require 5y, some 10y depending on matter type) — but the
// shape stays the same.
//
// Madde 5 references on each processing purpose
// =============================================
//
// Each `ProcessingPurpose.legal_basis` cites a KVKK Madde 5 sub-clause:
//   - 5/2/a — açık rıza (explicit consent)
//   - 5/2/c — sözleşmenin ifası (performance of a contract)
//   - 5/2/ç — hukuki yükümlülük (legal obligation, e.g. bar reporting)
//   - 5/2/e — bir hakkın tesisi, kullanılması veya korunması
//             (establishment, exercise, or defence of a legal right —
//              the catchall for litigation prep)
//   - 5/2/f — meşru menfaat (legitimate interest, balanced against the
//             subject's fundamental rights)
//
// The defence-of-a-legal-right clause (5/2/e) is the load-bearing one
// for legal-tech: a lawyer holding case files about a client is
// processing personal data for the establishment / exercise / defence
// of the client's legal right. KVKK explicitly carves this out as a
// lawful basis NOT requiring explicit consent — which is what makes a
// litigation SaaS legally viable in TR at all.

import type { ProcessingPurpose } from "./kvkk-sar";

// ---- Public shape ---------------------------------------------------------

/**
 * The set of controller-level declarations Example ships with by
 * default. The SAR engine inlines these into every `SARRecord`; the
 * SAR PDF formatter renders them verbatim in Sections 3-6.
 */
export interface KVKKControllerConfig {
  /** The processing-purpose set, each with KVKK Madde 5 legal basis. */
  processing_purposes: ProcessingPurpose[];
  /** The categories of personal data the controller processes. */
  data_categories: string[];
  /**
   * Third-party recipients the controller transfers data TO. NOT
   * dynamically discovered — this is the static, declared set.
   */
  third_party_recipients: string[];
  /** The retention period applied to subject data. */
  retention_period: string;
  /** The data controller's contact block for the SAR cover sheet. */
  controller_contact: {
    name: string;
    email: string;
    address: string;
  };
}

// ---- The Example defaults ----------------------------------------------

/**
 * The default config Example ships with. Bilingual where it makes
 * sense; Madde 5 refs are stable identifiers (not localized).
 */
export const EXAMPLE_CONTROLLER_CONFIG: KVKKControllerConfig = {
  processing_purposes: [
    {
      purpose: "case_preparation",
      legal_basis: "KVKK Madde 5/2/e — bir hakkın tesisi/kullanılması/korunması",
      retention: "Vekalet süresi + 5 yıl / Duration of representation + 5 years",
    },
    {
      purpose: "client_correspondence",
      legal_basis: "KVKK Madde 5/2/c — sözleşmenin ifası",
      retention: "Vekalet süresi + 5 yıl / Duration of representation + 5 years",
    },
    {
      purpose: "billing_and_invoicing",
      legal_basis: "KVKK Madde 5/2/ç — hukuki yükümlülük (VUK 253)",
      retention: "10 yıl (VUK) / 10 years (Tax Procedure Law)",
    },
    {
      purpose: "uyap_filing",
      legal_basis: "KVKK Madde 5/2/ç — hukuki yükümlülük (HMK)",
      retention: "Dosyanın kesinleşmesi + 30 yıl / Case finality + 30 years",
    },
    {
      purpose: "bar_association_reporting",
      legal_basis: "KVKK Madde 5/2/ç — hukuki yükümlülük (Avukatlık K. 65)",
      retention: "Yıllık raporlama döngüsü / Annual reporting cycle",
    },
  ],
  data_categories: [
    "Kimlik verileri / Identity data (TC, ad-soyad)",
    "İletişim verileri / Contact data (email, telefon, adres)",
    "Dava dosyası içeriği / Matter file content (notlar, dilekçeler)",
    "Vekalet kayıtları / Power-of-attorney records",
    "Müvekkil yazışmaları / Client correspondence",
    "Faturalama verileri / Billing data",
  ],
  third_party_recipients: [
    "UYAP (Ulusal Yargı Ağı Bilişim Sistemi) — yargısal sunum",
    "Türkiye Barolar Birliği / Bolu Barosu — meslek denetimi",
    "Vergi dairesi / Tax authority — VUK uyumu",
    "Aktarım yapılmaz: bulut sağlayıcı yok (yerel-öncelikli mimari)",
  ],
  retention_period:
    "Vekalet süresi + 5 yıl (genel kural) — UYAP dosyaları için 30 yıla kadar uzayabilir.\nDuration of representation + 5 years (general rule) — UYAP-filed matters extend to 30 years.",
  controller_contact: {
    name: "Example — [Avukat adı ayarlardan / Lawyer name from settings]",
    email: "kvkk@example.com",
    address:
      "[Avukat ofis adresi ayarlardan / Lawyer office address from settings]",
  },
};
