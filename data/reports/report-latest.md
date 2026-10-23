# 守（Mamori）脅威レポート — 2026-10-23 09:44 JST

- 取得: 33件 / 要対応: **4件** / 要確認: 0件

## 🆕 直近7日の新着 (9件・2026-10-16以降)
- ・ 2026-10-22 [JPCERT注意喚起] PHPにおける複数の脆弱性（CVE-2026-109618、CVE-2026-109619）に関する注意喚起 (公開) — https://www.jpcert.or.jp/at/2026/at260033.html
- ・ 2026-10-20 [CISA KEV] EG Secure Solutions SiteGuard Server Edition: EG Secure Solutions SiteGuard Server Edition — https://nvd.nist.gov/vuln/detail/CVE-2026-106931
- 🔴 2026-10-20 [CISA KEV] Plex Media Server: Plex Media Server External Control of File Name or Path Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-96656
- 🔴 2026-10-20 [CISA KEV] Plex Media Server: Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-96655
- 🔴 2026-10-20 [CISA KEV] Plex Media Server: Plex Media Server Improper Neutralization of Encoded URI Schemes in a W — https://nvd.nist.gov/vuln/detail/CVE-2026-96654
- 🔴 2026-10-20 [CISA KEV] Plex Media Server: Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-96652
- ・ 2026-10-20 [CISA KEV] Siemens Software Center: Siemens Software Center Uncontrolled Search Path Element Vulnerab — https://nvd.nist.gov/vuln/detail/CVE-2026-110936
- ・ 2026-10-16 [CISA KEV] BeyondTrust Remote Support: BeyondTrust Remote Support Authentication Bypass by Spoofing V — https://nvd.nist.gov/vuln/detail/CVE-2026-102764
- ・ 2026-10-16 [CISA KEV] Fortinet Multiple Products: Fortinet Multiple Products Path Traversal Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2025-61624

## 🔴 要対応 (4件)
### CVE-2026-96656 — Plex Media Server: Plex Media Server External Control of File Name or Path Vulnerability
- [緊急] CVE-2026-96656 は悪用確認済み。CISA対応期限: 2026-10-23
- 【plex】具体的対策:
-   - Plex Media Server のバージョン確認: 設定 → サーバー → 一般 で現在バージョンを確認
-   - 最新版へ更新: https://www.plex.tv/media-server-downloads/ から最新を適用
-   - 外部公開の確認: リモートアクセス（32400番ポート）が不要なら無効化
-   - 参考: Plex セキュリティ情報 https://www.plex.tv/blog/category/security/
- CISA指定の対応（要約）: ベンダーの指示どおりに修正・緩和策を適用。できない場合は製品の使用を止める。期限は米国政府機関向けの目安
-   原文: Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discon
- 一次情報: https://nvd.nist.gov/vuln/detail/CVE-2026-96656

### CVE-2026-96655 — Plex Media Server: Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability
- [緊急] CVE-2026-96655 は悪用確認済み。CISA対応期限: 2026-11-03
- 【plex】具体的対策:
-   - Plex Media Server のバージョン確認: 設定 → サーバー → 一般 で現在バージョンを確認
-   - 最新版へ更新: https://www.plex.tv/media-server-downloads/ から最新を適用
-   - 外部公開の確認: リモートアクセス（32400番ポート）が不要なら無効化
-   - 参考: Plex セキュリティ情報 https://www.plex.tv/blog/category/security/
- CISA指定の対応（要約）: ベンダーの指示どおりに修正・緩和策を適用。できない場合は製品の使用を止める。期限は米国政府機関向けの目安
-   原文: Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discon
- 一次情報: https://nvd.nist.gov/vuln/detail/CVE-2026-96655

### CVE-2026-96654 — Plex Media Server: Plex Media Server Improper Neutralization of Encoded URI Schemes in a Web Page Vulnerability
- [緊急] CVE-2026-96654 は悪用確認済み。CISA対応期限: 2026-10-23
- 【plex】具体的対策:
-   - Plex Media Server のバージョン確認: 設定 → サーバー → 一般 で現在バージョンを確認
-   - 最新版へ更新: https://www.plex.tv/media-server-downloads/ から最新を適用
-   - 外部公開の確認: リモートアクセス（32400番ポート）が不要なら無効化
-   - 参考: Plex セキュリティ情報 https://www.plex.tv/blog/category/security/
- CISA指定の対応（要約）: ベンダーの指示どおりに修正・緩和策を適用。できない場合は製品の使用を止める。期限は米国政府機関向けの目安
-   原文: Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discon
- 一次情報: https://nvd.nist.gov/vuln/detail/CVE-2026-96654

### CVE-2026-96652 — Plex Media Server: Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability
- [緊急] CVE-2026-96652 は悪用確認済み。CISA対応期限: 2026-11-03
- 【plex】具体的対策:
-   - Plex Media Server のバージョン確認: 設定 → サーバー → 一般 で現在バージョンを確認
-   - 最新版へ更新: https://www.plex.tv/media-server-downloads/ から最新を適用
-   - 外部公開の確認: リモートアクセス（32400番ポート）が不要なら無効化
-   - 参考: Plex セキュリティ情報 https://www.plex.tv/blog/category/security/
- CISA指定の対応（要約）: ベンダーの指示どおりに修正・緩和策を適用。できない場合は製品の使用を止める。期限は米国政府機関向けの目安
-   原文: Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discon
- 一次情報: https://nvd.nist.gov/vuln/detail/CVE-2026-96652
