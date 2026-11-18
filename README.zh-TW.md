# Certower

**自架的 TLS 憑證中控塔台。** 找出你所有正在使用的憑證，透過 ACME 向任何 CA
簽發與續期，並自動部署到伺服器與網路設備，同時提供多租戶權限控管。

[English](README.md)

> 狀態：早期開發中，尚不適合正式環境使用。

## 為什麼需要

公開 TLS 憑證的效期正在縮短：2026 年 3 月起 200 天、2027 年 3 月起 100 天、
2029 年 3 月起只剩 47 天。人工換憑證跟不上這個速度。Certower 將整個生命週期
自動化，無法自動化的部分也會清楚列出。

## 功能（v0.1 規劃）

- **探索**：掃描端點，找出未納管的憑證，並標示即將到期、弱金鑰、效期超過上限，
  以及瀏覽器已不信任的根憑證（例如 2025/7/31 之後簽發的中華電信憑證）。
- **支援任何 ACME CA**：Let's Encrypt、ZeroSSL、Google Trust Services、
  Sectigo、GlobalSign、DigiCert、TWCA 等，支援 EAB。DNS-01 驗證支援 150 多家 DNS 供應商。
- **私鑰不離開主機的 Agent**：私鑰在主機上產生且不會外傳；每次部署都會檢查線上
  端點，失敗自動回滾。
- **組織、專案與角色**：可依網域、CA、金鑰類型設定 Policy 護欄，支援 OIDC
  單一登入與稽核日誌。
- **插件**：Issuer、DNS、Deployer、Notifier 皆可擴充。

## 文件

- [架構](docs/architecture.md)
- [REST API](docs/api.md)
- [資料模型](docs/data-model.md)
- [CA 支援狀況](docs/ca-support.md)
- [簽發測試](docs/testing-issuance.md)：Pebble 自動化測試，以及用 Cloudflare DNS 實測 Let's Encrypt

## 授權

[GNU Affero General Public License v3.0](LICENSE)。
