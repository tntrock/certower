# Certower 管理員手冊

[English](../admin-guide.md) | 繁體中文 | [简体中文](../zh-CN/admin-guide.md)

本手冊寫給負責安裝與維運 Certower 的人，內容涵蓋安裝、設定、安全強化、備份、升級與疑難排解。日常操作（申請憑證、部署、憑證探索）請看[使用者手冊](user-guide.md)。

> Certower 仍在早期開發階段。歡迎試用，但目前還不建議把正式環境的憑證完全交給它。

- [架構概觀](#架構概觀)
- [系統需求](#系統需求)
- [安裝](#安裝)
- [安裝後的第一步](#安裝後的第一步)
- [設定參考](#設定參考)
- [HTTPS 與反向代理](#https-與反向代理)
- [資料庫](#資料庫)
- [金鑰加密金鑰 KEK](#金鑰加密金鑰-kek)
- [備份與還原](#備份與還原)
- [升級](#升級)
- [使用者與權限](#使用者與權限)
- [安裝 Agent](#安裝-agent)
- [監控與日誌](#監控與日誌)
- [安全檢查清單](#安全檢查清單)
- [疑難排解](#疑難排解)
- [解除安裝](#解除安裝)

## 架構概觀

```
             瀏覽器、API 用戶端                          你主機上的 Agent
                     │ HTTPS（經過你的反向代理）               │ 雙向 TLS，由 Agent 主動連出
                     ▼                                         ▼
          ┌──────────────────── certower serve ───────────────────────┐
          │ Web 介面 + REST API :8080          Agent API :8443         │
          │ 簽發引擎、排程、憑證探索掃描、通知                          │
          └──────┬───────────────────────────┬────────────────────────┘
                 │                           │
        SQLite 或 PostgreSQL         certower.kek（加密所有保存的
        （所有狀態資料）               私鑰與憑據）
                 │
                 └──► ACME CA、DNS 供應商、Webhook、SMTP（皆為對外連線）
```

- **伺服器**（`certower`）：單一程式，包含 Web 介面、API，以及負責簽發、續期、掃描、通知的背景引擎。
- **Agent**（`certower-agent`，選用）：安裝在實際使用憑證的主機上。私鑰在該主機產生、不會離開，並負責把憑證安裝到 nginx 等服務。Agent 主動連線到伺服器，伺服器不會連進 Agent。
- **資料庫**：SQLite（單一檔案，多數情況已足夠）或 PostgreSQL。
- **金鑰加密金鑰（KEK）**：一個檔案，用來加密資料庫中保存的所有私鑰與憑據，詳見[下文](#金鑰加密金鑰-kek)。

## 系統需求

| 項目 | 需求 |
|---|---|
| 作業系統 | Linux（amd64、arm64）、Windows Server 2019 以上／Windows 10 以上（amd64），或任何容器執行環境。另有 macOS 版本供測試。 |
| CPU／記憶體 | 1 vCPU、256 MB 就足以管理數千張憑證。 |
| 磁碟 | 多數情況不到 1 GB。 |
| 對內連線 | 8080（Web 介面與 API，前面請加 HTTPS）。8443（Agent API）只有使用 Agent 時才需要。 |
| 對外連線 | 連到 CA 與 DNS 供應商 API 的 HTTPS；查詢 DNS-01 紀錄用的 DNS（53）；SMTP 伺服器或 Webhook；要掃描的端點。 |

## 安裝

以下方式擇一即可，執行的是同一套程式。

### 容器（Docker、Podman、Kubernetes）

```sh
docker run -d --name certower --restart unless-stopped \
  -p 8080:8080 -p 8443:8443 \
  -v certower-data:/data \
  -e CERTOWER_AGENT_URL=https://certower.example.com:8443 \
  ghcr.io/tntrock/certower:latest

docker exec certower certower bootstrap -email you@example.com
```

映像檔採用 distroless（沒有 shell），以非特權使用者（UID 65532）執行，資料庫與 KEK 存放在 `/data` volume。提供 `linux/amd64` 與 `linux/arm64`，標籤有版本號（`0.1.0`、`0.1`）與 `latest`。正式環境請固定版本號。

Docker Compose 範例在 [`deploy/`](../../deploy)：[`docker-compose.yml`](../../deploy/docker-compose.yml)（SQLite）與 [`docker-compose.postgres.yml`](../../deploy/docker-compose.postgres.yml)。

### Debian、Ubuntu、RHEL、Rocky、Fedora

從 [Releases 頁面](https://github.com/tntrock/certower/releases)下載對應架構的 `.deb` 或 `.rpm`：

```sh
sudo apt install ./certower_0.1.0_amd64.deb      # Debian、Ubuntu
sudo dnf install ./certower_0.1.0_amd64.rpm      # RHEL、Rocky、Fedora

sudo -u certower certower bootstrap -config /etc/certower/certower.env -email you@example.com
```

套件會建立 `certower` 系統帳號，安裝經過強化的 systemd 服務並啟動。

| 路徑 | 用途 |
|---|---|
| `/usr/bin/certower` | 主程式 |
| `/etc/certower/certower.env` | 設定檔（擁有者 `root:certower`，權限 0640） |
| `/var/lib/certower/` | 資料庫與 KEK（權限 0750） |
| `certower.service` | `systemctl status certower`；日誌用 `journalctl -u certower` 查看 |

### Windows

從 Releases 頁面下載 `certower_<版本>_windows_amd64.msi` 直接執行，或用靜默安裝：

```powershell
msiexec /i certower_0.1.0_windows_amd64.msi /qn
& "C:\Program Files\Certower\certower.exe" bootstrap -config C:\ProgramData\Certower\certower.env -email you@example.com
```

安裝程式會：

- 安裝 `C:\Program Files\Certower\certower.exe`，並加入 `PATH`；
- 建立只有 SYSTEM 與 Administrators 能存取的 `C:\ProgramData\Certower\`，裡面放 `certower.env`（設定檔）、資料庫、KEK 與 `certower.log`；
- 註冊並啟動 **Certower** 服務（自動啟動，異常結束時會自動重啟）。

修改 `certower.env` 後執行 `Restart-Service Certower`。若其他電腦需要連線，請在 Windows 防火牆開放連接埠：

```powershell
New-NetFirewallRule -DisplayName "Certower" -Direction Inbound -Protocol TCP -LocalPort 8080,8443 -Action Allow
```

### 直接使用執行檔

Releases 頁面有 Linux、Windows、macOS 的壓縮檔。在要存放資料的目錄執行 `certower serve`，或用 `-config` 指定設定檔。下載後可用 `checksums.txt` 驗證，或用 GitHub 的建置來源證明（build provenance）驗證：

```sh
gh attestation verify certower_0.1.0_linux_amd64.tar.gz --repo tntrock/certower
```

### 從原始碼建置

需要 Go 1.26 以上與 Node.js 22 以上：

```sh
git clone https://github.com/tntrock/certower && cd certower
(cd web && npm ci && npm run build)
go build -o bin/ ./cmd/...
```

## 安裝後的第一步

1. 用 `certower bootstrap -email ...` **建立第一位管理員**（指令見上文），密碼只會顯示一次。
2. 開啟 `http://<伺服器>:8080` 登入，並在側邊欄點 **變更密碼** 換掉初始密碼。
3. **建立組織**（只有系統管理員可以），並在組織內建立**專案**。
4. 開通帳號：到 **使用者** 頁新增帳號（或設定[單一登入](../authentication.md)），再到 **成員** 頁授予角色。
5. 依照[使用者手冊](user-guide.md#快速開始)新增 CA 與 DNS 供應商，申請第一張憑證。
6. 正式使用前：[加上 HTTPS](#https-與反向代理)，並[備份 KEK](#金鑰加密金鑰-kek)。

## 設定參考

每個設定都可以用命令列參數或環境變數指定。設定檔（`-config <檔案>` 或 `CERTOWER_CONFIG=<檔案>`）內容是同樣變數的 `KEY=VALUE` 行，Linux 與 Windows 安裝套件都使用設定檔。優先順序：命令列參數 > 環境變數 > 設定檔。

| 環境變數 | 參數 | 預設值 | 說明 |
|---|---|---|---|
| `CERTOWER_DB` | `-db` | `sqlite:certower.db` | `sqlite:<路徑>` 或 `postgres://user:pass@host/db?sslmode=...` |
| `CERTOWER_KEK_FILE` | `-kek-file` | `certower.kek` | 金鑰加密金鑰檔案，不存在時自動建立 |
| `CERTOWER_LISTEN` | `-listen` | `:8080` | Web 介面與 API 的監聽位址 |
| `CERTOWER_AGENT_LISTEN` | `-agent-listen` | `:8443` | Agent API 位址；設為空值則停用 Agent |
| `CERTOWER_AGENT_URL` | `-agent-url` | `https://<主機名稱>:8443` | Agent 連線用的 Agent API 網址（會顯示在註冊指令中） |
| `CERTOWER_PUBLIC_URL` | `-public-url` | | 對外的 Web 網址，用於通知中的連結與 SSO 回呼 |
| `CERTOWER_SECURE_COOKIES` | `-secure-cookies` | `false` | 為登入 Cookie 加上 Secure；使用 HTTPS 時請設為 `true` |
| `CERTOWER_TRUSTED_PROXIES` | `-trusted-proxies` | | 信任其 `X-Forwarded-For` 標頭的反向代理（IP 或 CIDR） |
| `CERTOWER_LOG_FILE` | `-log-file` | 標準錯誤輸出 | 把日誌附加寫入檔案（Windows 服務使用） |
| `CERTOWER_DNS_RESOLVERS` | `-dns-resolvers` | 系統設定 | 檢查 DNS-01 紀錄用的 DNS 伺服器，例如 `1.1.1.1,8.8.8.8` |
| `CERTOWER_DNS_CHECK` | `-dns-check` | `auto` | `auto`、`authoritative` 或 `recursive` |
| | `-workers` | `4` | 同時執行的背景工作數 |
| | `-discovery-allow-link-local` | `false` | 允許憑證探索掃描 169.254.0.0/16（預設關閉，避免被用來探測雲端 metadata） |
| `CERTOWER_OIDC_*` | `-oidc-*` | | 單一登入，見[登入與驗證](../authentication.md) |

完整清單請執行 `certower serve -h`。Agent 的設定見 [Agent 說明](../agent.md)。

## HTTPS 與反向代理

Certower 在 8080 提供的是 HTTP，前面需要有人處理 TLS。請放一台反向代理，並設定：

```sh
CERTOWER_PUBLIC_URL=https://certower.example.com
CERTOWER_SECURE_COOKIES=true
CERTOWER_TRUSTED_PROXIES=127.0.0.1     # Certower 看到的反向代理位址
```

nginx 範例：

```nginx
server {
    listen 443 ssl;
    server_name certower.example.com;
    ssl_certificate     /etc/certower/certs/certower.example.com/fullchain.pem;
    ssl_certificate_key /etc/certower/certs/certower.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Caddy 只要一行：`certower.example.com { reverse_proxy 127.0.0.1:8080 }`。

**不要讓 Agent 的連接埠（8443）經過會終止 TLS 的反向代理。** Agent 使用 Certower 自己的 Agent CA 簽發的用戶端憑證做雙向 TLS 驗證，連線必須直接到達 Certower，或只經過 TCP（第 4 層）轉送。Agent 是用註冊指令中的 CA 指紋來確認伺服器身分，而不是公開憑證。

Certower 可以替自己的反向代理簽發憑證，但請保留一條萬一該憑證失效時仍能連進去的路。

`CERTOWER_TRUSTED_PROXIES` 會影響稽核日誌與登入失敗次數限制：沒設定時，所有請求看起來都來自反向代理，一個攻擊者的錯誤嘗試就可能讓所有人都被擋住。

## 資料庫

**SQLite**（預設）不需要其他元件，單一伺服器管理數千張憑證沒有問題。資料庫請放在本機磁碟，不要放在網路磁碟上。

**PostgreSQL 15 以上** 適合已經在維運 PostgreSQL、需要託管備份，或要執行多個 Certower 程序的情況：

```sh
CERTOWER_DB=postgres://certower:密碼@db.example.com:5432/certower?sslmode=verify-full
```

密碼中的特殊字元要做 URL 編碼（`@` 寫成 `%40`、`/` 寫成 `%2F`）。只需建立資料庫與擁有者角色，資料表由 Certower 自行建立。

資料庫結構的遷移會在啟動時自動執行，不需要手動跑遷移工具。目前不支援在 SQLite 與 PostgreSQL 之間搬移資料，請在開始使用前決定。

## 金鑰加密金鑰 KEK

所有私鑰與憑據（CA 帳號金鑰、EAB 密鑰、DNS API token、Webhook 網址、SMTP 密碼）都以加密形式存在資料庫，而這些加密用的金鑰又由 `certower.kek` 這把 KEK 加密。

- **務必備份**，而且要和資料庫備份分開存放，放在只有管理員能讀取的地方（密碼管理器或機密管理系統）。
- **一旦遺失**，加密的資料就無法還原。憑證、設定與歷史紀錄都還在，但所有憑據都要重新輸入，私鑰保存在伺服器上的憑證也必須重新簽發。
- **若與資料庫複本一起外洩**，所有保存的機密都等同公開，請更換 CA、DNS 與通知相關的所有憑據。
- 這個檔案在第一次啟動時建立，Linux 上權限為 0600；Windows 安裝程式則放在受保護的資料夾中。

## 備份與還原

要備份的是**資料庫**與 **KEK**。Agent 的私鑰保存在各自的主機上，伺服器端不需要備份。

**SQLite**：Certower 執行中直接複製檔案可能得到不一致的副本。請先短暫停止服務：

```sh
sudo systemctl stop certower
sudo cp -a /var/lib/certower/certower.db /backup/certower-$(date +%F).db
sudo systemctl start certower
```

或使用檔案系統／磁碟區快照。容器環境請先停止容器，再備份 volume（`docker run --rm -v certower-data:/data -v $PWD:/b alpine tar czf /b/certower.tgz -C /data .`）。

**PostgreSQL**：執行中直接 `pg_dump -Fc certower > certower.dump` 即可。

**還原**：停止 Certower，放回資料庫與**對應的** KEK，再啟動。沒有對應 KEK 的資料庫無法解開其中的機密。

## 升級

1. 先閱讀版本說明（release notes）。
2. 備份資料庫與 KEK。
3. 升級：
   - 容器：`docker pull ghcr.io/tntrock/certower:<版本>`，用同一個 volume 重建容器。
   - 套件：安裝新的 `.deb`／`.rpm`，服務會自動重新啟動。
   - Windows：執行新版 `.msi`，會取代舊版並保留 `C:\ProgramData\Certower`。
4. 遷移會在啟動時執行。用 `certower version` 與日誌確認結果。

新版遷移過資料庫後就不支援降版，需要退回時請還原備份。

## 使用者與權限

**系統管理員**（由 `bootstrap` 建立，或在 **使用者** 頁設定）可以建立組織與管理帳號。在組織內能做什麼仍取決於角色，不過系統管理員可以替自己授予任何角色。

系統管理員在 **使用者** 頁（側邊欄「系統管理」區）可以：

- 新增密碼帳號（對話框會建議一組強密碼）；
- 重設密碼、停用或重新啟用帳號、設定或取消系統管理員。停用或重設密碼會讓該使用者在所有裝置上登出。不能停用自己，也不能取消自己的系統管理員權限。

使用者可以從側邊欄自行變更密碼。密碼至少 12 個字元，以 Argon2id 儲存。15 分鐘內同一帳號登入失敗 10 次會暫時封鎖該帳號，同一來源位址失敗 30 次則封鎖該位址。

**單一登入**：支援 Google、Microsoft Entra ID、Okta、Keycloak 以及任何 OpenID Connect 身分提供者，見[登入與驗證](../authentication.md)。設定 `CERTOWER_OIDC_AUTO_CREATE=true` 可在第一次登入時自動建立帳號；也可以把角色授予身分提供者的群組，讓權限跟著公司的目錄服務走。

角色以組織或專案為單位授予，見[使用者手冊](user-guide.md#角色)。自動化作業請使用**服務帳號**搭配 API token，透過 [API](../api.md) 建立。

## 安裝 Agent

只有在私鑰必須留在主機上（或需要自動部署）時才需要 Agent。伺服器端請確認那些主機能連到 8443，且 `CERTOWER_AGENT_URL` 是它們實際使用的位址。

在介面中開啟專案的 **Agent 與部署目標** 頁，點 **新增 Agent**，畫面會顯示含一次性 token 的註冊指令。在主機上：

**Debian/Ubuntu/RHEL**：

```sh
sudo apt install ./certower-agent_0.1.0_amd64.deb     # 或 dnf install ...rpm
sudo certower-agent enroll -server https://certower.example.com:8443 -token cwe_... -ca-sha256 ...
sudo systemctl start certower-agent
```

**Windows**：

```powershell
msiexec /i certower-agent_0.1.0_windows_amd64.msi /qn
certower-agent enroll -server https://certower.example.com:8443 -token cwe_... -ca-sha256 ...
Set-Service CertowerAgent -StartupType Automatic; Start-Service CertowerAgent
```

啟動前請先檢查狀態目錄（`/var/lib/certower-agent` 或 `C:\ProgramData\Certower\agent`）中的 `agent.json`：裡面列出 Agent 可以寫入的目錄與可以執行的指令，伺服器無法要求 Agent 做清單以外的事。部署方式與安全模型的細節見 [Agent 說明](../agent.md)。

## 監控與日誌

- **健康檢查**：`GET /healthz` 回傳 `ok`。`certower healthcheck` 可檢查本機伺服器（容器映像檔就是用它）。
- **日誌**：`journalctl -u certower`、`docker logs certower`，Windows 上是 `C:\ProgramData\Certower\certower.log`。登入失敗、工作重試、簽發錯誤會以 WARN 等級記錄。
- **通知**：新增通知管道（Email，或 Webhook 送到 Slack、Mattermost、Google Chat、Discord），訂閱 `cert.issue_failed`、`cert.expiring`、`cert.deploy_failed`，確保失敗時有人收到。見[通知](../discovery-and-notifications.md#notifications)。
- 每個專案的 **工作佇列** 頁可以看到重試狀況與錯誤。
- **稽核日誌** 記錄每一筆變更：誰、何時、從哪裡。

## 安全檢查清單

- [ ] Web 介面前有 HTTPS，已設定 `CERTOWER_SECURE_COOKIES=true` 與 `CERTOWER_PUBLIC_URL`。
- [ ] `CERTOWER_TRUSTED_PROXIES` 只列出你自己的反向代理。
- [ ] 8080 沒有直接暴露在網際網路上；8443 只開放給 Agent 所在的網段。
- [ ] KEK 已備份，且與資料庫備份分開存放。
- [ ] 已更換 bootstrap 產生的密碼；系統管理員人數盡量少。
- [ ] 若使用單一登入，已設定 `-oidc-allowed-domains`。
- [ ] 已設定失敗與到期通知。
- [ ] 每台主機上 Agent 的 `allowedPaths` 與 `allowedCommands` 都已檢查過。
- [ ] 下載的版本已用 checksum 或 `gh attestation verify` 驗證。
- [ ] 已訂閱[安全性公告](https://github.com/tntrock/certower/security/advisories)（Watch → Custom → Security alerts）。

## 疑難排解

| 症狀 | 檢查項目 |
|---|---|
| 服務無法啟動 | 查看日誌（見上文）。常見原因：連接埠被占用、資料庫路徑無法寫入、`certower.env` 無法讀取。 |
| 出現「value was sealed with key ..., but key ... is loaded」或「decryption failed」 | KEK 與資料庫不對應。請放回對應的 `certower.kek`。 |
| 簽發一直是「失敗重試中」，錯誤與 DNS 有關 | 檢查 DNS 供應商 token 的權限（Cloudflare 需要該 zone 的 Zone:Read 與 DNS:Edit）。若伺服器連不到權威 DNS 伺服器，把 `CERTOWER_DNS_RESOLVERS` 設為能連到的解析器，或設定 `CERTOWER_DNS_CHECK=recursive`。 |
| Let's Encrypt 回報「rateLimited」 | 先用「Let's Encrypt (staging)」測試；正式環境的頻率限制以網域、每週計算。 |
| 登入時顯示失敗次數過多 | 等 15 分鐘，或請管理員重設密碼。若在反向代理後面，檢查 `CERTOWER_TRUSTED_PROXIES`。 |
| 登入頁顯示 SSO 錯誤 | 訊息會說明原因，見[登入與驗證](../authentication.md#how-sign-in-maps-to-accounts)。 |
| Agent 顯示「離線」 | 在主機上查看 `journalctl -u certower-agent` 或 `agent.log`。主機能否連到 `CERTOWER_AGENT_URL`？8443 是否沒有經過 TLS 終止？ |
| 部署「失敗」 | 憑證頁面會顯示 Agent 回報的訊息，例如 `nginx -t` 的輸出，或路徑不在 `allowedPaths` 內。 |

問題與錯誤回報請到 [GitHub Issues](https://github.com/tntrock/certower/issues)；安全漏洞請依 [SECURITY.md](../../SECURITY.md) 私下回報。

## 解除安裝

- 容器：`docker rm -f certower`；確定不再需要時才刪除 volume。
- 套件：`sudo apt remove certower`／`sudo dnf remove certower`。`/var/lib/certower` 與 `/etc/certower` 會保留，需要時請自行刪除。
- Windows：「設定 → 應用程式 → Certower Server → 解除安裝」，或 `msiexec /x certower_0.1.0_windows_amd64.msi /qn`。`C:\ProgramData\Certower` 會保留。

解除安裝不會撤銷憑證，憑證在到期前仍然有效。
