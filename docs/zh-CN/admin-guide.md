# Certower 管理员手册

[English](../admin-guide.md) | [繁體中文](../zh-TW/admin-guide.md) | 简体中文

本手册面向负责安装和运维 Certower 的人员，内容包括安装、配置、安全加固、备份、升级和故障排查。日常使用（申请证书、部署、证书发现）请参阅[用户手册](user-guide.md)。

> Certower 目前处于早期开发阶段。欢迎试用，但暂不建议将生产环境的证书完全交给它管理。

- [整体架构](#整体架构)
- [系统要求](#系统要求)
- [安装](#安装)
- [安装后的第一步](#安装后的第一步)
- [配置参考](#配置参考)
- [HTTPS 与反向代理](#https-与反向代理)
- [数据库](#数据库)
- [密钥加密密钥 KEK](#密钥加密密钥-kek)
- [备份与恢复](#备份与恢复)
- [升级](#升级)
- [用户与权限](#用户与权限)
- [安装 Agent](#安装-agent)
- [监控与日志](#监控与日志)
- [安全检查清单](#安全检查清单)
- [故障排查](#故障排查)
- [卸载](#卸载)

## 整体架构

```
             浏览器、API 客户端                          您主机上的 Agent
                     │ HTTPS（经由您的反向代理）               │ 双向 TLS，由 Agent 主动连出
                     ▼                                         ▼
          ┌──────────────────── certower serve ───────────────────────┐
          │ Web 界面 + REST API :8080          Agent API :8443         │
          │ 签发引擎、调度、证书发现扫描、通知                          │
          └──────┬───────────────────────────┬────────────────────────┘
                 │                           │
        SQLite 或 PostgreSQL         certower.kek（加密所有已存储的
        （全部状态数据）               私钥和凭据）
                 │
                 └──► ACME CA、DNS 服务商、Webhook、SMTP（均为出站连接）
```

- **服务器**（`certower`）：单个进程，包含 Web 界面、API，以及负责签发、续期、扫描和通知的后台引擎。
- **Agent**（`certower-agent`，可选）：部署在实际使用证书的主机上。私钥在该主机上生成，不会离开主机，并负责把证书安装到 nginx 等服务中。Agent 主动连接服务器，服务器不会连入 Agent。
- **数据库**：SQLite（单个文件，大多数场景已足够）或 PostgreSQL。
- **密钥加密密钥（KEK）**：一个文件，用于加密数据库中存储的所有私钥和凭据，详见[下文](#密钥加密密钥-kek)。

## 系统要求

| 项目 | 要求 |
|---|---|
| 操作系统 | Linux（amd64、arm64）、Windows Server 2019 及以上／Windows 10 及以上（amd64），或任意容器运行环境。另提供 macOS 版本供测试使用。 |
| CPU／内存 | 1 vCPU、256 MB 即可管理数千张证书。 |
| 磁盘 | 大多数场景不超过 1 GB。 |
| 入站 | 8080（Web 界面和 API，前面请加 HTTPS）。8443（Agent API）仅在使用 Agent 时需要。 |
| 出站 | 访问 CA 和 DNS 服务商 API 的 HTTPS；用于检查 DNS-01 记录的 DNS（53）；SMTP 服务器或 Webhook；需要扫描的端点。 |

## 安装

以下方式任选其一，运行的是同一个程序。

### 容器（Docker、Podman、Kubernetes）

```sh
docker run -d --name certower --restart unless-stopped \
  -p 8080:8080 -p 8443:8443 \
  -v certower-data:/data \
  -e CERTOWER_AGENT_URL=https://certower.example.com:8443 \
  ghcr.io/tntrock/certower:latest

docker exec certower certower bootstrap -email you@example.com
```

镜像基于 distroless（不含 shell），以非特权用户（UID 65532）运行，数据库和 KEK 保存在 `/data` 卷中。提供 `linux/amd64` 和 `linux/arm64`，标签包括版本号（`0.1.0`、`0.1`）和 `latest`。生产环境请固定版本号。

Docker Compose 示例位于 [`deploy/`](../../deploy)：[`docker-compose.yml`](../../deploy/docker-compose.yml)（SQLite）和 [`docker-compose.postgres.yml`](../../deploy/docker-compose.postgres.yml)。

如果访问 ghcr.io 较慢，可以先在能访问的环境中拉取镜像，再导入私有镜像仓库。

### Debian、Ubuntu、RHEL、Rocky、Fedora、openEuler

从 [Releases 页面](https://github.com/tntrock/certower/releases)下载对应架构的 `.deb` 或 `.rpm`：

```sh
sudo apt install ./certower_0.1.0_amd64.deb      # Debian、Ubuntu
sudo dnf install ./certower_0.1.0_amd64.rpm      # RHEL、Rocky、Fedora、openEuler

sudo -u certower certower bootstrap -config /etc/certower/certower.env -email you@example.com
```

安装包会创建 `certower` 系统用户，安装经过加固的 systemd 服务并启动。

| 路径 | 用途 |
|---|---|
| `/usr/bin/certower` | 主程序 |
| `/etc/certower/certower.env` | 配置文件（属主 `root:certower`，权限 0640） |
| `/var/lib/certower/` | 数据库和 KEK（权限 0750） |
| `certower.service` | `systemctl status certower`；日志通过 `journalctl -u certower` 查看 |

### Windows

从 Releases 页面下载 `certower_<版本>_windows_amd64.msi` 直接运行，或静默安装：

```powershell
msiexec /i certower_0.1.0_windows_amd64.msi /qn
& "C:\Program Files\Certower\certower.exe" bootstrap -config C:\ProgramData\Certower\certower.env -email you@example.com
```

安装程序会：

- 安装 `C:\Program Files\Certower\certower.exe` 并添加到 `PATH`；
- 创建仅 SYSTEM 和 Administrators 可以访问的 `C:\ProgramData\Certower\`，其中存放 `certower.env`（配置文件）、数据库、KEK 和 `certower.log`；
- 注册并启动 **Certower** 服务（自动启动，异常退出时自动重启）。

修改 `certower.env` 后执行 `Restart-Service Certower`。如需其他机器访问，请在 Windows 防火墙中放行端口：

```powershell
New-NetFirewallRule -DisplayName "Certower" -Direction Inbound -Protocol TCP -LocalPort 8080,8443 -Action Allow
```

### 直接使用可执行文件

Releases 页面提供 Linux、Windows、macOS 的压缩包。在用于存放数据的目录中运行 `certower serve`，或通过 `-config` 指定配置文件。下载后可以用 `checksums.txt` 校验，或用 GitHub 的构建溯源证明（build provenance）校验：

```sh
gh attestation verify certower_0.1.0_linux_amd64.tar.gz --repo tntrock/certower
```

### 从源码构建

需要 Go 1.26 及以上和 Node.js 22 及以上：

```sh
git clone https://github.com/tntrock/certower && cd certower
(cd web && npm ci && npm run build)
go build -o bin/ ./cmd/...
```

如果下载 Go 模块或 npm 包较慢，可以设置 `GOPROXY=https://goproxy.cn,direct` 和 npm 镜像源。

## 安装后的第一步

1. 运行 `certower bootstrap -email ...` **创建第一个管理员**（命令见上文），密码只显示一次。
2. 打开 `http://<服务器>:8080` 登录，并在侧边栏点击 **修改密码** 更换初始密码。
3. **创建组织**（仅系统管理员可以），并在组织中创建**项目**。
4. 开通账号：在 **用户** 页面新建账号（或配置[单点登录](../authentication.md)），再在 **成员** 页面授予角色。
5. 按照[用户手册](user-guide.md#快速开始)添加 CA 和 DNS 服务商，申请第一张证书。
6. 正式使用前：[配置 HTTPS](#https-与反向代理)，并[备份 KEK](#密钥加密密钥-kek)。

## 配置参考

每项配置都可以通过命令行参数或环境变量指定。配置文件（`-config <文件>` 或 `CERTOWER_CONFIG=<文件>`）的内容是相同变量的 `KEY=VALUE` 行，Linux 和 Windows 安装包都使用配置文件。优先级：命令行参数 > 环境变量 > 配置文件。

| 环境变量 | 参数 | 默认值 | 说明 |
|---|---|---|---|
| `CERTOWER_DB` | `-db` | `sqlite:certower.db` | `sqlite:<路径>` 或 `postgres://user:pass@host/db?sslmode=...` |
| `CERTOWER_KEK_FILE` | `-kek-file` | `certower.kek` | 密钥加密密钥文件，不存在时自动创建 |
| `CERTOWER_LISTEN` | `-listen` | `:8080` | Web 界面和 API 的监听地址 |
| `CERTOWER_AGENT_LISTEN` | `-agent-listen` | `:8443` | Agent API 地址；设为空值则禁用 Agent |
| `CERTOWER_AGENT_URL` | `-agent-url` | `https://<主机名>:8443` | Agent 访问 Agent API 使用的 URL（显示在注册命令中） |
| `CERTOWER_PUBLIC_URL` | `-public-url` | | 对外的 Web 地址，用于通知中的链接和 SSO 回调 |
| `CERTOWER_SECURE_COOKIES` | `-secure-cookies` | `false` | 为登录 Cookie 设置 Secure 属性；使用 HTTPS 时请设为 `true` |
| `CERTOWER_TRUSTED_PROXIES` | `-trusted-proxies` | | 信任其 `X-Forwarded-For` 头的反向代理（IP 或 CIDR） |
| `CERTOWER_LOG_FILE` | `-log-file` | 标准错误输出 | 将日志追加写入文件（Windows 服务使用） |
| `CERTOWER_DNS_RESOLVERS` | `-dns-resolvers` | 系统配置 | 检查 DNS-01 记录使用的 DNS 服务器，例如 `223.5.5.5,119.29.29.29` |
| `CERTOWER_DNS_CHECK` | `-dns-check` | `auto` | `auto`、`authoritative` 或 `recursive` |
| | `-workers` | `4` | 并发执行的后台任务数 |
| | `-discovery-allow-link-local` | `false` | 允许证书发现扫描 169.254.0.0/16（默认关闭，防止被用于探测云厂商元数据服务） |
| `CERTOWER_OIDC_*` | `-oidc-*` | | 单点登录，参见[登录与认证](../authentication.md) |

完整列表请运行 `certower serve -h`。Agent 的配置参见 [Agent 说明](../agent.md)。

## HTTPS 与反向代理

Certower 在 8080 端口提供的是 HTTP，需要在前面终止 TLS。请部署反向代理，并配置：

```sh
CERTOWER_PUBLIC_URL=https://certower.example.com
CERTOWER_SECURE_COOKIES=true
CERTOWER_TRUSTED_PROXIES=127.0.0.1     # Certower 看到的反向代理地址
```

nginx 示例：

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

Caddy 只需一行：`certower.example.com { reverse_proxy 127.0.0.1:8080 }`。

**不要让 Agent 端口（8443）经过会终止 TLS 的反向代理。** Agent 使用 Certower 自带的 Agent CA 签发的客户端证书进行双向 TLS 认证，连接必须直接到达 Certower，或只经过 TCP（四层）转发。Agent 通过注册命令中的 CA 指纹确认服务器身份，而不是公网证书。

Certower 可以为自己的反向代理签发证书，但请保留一条该证书失效时仍能访问的途径。

`CERTOWER_TRUSTED_PROXIES` 会影响审计日志和登录失败次数限制：如果不配置，所有请求看起来都来自反向代理，一个攻击者的错误尝试就可能让所有人都被锁定。

## 数据库

**SQLite**（默认）无需其他组件，单台服务器管理数千张证书没有问题。数据库请放在本地磁盘，不要放在网络存储上。

**PostgreSQL 15 及以上** 适合已经在运维 PostgreSQL、需要托管备份，或需要运行多个 Certower 进程的场景：

```sh
CERTOWER_DB=postgres://certower:密码@db.example.com:5432/certower?sslmode=verify-full
```

密码中的特殊字符需要 URL 编码（`@` 写作 `%40`，`/` 写作 `%2F`）。只需创建数据库和属主角色，数据表由 Certower 自行创建。

数据库结构迁移在启动时自动执行，无需手动运行迁移工具。目前不支持在 SQLite 和 PostgreSQL 之间迁移数据，请在开始使用前确定。

## 密钥加密密钥 KEK

所有私钥和凭据（CA 账号密钥、EAB 密钥、DNS API 令牌、Webhook 地址、SMTP 密码）都以加密形式存储在数据库中，而用于加密的密钥又由 `certower.kek` 这把 KEK 加密。

- **务必备份**，并与数据库备份分开存放，放在只有管理员能读取的地方（密码管理器或密钥管理系统）。
- **一旦丢失**，加密数据将无法恢复。证书、配置和历史记录仍然保留，但所有凭据都需要重新输入，私钥存储在服务器上的证书也必须重新签发。
- **如果与数据库副本一起泄露**，所有已存储的机密都等同公开，请更换 CA、DNS 和通知相关的全部凭据。
- 该文件在首次启动时创建，Linux 上权限为 0600；Windows 安装程序会将其放在受保护的目录中。

## 备份与恢复

需要备份的是**数据库**和 **KEK**。Agent 的私钥保存在各自的主机上，服务器端无需备份。

**SQLite**：在 Certower 运行时直接复制文件可能得到不一致的副本。请先短暂停止服务：

```sh
sudo systemctl stop certower
sudo cp -a /var/lib/certower/certower.db /backup/certower-$(date +%F).db
sudo systemctl start certower
```

或使用文件系统／存储卷快照。容器环境请先停止容器，再备份卷（`docker run --rm -v certower-data:/data -v $PWD:/b alpine tar czf /b/certower.tgz -C /data .`）。

**PostgreSQL**：运行中直接执行 `pg_dump -Fc certower > certower.dump` 即可。

**恢复**：停止 Certower，放回数据库和**对应的** KEK，再启动。没有对应 KEK 的数据库无法解密其中的机密。

## 升级

1. 先阅读版本说明（release notes）。
2. 备份数据库和 KEK。
3. 升级：
   - 容器：`docker pull ghcr.io/tntrock/certower:<版本>`，使用同一个卷重建容器。
   - 安装包：安装新的 `.deb`／`.rpm`，服务会自动重启。
   - Windows：运行新版 `.msi`，会替换旧版本并保留 `C:\ProgramData\Certower`。
4. 迁移在启动时执行。通过 `certower version` 和日志确认结果。

新版本迁移过数据库后不支持降级，如需回退请恢复备份。

## 用户与权限

**系统管理员**（由 `bootstrap` 创建，或在 **用户** 页面设置）可以创建组织和管理账号。在组织内能做什么仍由角色决定，不过系统管理员可以为自己授予任何角色。

系统管理员在 **用户** 页面（侧边栏“系统管理”区域）可以：

- 新建密码账号（对话框会建议一个强密码）；
- 重置密码、禁用或重新启用账号、设置或取消系统管理员。禁用或重置密码会让该用户在所有设备上退出登录。不能禁用自己，也不能取消自己的系统管理员权限。

用户可以在侧边栏自行修改密码。密码至少 12 个字符，使用 Argon2id 存储。15 分钟内同一账号登录失败 10 次会暂时锁定该账号，同一来源地址失败 30 次则锁定该地址。

**单点登录**：支持 Microsoft Entra ID、Okta、Keycloak、Authing 等任何 OpenID Connect 身份提供方，参见[登录与认证](../authentication.md)。设置 `CERTOWER_OIDC_AUTO_CREATE=true` 可在首次登录时自动创建账号；也可以把角色授予身份提供方的用户组，让权限跟随企业目录自动变化。

角色按组织或项目授予，参见[用户手册](user-guide.md#角色)。自动化场景请使用**服务账号**配合 API 令牌，通过 [API](../api.md) 创建。

## 安装 Agent

只有在私钥必须留在主机上（或需要自动部署）时才需要 Agent。服务器端请确认这些主机能访问 8443 端口，并且 `CERTOWER_AGENT_URL` 是它们实际使用的地址。

在界面中打开项目的 **Agent 与部署目标** 页面，点击 **添加 Agent**，页面会显示包含一次性令牌的注册命令。在主机上：

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

启动前请检查状态目录（`/var/lib/certower-agent` 或 `C:\ProgramData\Certower\agent`）中的 `agent.json`：其中列出了 Agent 可以写入的目录和可以执行的命令，服务器无法让 Agent 执行列表之外的操作。部署方式和安全模型的详细说明参见 [Agent 说明](../agent.md)。

## 监控与日志

- **健康检查**：`GET /healthz` 返回 `ok`。`certower healthcheck` 可检查本机服务器（容器镜像即使用此命令）。
- **日志**：`journalctl -u certower`、`docker logs certower`，Windows 上为 `C:\ProgramData\Certower\certower.log`。登录失败、任务重试、签发错误会以 WARN 级别记录。
- **通知**：添加通知渠道（邮件，或通过 Webhook 发送到 Slack、Mattermost、Google Chat、Discord），订阅 `cert.issue_failed`、`cert.expiring`、`cert.deploy_failed`，确保出现故障时有人收到。参见[通知](../discovery-and-notifications.md#notifications)。
- 每个项目的 **任务队列** 页面可以查看重试情况和错误信息。
- **审计日志** 记录每一次变更：谁、何时、从哪里操作。

## 安全检查清单

- [ ] Web 界面前已配置 HTTPS，并设置了 `CERTOWER_SECURE_COOKIES=true` 和 `CERTOWER_PUBLIC_URL`。
- [ ] `CERTOWER_TRUSTED_PROXIES` 只包含您自己的反向代理。
- [ ] 8080 端口没有直接暴露在公网上；8443 端口只对 Agent 所在网段开放。
- [ ] KEK 已备份，并与数据库备份分开存放。
- [ ] 已更换 bootstrap 生成的密码；系统管理员数量尽量少。
- [ ] 如使用单点登录，已配置 `-oidc-allowed-domains`。
- [ ] 已配置故障和到期通知。
- [ ] 每台主机上 Agent 的 `allowedPaths` 和 `allowedCommands` 均已检查。
- [ ] 下载的版本已通过校验和或 `gh attestation verify` 校验。
- [ ] 已订阅[安全公告](https://github.com/tntrock/certower/security/advisories)（Watch → Custom → Security alerts）。

## 故障排查

| 现象 | 检查项 |
|---|---|
| 服务无法启动 | 查看日志（见上文）。常见原因：端口被占用、数据库路径不可写、`certower.env` 无法读取。 |
| 出现“value was sealed with key ..., but key ... is loaded”或“decryption failed” | KEK 与数据库不匹配。请放回对应的 `certower.kek`。 |
| 签发一直处于“失败重试中”，错误与 DNS 有关 | 检查 DNS 服务商令牌的权限（Cloudflare 需要该区域的 Zone:Read 和 DNS:Edit）。如果服务器无法访问权威 DNS 服务器，请把 `CERTOWER_DNS_RESOLVERS` 设为可访问的解析器，或设置 `CERTOWER_DNS_CHECK=recursive`。 |
| Let's Encrypt 返回“rateLimited” | 先使用“Let's Encrypt (staging)”测试；生产环境的频率限制按域名、按周计算。 |
| 登录时提示失败次数过多 | 等待 15 分钟，或请管理员重置密码。如果部署在反向代理后，请检查 `CERTOWER_TRUSTED_PROXIES`。 |
| 登录页显示 SSO 错误 | 提示信息会说明原因，参见[登录与认证](../authentication.md#how-sign-in-maps-to-accounts)。 |
| Agent 显示“离线” | 在主机上查看 `journalctl -u certower-agent` 或 `agent.log`。主机能否访问 `CERTOWER_AGENT_URL`？8443 端口是否没有经过 TLS 终止？ |
| 部署“失败” | 证书页面会显示 Agent 返回的信息，例如 `nginx -t` 的输出，或路径不在 `allowedPaths` 中。 |

问题和缺陷请提交到 [GitHub Issues](https://github.com/tntrock/certower/issues)；安全漏洞请按照 [SECURITY.md](../../SECURITY.md) 私下报告。

## 卸载

- 容器：`docker rm -f certower`；确认不再需要时再删除卷。
- 安装包：`sudo apt remove certower`／`sudo dnf remove certower`。`/var/lib/certower` 和 `/etc/certower` 会保留，如需删除请手动处理。
- Windows：“设置 → 应用 → Certower Server → 卸载”，或 `msiexec /x certower_0.1.0_windows_amd64.msi /qn`。`C:\ProgramData\Certower` 会保留。

卸载不会吊销证书，证书在到期前仍然有效。
