# Audn 40 項對照矩陣（knowlet/artex-ymh `main` 驗證）

## 摘要

| 項目 | 值 |
|---|---|
| 對照基準 commit（驗證起點） | `f10a1941c12529aba5d89159d18cbc1fd7e7c153` |
| 已合併安全修補 | `9f6ce4e`（PR #14）、`f10a194` 含 #12 掃描能力 |
| 本分支額外修補 | HTTP 服務資產僅允許 `http`/`https` 入庫（Audn #31 縱深防禦） |
| 報告來源 | Audn 對 `ozgurnew/ARTEX` 2026-11-05 快照；**未**對報告標示之第三方目標重放攻擊 |
| 動態 7 項 | 證據指向 Juice Shop 等路由（`/rest/*`、`/ftp` 等），**本 fork 無對應介面** → 判為不適用 |
| 靜態 33 項 | 在 `main` 上逐項對照程式與 `*security*_test.go`；適用項已由 #14 覆蓋或本分支補強 |

### 分類統計（40 項）

| 分類 | 數量 | 說明 |
|---|---:|---|
| 不適用（第三方目標／介面不存在） | 7 | 僅報告動態觀察，非本程式碼面 |
| 已於 `main` 修補（證據：#14 + 回歸測） | 32 | 含攔截、憑證綁定、流量、自更新、資源上限等 |
| 本次分支縱深防禦 | 1 | #31 服務 URL 入庫 scheme 閘門（前端已有 `safeHref`） |

### 驗證方法

- 原始碼審查 + 本機 `go vet ./...`、`go test -count=1 -p=1 ./...`（日誌見 `artifacts/audn-verify-test.log`）
- 合成資料／fixture；需 PostgreSQL 的測試依 `ARTEX_AUTH_TEST_DSN`／CI `postgres:16` 服務
- **未**執行報告中的遠端 exploit 指令或連線報告目標主機

### 與 PR15（advisory 自動化）整合風險

| 區域 | 重疊檔案／不變量 | 風險 |
|---|---|---|
| 審批／待決佇列 | `server/server.go` 路由、`intercept/intercept.go`、`interceptDecide` | PR15 不得自動呼叫 `Decide` 或略過 `requireAuth`；本分支不修改這些路徑 |
| 設定／租約 | `db/settings.go`、可能的背景工作表 | 本分支僅觸及 `db/assets.go`；合併時注意 settings 鍵命名空間 |
| UI 審批記錄 | `web/src/components/approval-records.tsx` | 與資產頁 `safeHref` 無直接衝突 |
| **安全不變量** | JWT 版本撤銷、登入限速、攔截 fail-closed、憑證目的地綁定 | PR15 背景工作必須維持「僅建議、不自動核准」；不得寫入 `auth_*` 或繞過 `endpoint.ErrCredentialDestination` |

---

## 40 項證據矩陣（報告排名序）

| # | 報告要旨 | 本版分類 | 證據（`main` + 測試） | 備註 |
|---:|---|---|---|---|
| 1 | SQL 注入登入 JWT | **不適用** | 無 `/rest/user/login` | 動態 Juice Shop |
| 2 | 商品搜尋 SQL 注入 | **不適用** | 無 `/rest/products/search` | 動態 |
| 3 | 頭像 URL SSRF | **不適用** | 無 `/profile/image/url` | 動態 |
| 4 | 使用者／購物車 IDOR | **不適用** | 無對應 REST | 動態 |
| 5 | FTP 敏感檔案 | **不適用** | 無 `/ftp` | 動態 |
| 6 | memories 洩漏雜湊 | **不適用** | 無 `/rest/memories` | 動態 |
| 7 | DOM 反射 XSS `/#/search` | **不適用** | 非本前端路由 | 動態 |
| 8 | 登入無節流 | **已修補** | `server/auth_limiter.go`、`TestAuthLoginRateLimit` 類測試 | `9f6ce4e` |
| 9 | `_index` 刪除內部流量目錄 | **已修補** | `traffic/isLegacyHostPath`、`traffic/host_delete_security_test.go` | `9f6ce4e` |
| 10 | 未初始化 `authInit` 搶管理員 | **已修補** | `SetSettingIfAbsent`、`TestSecurityPGBootstrapOneWinner` | 原子初始化 |
| 11 | `reset-password.sh` source `.env` | **已修補** | 字面值解析、`server/deployment_security_test.go` | `9f6ce4e` |
| 12 | `install.sh` curl Docker 腳本 | **已修補** | 改為官方說明、無 pipe `sh` | `install.sh` |
| 13 | 改密碼不撤銷 JWT | **已修補** | JWT 2h + `auth_key_version`、`TestSecurityPGResetRevokesAndRollsBack` | 非 7 日 token |
| 14 | 命令模板遞迴替換 | **已修補** | `server/command_template.go`、`*_security_test.go` | `9f6ce4e` |
| 15 | 攔截比對原始 JSON | **已修補** | `intercept/toolInputSubjects`、`intercept/input_security_test.go` | `9f6ce4e` |
| 16 | SSE URL 帶 bearer | **已存在防護** | `sseUrl` + 60s ticket | `web/src/lib/api.ts` |
| 17 | LLM base URL 換址沿用 key | **已修補** | `reuseLLMKey`、`db/config.go`、`credential_binding_*_test.go` | `9f6ce4e` |
| 18 | `config.json` 世界可讀 | **已修補** | umask、`chmod 600`、`mktemp`+`mv` | `install.sh` |
| 19 | stdio MCP 繼承密鑰 | **已修補** | `server/mcp_environment.go`、`*_security_test.go` | `9f6ce4e` |
| 20 | MCP `env: null` panic | **已修補** | `decodeStrMap` 非 nil map | `server/manager.go` |
| 21 | commands 分頁無上限 | **已修補** | `db/commands.go` clamp 200 | `db/commands_security_test.go` |
| 22 | 資產匯入無界 | **已修補** | `decodeBoundedJSON`、`server/request_limits.go` | `9f6ce4e` |
| 23 | 對話訊息無界 | **已修補** | `decodeBoundedJSON` on send message | `request_limits_security_test.go` |
| 24 | SKILL ZIP 換行放大 | **已修補** | 逐行 frontmatter 解析 | `server_mgmt` 測試 |
| 25 | 代理上游 TLS 不驗證 | **已修補** | 預設驗證、`ARTEX_PROXY_SSL_INSECURE` | `traffic/tls_security_test.go` |
| 26 | CSV 公式注入 | **已修補** | `report/findings.go`、`findings_security_test.go` | `9f6ce4e` |
| 27 | MCP SSE 無界讀取 | **已修補** | `mcphttp` 8MiB 限制、`sse_security_test.go` | `9f6ce4e` |
| 28 | log fan-out panic | **已修補** | `server/logsink.go`、`logsink_security_test.go` | `9f6ce4e` |
| 29 | 並行 rollback `.swap` | **已修補** | `update.go` 互斥、`selfupdate/security_test.go` | `9f6ce4e` |
| 30 | SMTP STARTTLS 降級 | **已修補** | `notify/email.go`、`email_security_test.go` | `9f6ce4e` |
| 31 | 資產 href 儲存型 XSS | **已修補 + 縱深** | 前端 `safeHref`；**本次** `endpoint.AssetURL` + `UpsertHTTPService` | 見本分支 commit |
| 32 | reset 印完整 DSN | **已修補** | 紅acted 輸出、`deployment_security_test.go` | `9f6ce4e` |
| 33 | 非標準 IP 繞過資產規則 | **已修補** | `assetInterceptIP`、`asset_gate_security_test.go` | `9f6ce4e` |
| 34 | ScopeSentry URL SSRF | **管理功能 + 憑證邊界** | `prepareMCPSave`、`sync_scopesentry` 限制 | 不封內網 MCP；綁定 API key |
| 35 | 更新 ZIP 無 byte cap | **已修補** | `selfupdate/stage.go` 串流上限 | `9f6ce4e` |
| 36 | DSL OR 逃出 task 範圍 | **已修補** | `db/asset_dsl.go` 括號、`asset_dsl_security_test.go` | `9f6ce4e` |
| 37 | exact-domain 尾點繞過 | **已修補** | `DomainKey` 正規化 | `asset_intercept_match` 測試 |
| 38 | ScopeSentry sync 無界 body | **已修補** | 64KiB / 100 targets | `sync_scopesentry` + limits |
| 39 | testLLM 任意 base_url 洩 key | **已修補** | `reuseLLMKey` on test path | `server.go` testLLM |
| 40 | DSN Redact 失敗洩密 | **已修補** | `config/redact_security_test.go` | `9f6ce4e` |

---

## 本次程式變更（相對於 `f10a194`）

| 檔案 | 變更 |
|---|---|
| `internal/endpoint/endpoint.go` | 新增 `AssetURL`：僅允許 `http`/`https` |
| `db/assets.go` | `UpsertHTTPService` 入庫前驗證 URL |
| `internal/endpoint/endpoint_security_test.go` | 拒絕 `javascript:` / `data:` |
| `db/assets_test.go` | `TestUpsertHTTPServiceRejectsNonHTTPScheme` |

### 失敗前／修復後（隔離回歸）

| 測試 | 基準 `f10a194` | 本分支 head |
|---|---|---|
| `TestUpsertHTTPServiceRejectsNonHTTPScheme` | **FAIL**（`javascript:` 可入庫） | **PASS** |
| `TestAssetURL` / `endpoint` 安全測試擴充 | 無 `AssetURL` 案例 | **PASS** |

---

## 殘餘風險與決策保留

1. **管理員可設定內網 MCP／LLM URL**：屬預期能力；風險由憑證目的地綁定與 `allow_insecure` 明示承擔，不在此分支封鎖。
2. **`OPENAI_BASE_URL` 環境變數變更**：與空白 `base_url` 的 profile 互動屬部署層責任（與 #17 審查結論一致）。
3. **無 PostgreSQL 的本機全測**：部分 PG 測試 skip；以 CI `security-regressions` 為準。
4. **PR15 advisory 背景工作**：須遵守「不自動核准」；合併前請人工確認未觸及 `auth`、`mcp_save`、`intercept.Decide` 語意。

---

本文件不含 Audn 報告 session 參數或第三方目標憑證。完整歷史對照見 `security/audn-2026-11-06.md`。
