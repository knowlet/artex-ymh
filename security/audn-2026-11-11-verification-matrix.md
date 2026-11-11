# Audn 40 項對照矩陣（knowlet/artex-ymh `main` 驗證）

## 摘要

| 項目 | 值 |
|---|---|
| 對照基準 commit（驗證起點） | `f10a1941c12529aba5d89159d18cbc1fd7e7c153` |
| 已合併安全修補 | `9f6ce4e`（PR #14）、`f10a194` 含 #12 掃描能力 |
| 本分支額外修補 | Audn #31：**入庫** scheme 閘門（`ValidateAssetURL`）；UI 仍靠 `safeHref` 阻斷危險 href **渲染** |
| 報告來源 | Audn 對 `ozgurnew/ARTEX` 2026-11-05 快照；**未**對報告標示之第三方目標重放攻擊 |
| 動態 7 項 | 證據指向 Juice Shop 等**第三方**路由（`/rest/*`、`/ftp` 等）；本 fork **無對應介面** → **第三方目標不適用**（非「全倉已修補」） |
| 靜態 33 項 | 在 `main` 上對照原始碼與 `*security*_test.go`；多數為 **#14 已修補（靜態靜態＋單元／隔離 PG 證據）**，未逐項動態 exploit |

### 分類統計（40 項，用語區分證據強度）

| 分類 | 數量 | 說明 |
|---|---:|---|
| 第三方目標／介面不存在 | 7 | 僅報告動態觀察；本程式碼面無對應路由 |
| `main` 已修補（原始碼＋回歸測，非動態重放） | 31 | #14 範圍內範圍內攔截、憑證、流量、上限等 |
| 縱深防禦（本次分支） | 1 | #31：**儲存**路徑 scheme 驗證；**渲染**_sink 仍由 `safeHref` 緩解 |
| 部分／設計取捨（未封殺管理能力） | 1 | #34 ScopeSentry 內網 URL（憑證綁定＋管理員設定） |

### 驗證方法

- 原始碼審查 + `gofmt` / `go vet ./...` / `go test -count=1 -p=1 ./...` / `go build ./cmd/artex`
- 需 PostgreSQL 的隔離測試：**`ARTEX_AUTH_TEST_DSN`**（本機 disposable PG16；CI `postgres:16` 服務）
- 本分支資產 URL 回歸：`TestValidateAssetURL`、`TestSecurityPGHTTPServiceURLSchemeGate`（含 **negative control**：`normalizeURL` 不阻擋 `javascript:`）
- **未**執行報告中的遠端 exploit 或連線報告目標主機

### 與 PR15（advisory 自動化）整合風險

| 區域 | 重疊檔案／不變量 | 風險 |
|---|---|---|
| 審批／待決佇列 | `server/server.go`、`intercept/intercept.go` | PR15 不得自動 `Decide` 或略過 `requireAuth`；本分支不修改 |
| 設定／租約 | `db/settings.go` | 本分支觸及 `db/assets.go`、`task_archives_restore.go`、`enrich` 錯誤記錄 |
| **安全不變量** | JWT 撤銷、攔截 fail-closed、`endpoint.ErrCredentialDestination` | PR15 須維持「僅建議、不自動核准」 |

---

## 40 項證據矩陣（報告排名序）

| # | 報告要旨 | 本版分類 | 證據類型 | 證據（`main` + 測試） |
|---:|---|---|---|---|
| 1 | SQL 注入登入 JWT | **第三方目標不適用** | 程式庫對照 | 無 `/rest/user/login` |
| 2 | 商品搜尋 SQL 注入 | **第三方目標不適用** | 同上 | 無 `/rest/products/search` |
| 3 | 頭像 URL SSRF | **第三方目標不適用** | 同上 | 無 `/profile/image/url` |
| 4 | 使用者／購物車 IDOR | **第三方目標不適用** | 同上 | 無對應 REST |
| 5 | FTP 敏感檔案 | **第三方目標不適用** | 同上 | 無 `/ftp` |
| 6 | memories 洩漏雜湊 | **第三方目標不適用** | 同上 | 無 `/rest/memories` |
| 7 | DOM 反射 XSS `/#/search` | **第三方目標不適用** | 同上 | 非本前端該路由 |
| 8 | 登入無節流 | **已修補** | 靜態＋單元 | `auth_limiter.go`、登入限速測試 |
| 9 | `_index` 刪內部流量目錄 | **已修補** | 靜態＋單元 | `traffic/host_delete_security_test.go` |
| 10 | 未初始化 `authInit` | **已修補** | 靜態＋隔離 PG | `SetSettingIfAbsent`、`TestSecurityPGBootstrapOneWinner` |
| 11 | `reset-password.sh` source `.env` | **已修補** | 靜態＋單元 | `deployment_security_test.go` |
| 12 | `install.sh` curl 管線 | **已修補** | 原始碼 | 無 pipe 官方腳本 |
| 13 | 改密不撤銷 JWT | **已修補** | 靜態＋隔離 PG | `auth_key_version`、reset 撤銷測試 |
| 14 | 命令模板遞迴替換 | **已修補** | 靜態＋單元 | `command_template`、security 測試 |
| 15 | 攔截比對原始 JSON | **已修補** | 靜態＋單元 | `intercept/input_security_test.go` |
| 16 | SSE URL 帶 bearer | **渲染／傳輸緩解** | 靜態 | 60s ticket；非「禁止 SSE」 |
| 17 | LLM base URL 換址沿用 key | **已修補** | 靜態＋單元 | `reuseLLMKey`、`credential_binding_*_test.go` |
| 18 | `config.json` 世界可讀 | **已修補** | 原始碼＋部署測試 | umask、`chmod 600` |
| 19 | stdio MCP 繼承密鑰 | **已修補** | 靜態＋單元 | `mcp_environment` 測試 |
| 20 | MCP `env: null` panic | **已修補** | 靜態＋單元 | `decodeStrMap` |
| 21 | commands 分頁無上限 | **已修補** | 靜態＋單元／PG | `commands_security_test.go` |
| 22 | 資產匯入無界 | **已修補** | 靜態＋單元 | `decodeBoundedJSON` |
| 23 | 對話訊息無界 | **已修補** | 靜態＋單元 | `request_limits_security_test.go` |
| 24 | SKILL ZIP 換行放大 | **已修補** | 靜態＋單元 | frontmatter 逐行解析 |
| 25 | 代理上游 TLS 不驗證 | **已修補** | 靜態＋單元 | 預設驗證、`tls_security_test.go` |
| 26 | CSV 公式注入 | **已修補** | 靜態＋單元 | `findings_security_test.go` |
| 27 | MCP SSE 無界讀取 | **已修補** | 靜態＋單元 | 8MiB 上限 |
| 28 | log fan-out panic | **已修補** | 靜態＋單元 | `logsink_security_test.go` |
| 29 | 並行 rollback `.swap` | **已修補** | 靜態＋單元 | `selfupdate/security_test.go` |
| 30 | SMTP STARTTLS 降級 | **已修補** | 靜態＋單元 | `email_security_test.go` |
| 31 | 資產 href 儲存型 XSS | **縱深：儲存阻斷＋渲染緩解** | 靜態＋單元＋隔離 PG | UI `safeHref`（fail-closed **sink**）；**本次** `ValidateAssetURL` + `UpsertHTTPService`／歸檔還原（**storage**） |
| 32 | reset 印完整 DSN | **已修補** | 靜態＋單元 | redacted 輸出、`deployment_security_test.go` |
| 33 | 非標準 IP 繞過資產規則 | **已修補** | 靜態＋單元 | `asset_gate_security_test.go` |
| 34 | ScopeSentry URL SSRF | **管理功能取捨** | 靜態＋單元 | MCP 儲存邊界；未封內網（管理員能力） |
| 35 | 更新 ZIP 無 byte cap | **已修補** | 靜態＋單元 | `selfupdate/stage.go` |
| 36 | DSL OR 逃出 task 範圍 | **已修補** | 靜態＋隔離 PG | `asset_dsl_pg_security_test.go` |
| 37 | exact-domain 尾點繞過 | **已修補** | 靜態＋單元 | `DomainKey` 正規化 |
| 38 | ScopeSentry sync 無界 body | **已修補** | 靜態＋單元 | 64KiB／100 targets |
| 39 | testLLM 任意 base_url 洩 key | **已修補** | 靜態＋單元 | `reuseLLMKey` on test path |
| 40 | DSN Redact 失敗洩密 | **已修補** | 靜態＋單元 | `redact_security_test.go` |

---

## 本次程式變更（相對於 `f10a194`）

| 檔案 | 變更 |
|---|---|
| `internal/endpoint/endpoint.go` | `ValidateAssetURL`：僅允許 `http`/`https`；**不改寫** URL 字串 |
| `internal/endpoint/asset_url_test.go` | `TestValidateAssetURL` |
| `db/assets.go` | `UpsertHTTPService` 入庫前驗證；保留既有 `normalizeURL` 去重語意 |
| `db/assets_url_security_pg_test.go` | 隔離 PG：拒絕寫入、`#/fragment` 保留、歸檔還原跳過 |
| `db/task_archives_restore.go` | 歸檔還原 HTTP 服務資產同源驗證 |
| `enrich/enrich.go` | `UpsertHTTPService` 失敗記錄（非靜默吞錯） |
| `db/assets_test.go` | `javascript:`／`ftp://` 拒絕 |

### 失敗前／修復後（隔離回歸）

| 測試 | 基準 `f10a194`（推論／對照） | 本分支 |
|---|---|---|
| `normalizeURL("javascript:…")` | **不阻擋**（negative control） | 仍不阻擋（邊界在 `ValidateAssetURL`） |
| `UpsertHTTPService` + `javascript:` | 可入庫（**未驗證**於本機基準執行） | **錯誤且無列** |
| `TestValidateAssetURL` | 不存在 | **PASS** |
| `TestSecurityPGHTTPServiceURLSchemeGate` | 不存在 | **PASS**（需 `ARTEX_AUTH_TEST_DSN`） |

---

## 殘餘風險與決策保留

1. **#31**：惡意 scheme 在 **UI 層**仍由 `safeHref` 擋下；本分支阻斷 **寫入**與**歸檔還原**旁路，非保證歷史庫已無畸形列（未做資料遷移）。
2. **管理員可設定內網 MCP／LLM URL**：預期能力；憑證目的地綁定與明示 `allow_insecure`。
3. **無 `ARTEX_AUTH_TEST_DSN` 的本機全測**：`TestSecurityPG*` **失敗或 skip 視檔案而定**；合併前以 CI `security-regressions` 為準。
4. **PR15**：須遵守「不自動核准」；與本分支檔案不重疊。

---

本文件不含 Audn 報告 session 參數或第三方目標憑證。歷史對照見 `security/audn-2026-11-06.md`。
