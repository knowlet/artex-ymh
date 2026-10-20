# 已核對的 ARTEX API 與副作用

基準 commit：`3de6a1eeaec220d7763f167c1f89e77e411756c3`。此表是原始碼參考，並不提供連線。請先讀實際部署版本，再使用已發現工具。

## 認證與介面

[server/auth.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/auth.go)：Authorization: Bearer JWT；access token 2 小時、refresh token 14 天。不要把這套登入說成標準 MCP OAuth。門控 cookie 可能另行需要。登入或刷新會更新認證狀態，不屬於無副作用的資料讀取。

[server/server.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go) 與 [mcphttp/client.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/mcphttp/client.go)：/api/mcp 用於管理 ARTEX 對外 MCP 連線，並非 MCP JSON-RPC server。ScopeSentry 技能中的 /mcp 屬於另一個服務。

登入路徑為 `POST /api/auth/login`，JSON 欄位為 username、password；此版 username 固定為大寫 `ARTEX`。成功回傳 token 並設定 refresh cookie。使用宿主的秘密輸入與儲存方式，不要求把完整帳密貼入公開紀錄。

## 常用讀取

| 路徑 | 用途／注意事項 |
| --- | --- |
| GET /api/health | 免 JWT 但可能需要 gate cookie；檢查 JSON 而非只看 200 |
| GET /api/tasks；GET /api/tasks/{id} | 任務清單、指定任務 |
| GET /api/tasks/{id}/scope | 已登錄範圍 |
| GET /api/tasks/{id}/constraints | 操作限制；文字限制不自動等於強制控制 |
| GET /api/tasks/{id}/pending-scope | 待決定的範圍，讀取不代表核准 |
| GET /api/tasks/{id}/coverage | 覆蓋資料；仍須查分母、排除項與實際驗證深度 |
| GET /api/exploration/findings | 分頁清單用 task_id；task 參數是不同的舊節點視圖 |
| GET /api/exploration/findings/{id}/lineage | 發現來源關係 |
| GET /api/exploration/findings/{id}/retests | 複測紀錄 |
| GET /api/traffic；GET /api/commands；GET /api/audit | 讀流量、指令與稽核；查 handler／工具 schema 再使用篩選參數 |
| GET /api/report?task={id} | Markdown；資產數來自全域圖，不能當該任務覆蓋率 |

findings 的全域清單篩選：page、limit、severity、status、vulnclass、task_id、q、sort、asset_scope。要讀指定任務，明確傳 `page=1&limit=20&task_id={id}`，並依 total 讀完需要的頁數。**同時省略 page 與 limit 會走最多 500 筆的裸陣列分支，該分支不套用 task_id 等篩選。** 只加 task_id 不足以保證隔離。舊 `task=` 視圖含繼承來源且每個來源有 200 筆上限，不能互換使用。[findings_groups.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/findings_groups.go)、[findings handler](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go)

匯出指定任務可使用 `GET /api/exploration/findings/export?format=json&scope=filtered&task_id={id}`。format 為 md-single、md-zip、csv 或 json；必須提供合法格式。scope=all 會取全域資料，不能用於只允許單任務的匯出。

## 證據識別碼與更新版本

[finding_traffic.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/finding_traffic.go)、[orchestration.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/orchestration.go)：

- `GET /api/exploration/findings/{finding_id}/traffic` 讀綁定清單；`/{binding_id}/body?side=response&offset=0&length=8192` 讀該證據片段。
- ARTEX 原生 `get_finding_traffic(finding_id)` 使用獨立漏洞記錄 ID；`update_finding_report(finding_id=...)` 反而使用探索節點 ID。記錄回傳的 finding_id 與 finding_node_id，不能互換。
- 更新報告時帶入真正讀取的 version 作為 evidence_version。版本衝突須重讀證據並重新判斷，不得只換版本號重送。
- 空流量清單可能是未錄製或非 HTTP 情境，不等於沒有漏洞。可以分析既有命令證據；不要為補綁定而自行重發流量。
- 本外掛不自帶上述原生工具；只有真正連線並看到相應 schema 後才能呼叫。

## 建任務不是草稿

[createTask](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go)、[launchTask](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/goals.go)。

可見欄位：name、category_id、description、goal、llm_profile_id、llm_profile_ids、source_task_ids、company_ids、timeout_seconds、plan_heartbeat_seconds、seed_first_intent、coverage_enabled、intercept_rules。

- source_task_ids 為十進位字串；company／LLM ID 為數字。不要猜 ID。
- timeout_seconds 為 0／省略表示不限時。
- plan_heartbeat_seconds 省略或過低會使用至少 600 秒；這不是請求速率上限。
- seed_first_intent 控制是否直接送第一條 worker 意圖，false 不會停用 planner／engine。
- coverage_enabled 是覆蓋功能，不是允許或禁止執行的開關。
- 此 request 沒有原子的 task_scope、constraints、paused 或 dry_run 欄位。不能用未知欄位獲得安全保證。
- intercept_rules 的 enabled 省略為 false。使用規則前重讀 schema 與比對實作，不能把只有 action／pattern 的草稿說成已啟用防護。
- 任務建立可能立刻執行。不要建完才補 scope，再宣稱啟動前已套用。

## 有副作用的操作

| 路徑 | 已確認意義 |
| --- | --- |
| POST /api/tasks | 建立並啟動任務 |
| POST /api/tasks/{id}/control | body action 為 pause 或 resume；勿編造 stop／start |
| POST /api/tasks/{id}/scope | 新增範圍，可能擴大後續活動 |
| POST /api/pending-scope/{id}/decide | 範圍決定，需現有明確授權 |
| POST／PATCH /api/tasks/{id}/goals | 可能復活任務 |
| POST /api/exploration/findings/{id}/retests | 啟動複測，會執行工作 |
| POST /api/exploration/findings/{id}/checks | 啟動檢查，會執行工作 |
| POST /api/chat；POST /api/tools/custom/test | 可能調用工具／執行命令，不能當唯讀診斷 |
| POST /api/tasks/{id}/chat/stop | 停止該 main chat；不代表整個任務或所有外部程序停止 |

## RoE 的實作限制

[roe.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/guard/roe.go) 與 [scope.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/guard/scope.go)：預設 warn；ScopeUnknown、空 scope、沒有 task ID 或抽不到目標可能放行。strict 遇到明確 scope-out 走審批，不能描述為一律 fail-closed。已拒絕規則不能以改成 warn／off 規避。範圍要求若關係到隔離保證，另以已驗證的網路與環境限制實現。

