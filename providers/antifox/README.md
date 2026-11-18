# AntiFox 整合

來源固定於 [AntiFox-AI/antifox `070f798`](https://github.com/AntiFox-AI/antifox/tree/070f798bf590667bc2a0a13c687dd87d8a4413bf)，查核日期為 2026-11-12。來源根目錄的 [LICENSE](snapshot/LICENSE) 為 AGPL-3.0；每個相容版均保留原文及完整授權。

## 已整合

- 23 個 `antifox-*` 技能：22 個 Web/API、程式碼、雲端、容器、行動應用程式、網路、事件應變及其他安全程序，加上 ARTEX 證據報告相容版。
- `api-recon`、`playwright-cli`、`scopesentry` 與目前 ARTEX 內容相同，沿用現有檔案；[overlap.json](overlap.json) 保存三者雜湊。
- `search_knowledge` 與 `list_knowledge_categories`：依目前代理已獲授權的技能清單建立離線檢索，不需要新服務、LLM 或網路。支援英文詞與中文雙字詞，回傳技能名稱、段落與字詞分數。
- 17 個上游報告資源：兩個提示詞、繁體／簡體／英文的五組骨架。位於報告技能的 `references/upstream/`，供寫作參考。
- [catalog.json](catalog.json)：23 個來源記錄、33 個相依項的名稱與別名。這是來源／相依索引，不能當作安裝、二進位校驗或工具執行成功的證明。

## 使用方式

沿用原有編譯與部署流程。兩種 Dockerfile 與 release 壓縮包會附上技能、來源目錄與檢查程式；自訂技能 volume 或 `ARTEX_SKILL_DIR` 會依原有設定優先，請使用包含所需技能的目錄。

首次啟動會把 22 個程序技能綁給 `planner`、`worker`、`pentest`，報告相容版綁給 `reporter`。資料庫只新增不存在的預設列，不改寫既有綁定。之後可在技能頁逐一停用或調整可見性。停用保留明確的關閉記錄，重新啟動不會開回來；批次設定亦然。

兩個檢索工具預設綁給 `planner`、`worker`、`pentest`、`auto`、`reporter`，也可在工具頁停用或重新綁定。`auto` 只搜尋其已獲授權的技能；工具的預設綁定不會額外授予技能。

工具在裝配時即核對綁定與啟用狀態；既有同名自訂工具仍保有原本的執行方式，不會被新的內建實作取代。

工具呼叫範例（由目前代理執行）：

```json
{"query":"SQL injection","top_k":5}
```

可先呼叫 `list_knowledge_categories({})`，再把回傳的完整技能名稱傳入 `category`。預設回傳 5 段，最多 20 段，每段最多 1,000 字元；每個技能最多佔兩段。索引最多 200 個技能、2,048 段，每個技能最多讀取 64,000 字元，截斷會明示 `index_truncated`。`lexical_score` 只代表字詞相符程度，不是語意相似度、信心值或漏洞判定。

舊技能若含過長的名稱、描述或標題，索引也會限制其大小並揭露截斷，避免可編輯的 metadata 使結果長度失控。完整技能仍由既有 `Skill` 工具處理。

檢索僅讀取已依目錄名稱與來源庫識別篩選的本次技能快照，不讀取其他代理的技能、原始參考檔、任務上傳文件或全域資料庫。它不呼叫 `Skill`、不記為技能執行、不解鎖 MCP。需要完整程序時再呼叫 `Skill`。更改可見性在新的執行生效；已執行中的代理可能保留先前的上下文。

## 報告與工具相容性

報告相容版使用 ARTEX 既有的發現、流量核對、證據版本與 `update_finding_report`。獨立漏洞 ID 與探索節點 ID 沿用各工具的真實參數契約。

AntiFox 的原始 `report-generation` 仰賴其獨立報告引擎，因此 catalog 將該原文標為 `metadata-only`；正常隨附的是已改寫的 `antifox-report-generation`。本次未移植 AntiFox 的 DOCX 引擎、專用報告管理頁、pgvector 知識服務或任務文件上傳流程。外部 CLI／商業工具／套件亦沒有因本次整合而自動安裝。

## 來源檢查與維護

```sh
python3 scripts/sync_antifox.py --check
```

檢查來源、授權、報告資源及相容版的固定雜湊／內容，不會連網或執行來源範例。`--write` 只建立缺少的相容版檔案；遇到既有修改會拒絕覆寫。更新來源需另行查核新 commit、授權與內容，調整 catalog／相容約定後逐檔審查差異。此程式不是供不可信來源使用的通用安裝器。

在 Linux 上，可用 `artex provider catalog -catalog providers/antifox/catalog.json` 檢視來源 metadata。provider CLI 的檔案操作仍沿用 Linux 限制；隨附的 `skills/antifox-*` 透過原本 Norma loader 載入，沒有這項限制。

設計比較見 [RESEARCH.md](RESEARCH.md)，本次執行結果與驗收限制見 [VALIDATION.md](VALIDATION.md)。
