# ARTEX 工具更新與低流量偵察決策

研究日期：2026-10-24（台灣時間）。基準：`main` / `5cddfce1fd7de9ffde26bacbf5e6366b49019492`，原工作目錄乾淨。以獨立副本開發，既有 PR #1、#2、#3、#5、#6 不納入本次修改。

## 問題與選擇

原 `packaging/tools-manifest.json` 只保存部署時的檔案雜湊，多數版本為空。它不能證明工具仍新，也不能把「清單列了新版」當作安裝成功。現有工具多由 Bash 呼叫，沒有統一的 ProjectDiscovery 參數契約。

| 候選 | 匹配與授權 | 決定 |
| --- | --- | --- |
| ProjectDiscovery nuclei/httpx/katana/naabu/subfinder | 現成 CLI、JSONL、速率限制；已讀各 repo `LICENSE.md`，MIT | 直接呼叫既有執行檔，採用固定 argv；版本與 release archive digest 用獨立 lock 保存 |
| usestrix/strix | 多 agent、限定掃描深度、候選反證、coverage 與 runtime 狀態分離；Apache-2.0 | 只參考設計，不複製程式碼、不嵌入另一套模型／Docker runtime |
| CISA KEV（cisagov/kev-data） | 已遭利用 CVE 的官方資料鏡像；CC0 | 匯入完整 KEV 情資快照，保留官方版本、日期、commit 與原始資料 hash |
| CVEProject/cvelistV5 | 官方全量 CVE、CNA 與 ADP 容器；CVE Program Terms of Use | 本批不下載龐大的全量清單；KEV 不冒充全量 CVE。完整 CVE、EPSS／產品關聯留給後續獨立功能 |

選擇擴充現有系統：新增獨立 `discovery` package 與 `artex discovery plan|run`，不修改既有 worker、資料庫、證據驗證與權限模型。使用者／agent 可在原有執行權限內明確呼叫 CLI；受管預設不限制其他 Bash 指令。

## 已讀核心實作

這些是原始碼觀察，並非本次執行上游掃描的結果。

- [Strix `prompt.py::_resolve_skills`](https://github.com/usestrix/strix/blob/14cc948c36e90517a774cf32bdfe5d8cd3605b62/strix/agents/prompt.py)：依模式加入技能與反證規則；`quick` 縮減探索廣度，並不是提高封包速度。
- [Strix `coverage.py::build_coverage_document/_completeness`](https://github.com/usestrix/strix/blob/14cc948c36e90517a774cf32bdfe5d8cd3605b62/strix/report/coverage.py)：區分 agent 自述與 runtime 的完成情況。借用此區分，CLI receipt 只記 `process_exited/failed/timed_out/cancelled`，coverage 永遠是 `unknown`，工具輸出永遠是 `unverified`。
- [Strix `coverage/tools.py`](https://github.com/usestrix/strix/blob/14cc948c36e90517a774cf32bdfe5d8cd3605b62/strix/tools/coverage/tools.py)：以 surface/risk_area 保存 ruled_out、needs_follow_up 與證據。完整 ledger 需新的資料模型，本批未聲稱已實作。
- [Strix `reporting/tool.py::_validate_analysis_fields`](https://github.com/usestrix/strix/blob/14cc948c36e90517a774cf32bdfe5d8cd3605b62/strix/tools/reporting/tool.py)：報告要求反證、信心與 severity 前提。ARTEX 已有 verifier 與流量證據綁定，不另建平行 findings 系統。
- [Strix Nuclei playbook](https://github.com/usestrix/strix/blob/14cc948c36e90517a774cf32bdfe5d8cd3605b62/strix/skills/tooling/nuclei.md)：明確選模板、限制 `-rl/-c/-bs`、JSONL、停用 OAST；其 50 rps 範例不適合作為本批低流量預設。
- [Nuclei `cmd/nuclei/main.go`](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/cmd/nuclei/main.go)：`-rl` 全域速率與 `-c/-pc/-prc` 並行；`--per-host-rate-limit` 會讓全域速率失效，因此不啟用；另核對 `-dut/-ni/-duc`。
- [httpx `runner/options.go`](https://github.com/projectdiscovery/httpx/blob/4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8/runner/options.go)：核對 threads、rate、scheme fallback、重試與更新檢查參數。
- [Katana `cmd/katana/main.go`](https://github.com/projectdiscovery/katana/blob/35267ac5c8ff1db9694a319d0eb466ed97b0969f/cmd/katana/main.go)：原預設 field-scope 為 registered domain；本批使用 fqdn 與明確 crawl scope，避免自動擴成所有子網域。
- [CISA KEV schema](https://github.com/cisagov/kev-data/blob/b9c486ef8f3ba0709bb662ae843ffee96953c400/known_exploited_vulnerabilities_schema.json)：依 count、CVE ID、必填字串與日期驗證資料，不把截斷或重複資料覆蓋舊快照。
- [CVE List README](https://github.com/CVEProject/cvelistV5/blob/main/README.md)：官方 JSON 5.x 清單可能有 CNA、CVE Program 與多個 ADP 容器；僅讀 CNA 不足以建立完整參考索引。

Strix 研究固定於 `14cc948c36e90517a774cf32bdfe5d8cd3605b62`（2026-10-23），不宣稱其為即時最新 HEAD。ProjectDiscovery release 版本／commit／asset 明細以 `packaging/projectdiscovery-lock.json` 為準。沒有複製上游程式碼或模板請求；資料的再利用保留來源與授權資訊。

## 資料包與技能的後續實作

沿用前述決策，將已驗證的 KEV 與 release lock 做成 SHA-256 綁定的離線資料包，新增 `artex intel status|search`，避免把整份 JSON 灌入模型 context。兩個新技能使用 ARTEX 既有 `norma/skill.LoadDir` 與 `${SKILL_DIR}` 展開機制，不加入外掛 runtime 或自動可見性授權。

另已實讀 [官方 `yaml2json/main.go`](https://github.com/projectdiscovery/nuclei-templates/blob/79fb682760ab3d5b0e22afbb44709353cbebf023/.github/scripts/yaml2json/main.go)：上游從 http/network/javascript 的 CVE YAML 只輸出 ID、Info 與 file_path 的 JSONL。新增更新器再裁成 metadata，省略 description 與所有請求內容；只直接採用資料，不複製 Go 程式碼。固定輸入 `cves.json` 的 Git blob 為 `6c714398fcb591949f0e150375018f200f947d8d`、原始 SHA-256 為 `91c06aa2b36c543e321a2b66a6f0b818ea16ee192b208279fcddfbb23312287c`，保留同 commit 的 MIT 原文。4,509 筆索引包含 4,407 http、60 network、42 javascript；目前 runner 僅使用 HTTP，metadata 不自動轉成執行範圍。

對照現有 `build.sh::package_binary`、兩份 Dockerfile 與 `selfupdate/stage.go::extractBinary`，確認 release/image 原本漏帶 packaging 資料，且頁面更新只換 binary。本批修正完整發行包／image 收錄，未擴大線上自動更新的交易與信任範圍。以實際產生的 ZIP 和 Docker COPY context 驗證收錄，並用同一測試重現舊 builder 的漏檔。

## 行為與限制

預設減少主動接觸：每個 subprocess 使用低 rate／concurrency、有限 timeout／retry、不自動放大目標集合，並停用工具自動更新。被動 Subfinder 仍會查詢外部資料供應商；輸出子網域是候選，不會自動加入主動範圍。

「低流量」不是無法偵測、匿名或 EDR/WAF 繞過。此變更不加入來源輪替、工具指紋隱藏或規避監控。既有 UA pool 沒有在本批重寫。CLI 控制單次 subprocess，沒有跨所有 Bash 指令或多 worker 的全域流量配額。

工具設定、二進位與模板必須由操作者審核；本機模板 hash 只證明本次選了哪些檔案，不證明模板可信或必定不連外。Nuclei 的 HTTP protocol 與 exclude-tags 不是任意模板的靜態安全驗證。需要硬性網路邊界時應使用執行環境的網路限制。

ARTEX 既有 `db/task_scope.go::covTargetCTE` 用 fact 錨點表示粗略 asset coverage，包含 inferred fact，不能用來宣稱所有漏洞類別已測完。本批不更動這個資料模型。release archive hash、安裝後 binary hash、實際執行版本是三種不同證據；版本 lock 不代表已替換部署。

## 驗證方法

離線測試涵蓋不合法目標與路徑、argv 限制、取消／逾時、JSON receipt、更新資料格式、錯誤保留舊檔。以 stub 執行檔驗證程序契約，不把它報成官方二進位相容性或真實靶場驗證。實際命令、環境及限制另見 [VALIDATION.md](VALIDATION.md)。
