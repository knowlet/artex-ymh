# ProjectDiscovery 工具與情資更新

`artex discovery` 是獨立的本機 CLI，不啟動 PostgreSQL、agent 或 HTTP server。操作者／已具有 Bash 權限的 agent 可以明確呼叫它；本批未自動新增 agent 綁定或替換既有 Bash 執行方式。

## 版本與安裝

`packaging/projectdiscovery-lock.json` 保存本次核對的官方 release tag、commit、MIT 授權與 Linux amd64/arm64 **壓縮檔** SHA-256：Nuclei 3.11.1、httpx 1.12.0、Naabu 2.6.1、Katana 1.8.0、Subfinder 2.17.0、nuclei-templates 10.5.1。

```sh
# 只驗證本地 lock 結構，不連網，也不證明仍是最新。
python3 scripts/update_projectdiscovery.py --validate

# 比較官方最新穩定版，不改檔；有差異 exit 1，查詢／驗證失敗 exit 2。
python3 scripts/update_projectdiscovery.py --check

# 產生更新候選，審查 diff 與 CLI 參數相容性後才採用。
python3 scripts/update_projectdiscovery.py --output /tmp/projectdiscovery-lock.candidate.json
```

安裝器目前支援 Linux/amd64，依 lock 驗證壓縮檔 SHA-256，再取出指定工具的執行檔並保留 MIT 授權通知，以原子替換寫入 `data/tools/`。它可在 macOS 準備 Linux 部署檔，不會執行下載的程式。請先備份需保留的舊 binary。

```sh
python3 scripts/install_projectdiscovery.py --tool httpx --data-dir ./data

# 離線部署：事先取得 lock 對應的官方 ZIP，再做相同 hash 驗證。
python3 scripts/install_projectdiscovery.py --tool httpx --data-dir ./data --archive /tmp/httpx_1.12.0_linux_amd64.zip
```

安裝後回傳的 binary SHA-256 才能用於更新部署 manifest。原清單中的舊 binary SHA 不會被 release archive SHA 覆蓋；若替換了既有 httpx/katana/naabu 而未同步部署清單，`artex doctor` 仍會正確顯示舊 hash 不符。版本欄位來自下載來源，安裝器不宣稱已實際執行 `--version`。

原始 MIT 通知保存至 `data/tools/licenses/<tool>/<archiveSHA>.LICENSE.txt`，receipt 同時記錄 notice 路徑與 hash。授權通知寫入失敗時不替換 binary；若通知保存成功但 binary 替換失敗，可能留下已驗證的通知檔。若 binary 已替換但 stdout 收據回報失敗，installer exit 3，代表安裝已提交，重試前應先檢查實際檔案。

templates release 沒有提供帶官方 SHA-256 的 archive。lock 固定其 Git commit；本批安裝器只安裝五個 binary。請在部署工具鏈取得並審核該 commit 的模板目錄，再明確選取模板檔案。不能拿 checksums 檔本身的 hash 當成模板 archive hash。

## 受管偵察

先在部署主機編譯 ARTEX（`go build -o artex ./cmd/artex`），將所需工具安裝在明確的工具目錄。`plan` 也會檢查 binary 存在且可執行，並完全不執行工具。

```sh
./artex discovery plan --tool httpx --target https://service.example --tools-dir ./data/tools

# 只有明確的 run 才執行；目標應來自當次演練範圍。
./artex discovery run --tool httpx --target https://service.example --tools-dir ./data/tools --report ./httpx-receipt.json > ./httpx.jsonl

./artex discovery plan --tool subfinder --profile passive --target example.org --tools-dir ./data/tools

./artex discovery plan --tool nuclei --target https://service.example --tools-dir ./data/tools --templates-dir ./data/tools/nuclei-templates --template http/technologies/tech-detect.yaml
```

範例域名只是格式示意。Nuclei 範例檔名需與部署的模板目錄實際內容一致；操作者要審核選定檔案及其嵌入請求。CLI 記錄每個所選模板的 SHA-256，並以 `-dut` 拒絕未簽章／簽章無效的模板；本機檔案 hash 不是上游來源驗證。

| Profile | rate／並行 | 行為 |
| --- | --- | --- |
| low-noise（預設） | 1／1 | 單一 URL／host；Katana depth 1；Naabu 僅 CONNECT 掃 80、443、8080、8443 |
| standard | 5／2 | 相同目標契約；Katana depth 2 |
| passive | 1／1 | 僅 Subfinder；查第三方被動來源，不啟用 active DNS 驗證 |

httpx 不跟隨重新導向且不改用另一種 scheme；Katana 限同 origin、停用重新導向；Nuclei 僅明確指定的本機 HTTP 模板，停用更新檢查、Interactsh、重新導向並排除 intrusive/code/headless/dos/fuzz 等 tags。Naabu 不使用 raw SYN，也不自動接 Nmap。所有工具停用自動更新檢查，使用獨立 HOME／設定目錄及 cwd，避免既有設定擴大操作。環境只保留必要 PATH、locale、proxy 與 TLS trust 變數，不繼承 API／provider 憑證；因此付費 Subfinder 來源不會自動可用。

預設整個 subprocess 上限 2 分鐘，可用 `--timeout` 調整，最多 1 小時。限制是單次 subprocess 的工具參數，不是所有 worker／Bash 的合計限額。HTTP tag/protocol 與爬蟲 scope 都不等於 OS 層 egress allowlist。

stdout 是工具原生 JSONL；診斷在 stderr。`--report` 檔名必須尚不存在，執行前先建立 `running` 收據，結束後更新為 `process_exited`、`failed`、`timed_out` 或 `cancelled`。SIGKILL／主機故障可能留下 `running`。程序正常退出只代表 subprocess 結束：receipt 的 coverage 是 `unknown`、findings_validation 是 `unverified`。工具輸出需依 ARTEX 既有事實、finding 與流量證據流程驗證，不能直接當成確認漏洞。plan／模板 hash 是執行前的本機快照；執行期間不得同時替換工具或模板，CLI 不鎖住本機檔案，也不防止其他本機程序同時改檔。

exit 0 為 plan 寫出成功或 subprocess 正常退出；一般執行／收據錯誤為 1；輸入／plan 驗證失敗為 2；逾時為 124；取消為 130。若 subprocess 已執行但最後收據寫入失敗，exit 非零且 stderr 說明可能已產生流量。收據不包含 JSONL 本體，須同時保留輸出檔案。

## CVE 情資與後續改進

### 離線資料包與技能

`packaging/discovery-data-manifest.json` 綁定 KEV、ProjectDiscovery lock 與 Nuclei CVE 索引的檔案大小、SHA-256、資料日期及授權。`intel` 在載入前驗證三份資料；不下載或執行任何工具。

```sh
./artex intel status --data-pack ./packaging/discovery-data-manifest.json
./artex intel search --data-pack ./packaging/discovery-data-manifest.json --cve CVE-2021-44228 --limit 20
./artex intel search --data-pack ./packaging/discovery-data-manifest.json --vendor Microsoft --product Windows --limit 10

# 更新任一來源快照後重建 manifest，再審查 diff；不要在資料不匹配時跳過校驗。
python3 scripts/build_intel_pack.py
python3 scripts/build_intel_pack.py --check
```

status 回傳資料年齡、是否為未來日期、本機檔案完整性、來源與推薦工具版本。`freshness=not-checked-online` 表示沒有線上核對，不宣稱當下最新。manifest 與快照都來自本機，hash 只能核對綁定檔案，不能獨立證明上游來源真實。

search 預設每個集合最多 20 筆，上限 100，至少需要一個篩選條件。`--cve` 精確比對；vendor／product／query 對 KEV 採大小寫不敏感 AND 篩選，再以匹配的 CVE 連接模板索引。只傳完整 CVE 時，即使 KEV 未列入，也能回傳索引候選。分別查看 `kev_matches`、`template_matches` 與各自 total／truncated；查無 KEV 不能當成查無模板或沒有風險。輸出的 `target_vulnerability=unverified` 不會因情資命中而變成確認漏洞。

新增兩個 ARTEX 技能：`projectdiscovery-recon` 使用受管 CLI 規劃／執行；`vulnerability-triage` 使用離線查詢與證據流程分流。沿用既有技能目錄名稱的可見性設定，**不新增預設 agent 綁定或 MCP 權限**。部署後須在原技能可見性設定中選用；對既有同名授權也應核對實際載入的內容。技能透過 `${SKILL_DIR}` 定位自己的 references，部署 binary／工具／資料包路徑則使用明確設定，不能從 worker cwd 或自訂 skill root 推算。

Release ZIP 與兩份 Docker 建置流程會收錄資料包、技能、維護腳本、操作文件及授權通知。資料放在 `packaging/`，避開 Docker 的 `data/` 持久化掛載。Compose 原有 `./skills` 掛載會覆蓋 image 內技能，須同步更新該目錄。

既有頁面自動更新仍只替換 ARTEX binary；它不會安裝新的技能或資料。使用完整 Release 解壓、重建 image，或審核後手動更新這些檔案。維護腳本需要 Python 3，binary 的離線 `intel` 查詢不需要 Python。

### 官方 Nuclei CVE 索引

`packaging/nuclei-cve-index.json` 收錄 nuclei-templates `v10.5.1` 的 **4,509 筆模板 metadata、4,509 個 CVE**；含 CVE／template ID、名稱、嚴重度、上游 CVSS、檔案路徑與 protocol，省略描述、請求與 payload。來源固定在同一模板 commit；原始 MIT 通知保存在 [NUCLEI-LICENSE.txt](NUCLEI-LICENSE.txt)。metadata 的 CVSS 不是本次目標評分。

```sh
# 讀取 lock 指定 commit 的官方 metadata 與 MIT 通知，明確執行才連網。
python3 scripts/update_nuclei_index.py
python3 scripts/update_nuclei_index.py --check
```

索引的 http／network／javascript 路徑不代表本機已具備模板、簽章已驗證或目標適用。目前受管 Nuclei runner 僅支援 HTTP；其他 protocol 仍是查詢候選，不能自動接到這個 runner。更新器不會安裝 YAML，也不啟動任何 CVE 驗證。

### CISA KEV 快照

`packaging/vulnerability-intel.json` 是 CISA KEV 的情資快照，保留來源 commit、catalog 日期、內容 hash 與 CC0 資訊。本批完整匯入 **1,756 筆**，catalog 為 `2026.10.23`、發布時間 `2026-10-23T19:30:18.9209Z`，固定來源 commit `b9c486ef8f3ba0709bb662ae843ffee96953c400`。它列出已被實際利用的 CVE，**不是全量 CVE 清單**，也不代表受測主機具備這些漏洞。

```sh
# 明確執行才連網，解析官方 mirror commit 再更新。
python3 scripts/update_vulnerability_intel.py

# 不改本機快照；相同 exit 0、有變更／缺檔 exit 2、更新失敗 exit 1。
python3 scripts/update_vulnerability_intel.py --check

# 重現指定官方版本。
python3 scripts/update_vulnerability_intel.py --commit b9c486ef8f3ba0709bb662ae843ffee96953c400 --output /tmp/kev.candidate.json

# 離線原始資料一律標記 local-unverified，不能與 --commit 混用。
python3 scripts/update_vulnerability_intel.py --input /tmp/known_exploited_vulnerabilities.json --output /tmp/kev.local.json
```

更新器限制下載大小、HTTPS 來源與逾時，拒絕重新導向，驗證筆數、唯一 CVE ID、必要欄位、日期及重複 JSON key，成功後才原子替換。本批快照由 GitHub 連接器讀取官方 Git blob 後匯入並執行同一驗證器；終端網路更新尚未在此環境實測。CVE 資料是供 Read／離線分析使用的情資，未自動匯入 ARTEX findings 或啟動掃描。

所有維護命令的提交後 stdout 回報失敗都會明確標示已寫入並退出 `3`；不能把這種狀態當作舊檔仍在。先檢查實際內容，再決定是否重試。各命令的查詢／差異／驗證失敗 exit code 見 `--help` 與錯誤訊息。

Strix 的來源比較、採用與不適用處見 [RESEARCH.md](RESEARCH.md)，本批驗證與缺口見 [VALIDATION.md](VALIDATION.md)。後續較大的功能應分開處理：surface/risk-area coverage ledger、根因層級 findings 去重、跨 worker 流量配額，以及依產品版本對照的完整 CVE／EPSS 索引。
