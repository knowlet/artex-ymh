# 驗證紀錄

日期：2026-10-24，台灣時間。基準 main：`5cddfce1fd7de9ffde26bacbf5e6366b49019492`。在 `/tmp/artex-modern-tools-20261024` 的隔離分支 `feat/modern-discovery-tooling` 驗證，完成後將修改套回原工作目錄；保留原工作目錄既有修改與 Git HEAD／分支，不修改其他 PR。

環境：Darwin arm64、Go `1.27.3`、Python `3.15.0`。`go.mod` 的最低版本仍為 Go `1.26.3`；本批不新增 Go／Python 第三方相依套件。CI 設定使用 `go.mod` 版本。

## 資料包與技能更新的最終本機結果

- `python3 -m unittest discover -s scripts -p 'test_*.py' -q`：exit 0，**75 項測試**。包含實際 OS pipe 關閉讀端後的子程序退出碼、失敗保留舊檔、三份資料 manifest、官方索引正規化及真實 ZIP 收錄。
- `go test -race -json ./discovery ./intelpack ./tools -count=1`：exit 0，**86 個測試／子測項、0 skips**；另兩組 standalone CLI race 測試分別為 discovery **7**、intel **4**，均 exit 0／0 skips。
- 上述三個 package 與兩組 CLI 檔案的 `go vet`：exit 0。gofmt、`bash -n build.sh`、Python 語法編譯及 `git diff --check` 通過。
- 實際 `build_intel_pack.py --check` 與 `update_projectdiscovery.py --validate`：exit 0。離線資料綁定 1,756 筆 KEV、六個 release 記錄與 4,509 筆模板 metadata；沒有模板 YAML／請求／payload。
- 以 fake compiler 產生 Linux／Windows ZIP，檢查資料、技能、文件、維護腳本與授權；缺資料檔時拒絕打包。相同測試對未修改 `build.sh` 的基準可重現漏檔。兩份 Docker COPY 的實際 context 亦通過檔案收錄驗證；未建置／執行真實 Docker image。
- 真實 Unix FIFO 測試證明 reader 在開檔前拒絕非 regular file；資料的 path／CVE／protocol 驗證與 Python builder 一致。
- 技能 frontmatter／references 檢查與獨立情境試用通過。獨立 agent 能正確處理 banner-only、timeout、過時 KEV、查無 CVE、自訂技能路徑與 worker cwd，未執行掃描或把陰性／缺資料當安全證明。
- `skillcheck/skills_test.go` 使用實際 `norma/skill.LoadDir` 與 Skill 呼叫，檢查兩份技能及 `${SKILL_DIR}` 展開、不隱含啟用 MCP。**本機未跑到測試本體**：Norma 相依下載因 DNS 失敗而阻擋；CI 將此項列為必要步驟，不能當作本機通過。
- 新 intel package／CLI 的 Linux amd64 測試執行檔跨編譯成功；Linux runtime 由 PR CI 驗證。本機沒有完整後端編譯成功的證據。

獨立 review 找到並修正 FIFO 開檔阻塞、模板 schema 差異與提交後回報錯誤。對 updater／builder／installer，以實際 OS pipe 證明已提交內容時維持 exit 3，避免 Python 結束時再次 flush 把退出碼改成 120。發行包與技能的人工可見性、頁面更新僅替換 binary 的限制另見 README。

以下保留第一批工具改進的驗證細節；最終完整離線套件以本節結果為準。PR 與遠端 CI 的目前 head、run/job 與結果以 PR 描述／GitHub 為準，不拿本機測試替代遠端證據。

## 已執行且通過

| 命令／檢查 | 結果與證據範圍 |
| --- | --- |
| `python3 -m unittest discover -s scripts -p 'test_*projectdiscovery.py' -v` | exit 0，29 個測試：10 個版本更新器與 19 個安裝器測試；本機 fixture、失敗保留舊檔、官方 URL／digest 約束、MIT 保留、取消與提交後回報失敗 |
| `python3 -m unittest discover -s scripts -p 'test_update_vulnerability_intel.py' -v` | exit 0，8 個測試，包含不合法資料、網路錯誤、離線來源、官方資料格式與原子寫入；子測項使用多種損壞資料 |
| `python3 scripts/update_projectdiscovery.py --validate` | exit 0，實際本機 lock 通過驗證；不是線上 freshness 檢查 |
| `python3 -m py_compile scripts/update_projectdiscovery.py scripts/install_projectdiscovery.py scripts/update_vulnerability_intel.py` | exit 0 |
| `GOCACHE=/tmp/artex-go-cache go test -race ./discovery ./tools -count=1` | exit 0，含實際 helper subprocess 的 literal argv、設定／環境隔離、逾時與取消；不使用官方掃描工具或外部目標 |
| `GOCACHE=/tmp/artex-go-cache go test -race ./cmd/artex/discovery.go ./cmd/artex/discovery_test.go -count=1` | exit 0，7 個 CLI 測試：明確 action、plan 不執行、收據衝突、正常／失敗／取消／逾時狀態 |
| `GOCACHE=/tmp/artex-go-cache go vet ./discovery ./tools` 及 CLI 檔案的 `go vet` | exit 0 |
| `GOOS=linux GOARCH=amd64 go test -c`（discovery package 與 CLI 檔案測試） | exit 0，跨編譯成功；Linux runtime 未執行 |
| KEV 實際快照 | 驗證完整 1,756 個不重複 CVE；catalog `2026.10.23`；來源 commit `b9c486ef8f3ba0709bb662ae843ffee96953c400`，Git blob `4733f9e8d88d6a219efe5a86f89f5f3b6847fc8f`，原始 bytes SHA-256 `97a6e54bc74c651ab3c55657191db9adec6c63b05ca54e4205327cfd97a8fb70`。正規化後的 JSON bytes 與原始 bytes hash 不同，source.sha256 明確指原始 bytes |
| `git diff --check` 與 gofmt | 通過 |

額外獨立 review 修正：Naabu 的 `DurationVar` 把裸數字當秒，因此改用 `-timeout 1s`；其餘四個工具的 timeout 為 IntVar 秒數，已核對上游。安裝器保留 hash-verified ZIP 中的 MIT 原文，並把授權檔保存失敗列為不替換 binary 的條件。

## 受環境限制／未執行

- `GOCACHE=/tmp/artex-go-cache GOMODCACHE=/tmp/artex-go-modcache go build ./cmd/artex`：exit 1，下載既有相依套件時 `proxy.golang.org` DNS 解析失敗；未到完整後端編譯階段。不是程式碼測試斷言失敗，也不能宣稱完整後端可建置。全庫、PostgreSQL 與既有 guard regression 未完成。
- 原預設 Go build/module cache 在唯讀範圍；改用可寫入暫存 cache 後，純標準庫的新 package、CLI 與既有 tools 測試成功，其他相依仍受 DNS 限制。
- 官方 release 版本、commit、license 與 asset digest 經 GitHub 連接器查核；終端的線上 updater／installer 未實跑。沒有安裝、執行官方 ProjectDiscovery binary，沒有替換任何部署工具。
- 沒有外部目標、TPot、真實 Nuclei 模板與 egress／proxy 的驗收；stub 契約測試不能取代這些測試。低流量不是無法偵測的證據。
- 沒有 deploy、release、merge 或外部目標測試。新增 path-filtered workflow 包含離線測試、實際 Norma loader、完整後端編譯與 built-binary 離線 dispatch；遠端結果以 PR 當前 head 為準。

變更的本機工具／template hash 是驗證時快照；不防本機同時修改。安裝器保留的授權通知可能先於失敗的 binary 替換而存在；程序遭 SIGKILL 時 CLI 收據可能停在 `running`。這些狀態沒有被標為已完成掃描。
