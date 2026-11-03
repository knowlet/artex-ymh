# 安全情資與掃描工具來源自動更新

ARTEX 保留可重現、可審核的弱點情資和工具來源，不把「有 CVE 索引／有更新」
誤寫成「目標有漏洞」。排程工作流在 **Asia/Taipei 每日約 09:17**
（GitHub Actions UTC 01:17，實際起跑可能延遲）比對上游；也可從 Actions
手動執行 `security-source-refresh.yml`。只有合格更新才提議 PR，
**不自動合併、安裝到正式環境或對外掃描**。

## 本次導入來源

| 用途 | 官方來源與資料處理 | 工具執行狀態 |
| --- | --- | --- |
| 已知遭利用 CVE | [CISA KEV](https://github.com/cisagov/kev-data)，原始 catalog commit、sha256、CC0 來源識別；整份快照 | 情資查詢，不執行 |
| CVE 檢測候選 | [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)，最新穩定 release + commit 的 `cves.json`，只收 CVE/模板路徑等 metadata | **不下載／執行 YAML 或 PoC** |
| 受管偵察與驗證工具 | [Nuclei](https://github.com/projectdiscovery/nuclei)、[HTTPx](https://github.com/projectdiscovery/httpx)、[Naabu](https://github.com/projectdiscovery/naabu)、[Katana](https://github.com/projectdiscovery/katana)、[Subfinder](https://github.com/projectdiscovery/subfinder) 的穩定版與官方 asset digest | Naabu/HTTPx/Katana 納入工具封裝；Nuclei/Subfinder 仍按既有 installer 明確安裝 |
| PHP2Shell 專用掃描器 | [Assetnote php2shell-scanner](https://github.com/assetnote/php2shell-scanner)：沒有穩定 Release 時追蹤 master 的完整 commit SHA | **僅監控上游，不自動取得或執行** |
| 依賴／映像弱點工具 | [OSV-Scanner](https://github.com/google/osv-scanner)、[Trivy](https://github.com/aquasecurity/trivy)：追蹤穩定 Release 與 SHA | 來源追蹤，尚未接入 ARTEX runner |
| Web 安全測試來源 | [ZAP](https://github.com/zaproxy/zaproxy)、[ffuf](https://github.com/ffuf/ffuf)：追蹤穩定 Release 與 SHA | 來源追蹤，尚未接入 ARTEX runner |

有來源記錄不代表已安裝。Nuclei 索引不是所有 CVE，
KEV 僅涵蓋已知遭利用 CVE；兩者均不能取代 NVD/CVE List、
系統套件版本、distribution backport 或現場驗證。
所有第三方回傳的描述皆是資料，不是 agent 操作指示。

## 資料與工具更新流程

1. `update_vulnerability_intel.py` 取 CISA 官方 GitHub mirror 的已固定 commit。
2. `update_projectdiscovery.py` 確認六個 ProjectDiscovery repo 的穩定發行版、
   commit、MIT 授權內容和檔案 SHA-256；來源回應不符合預期即拒絕。
3. `update_nuclei_index.py` 從上述鎖定的模板 commit 下載 `cves.json`
   並驗證已保留的同版本 MIT 通知，不會下載執行模板。
4. `sync_projectdiscovery_bundle.py` 將 **Naabu、HTTPx、Katana** 的
   `linux/amd64` 發行資產 URL/hash，以及來源 license 的 Git blob SHA
   同步到 `tools-sources.lock.json`。其餘 11 個既有 bundled 工具和 6 個
   external 項目保持原樣，**不使用浮動 latest 下載 URL**。
5. `update_scanner_sources.py` 向 GitHub 取得五個公開掃描專案的
   allowlisted repo 身分、授權 metadata、穩定 Release/commit，
   更新 `scanner-source-index.json`。這個檔只用來評估是否值得
   後續整合，未賦予任何安裝或使用權限。
6. `build_intel_pack.py` 重建離線三檔 SHA-256 manifest。
   跑 Python 離線回歸與 Go discovery/intel/tool 測試；
   **當工具來源鎖有變化**，以既有 builder 重新下載帶雜湊釘版的歸檔，
   驗證架構和檔案格式並產生可重現的 Linux/amd64 工具包，
   不啟動下載的二進位。通過後才由 Action 建立更新 PR。

PR 預設使用 `automation/security-source-refresh` 分支，
來源檔、版本、hash、差異與驗證記錄可供審查；若無變更便不開新 PR。
上游下載、授權變更、雜湊或 CI 失敗會中止寫入 PR（保留 workflow 日誌），
**不以降低安全限制換取自動更新成功**。

### CI 啟用先決條件

GitHub Actions 的 workflow `GITHUB_TOKEN` 必須具備 `contents: write`
及 `pull-requests: write`，而 repo 設定要允許 Actions 建立 PR；
否則配置具有最小權限的 repository secret `SECURITY_REFRESH_TOKEN`。
`GH_TOKEN` 只傳至 `api.github.com` 的 HTTPS metadata read，
不隨 raw source / release download 轉送。排程僅在受信任的
`main` 上執行，不能由 PR 分支觸發具寫入權限的更新 job。
由預設 `GITHUB_TOKEN` 建立的 PR 通常不會再次觸發一般
`pull_request` CI，因此排程工作已先跑對應硬門測試；
人工合併前仍應檢查完整 PR 保護規則。

## PHP2Shell（2026-10）特別邊界

[PHP 官方 2026 安全版本公告](https://www.php.net/archive/2026.php)
修補 **CVE-2026-109618／CVE-2026-109619**。
上游修正版本包括 PHP **8.2.35、8.3.36、8.4.27、8.5.12**
（舊版本和發行版 backport 必須依各供應商公告確認）。

Nuclei 上游 `CVE-2026-109618.yaml` 針對兩項漏洞的測試
含記憶體耗盡／當機探測，標為 `intrusive`；ARTEX 既有
受管 Nuclei runner 明確排除 `intrusive`、`dos` 等 tags，
因此不會把這類高風險測試當成日常低流量驗證。
Assetnote 的掃描器亦不會因來源 registry 更新就被安裝或執行。

一般流程先使用 SBOM、發行版公告、PHP CLI/FPM 版本、配置、package build
及已確認 backport 證據比對；無法取得可信版本時標記「尚待確認」。
公開 HTTP header 只作初步線索：可能隱藏、被代理改寫或不反映後端版本。
**版本候選不等於可利用證據**；需要可能造成服務中斷的主動複測時，必須有
當次明確核准、測試窗口及回復方案，不得默默跨越 RoE。

## 操作與復原

```bash
# 不連網：檢查離線快照、來源和 tool bundle 一致性
python3 scripts/update_projectdiscovery.py --validate
python3 scripts/sync_projectdiscovery_bundle.py --validate
python3 scripts/update_scanner_sources.py --validate
python3 scripts/build_intel_pack.py --check
python3 scripts/build_tools_bundle.py --validate

# 有網路／明確手動操作：只生成 PR 候選資料，不安裝／執行工具
python3 scripts/update_vulnerability_intel.py
python3 scripts/update_projectdiscovery.py
python3 scripts/update_nuclei_index.py
python3 scripts/sync_projectdiscovery_bundle.py
python3 scripts/update_scanner_sources.py
python3 scripts/build_intel_pack.py

# 實際部署是否具備工具請以現有 artex doctor 和執行收據為準
./artex intel status --data-pack packaging/discovery-data-manifest.json
```

維持原本 `tools-bundle.yml` 在 PR/main/release 上的獨立 archive
驗證；新增排程不能覆寫 `packaging/tools-manifest.json` 中描述現場安裝檔案
的哈希，也不會自動授權技能、載入額外 YAML、升級 PostgreSQL、
重啟服務或修改已有的其他 PR。
