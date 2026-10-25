---
name: projectdiscovery-recon
description: 使用 ARTEX 的受管 ProjectDiscovery CLI 規劃或執行低流量偵察。適用於 httpx 探活、Katana 端點探索、Naabu 小範圍連線掃描、Subfinder 被動來源查詢，以及明確選取 Nuclei 範本的驗證；區分計畫、執行與未驗證輸出。
---

# 受管 ProjectDiscovery 偵察

## 先確認執行位置與範圍

1. 沿用當次任務的目標、排除項目與操作限制。已列入同一網域或工具輸出的資產，不會自動擴大允許範圍。
2. 從部署設定或操作者提供的路徑定位 ARTEX binary、工具目錄、資料包及本次工作目錄；使用明確的絕對路徑。worker 的 cwd 可能是 task/intent 目錄，不能假設是 repo 根目錄；自訂技能目錄也不能用來推算部署根目錄。
3. 用 `artex intel status --data-pack <實際 manifest 絕對路徑>` 查看情資日期與推薦工具版本。推薦版本不代表已安裝；再用 `artex discovery plan` 檢查實際 binary 與參數。工具不存在或 plan 驗證失敗時保留原因，依當次需求處理部署，不以下載後直接執行替代驗證。
4. 僅需研究或規劃時停在 `plan`。只有當次任務涵蓋該具體目標與測試行為時才使用 `run`；載入技能本身不啟動掃描、安裝或更新。

## 選擇最小操作

| 目的 | 工具與預設 | 輸出限制 |
| --- | --- | --- |
| 既有 URL 探活／指紋 | httpx、low-noise | 不跟隨重新導向，也不切換 HTTP/HTTPS scheme |
| 同 origin 端點探索 | Katana、low-noise | depth 1；standard 為 depth 2；發現其他 origin 不自動接續測試 |
| 已指定 host 的少量連線檢查 | Naabu、low-noise | 僅 CONNECT 掃 80、443、8080、8443；不能據此宣稱完整端口覆蓋 |
| 子網域來源查詢 | Subfinder、passive | 查第三方被動來源，不啟用 active DNS 驗證；不得把新子域直接接入主動掃描 |
| 指定弱點假設的模板驗證 | Nuclei、low-noise | 明確選 1–64 個已審核的本機 YAML 檔，不傳目錄、任意外部範本或整套 CVE 掃描 |

low-noise 預設 rate 1、並行 1；standard 為 5、2；限制是單次 subprocess 的工具參數。多 worker 不能藉各自開程序而宣稱符合合計流量上限。低流量不等於無法偵測，CLI 也不是網路 egress allowlist。

Subfinder 的被動查詢仍可能向第三方傳送域名。任務要求不外傳域名時只分析現有本機資料，並把被動來源查詢列為未執行。CLI 隔離工具設定，不繼承 provider/API 憑證；不要假設付費來源或原使用者設定已啟用。

## 規劃後執行

先用 Read 讀取 [命令與輸出契約](${SKILL_DIR}/references/commands.md)，再執行 `plan`，核對單一目標、profile、timeout、工具路徑與完整 argv。`${SKILL_DIR}` 由 Skill 載入時替換為本技能目錄，只用來定位附帶參考文件，不用來推算部署位置。不要額外手工拼接原生工具參數來繞過受管限制；需要超出現有契約的測試時，記錄需求並依任務既有流程決定。

對 Nuclei，先讀取所選模板與任何被引用的請求，確認目標、協定與副作用。CLI 的簽章、HTTP protocol、排除 tags 與模板 hash 不能證明所有嵌入請求都符合任務範圍；有硬性出口需求時使用執行環境的網路限制。執行期間不要替換 binary 或模板。

需要 `run` 時為每次操作使用新的 JSONL 與 receipt 路徑，設定任務可接受的 timeout。優先保留原始輸出與錯誤，避免為了取得命中而增加速率、改身分、擴目標或反覆重試。

## 回寫與收尾

- 同時檢查 exit code、stderr、JSONL 與 receipt。`process_exited` 只表示程序正常退出；`coverage=unknown` 與 `findings_validation=unverified` 仍然成立。
- 對 failed、timed_out、cancelled、running 收據保留部分輸出與未覆蓋項目。空 JSONL、阻擋、連線失敗或逾時都不能寫成「沒有漏洞」。
- 將新資產與工具命中先作為候選／待驗證事實，保留來源、工具版本證據、目標、命令計畫、輸出路徑及模板 hash。只有可重現的目標行為與證據足夠時，才走 ARTEX 既有 finding／驗證流程。
- 依實際範圍交代已做、未做、失敗、需跟進的假設；不要用既有 asset coverage 百分比或單次程序成功推定漏洞類別全部測完。

這份技能只有流程文字，不新增 executable、MCP、agent 綁定或操作權限。ARTEX 仍按技能目錄名稱的既有可見性設定載入。
