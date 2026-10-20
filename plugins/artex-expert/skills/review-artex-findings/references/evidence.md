# 證據判定參考

## 以觀測支持結論

| 現有資料 | 可以說 | 還不能說／必要對照 |
| --- | --- | --- |
| 伺服器版本符合某 CVE 範圍 | 可能受影響，需驗證設定與修補 | 不能直接確認可利用；核對官方條件、backport 與可達路徑 |
| HTTP 302 到登入頁 | 這筆請求被重新導向 | 不能確認登入繞過、RCE 或權限提升 |
| payload 出現在 HTML | 字串反射或輸出編碼特徵 | 不能直接確認腳本執行；需匹配上下文與實際行為 |
| 單次慢回應 | 觀測到延遲 | 不能直接確認 time-based injection；排除負載、cache 與重試 |
| 低權限帳號取得其他測試帳號資料 | 存在可能的物件授權問題 | 需對照資源擁有者、可見性政策及測試帳號，避免將合法共享當越權 |
| 指令日誌顯示已送出請求 | 工具曾嘗試該步驟 | 不能直接證明目標執行或持久化成功 |
| finding.status 為 confirmed | 平台將其標為 confirmed | 報告仍需檢查原始證據、來源與信心 |
| 未出現藍隊告警 | 指定時間內未看到告警證據 | 需確認事件收集、時間同步、查詢範圍及通知路徑 |

驗證安排應匹配使用者授權與隔離條件。不得為補報告證據擴大目標、擷取不必要的敏感資料或自動啟動新的攻擊階段。

## ARTEX 資料限制

固定版本 `3de6a1eeaec220d7763f167c1f89e77e411756c3`：

- [report/report.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/report/report.go) 會呈現圖中的發現與 evidence.poc；輸出文字不是獨立驗證。
- [server/server.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go) 的 getReport 讀取指定 task 的 finding nodes，但 AssetCounts 取全域資產圖；不能據此報該 task 覆蓋率。報告還有筆數上限，需檢查是否截斷。
- [findings_groups.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/findings_groups.go) 的分頁 findings 使用 task_id 篩選；舊 task 參數切到含來源任務繼承的節點視圖。保留來源 ID 並去重，不把繼承項當新發現。
- 讀 /lineage、/retests、/checks 紀錄時，區分觀測資料、裁判判定、驗證工作執行與最後效果。
- 原始碼或 README 自述的測試通過數只能引用為作者結果；要稱為本次實測，需保留實際命令、版本、輸出與失敗案例。

## 讀取完整資料及識別碼

分頁查詢應明確傳 `page`、`limit` 與 `task_id`。在本版同時省略 page／limit 會走裸陣列分支，忽略 task_id 等篩選；不能把返回資料全算成指定任務發現。`task=` 的舊視圖又有繼承來源與截斷問題。來源見 [findings handler](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go)。

若使用 ARTEX 原生工具，`get_finding_traffic` 使用獨立漏洞記錄 ID，`update_finding_report` 的同名 finding_id 欄位卻使用探索節點 ID。保留兩種 ID；帶入實際讀到的 evidence version，遇衝突就重讀證據。只有已連線且具備真實工具時才更新平台；不需為分析資料而更新任何紀錄。來源見 [finding_traffic.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/finding_traffic.go) 與 [orchestration.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/orchestration.go)。

## 修補與複測

按實際風險排序：受影響資料／服務、可達性、需要的權限、影響範圍、已觀察利用條件、現有控制及修補成本。每項修補要有負責範圍、驗收條件與回復安排；期限未提供時提出建議，不當作已承諾。

「複測通過」至少要求原問題在修補前可重現，修補後同條件的負測試不再成功，合法流程仍能正常完成，並保留關聯證據。沒有修補前基線或環境已變動時，要描述結論限制。

精確 CVE、CWE、ATT&CK、CVSS 或工具行為需要最新官方來源時，先查原始文件並附來源；無法核對時使用一般技術名稱與暫定判斷。

