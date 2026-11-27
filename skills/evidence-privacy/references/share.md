# 離線 HAR 摘要與分享限制

設計靈感：[Claude-BugHunter evidence-hygiene](https://github.com/elementalsouls/Claude-BugHunter/blob/9b7fc8dcf599a48f5f986971fdc62146a7f5a431/skills/evidence-hygiene/SKILL.md)，Sachin Sharma，CC BY 4.0；本機摘要契約為 ARTEX 自行實作。

由操作者提供現有本機 HAR，使用已安裝且支援此命令的 ARTEX 版本：

```sh
artex evidence har-summary < capture.har > summary.json
```

輸入只從 stdin 讀取，最多 16 MiB；CLI 不開啟服務、資料庫、網路或其他檔案。成功時 stdout 只有 JSON 摘要：mode、entries、依方法及狀態排序的 counts。標準 HTTP 方法以固定白名單保留，其他方法標記 OTHER；狀態 0 表示 HAR 未記錄 HTTP 回應狀態。任何無效結構或超限輸入回傳非零，錯誤訊息不回顯捕獲資料。不要使用失敗執行留下的輸出檔。

摘要不含 URL、原始 header、cookie、request/response body、時間、使用者資料、網路位址或自訂 HAR 欄位。它並不是重新產生的 HAR，也不是充分的漏洞證據。統計仍可能揭露活動量或行為分布，對外分享前須確認接收者與資料分類。

原始 ZIP、HAR 與 Markdown 匯出行為不變；沒有自動清理原始檔或附件，也沒有完整 PII 偵測。保留原件於受控儲存，另製經核准與人工檢查的最小副本。
