---
name: evidence-privacy
description: "對既有 HTTP/HAR 證據與漏洞報告做資料最小化、分享前隱私檢查與離線摘要；不執行測試、不增加權限。"
---

# 證據隱私與分享

設計參考 Sachin Sharma 的 [Claude-BugHunter evidence-hygiene](https://github.com/elementalsouls/Claude-BugHunter/blob/9b7fc8dcf599a48f5f986971fdc62146a7f5a431/skills/evidence-hygiene/SKILL.md)（上游技能內容採 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)）。本技能與 ARTEX CLI 為獨立撰寫，未引入上游程式碼、攻擊程序或外部工具權限。

1. 使用已有且獲授權的證據，不因報告整理再發請求。原始證據留在受控儲存，不修改原件、不把秘密貼入對話。
2. 對外分享前，確認接收者、用途、資料分類及最少必要欄位。原始 ZIP、HAR、PCAP、HTTP header/body、截圖及報告文字可能含有憑證、個資或內部資訊；不得把任何未檢查的匯出視為已去識別。
3. 若僅需分享既有 HAR 的 HTTP 方法與回應狀態分布，可使用 ARTEX 本機唯讀 CLI。先讀取 [分享與摘要契約](${SKILL_DIR}/references/share.md)，並確認執行檔版本與輸入來源。不為了取得摘要新增網路操作。
4. 真正需要提供證據時，只製作經人工審核的最小副本，移除認證資料及非必要個資，檢查文字、截圖、附件和檔名是否仍含秘密。摘要不是可重現的證據，也不代表漏洞已確認或排除。
5. 沿用 ARTEX 既有 finding、原始證據與審批流程；不要覆寫原始證據或自動傳送附件。若無法確認分享安全性，保留於受控環境並註明限制。
