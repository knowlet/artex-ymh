---
name: antifox-report-generation
description: "依已確認漏洞與真實流量整理證據、重現步驟、修復建議與 ARTEX 報告（evidence report）。"
license: AGPL-3.0
---

改寫自 [AntiFox / report-generation](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/report-generation/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# ARTEX 證據導向報告

當需要整理已完成測試的發現、撰寫修復建議或更新漏洞報告時使用。

## 取得資料

1. 用目前可用的 `list_findings` / `list_task_findings` 找到對應任務與發現；以 `node_detail` / `get_task_node_detail` 讀取完整證據。保留來源任務及獨立漏洞、探索節點兩種編號。
2. 只收錄已確認發現。待驗證、誤報、未測試項與資料不足分開說明。重複觀察合併為同一根因，不能把多筆請求當多個漏洞。
3. 若流量綁定已開啟且工具可用，先讀 `get_finding_traffic`；需要補關聯時逐筆核對真實請求與回應，再用 `bind_finding_traffic`。讀取最新 evidence version 後才提交報告。關聯失敗時保留既有證據並說明原因。

## 撰寫與提交

每個漏洞包含：名稱、受影響範圍、前置條件、實際成因、分步重現、觀察結果、風險、可操作的修復及複測方式。每一步區分「預期」與「實測」，請求、命令及關鍵回應逐字引用已存在的證據；缺失的資料標為未取得，不補造。分享版遮蔽秘密與個資，原始證據留在既有受控儲存。

只使用已有嚴重度；如需調整，寫出依據。CVSS 向量與分數須一致，缺少可確認的條件時不猜分。測試項未被命中不等於已通過；工具清單只列本次真實使用且有紀錄的工具。

使用目前可用的 `update_finding_report` 儲存，按照它的真實 schema 傳入；此工具目前的 `finding_id` 參數使用探索節點編號（`finding_node_id`）。報告完成後重新讀回核對，沒有執行或沒有回讀時不要宣稱已儲存。

整份報告依需要包含範圍與日期、方法、摘要、嚴重度分布、漏洞明細、優先修復順序、複測結果與限制。預設使用台灣繁體中文，可依要求改為簡體或英文；保留原始技術識別名稱。

## 上游模板參考

`${SKILL_DIR}/references/upstream/prompts/` 保留 AntiFox 的兩個原始提示詞；`${SKILL_DIR}/references/upstream/skeleton/zh-TW/`、`zh-CN/`、`en-US/` 保留三語方法與清單。它們只供參考，必須按本次證據改寫。ARTEX 沒有接入 AntiFox 的獨立 DOCX 報告引擎、專用報告管理頁或模板熱更新路由，不能宣稱已生成 DOCX。
