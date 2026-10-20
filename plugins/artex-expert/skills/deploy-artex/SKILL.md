---
name: deploy-artex
description: "使用者需要安裝、升級、設定、排障或審查 knowlet/artex-ymh／ARTEX 的 Docker、Go／Next.js 編譯、PostgreSQL、LLM profile、入口門控、doctor、自訂工具及外部 MCP 整合時使用。"
---

# ARTEX 部署與診斷

以台灣繁體中文說明觀察、原因、修正與驗證。閱讀 [部署參考](references/deployment.md)，需要精確參數時核對固定版本原始碼與目標環境。對使用者引用平台事實時使用固定 commit 的原始碼連結，不引用內部技能檔案作為證據。

## 先確認現況

沿用已知的主機／OS／架構、部署方式、資料目錄、fork、commit 與使用者授權。取得目前程式版本、容器設定及最小相關日誌；不得為排障一次倒出整份環境變數、LLM key、JWT key 或資料庫密碼。沒有主機存取能力時，完成可用的部署設計與診斷，將未執行命令明確標示。

若使用者要實際部署，使用其已指定且可操作的執行環境。這個技能本身不提供主機或遠端 shell；不要把手機的 localhost 當成 ARTEX 主機。

## 建立可重現部署

1. 使用 `knowlet/artex-ymh` 與已核對的 commit；不無聲替換成上游映像或 README 殘留的其他 fork。
2. 依參考核對 Go、Node、PostgreSQL、靜態前端與嵌入目錄。容器與本機編譯分開處理，不臆測二者使用相同路徑。
3. 讀實際 Compose ports、volume、啟動參數與設定優先序；依使用者要存取的位置設定綁定位址。避免單憑二進位預設 loopback 就宣稱 Docker 也只綁 loopback。
4. 用宿主既有秘密儲存或私有環境設定處理密碼／token，不寫入技能、公開 Git 或報告。讀取含秘密的 Compose 展開結果時只保留必要欄位。
5. 啟動前整理資料庫與 data 目錄的備份／回復方法；升級時確認 migration 與版本相容性。
6. 以現有 instance 的自我檢查驗證部署，不將部署測試當作對第三方目標啟動演練。

## 診斷順序

- 比對程式與前端來源版本，再看啟動日誌。
- 檢查 PostgreSQL 連線與 schema、實際設定檔位置、資料目錄權限。
- 正確處理入口門控與登入狀態；HTTP 200 的 nginx HTML 不是 ARTEX JSON 健康結果。門控 cookie 與 Bearer JWT 是兩層，不能以停用門控代替診斷。
- 執行該部署環境的 `artex doctor`，保留 OK／WARN／FAIL／SKIP 的實際內容；沒有 FAIL 不代表所有工具及 LLM 已可用。
- 確認 LLM profile、實際回應、速率／超時與費用。支援 OpenAI／Anthropic 協定不代表每一個相容端點都已驗證。
- 外部工具分別查「檔案存在」「版本／hash」「已註冊」「agent 可見」「可在正確 runtime 執行」。只有清單或註冊項都不足以證明可用。
- 連接外部 MCP 時核對 transport、TLS、認證與工具發現。現有 ARTEX MCP client 不能當成可被 ChatGPT 呼叫的 MCP server。

## 完成與驗證

只執行使用者要求且對當前環境必要的變更，保留可回復步驟。已授權的普通修正不重複詢問；若需要新秘密或目前沒有主機權限，完成準備並明確列出真正缺少的項目。

回覆部署結果、實際版本、可用入口、健康檢查內容、尚未可用的功能及下一個必要步驟。不能以「命令寫好了」當成「部署完成」，也不能把原始碼檢查說成端到端驗證。

