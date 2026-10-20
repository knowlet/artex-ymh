# ARTEX 紅隊演練專家

這是可安裝至 ChatGPT 的專家技能外掛，參考 [knowlet/artex-ymh](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/README.md) 的實際原始碼，以台灣繁體中文協助演練規劃、部署診斷、任務操作及證據驗證。

## 提供的技能

| 技能 | 用途 |
| --- | --- |
| plan-artex-exercise | 建立具體範圍、假設、證據標準、負載預算及復原安排 |
| deploy-artex | 對照 fork 版本、Docker／原始碼部署、資料庫、LLM、門控與工具依賴 |
| operate-artex | 依實際連線能力讀取任務、準備操作、核對 API 副作用與操作結果 |
| review-artex-findings | 檢查原始證據、誤報、修補優先序、紫隊觀測及複測結果 |

這個套件沒有伺服器、秘密資訊或預設演練目標。安裝外掛不等於已部署 ARTEX；直接操作 instance 必須有實際可用的連線工具及既有授權。

## 原始碼基準

- Repository: https://github.com/knowlet/artex-ymh
- Commit: `3de6a1eeaec220d7763f167c1f89e77e411756c3`
- 查核日期：2026-10-21（Asia/Taipei）。
- README 將原始專案歸屬於 Autumn-27/ARTEX；此套件是獨立撰寫的操作技能，沒有搬入原始攻擊鏈提示詞，也不宣稱原作者背書。
- 本套件以 AGPL-3.0-only 提供；保留 LICENSE 與來源說明。原儲存庫 README 的額外使用聲明與 LICENSE 文字應分別閱讀，不能互相替代。

## 已納入的版本注意事項

1. `mcphttp/client.go` 是對外連線的 MCP client，`/api/mcp` 是管理 API，沒有因此產生可供 ChatGPT 連線的 MCP server。
2. `POST /api/tasks` 會啟動執行；`seed_first_intent:false` 不是草稿或 dry-run。
3. RoE 預設 warn；strict 遇到未知／空白範圍並不保證阻擋。
4. 入口門控可能回傳 HTTP 200 的 nginx 歡迎頁；這不能算健康檢查通過。
5. `GET /api/report?task=...` 的資產計數來自全域資產圖，不能當成該任務覆蓋率。

每項細節及固定版本來源都放在技能的 references 目錄。更新儲存庫後應重新查核，不能把這個快照當成未來版本保證。

