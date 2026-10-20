# ARTEX 原始碼與能力地圖

查核基準：2026-10-21（Asia/Taipei），commit `3de6a1eeaec220d7763f167c1f89e77e411756c3`。以下是版本快照；操作前對照實際部署 commit，若不同則重讀相應檔案。

| 主題 | 確認內容 | 固定版本來源 |
| --- | --- | --- |
| 架構 | Go 後端、Next.js 前端、PostgreSQL；全域資產圖與任務探索圖 | [README](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/README.md)、[fork 說明](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/README-FORK.md) |
| 編譯與 SDK | go.mod 指定 Go 1.26.3、norma v0.4.3 | [go.mod](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/go.mod) |
| 外部 MCP | mcphttp 是對外 Streamable HTTP／SSE client；/api/mcp 是設定管理 | [client.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/mcphttp/client.go)、[routes](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go) |
| 任務啟動 | createTask 會呼叫 launchTask；不存在已查證的 dry_run 或草稿欄位 | [server.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go)、[goals.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/goals.go) |
| 範圍門控 | 預設 warn；strict 對明確範圍外要求審批。空範圍、未知目標及抽取不到目標可能放行 | [roe.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/guard/roe.go)、[scope.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/guard/scope.go) |
| 證據 | 任務資料、流量、指令、發現、複測、報告有獨立 API；來源關係需保留 | [routes](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/server.go)、[report](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/report/report.go) |
| 原有技能 | 12 個 SKILL.md；依賴 ARTEX 原生工具與特定執行環境，不能假稱在 ChatGPT 可直接使用 | [skills](https://github.com/knowlet/artex-ymh/tree/3de6a1eeaec220d7763f167c1f89e77e411756c3/skills) |
| 工具清單 | 外部程式、版本／hash 清單、註冊狀態及 agent 可見性是不同層次 | [manifest](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/packaging/tools-manifest.json)、[doctor](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/cmd/artex/doctor.go) |
| 授權來源 | LICENSE 為 GNU AGPL v3；README 的作者使用聲明另行記載 | [LICENSE](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/LICENSE)、[README](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/README.md) |

## 平台能力不等於外掛已連線

此專家套件只包含技能與參考資料，沒有 ARTEX 主機、帳密或自帶 MCP server。沒有實際工具時，可以規劃、分析上傳資料及準備部署步驟；不能聲稱已掃描、登入、建立任務或調用 `insert_assets`、`report_finding` 等 ARTEX 原生工具。

README 的效能、成功率與「12/12」防護結果是作者自述。除非取得可重現紀錄並重跑，不能稱為本次獨立驗證。

## 更新原則

優先讀使用者指定 fork 與確切 commit。README 安裝範例中仍有 r0th-m/artex-ymh，不能無聲切換使用者指定的 knowlet/artex-ymh。讀取原始碼後再引用參數、API 與限制；版本不明時標示不確定。

若複製上游程式或技能，保留來源、LICENSE 與變更說明。不要把 README 的額外聲明說成 AGPL 本身，也不要將作者聲明簡化成法律結論。

