# 部署參考：固定版本 3de6a1e

## 基準與來源

| 項目 | 版本／行為 | 來源 |
| --- | --- | --- |
| Go | go.mod 指定 1.26.3；Docker build 使用 golang:1.26-alpine，實際拉到的 patch 需核對 | [go.mod](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/go.mod)、[Dockerfile.source](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/Dockerfile.source) |
| Node | README 建議 Node ≥20；Docker 前端 build 使用 node:22-alpine | [README](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/README.md)、[Dockerfile.source](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/Dockerfile.source) |
| PostgreSQL | Compose 為 postgres:16-alpine，密碼必填；不是無資料庫模式 | [Compose](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/docker-compose.yml) |
| 程式預設 | -addr 127.0.0.1:8787；-proxy 127.0.0.1:8788 | [main.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/cmd/artex/main.go) |
| Docker 對外 | Compose 的 8787:8787 對外綁定；8788 明確綁 127.0.0.1 | [Compose](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/docker-compose.yml) |
| 設定 | ARTEX_PG_DSN 優先於 config.json；非空 database.dsn 優先於分欄；ARTEX_SKILL_DIR 優先於 skill_dir | [config.example.json](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/config.example.json) |

## 原始碼編譯指引

以下是準備步驟，不代表已執行。執行前核對本機版本與既有目錄；不要覆寫使用者尚未提交的變更。

```bash
git clone https://github.com/knowlet/artex-ymh.git
cd artex-ymh
git checkout 3de6a1eeaec220d7763f167c1f89e77e411756c3
cd web
npm ci
npm run build:static
cd ..
mkdir -p server/webui/dist
cp -R web/out/. server/webui/dist/
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
```

依實際部署設定資料庫及 skill_dir，再選直接執行、專案 start.sh 或 systemd；先讀入口腳本與 unit，不能假定沒有其他副作用。使用獨立資料目錄並保留可回復備份。

## Docker 指引

保留 repository 的 Dockerfile.source 建置方式。填妥私有 .env 的 POSTGRES_PASSWORD 後再 `docker compose up -d --build`。不要把來源映像換成 autumn27/artex，否則會失去這個 fork 的修改。若只需本機管理，明確調整 8787 的 port binding；使用 Compose override 時驗證最終合併結果，避免原本對外的 mapping 還存在。

預設 data 綁定至 /app/data、skills 綁至 /app/skills，PostgreSQL 使用 pgdata volume。備份需涵蓋資料庫與本地 data；JWT／加密相關 key 應以秘密方式保管。

## 健康檢查與門控

- [auth.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/auth.go) 讓 /api/health 免 Bearer JWT，但 [gate.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/server/gate.go) 的外層門控仍可能攔截。
- 在有權使用的 instance 上，透過正確入口及門控 cookie 存取。看到固定 nginx 歡迎頁只能說尚未通過門控，不能說 ARTEX 正常，也不能推斷一定跑錯服務。
- 檢查 /api/health 的 Content-Type 與實際 JSON，至少確認 ok、service、version；LLM 與任務執行能力仍需分別驗證。
- `artex doctor` 先於服務初始化執行，有 FAIL 時 exit code 1；WARN／SKIP 仍可能表示依賴不可用。[doctor.go](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/cmd/artex/doctor.go)

## 更新與依賴

README 指出 UI 一鍵更新會跟上游 release，可能覆蓋 fork。對此版本優先使用固定來源的可回復 build／deploy 流程，升級前備份並讀變更。

[tools-manifest.json](https://github.com/knowlet/artex-ymh/blob/3de6a1eeaec220d7763f167c1f89e77e411756c3/packaging/tools-manifest.json) 是查核清單，不是工具隨附或完整 hash 保證。按本次演練需要安裝及註冊，使用各工具官方來源並檢查版本；不自動下載完整工具庫。

沒有本次實測時，不宣稱已支援 ARM64、所有 CPU 架構或某 LLM 的完整能力；讀對應建置設定再給結論。

