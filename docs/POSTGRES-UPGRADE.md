# PostgreSQL 升級與資料目錄版本不符的復原

## 先判斷是哪一層失敗

若日誌出現以下訊息，PostgreSQL 尚未啟動，ARTEX 也無法執行應用程式的 schema migration：

```text
FATAL: database files are incompatible with server
DETAIL: The data directory was initialized by PostgreSQL version 16,
which is not compatible with this version 17.12.
```

2026-11-18 合併的 [PR #18](https://github.com/knowlet/artex-ymh/pull/18)，
[commit `31277e5`](https://github.com/knowlet/artex-ymh/commit/31277e574d5b8d070bd05fd8a5b41bac8e83e159)，
把 Compose 的映像從 `postgres:16-alpine` 改成 `postgres:17-alpine`，卻仍掛載原本的
`pgdata:/var/lib/postgresql/data`。既有 PostgreSQL 16 資料目錄沒有經過大版本轉換，
因此 PostgreSQL 17 拒絕啟動。ARTEX 的 `depends_on: service_healthy` 隨之阻止應用程式啟動；
容器停在 `Created` 是這個相依關係的結果。

當時的 `scripts/rehearse_pg16_to_pg17_major.sh` 驗證的是一次性測試資料庫的 dump/restore，
沒有接到正式 Compose 更新流程。該演練也不會自動轉換使用者的既有 volume。
`db/schema.sql` 能更新應用程式資料表，不能轉換 PostgreSQL 的實體資料格式。

## 目前部署行為

- Compose 預設使用 `postgres:16-alpine`，保留既有 PostgreSQL 16 部署的相容性。
- `.env` 的 `POSTGRES_IMAGE` 可明確指定映像。**已經使用 PostgreSQL 17 的資料目錄必須保留
  `POSTGRES_IMAGE=postgres:17-alpine`；不能改用 16 啟動。**
- Compose 把 `PGDATA` 固定為 `/var/lib/postgresql/data`，也就是具名 volume `pgdata` 的掛載點。
  PostgreSQL 16／17 的叢集檔本來就在這個目錄，既有 volume 版面不變。官方 PostgreSQL 18
  以上映像的預設 `PGDATA` 是 `/var/lib/postgresql/<major>/docker`，volume 宣告則改到
  `/var/lib/postgresql`。若沿用本倉庫的掛載點卻不覆寫 `PGDATA`，資料目錄不在具名 volume 上。
  目前的官方 entrypoint 若偵測到 `/var/lib/postgresql/data` 有未使用的掛載，會拒絕初始化；
  若沒有偵測到，會把新叢集寫進容器層，容器重建後資料消失。不要為了 18 的新目錄把既有
  volume 改掛到 `/var/lib/postgresql`，那會讓 16／17 的叢集檔落在伺服器尋找的資料目錄之外。
- `bash scripts/check_postgres_version.sh` 比對選定映像與資料目錄的 `PG_VERSION`，
  不會啟動 PostgreSQL 或執行版本轉換。掛載存在時，預檢拒絕不在該掛載點上的 `PGDATA`。
  `PGDATA` 若與 `/var/lib/postgresql/data` 不同，標準目錄裡已有 `PG_VERSION`，或目錄非空
  但沒有 `PG_VERSION`，也都會拒絕，避免不完整的舊目錄被當成可忽略。安裝／更新腳本會使用
  此預檢；手動執行 Compose 時也應先執行。版本不符時先處理資料與映像的對應，再啟動服務。
- `POSTGRES_IMAGE` 只選擇伺服器映像，並不代表同時執行 PostgreSQL 大版本升級。

預檢依照 Compose 解析後的映像、掛載與 `PGDATA` 工作；本指南使用倉庫的標準 16／17
資料目錄配置。若自訂啟動命令另以 `postgres -D ...` 指向不同位置，須先讓 `PGDATA`
與實際資料目錄一致，不能用不同目錄的預檢結果判斷相容性。

| 現有資料目錄 | 應使用的設定 | 動作 |
| --- | --- | --- |
| `PG_VERSION` 為 `16` | `POSTGRES_IMAGE=postgres:16-alpine`，或使用預設值 | 沿用原 volume |
| `PG_VERSION` 為 `17` | `POSTGRES_IMAGE=postgres:17-alpine` | 沿用原 volume，不能降回 16 |
| 全新空資料目錄 | 預設 16，或明確選擇 17 | 首次初始化後須維持相同 major |
| 16 資料目錄，計畫升到 17 | 先保持 16，完成下方獨立 volume 的轉移後再切換 | 需要備份、還原及驗證 |

## 立即復原：16 的資料目錄被 17 啟動

以下範例對應 `artex-ymh_pgdata`。請在**原本的專案目錄**、使用原本的 Compose project name
及設定檔執行；其他部署名稱請替換 volume 名稱。不要改 project name 來繞過錯誤，那可能建立
一個空資料庫。若平常有使用 `-f`、`--env-file` 或 `COMPOSE_FILE`，復原時也要使用相同設定。
預檢腳本不接收 Compose CLI 參數；非預設設定請先 `export COMPOSE_FILE`（依原順序列出
設定檔的絕對路徑，Linux／macOS 以 `:` 分隔）、`COMPOSE_ENV_FILES`（環境檔以 `,` 分隔）
及原本的 `COMPOSE_PROJECT_NAME`，讓預檢與後續 Compose 指令使用同一份設定。

### 1. 停止寫入並確認版本

在維護用 Bash shell 執行。`set -e` 會在失敗時停止後續指令；不要忽略任何錯誤繼續操作。

```bash
set -euo pipefail
umask 077
docker compose stop artex postgres
docker volume inspect artex-ymh_pgdata >/dev/null

docker run --rm --network none --read-only \
  --entrypoint sh \
  --mount type=volume,src=artex-ymh_pgdata,dst=/source,readonly \
  postgres:17-alpine -ec 'cat /source/PG_VERSION'
```

最後一個指令使用已下載的 17 映像作為唯讀檔案工具，**不啟動資料庫**。
本節只適用於輸出 `16` 的情況。若輸出 `17`，請保留 PostgreSQL 17 的映像設定，
不要執行以下改回 16 的步驟。

### 2. 備份原 volume 與本機設定

```bash
backup_dir="$PWD/backups/pg16-recovery-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
cp -p docker-compose.yml "$backup_dir/docker-compose.yml"
if [ -f .env ]; then cp -p .env "$backup_dir/.env"; fi
if [ -f docker-compose.override.yml ]; then
  cp -p docker-compose.override.yml "$backup_dir/docker-compose.override.yml"
fi

docker run --rm --network none --read-only \
  --entrypoint sh \
  --mount type=volume,src=artex-ymh_pgdata,dst=/source,readonly \
  --mount "type=bind,src=$backup_dir,dst=/backup" \
  postgres:17-alpine -ec '
    test "$(cat /source/PG_VERSION)" = 16
    tar -czf /backup/pgdata16.tgz -C /source .
    tar -tzf /backup/pgdata16.tgz >/dev/null
  '
test -s "$backup_dir/pgdata16.tgz"
if [ -d data ]; then tar -czf "$backup_dir/artex-data.tgz" data; fi
```

這是停止資料庫後的冷備份，適用於倉庫預設的單一 `pgdata` volume。
若有外部 tablespace、外接 WAL 或其他資料掛載，須一併備份。
`tar -t` 只能驗證封存檔可讀；完整的可復原性還需要獨立資料庫的還原測試。
備份包含資料與可能的機密設定，請保留目錄的私人權限。

### 3. 只修正 PostgreSQL 的映像設定

若已套用本次修正，確認 `docker-compose.yml` 的 PostgreSQL image 使用：

```yaml
services:
  postgres:
    image: ${POSTGRES_IMAGE:-postgres:16-alpine}
```

在 `.env` 中設定 `POSTGRES_IMAGE=postgres:16-alpine`，或移除之前設定為 17 的這一個變數，
以使用預設值。也要確認目前 shell 沒有用 `POSTGRES_IMAGE` 覆蓋 `.env`。
若使用尚未套用修正、寫死 image 的舊版 Compose，先把該行改成 `image: postgres:16-alpine`。

保留 `pgdata:/var/lib/postgresql/data`、`PGDATA=/var/lib/postgresql/data`、原 volume 名稱、
Traefik 設定及 `artex-ymh:local`。
不要用 `git restore docker-compose.yml` 覆蓋整份已修改的本機設定。
以下預檢指令使用本次修正新增的 `scripts/check_postgres_version.sh`；請先取得該修正。

```bash
bash scripts/check_postgres_version.sh
docker compose up -d --no-deps --wait --wait-timeout 120 postgres
docker compose exec -T postgres sh -ec '
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v ON_ERROR_STOP=1 -c "SHOW server_version;"
'
```

伺服器應顯示 16.x 並通過 healthcheck。`docker compose up` 會套用新的 image 設定並沿用掛載的
volume；單純 `docker compose restart` 不會套用 image 設定的修改。

### 4. 取得邏輯備份後啟動 ARTEX

```bash
docker compose exec -T postgres sh -ec \
  'pg_dumpall -U "$POSTGRES_USER"' > "$backup_dir/cluster.sql"
test -s "$backup_dir/cluster.sql"

docker compose up -d --no-deps --no-build --pull never artex
docker compose ps
docker compose logs --tail=100 postgres artex
```

確認 ARTEX 啟動、登入、歷史任務與設定可讀，再恢復演練。這裡沿用已存在的本機 ARTEX 映像；
若另有程式更新需要建置，應在資料庫復原後依一般更新流程處理。
不能把不相容版本的啟動錯誤，當作可以刪掉資料庫重建的理由。

## 有計畫地從 PostgreSQL 16 升到 17

以下是**單一 ARTEX 資料庫、標準 Compose 帳號與 volume**的邏輯轉移步驟。
先完成上方復原，確定來源由 16.x 正常提供服務。全程保留舊 volume，目標使用新的獨立 volume。
正式維護前應先在複本上演練；這不是 `rehearse_pg16_to_pg17_major.sh` 的正式環境用法。

### 1. 停止寫入並建立可驗證的備份

```bash
set -euo pipefail
umask 077
backup_dir="$PWD/backups/pg16-to-17-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
docker compose stop artex
docker compose exec -T postgres sh -ec '
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v ON_ERROR_STOP=1 -c "SHOW server_version;" \
    -c "SELECT rolname FROM pg_roles WHERE left(rolname, 3) <> '\''pg_'\'' ORDER BY 1;" \
    -c "SELECT extname, extversion FROM pg_extension ORDER BY 1;" \
    -c "SELECT spcname FROM pg_tablespace ORDER BY 1;"
'
```

確認來源為 16.x。除 Compose 指定的 `POSTGRES_USER`、內建角色、`plpgsql` 與預設 tablespace
以外，若還有自訂角色、extension 或 tablespace，先規劃其目標安裝與權限；下方的標準路徑不會
替你建立這些額外資源。若叢集內還有其他業務資料庫，也要為它們另做 dump/restore。
ARTEX 以外的寫入來源同樣需要停止。

```bash
cp -p docker-compose.yml "$backup_dir/docker-compose.yml"
if [ -f .env ]; then cp -p .env "$backup_dir/.env"; fi
if [ -f docker-compose.override.yml ]; then
  cp -p docker-compose.override.yml "$backup_dir/docker-compose.override.yml"
fi
if [ -d data ]; then tar -czf "$backup_dir/artex-data.tgz" data; fi

docker compose exec -T postgres sh -ec \
  'pg_dumpall -U "$POSTGRES_USER" --globals-only' > "$backup_dir/globals.sql"
docker compose exec -T postgres sh -ec \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$backup_dir/artex-pg16.dump"
test -s "$backup_dir/artex-pg16.dump"
docker compose exec -T postgres pg_restore --list \
  < "$backup_dir/artex-pg16.dump" > "$backup_dir/archive-contents.txt"

docker compose exec -T postgres sh -ec '
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1 \
    -c "SELECT '\''companies'\'', count(*) FROM companies UNION ALL SELECT '\''tasks'\'', count(*) FROM tasks ORDER BY 1;"
' > "$backup_dir/source-counts.txt"
```

此處刻意保留 PG16 client 建立的 custom-format 備份，供 PG17 還原及必要時的 PG16 復原使用。
`globals.sql` 是角色／全域設定備份；標準目標已由相同 `POSTGRES_USER` 初始化，不要不經檢查
直接重播 globals，以免重複建立角色。`--list` 是封存檔檢查，下一步實際還原才是關鍵驗證。

### 2. 建立獨立的 PG17 目標並還原

先確認新 volume 名稱沒有被使用。若已存在，先查清用途並另選新名稱，不能刪除後重用。

```bash
if docker volume inspect artex-ymh_pgdata17 >/dev/null 2>&1; then
  echo 'artex-ymh_pgdata17 已存在；請先確認用途並選擇新的目標名稱。' >&2
  exit 1
fi
docker volume create artex-ymh_pgdata17

cat > "$backup_dir/compose.pg17-migrate.yml" <<'YAML'
services:
  postgres17-migrate:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-artex}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?請在 .env 設定 POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB:-artex}
    volumes:
      - pgdata17:/var/lib/postgresql/data
    # 必須使用 TCP。映像初始化時的暫時伺服器只聽 Unix socket，socket 版 pg_isready 會在真正的 postmaster 接受連線前就通過。
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 5s
      timeout: 3s
      retries: 24
volumes:
  pgdata17:
    external: true
    name: artex-ymh_pgdata17
YAML

pg17_compose=(docker compose -f docker-compose.yml -f "$backup_dir/compose.pg17-migrate.yml")
"${pg17_compose[@]}" up -d --no-deps --wait --wait-timeout 180 postgres17-migrate
"${pg17_compose[@]}" exec -T postgres17-migrate sh -ec '
  pg_restore --exit-on-error --single-transaction \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB"
' < "$backup_dir/artex-pg16.dump"

"${pg17_compose[@]}" exec -T postgres17-migrate sh -ec '
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1 \
    -c "SELECT '\''companies'\'', count(*) FROM companies UNION ALL SELECT '\''tasks'\'', count(*) FROM tasks ORDER BY 1;"
' > "$backup_dir/target-counts.txt"
diff -u "$backup_dir/source-counts.txt" "$backup_dir/target-counts.txt"
"${pg17_compose[@]}" exec -T postgres17-migrate sh -ec '
  vacuumdb -U "$POSTGRES_USER" -d "$POSTGRES_DB" --analyze-in-stages
'
```

若原部署還有其他 `-f` 檔案或 `--env-file`，請也加入 `pg17_compose`，維持相同專案與環境設定。
目標未對宿主機發布資料庫連接埠。還原失敗或筆數不同時停止切換，保留來源及錯誤紀錄。
這裡的公司／任務筆數只是基本檢查；切換前還要核對部署所需的其他關鍵資料。

### 3. 持久化目標 volume 設定並切換

先停止來源與臨時目標，避免兩個 PostgreSQL 程序同時開啟同一份資料：

```bash
docker compose stop postgres
"${pg17_compose[@]}" stop postgres17-migrate
```

在原 `.env` 設定 `POSTGRES_IMAGE=postgres:17-alpine`。若本機 Compose 仍寫死映像，
也要改成上方的 `${POSTGRES_IMAGE:-postgres:16-alpine}` 寫法。
把以下內容**合併**到目前使用的 Compose override（一般為 `docker-compose.override.yml`）：

```yaml
volumes:
  pgdata:
    external: true
    name: artex-ymh_pgdata17
```

保留 override 其他設定。若使用 `COMPOSE_FILE` 或明確的 `-f` 清單，要讓日後每次啟動、更新與
預檢都包含這份 override。此設定將原本名為 `pgdata` 的掛載指向**已還原的新 volume**；
舊的 `artex-ymh_pgdata` 不刪除。

```bash
bash scripts/check_postgres_version.sh
docker compose up -d --no-deps --wait --wait-timeout 120 postgres
docker compose exec -T postgres sh -ec '
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v ON_ERROR_STOP=1 -c "SHOW server_version;"
'
docker compose up -d --no-deps --no-build --pull never artex
docker compose ps
docker compose logs --tail=100 postgres artex
```

確認版本為 17.x，並驗證登入、歷史任務、設定、檔案及應用程式日誌。保留舊 volume、邏輯備份、
`data/` 備份與原部署設定，直到遷移驗收完成。

### 4. 回復界線

若尚未允許 PostgreSQL 17 承接新寫入，可停止 `artex postgres`，把映像改回 16，
將 override 的 `pgdata.name` 改回原本的 `artex-ymh_pgdata`，確認預檢後啟動原資料庫與原應用程式。
如果切換時也更新應用程式或 `data/`，必須一併使用相符的備份版本。

**PG17 已產生新寫入之後，原 PG16 volume／備份只包含切換前資料。** 回復舊資料會失去切換後變更，
需要另外規劃資料對帳與搬移。啟動 ARTEX 本身就可能執行 schema 更新或背景寫入；尚未登入 UI
不代表目標資料庫沒有新變更。不能把 PG17 的實體資料目錄交給 PG16，也不能假設 PG17 dump
能直接還原到 PG16。不要刪除任一 volume、改寫 `PG_VERSION`，或用刪除資料重建的方式處理版本不符。

## 參考文件

- [PostgreSQL 17：升級資料庫叢集](https://www.postgresql.org/docs/17/upgrading.html)
- [PostgreSQL 17：pg_upgrade 與回復限制](https://www.postgresql.org/docs/17/pgupgrade.html)
- [Docker Official Image：PostgreSQL](https://hub.docker.com/_/postgres)
- [Docker Compose up：套用設定並保留掛載 volume](https://docs.docker.com/reference/cli/docker/compose/up/)
- [Docker volume 備份與還原](https://docs.docker.com/engine/storage/volumes/)
- [2026-11-11 歷史演練紀錄](../packaging/upgrades/MIGRATION-ROLLBACK-2026-11-11.md)
