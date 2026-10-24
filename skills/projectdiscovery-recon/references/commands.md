# 命令與輸出契約

以下 `$ARTEX_BIN`、`$TOOLS_DIR`、`$TARGET_URL`、`$TARGET_DOMAIN`、`$DATA_PACK`、`$RUN_DIR`、`$TEMPLATES_DIR` 是範例 shell 變數，需先由本次部署／任務的實際值設定；不是 ARTEX 自動提供的環境變數。路徑使用絕對路徑，目標使用已確定的當次範圍。不要直接執行未代入值的範例。

## 計畫

```sh
"$ARTEX_BIN" intel status --data-pack "$DATA_PACK"
"$ARTEX_BIN" discovery plan --tool httpx --target "$TARGET_URL" --tools-dir "$TOOLS_DIR" --profile low-noise --timeout 2m
"$ARTEX_BIN" discovery plan --tool subfinder --target "$TARGET_DOMAIN" --tools-dir "$TOOLS_DIR" --profile passive --timeout 2m
```

`plan` 不發動工具，但會檢查指定 binary 存在且可執行。httpx／Katana／Nuclei 的 target 需為單一絕對 HTTP(S) URL；Naabu 使用單一 hostname 或 IP；Subfinder 使用單一 DNS domain。CLI 不接受 target list、CIDR、wildcard 或任意附加參數。

## 執行與記錄

在已選定的全新工作目錄中，先確定輸出檔與 receipt 都不存在；避免重導向覆寫舊輸出。

```sh
"$ARTEX_BIN" discovery run --tool httpx --target "$TARGET_URL" --tools-dir "$TOOLS_DIR" --profile low-noise --timeout 2m --report "$RUN_DIR/httpx-receipt.json" > "$RUN_DIR/httpx.jsonl" 2> "$RUN_DIR/httpx.stderr"
```

stdout 是工具原生 JSONL；receipt 不包含 JSONL 本體。保留三份輸出與 exit code。`--report` 只用於 `run`，且拒絕既有檔案；若程序已執行但最後 receipt 寫入失敗，exit 非零不代表從未產生流量。

Nuclei 需再提供明確模板目錄與相對檔名。`$TEMPLATE_REL` 必須是已讀取、審核且存在的單一 `.yaml`／`.yml` 檔，不能是目錄或外部 URL；需多個模板時重複 `--template`。

```sh
"$ARTEX_BIN" discovery plan --tool nuclei --target "$TARGET_URL" --tools-dir "$TOOLS_DIR" --profile low-noise --timeout 2m --templates-dir "$TEMPLATES_DIR" --template "$TEMPLATE_REL"
```

plan 列出的 SHA-256 是本機模板內容快照，不是上游來源驗證。CLI 會拒絕未簽章／簽章無效模板，停用自動更新、Interactsh 與重新導向，並以 HTTP protocol／排除 tags 限制執行；仍需核對模板內的實際請求。

## 結束狀態

| exit／receipt | 解讀 |
| --- | --- |
| 0，plan JSON | 計畫已寫出，沒有執行工具 |
| 0，process_exited | subprocess 正常退出；不代表測試覆蓋完成或命中已確認 |
| 1，failed／輸出或 receipt 錯誤 | 保留錯誤與部分輸出；可能已執行 |
| 2 | 輸入或 plan 驗證失敗 |
| 124，timed_out | 整個 subprocess 超時，覆蓋未完成 |
| 130，cancelled | 已取消，覆蓋未完成 |
| running | 可能被 SIGKILL 或主機中斷；先查實際程序與輸出，不自動重跑 |

所有執行收據的 coverage 都是 `unknown`、findings_validation 都是 `unverified`。用原始證據與正常對照決定後續驗證，不以 exit 0 直接建立確認 finding。
