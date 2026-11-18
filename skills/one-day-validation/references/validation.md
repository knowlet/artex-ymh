# 驗證紀錄與對照

部署路徑一律使用已確認的絕對路徑。以下是命令格式；不得直接把範例網域當目標。

```sh
/absolute/artex intel status --data-pack /absolute/packaging/discovery-data-manifest.json
/absolute/artex intel search --data-pack /absolute/packaging/discovery-data-manifest.json --cve CVE-2023-23752 --limit 10
/absolute/artex discovery plan --tool nuclei --target https://authorized.example --tools-dir /absolute/data/tools --templates-dir /absolute/reviewed-templates --template http/cves/2023/CVE-2023-23752.yaml
/absolute/artex discovery run --tool nuclei --target https://authorized.example --tools-dir /absolute/data/tools --templates-dir /absolute/reviewed-templates --template http/cves/2023/CVE-2023-23752.yaml --report /absolute/evidence/new-receipt.json > /absolute/evidence/result.jsonl
```

`--report` 必須是尚不存在的檔案；執行失敗時仍可能已送出流量，保留部分證據。stdout、stderr 與 receipt 分開保存。命令中的模板名稱與目標需先通過本次的適用性審查。

每個 CVE 記錄：官方公告／修補參考、實際產品版本與組態、授權目標、工具執行版本及 hash、模板 commit／hash、必要前提、正向證據、正常對照、可能誤報、實際影響、限制與複測結果。未知內容保持未知。

| 結果 | 判讀 |
| --- | --- |
| 只有版本或索引符合 | 待驗證假設 |
| 有命中，缺正常對照／影響證據 | 待反證的工具命中 |
| 前置條件完整、可重現差異與實際影響 | 送交既有 finding 驗證流程 |
| timeout、模板未載入或環境不適用 | 未完成／未涵蓋 |
| 有效測試未命中 | 僅支持本次方法與範圍的陰性結果 |

不要為了驗證 RCE 而預設執行公開 exploit、讀取真實秘密、持久化或造成拒絕服務；若最小驗證仍需要這些行為，核對是否已獲本次明確授權。
