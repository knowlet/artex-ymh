# Cloudflare Proxy 與 Nginx SNI 強化部署

適用架構：瀏覽器 → Cloudflare（橘雲代理）→ 主機上的 Nginx `443/TLS` → `127.0.0.1:8787` ARTEX。本指南提供設定與驗收方式；套用前仍須準備自己的網域、憑證及來源主機防火牆。

## 防護範圍

| 層級 | 設定與效果 |
| --- | --- |
| 後端監聽 | Docker 預設只將 `8787` 發布到 localhost；原生部署也使用 loopback，避免繞過 Nginx。 |
| TLS | 預設 HTTPS virtual host 使用 `ssl_reject_handshake on`，未知或缺少 SNI 時，在送出網站憑證前拒絕交握。 |
| Cloudflare 來源 | 僅接受官方 IPv4／IPv6 網段的連線來源，判斷依據為 `$realip_remote_addr` 原始連線 IP。 |
| 訪客身分 | 僅信任上述來源提供的 `CF-Connecting-IP`，再覆寫傳給 ARTEX 的轉送標頭。 |
| HTTP Host | 另行驗證 Host，正確 SNI 搭配錯誤 Host 仍不能存取 ARTEX。 |
| 串流與快取 | 保留 Gate POST、SSE、WebSocket；關閉 Nginx 緩衝與快取，並要求 Cloudflare 對此管理網域略過快取。 |

Nginx 沒有名為 `sniStrict` 的指令；對應機制是獨立的預設 TLS server 加上 [`ssl_reject_handshake`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_reject_handshake)。此指令最低需要 Nginx 1.19.4，正式環境應使用仍獲安全更新的版本，並確認包含 HTTP SSL、Real IP 與 Geo 模組。`return 444` 發生於 HTTP 階段，不能單獨達成「送出憑證前拒絕」。

**這個設定控制的是 Cloudflare 到來源主機的 TLS。** 瀏覽器到 Cloudflare 的 TLS 由 Cloudflare 終止，來源端無法改變該段交握，也不能阻止 Cloudflare 在來源連線失敗時顯示自己的錯誤頁。知道正確網域的人仍可送出正確 SNI；若要阻止此人直接取得來源憑證，必須在網路防火牆先擋掉非 Cloudflare 來源。

## 1. 收斂 ARTEX 後端監聽

### Docker

在既有 `.env` 確認：

```dotenv
ARTEX_BIND_IP=127.0.0.1
```

使用仍獲支援、且至少為 **28.0.0** 的 Docker Engine，或另外驗證網路層已有有效隔離。Docker 官方指出，28.0.0 之前的版本可能讓同一 L2 網段上的其他主機存取發布到 localhost 的埠，不能只依賴這項綁定位址判定安全。[Docker 埠發布文件](https://docs.docker.com/engine/network/port-publishing/)

更新後重新建立 ARTEX 容器，讓埠發布設定生效：

```bash
docker compose config --quiet
docker compose up -d --no-deps artex
docker compose ps
```

對外發布應顯示 `127.0.0.1:8787`，錄製代理維持 `127.0.0.1:8788`；PostgreSQL 不發布主機埠。容器內的 ARTEX 仍監聽 `:8787`，其預設 Gate 行為不變。若曾自行關閉 Gate，部署前恢復啟用。

`ARTEX_BIND_IP` 可明確改成其他主機位址，但設定為 `0.0.0.0` 會讓後端繞過本指南的 Nginx 防護；此時必須自行限制網路存取。這份範例假設 Nginx 跑在同一台主機上；若 Nginx 也在容器內，`127.0.0.1` 指的是該 Nginx 容器，不能直接沿用此 upstream。

### 原生程序／systemd

原生程序改綁 loopback 時，ARTEX 的自動判斷會關閉 Gate，因此必須明確啟用：

```bash
ARTEX_GATE=on ./start.sh -addr 127.0.0.1:8787 -proxy 127.0.0.1:8788
```

systemd 使用 `sudo systemctl edit artex` 加入下列 override，將 `/opt/artex/artex` 換成實際二進位路徑：

```ini
[Service]
Environment=ARTEX_GATE=on
ExecStart=
ExecStart=/opt/artex/artex -addr 127.0.0.1:8787 -proxy 127.0.0.1:8788
```

既有 `EnvironmentFile` 的值會覆蓋 `Environment=`；若 `/etc/artex.env` 或其他環境檔設定了 `ARTEX_GATE=off`，也必須改為 `on`。接著執行：

```bash
sudo systemctl daemon-reload
sudo systemctl restart artex
sudo journalctl -u artex -n 30 --no-pager
```

確認啟動紀錄包含 Gate 已啟用，並確認 `8787`、`8788` 僅監聽 loopback。

## 2. 設定 Cloudflare

1. 將使用的 A／AAAA 或 CNAME 記錄設為 **Proxied／橘雲**。若來源未提供 IPv6，就不要建立指向無效來源的 AAAA 記錄。
2. SSL/TLS 模式使用 **Full (strict)**。來源憑證必須未過期、符合此網域，且由公開 CA 或 Cloudflare Origin CA 簽發。不要使用 Flexible；它會改用 HTTP 連來源，與此僅開放 TLS 的設定不相容。[官方條件](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/)
3. 開啟 **Always Use HTTPS**，讓訪客的 HTTP 重新導向在 Cloudflare 邊緣完成。來源不需開放 `80`；憑證可使用 DNS-01 驗證或 Origin CA。
4. 建立適用整個管理網域的 **Cache Rule → Bypass cache**，例如條件 `(http.host eq "artex.example.com")`。確認其他規則不會覆蓋此行為。若曾快取登入頁、Gate 或 API 回應，清除既有快取後再驗收。Nginx 的 `proxy_cache off` 只控制 Nginx，不能代替邊緣規則。
5. 確認 WebSockets 已啟用。使用 Pseudo IPv4 時，選擇 Off 或 Add Header，避免 Overwrite Headers 改寫實際 IPv6 訪客位址。此範例會清除替代的 `CF-Connecting-IPv6` 標頭，使用單一可信的 `CF-Connecting-IP`；不要開啟 Remove visitor IP headers 或其他會移除此標頭的轉換規則。[Cloudflare 標頭規則](https://developers.cloudflare.com/fundamentals/reference/http-headers/)

可另加 Cloudflare Access 限制管理網域的使用者；啟用前確認自動化用戶端與既有路由的認證方式。Access、ARTEX 管理員登入與 Gate 各有不同用途。

## 3. 安裝 Nginx 設定

本倉庫包含：

- [`packaging/nginx/artex-cloudflare.conf.example`](packaging/nginx/artex-cloudflare.conf.example)：放在 `http {}` 內的完整範例，通常透過 `/etc/nginx/conf.d/*.conf` 載入。
- [`packaging/nginx/cloudflare-realip.conf`](packaging/nginx/cloudflare-realip.conf)：僅在 ARTEX server 內載入的訪客 IP 信任設定。
- [`packaging/nginx/cloudflare-peers.geo`](packaging/nginx/cloudflare-peers.geo)：原始連線 IP 的 Cloudflare 網段清單。

先將範例複製到暫存檔，將其中所有 `artex.example.com` 改成你的完整網域名稱，包含 `server_name` 及 Host map；不要改成萬用字元。確認 upstream、憑證路徑與既有 Nginx 設定相容。同一個 IP／埠只能有一個 `default_server`；已有預設 HTTPS server 時，必須整合其拒絕策略，不能直接追加衝突設定。其他 virtual host 仍按各自設定提供服務。

```bash
staged_conf="$(mktemp)"
cp packaging/nginx/artex-cloudflare.conf.example "$staged_conf"
${EDITOR:-vi} "$staged_conf"

nginx_backup="/root/nginx-before-artex-$(date +%Y%m%d-%H%M%S)"
sudo cp -a /etc/nginx "$nginx_backup"
printf 'Nginx backup: %s\n' "$nginx_backup"

sudo install -d -m 755 /etc/nginx/snippets/artex
sudo install -d -m 700 /etc/nginx/ssl/artex
sudo install -m 644 packaging/nginx/cloudflare-realip.conf /etc/nginx/snippets/artex/cloudflare-realip.conf
sudo install -m 644 packaging/nginx/cloudflare-peers.geo /etc/nginx/snippets/artex/cloudflare-peers.geo
```

把你已取得的憑證與私鑰安裝到以下位置；來源檔名依實際情況修改，私鑰不要提交到 Git：

```bash
sudo install -m 644 ./origin-fullchain.pem /etc/nginx/ssl/artex/fullchain.pem
sudo install -m 600 ./origin-private-key.pem /etc/nginx/ssl/artex/privkey.pem
sudo install -m 644 "$staged_conf" /etc/nginx/conf.d/artex.conf
sudo nginx -t && sudo systemctl reload nginx
```

以上權限假設 Nginx master 以 root 讀取私鑰；使用無 root 的 Nginx 時，應改由專用服務帳號持有並保留最小讀取權限。憑證鏈應先放網站憑證，再放必要的中繼憑證。

**`nginx -t` 未通過就不要 reload。** 還原本次變動後再檢查，避免後續其他維護觸發 reload 時載入半套設定。

### 為什麼來源檢查與 Real IP 分開？

Real IP 模組會將 `$remote_addr` 改成訪客 IP，`$realip_remote_addr` 則保留連到 Nginx 的原始對端。此範例以後者判斷是否為 Cloudflare，再使用經驗證的訪客 IP 覆寫 `X-Real-IP`、`X-Forwarded-For` 與 `CF-Connecting-IP`。不能在改寫後對 `$remote_addr` 套用 Cloudflare IP 白名單，否則一般訪客會被誤擋。[Nginx Real IP 文件](https://nginx.org/en/docs/http/ngx_http_realip_module.html)

範例假設 Cloudflare 直接連到 Nginx。若中間還有負載平衡器或其他代理，原始對端就會不同；應另外設計該段身分驗證與可信代理鏈，不能直接把所有私有網段加入信任清單。

## 4. 來源防火牆與可選 AOP

在雲端安全群組或主機防火牆，僅允許 [Cloudflare 官方 IPv4／IPv6 網段](https://www.cloudflare.com/ips/) 存取 TCP `443`。IPv4 與 IPv6 都要涵蓋；管理用 SSH／VPN 規則另行保留。`8787`、`8788`、PostgreSQL 與本指南不需要的 `80` 不應對公網開放。確認 Docker 實際的埠發布與封包過濾路徑，不能只假設主機防火牆規則已涵蓋容器流量。

Nginx 的 Cloudflare 來源判斷在 HTTP 階段執行。因此非 Cloudflare 對端若送出正確 SNI，可能先取得來源憑證，再被關閉 HTTP 連線；要在交握前阻擋它，必須使用上述網路層規則。

若要加上 **Authenticated Origin Pulls（AOP）**，先依 [Cloudflare 官方步驟](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) 配置 Cloudflare 的用戶端憑證與 Nginx 信任的 CA，再啟用範例中的 `ssl_client_certificate`／`ssl_verify_client on`。不要把簽發伺服器憑證的 Origin CA 與驗證 AOP 用戶端憑證的 CA 混用。

Cloudflare IP 白名單與共用的全域 AOP 憑證只能證明流量來自 Cloudflare 基礎設施，不能證明屬於你的 zone。需要該身分邊界時，採用自己管理的 zone／hostname AOP 憑證。AOP 保護來源存取，並不隱藏 TLS 伺服器憑證。

## 5. 驗收

先執行倉庫內的本地整合測試；它需要 Python 3、OpenSSL 與可執行的 Nginx，使用暫存憑證、非特權埠及模擬上游：

```bash
python3 scripts/test_nginx_hardening.py
```

正式套用後，在來源主機測試拒絕未知／缺少 SNI：

```bash
openssl s_client -connect 127.0.0.1:443 -servername rejected.invalid -showcerts </dev/null
openssl s_client -connect 127.0.0.1:443 -noservername -showcerts </dev/null
```

預期為 TLS 交握失敗，且沒有 `BEGIN CERTIFICATE` 憑證內容；僅收到 HTTP 錯誤不算通過。可分別加上 `-tls1_2` 與 `-tls1_3` 驗證兩個版本。

再以實際網域透過 Cloudflare 檢查：

| 操作 | 預期結果 |
| --- | --- |
| 以 HTTPS 網域開啟正確 Gate 路徑並提交密碼 | POST 保留，成功後登入流程正常，Cookie 帶有 Secure。 |
| 登入後使用活動流 | SSE 事件逐筆到達，不會直到連線結束才一次出現。 |
| 使用需要 WebSocket 的頁面 | Upgrade 成功，雙向流量可用。 |
| 已登入頁面、Gate 與 API | Cloudflare 不命中舊快取；其他瀏覽器不取得前一位使用者的資料。 |
| 非 Cloudflare 網路直接連來源 `443` | 防火牆拒絕；僅配置 Nginx 時，正確 SNI 可交握但 HTTP 不到達 ARTEX。 |
| 非 Cloudflare 來源偽造 `CF-Connecting-IP`／XFF | 無法因此取得來源信任。 |
| 正確 SNI 搭配錯誤 Host | 不能到達 ARTEX。 |
| 從外部連來源 `8787`、`8788` 或 PostgreSQL | 不能建立連線。 |

來源防火牆生效後，從非 Cloudflare 網路直接測試 SNI 會先被防火牆阻擋；這不能代替上述來源主機內的 TLS 測試。倉庫測試驗證的是本地代理行為，正式 Cloudflare 路徑及實際 ARTEX 登入仍需完成這張驗收表。

## 6. 維護、限制與回復

- 兩份 Cloudflare 清單是帶日期的快照。部署前及更新時，同時核對 [IPv4](https://www.cloudflare.com/ips-v4/) 與 [IPv6](https://www.cloudflare.com/ips-v6/) 官方資料，將完全相同的 CIDR 集合更新到 `cloudflare-realip.conf`、`cloudflare-peers.geo` 及防火牆。先在暫存檔檢查有效 CIDR，不能把空回應、錯誤頁或 `0.0.0.0/0`／`::/0` 當成信任清單；兩份檔案完整安裝並通過 `nginx -t` 後才 reload。
- Nginx 的長逾時不能放寬 Cloudflare 自己的連線限制。SSE 應持續送出事件／心跳，WebSocket 用戶端仍需重連機制；長時間沒有回應的操作可能被邊緣中斷。[Cloudflare 連線限制](https://developers.cloudflare.com/fundamentals/reference/connection-limits/)
- 範例的 `client_max_body_size 512m` 配合 ARTEX 現有工作區上傳上限；Cloudflare 方案的請求大小限制可能更低，不能以此設定推定大型上傳一定可通過邊緣。部署時依實際需要縮小此值，並驗收常用檔案大小。[Cloudflare 413 與請求大小限制](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/)
- ARTEX 現有 Gate 限速使用 Go `r.RemoteAddr`。經 Nginx 轉送時，使用同一代理對端的訪客會共用 **每分鐘 10 次**密碼嘗試額度；本設定不會讓應用程式自動信任轉送標頭，也不代表 Gate 已具備每位訪客獨立限速。多人登入時應留意這項既有限制。
- Cloudflare 的一般代理不會替所有任意 TCP 埠提供轉送；此設定涵蓋管理介面的 HTTP／HTTPS。其他服務的連線路徑須另外規劃。

回復時，使用先前記錄的備份路徑，還原本次修改過的 Nginx 設定、兩份 include 及憑證檔案；首次新增且備份中不存在的檔案則移出啟用目錄。保留其他人在此期間所作的無關變更。執行 `sudo nginx -t` 成功後再 `sudo systemctl reload nginx`，並驗證原有服務。若需回復 systemd override，只移除本次新增的項目，再 daemon-reload／重啟 ARTEX。

不要為了回復 Nginx 而直接將 `8787` 改成對公網開放；可先透過 SSH tunnel 或管理網路維護服務。研究依據與設計決策見 [`packaging/nginx/RESEARCH.md`](packaging/nginx/RESEARCH.md)。
