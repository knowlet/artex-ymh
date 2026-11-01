# Grok 訂閱登入（xAI OAuth）

ARTEX 可以透過 xAI 的公開 OAuth device-code 流程，以 Grok 帳號的訂閱權限
使用 `https://api.x.ai/v1/responses`。預設模型為 `grok-4.6`；模型權限與額度
以 xAI 對該帳號的判定為準。這個選項不需要貼上 `sso` cookie 或 API key。

xAI 的[官方公告](https://x.ai/news/grok-hermes)明確支援 Hermes 訂閱整合。
ARTEX 參考 Hermes 與 Agno 的公開協定實作，使用相同公開 OAuth client；
這不表示 ARTEX 已獲 xAI 個別認證，也不保證所有訂閱方案都能使用每個模型。
查證日期、固定版本與授權見[研究紀錄](research/grok-subscription-oauth.md)
及 [OAuth 來源與限制](../xaioauth/REFERENCE.md)。

## 從介面登入

1. 以 ARTEX 管理員身分開啟「系統 → LLM」。
2. 新增設定，選擇 **Grok 訂閱（OAuth）**。
3. 按登入，開啟顯示的 xAI 官方驗證連結，核對畫面的驗證碼並批准存取。
   可以在手機瀏覽器完成；伺服器不需要桌面瀏覽器，也不需要本機 callback 或 SSH tunnel。
4. 等 ARTEX 顯示已登入後，選擇模型、儲存並啟用設定。
5. 需要確認帳號是否真的可推論時，使用既有的「測試連線」按鈕。
   這一步會發出實際模型請求，可能消耗訂閱額度；登入狀態本身不會呼叫模型。

每個 ARTEX 執行個體共用一組 xAI 訂閱登入；所有 `xai-oauth` profiles 共享它。
登入資訊不會出現在 profile JSON、API-key 欄位、前端儲存空間或對話提示中。
訂閱 profile 支援既有 Responses 串流、非串流、工具呼叫與用量記錄。
模型清單直接從 xAI 查詢，沒有權限時仍可手動輸入帳號支援的模型 ID。

## CLI 與無瀏覽器伺服器

```bash
# 登入：印出連結與驗證碼，在任意瀏覽器批准
./artex auth login xai-oauth

# 只查本機憑證狀態，不連線 xAI 或資料庫
./artex auth status xai-oauth

# 登出這個執行個體，移除本機 token 並使待完成的登入失效
./artex auth logout xai-oauth
```

CLI 與後端應使用同一個作業系統帳號、相同 `ARTEX_KEY_DIR`。有自訂 `-data`
路徑時，CLI 也要傳相同 `--data`，以驗證憑證位置在資料目錄之外。例如：

```bash
ARTEX_KEY_DIR=/var/lib/artex-keys ./artex auth login xai-oauth --data /var/lib/artex/data
```

也可用 `--key-dir DIR` 明確指定現有的 key 目錄。CLI 登入完成後，在已啟動
的後端重新啟用該 profile；使用網頁登入會自動更新後端的連線狀態。

純環境變數設定支援：

```bash
ARTEX_LLM_PROVIDER=xai-oauth
ARTEX_LLM_MODEL=grok-4.6
```

後端已有啟用的資料庫 profile 時，仍以該 profile 為準。需要自有已註冊 OAuth
client 的部署可設定 `ARTEX_XAI_CLIENT_ID`；它是 public client ID，不是密鑰。
OAuth 授權與 refresh 直接連線官方 `auth.x.ai`；profile 的 Proxy 僅作用於模型請求。

## 憑證保存與登出

Token 存在有效 key 目錄下的 `xai-oauth/session.json`，與 `jwt.key` 同屬私密
設定位置，不放在可瀏覽的 `data/` 工作區。Unix 使用 `0700` 目錄與 `0600`
檔案，寫入採同目錄暫存、同步與原子替換；跨程序鎖避免同時使用已旋轉的
refresh token。Docker 的既有 `ARTEX_KEY_DIR` volume 必須持續保存。

Windows 的 Unix mode bits 不等同 ACL；請使用只允許服務帳號存取的 NTFS
目錄。本次 Windows 驗證若僅交叉編譯，不代表已完成實機 ACL 與登入測試。

`status` 顯示的是本機登入狀態；已過期的 access token 會在下次請求時更新，
refresh token 遭撤銷則要求重新登入。登出會移除本機憑證並取消未完成登入，
既有快取 provider 的後續請求也無法再使用該 token。已送出的模型請求可能
仍會完成。需要撤銷上游授權時，請在 xAI 帳號設定中撤銷。

## 訂閱與付費 API 的界線

`xai-oauth` 不會讀取 `XAI_API_KEY`、`OPENAI_API_KEY` 或其他 profile 的金鑰。
訂閱額度用盡、登入失效或權限不足時會回報錯誤，不會自動切換到付費 profile，
包括模型 pool 與任務的明確 profile chain。若要改用按量計費 API，需自行
選擇相應 API-key profile；不要把訂閱 token 貼進 API Key 欄位。

| 狀態 | 處理方式 |
| --- | --- |
| 等待批准／過期／使用者拒絕 | 在授權時間內批准，或重新發起登入；可隨時取消。 |
| HTTP 401 | 只嘗試一次重新取得 token；失效的 refresh grant 會停止重播並提示重新登入。 |
| HTTP 403 | 檢查帳號、訂閱與模型權限。重新登入不會增加 entitlement。 |
| HTTP 402／額度用盡 | 等待額度恢復或在 xAI 檢查方案，不自動使用付費 API key。 |
| HTTP 429 | 遵循目前 provider 的重試與呼叫逾時；OAuth device polling 的 `slow_down` 會增加等待時間。 |
| 檔案權限或路徑錯誤 | 修正私密 key 目錄的權限與掛載；不會覆寫不安全的檔案或跟隨 token 檔案符號連結。 |

## 驗證範圍

新增自動化測試使用本機 HTTP/TLS fixture 與一次性 PostgreSQL，涵蓋登入、
拒絕／取消／過期、refresh token 旋轉、併發鎖、登出後不可復活、redirect
拒絕、敏感資訊遮罩、Responses 文字與工具串流、profile 儲存，以及訂閱
不得轉到付費模型的路由。CLI 另以實際編譯執行檔驗證無資料庫啟動的 status。

未使用真實帳號登入或執行 xAI 推論，因此不能把 fixture 通過解讀為你的
訂閱已被驗證可用。最新執行結果與 commit 對應以 PR 與 GitHub Actions 為準。

回復舊版前，先把 `xai-oauth` profiles 刪除或轉成其他格式，再回復程式碼；
舊版的 PostgreSQL format CHECK 不認得此新值。停用功能可先改選其他 profile
並登出，不需要刪除既有對話或任務資料。
