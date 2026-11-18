---
name: antifox-incident-response
description: "規劃資安事件分流、證據保存、圍堵、復原與後續調查（incident response）。"
license: AGPL-3.0
---

改寫自 [AntiFox / incident-response](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/incident-response/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# 安全事件响应

## 概述

安全事件响应是处理安全事件的关键流程。本技能提供安全事件响应的方法、工具和最佳实践。

## 响应流程

### 1. 准备阶段

**准备工作：**
- 建立响应团队
- 制定响应计划
- 准备工具和资源
- 建立通信渠道

### 2. 识别阶段

**识别事件：**
- 监控告警
- 异常检测
- 日志分析
- 用户报告

### 3. 遏制阶段

**遏制措施：**
- 隔离受影响系统
- 禁用账户
- 阻断网络连接
- 备份证据

### 4. 清除阶段

**清除威胁：**
- 移除恶意软件
- 修复漏洞
- 重置凭证
- 清理后门

### 5. 恢复阶段

**恢复系统：**
- 恢复备份
- 验证系统完整性
- 监控系统
- 逐步恢复服务

### 6. 总结阶段

**总结经验：**
- 事件报告
- 经验教训
- 改进措施
- 更新流程

## 工具使用

### 日志分析

**使用Splunk：**
```bash
# 搜索日志
index=security event_type="failed_login"

# 统计分析
index=security | stats count by src_ip

# 时间序列分析
index=security | timechart count by event_type
```

**使用ELK：**
```bash
# Elasticsearch查询
GET /logs/_search
{
  "query": {
    "match": {
      "event_type": "malware"
    }
  }
}
```

### 取证工具

**使用Volatility：**
```bash
# 分析内存镜像
volatility -f memory.dump imageinfo

# 列出进程
volatility -f memory.dump --profile=Win7SP1x64 pslist

# 提取进程内存
volatility -f memory.dump --profile=Win7SP1x64 memdump -p 1234 -D output/
```

**使用Autopsy：**
```bash
# 启动Autopsy
# 创建案例
# 添加证据
# 分析数据
```

### 网络分析

**使用Wireshark：**
```bash
# 捕获流量
wireshark -i eth0

# 分析PCAP文件
wireshark -r capture.pcap

# 过滤流量
# 显示过滤器: ip.addr == 192.168.1.100
# 捕获过滤器: host 192.168.1.100
```

**使用tcpdump：**
```bash
# 捕获流量
tcpdump -i eth0 -w capture.pcap

# 分析流量
tcpdump -r capture.pcap -A
```

## 事件类型

### 恶意软件

**响应步骤：**
1. 隔离受影响系统
2. 收集样本
3. 分析恶意软件
4. 清除威胁
5. 修复漏洞

**工具：**
- VirusTotal
- Cuckoo Sandbox
- YARA规则

### 数据泄露

**响应步骤：**
1. 确认泄露范围
2. 遏制泄露
3. 评估影响
4. 通知相关方
5. 修复漏洞

**检查项目：**
- 泄露数据量
- 受影响用户
- 泄露渠道
- 数据敏感性

### 拒绝服务

**响应步骤：**
1. 确认攻击类型
2. 启用防护措施
3. 过滤恶意流量
4. 监控系统状态
5. 恢复正常服务

**防护措施：**
- DDoS防护服务
- 流量清洗
- 限流措施
- CDN防护

### 未授权访问

**响应步骤：**
1. 禁用受影响账户
2. 重置凭证
3. 检查访问日志
4. 评估数据访问
5. 修复漏洞

**检查项目：**
- 访问时间
- 访问内容
- 访问来源
- 数据修改

## 响应清单

### 准备阶段
- [ ] 建立响应团队
- [ ] 制定响应计划
- [ ] 准备工具
- [ ] 建立通信渠道

### 识别阶段
- [ ] 确认事件
- [ ] 收集信息
- [ ] 评估影响
- [ ] 记录时间线

### 遏制阶段
- [ ] 隔离系统
- [ ] 禁用账户
- [ ] 阻断连接
- [ ] 备份证据

### 清除阶段
- [ ] 移除威胁
- [ ] 修复漏洞
- [ ] 重置凭证
- [ ] 验证清除

### 恢复阶段
- [ ] 恢复系统
- [ ] 验证完整性
- [ ] 监控系统
- [ ] 恢复服务

### 总结阶段
- [ ] 编写报告
- [ ] 总结经验
- [ ] 改进措施
- [ ] 更新流程

## 最佳实践

### 1. 准备

- 建立响应团队
- 制定响应计划
- 定期演练
- 准备工具

### 2. 响应

- 快速响应
- 系统化处理
- 记录所有操作
- 保护证据

### 3. 沟通

- 内部沟通
- 外部通知
- 状态更新
- 事后报告

### 4. 改进

- 事件分析
- 流程改进
- 工具更新
- 培训提升

## 注意事项

- 快速响应
- 保护证据
- 记录操作
- 遵守法律法规
