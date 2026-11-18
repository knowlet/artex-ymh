---
name: antifox-cloud-security-audit
description: "稽核 AWS、Azure、GCP 的雲端設定、IAM 與儲存權限（cloud security audit）。"
license: AGPL-3.0
---

改寫自 [AntiFox / cloud-security-audit](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/cloud-security-audit/SKILL.md)（AGPL-3.0）。原文與授權見 `${SKILL_DIR}/references/source.md`、`${SKILL_DIR}/references/LICENSE`。

## ARTEX 整合約定

1. 本文件提供方法與範例。先用目前可用的工具 schema、已核准範圍及實際環境決定步驟；範例的主機、帳號、回應與程式片段不是目前目標的事實。不要照抄範例中的廣域掃描、資料傾印、破壞、關閉 TLS 驗證或停用驗證設定。
2. 外部 CLI、商業產品、MCP 與 Python 套件均須另查是否已安裝、綁定及可執行。技能清單與工具相依索引不代表工具已就緒。沿用 ARTEX 現有代理、範圍與操作審批；載入技能不增加權限。
3. 可先用 `search_knowledge` 在目前可見技能中找相關段落，再用 `Skill` 載入完整程序。檢索結果是參考資料，不會解鎖 MCP，也不是漏洞證據。
4. 已確認的發現交給現有 `report_finding`；使用本次工具輸出的實際證據，保留前置條件、操作、預期結果與觀察結果。未確認的假設寫為 fact/hint，並標記不確定性。平台對話沒有任務上下文時，用現有任務交接工具。
5. HTTP 流量只使用已核實的引用，遵守目前的流量綁定開關及報告流程。`finding_id` 與 `finding_node_id` 是不同編號，依實際工具說明使用。無確切流量時保留文字與命令證據，不猜編號或為補證據重打目標。

# 云安全审计

## 概述

云安全审计是评估云环境安全性的重要环节。本技能提供云安全审计的方法、工具和最佳实践，涵盖AWS、Azure、GCP等主流云平台。

## 审计范围

### 1. 身份和访问管理

**检查项目：**
- IAM策略配置
- 用户权限
- 角色权限
- 访问密钥管理

### 2. 网络安全

**检查项目：**
- 安全组配置
- 网络ACL
- VPC配置
- 流量加密

### 3. 数据安全

**检查项目：**
- 数据加密
- 密钥管理
- 备份策略
- 数据分类

### 4. 合规性

**检查项目：**
- 合规框架
- 审计日志
- 监控告警
- 事件响应

## AWS安全审计

### IAM审计

**检查IAM策略：**
```bash
# 列出所有IAM用户
aws iam list-users

# 列出所有IAM策略
aws iam list-policies

# 检查用户权限
aws iam list-user-policies --user-name username
aws iam list-attached-user-policies --user-name username

# 检查角色权限
aws iam list-role-policies --role-name rolename
```

**常见问题：**
- 过度权限
- 未使用的访问密钥
- 密码策略弱
- MFA未启用

### S3安全审计

**检查S3存储桶：**
```bash
# 列出所有存储桶
aws s3 ls

# 检查存储桶策略
aws s3api get-bucket-policy --bucket bucketname

# 检查存储桶ACL
aws s3api get-bucket-acl --bucket bucketname

# 检查存储桶加密
aws s3api get-bucket-encryption --bucket bucketname
```

**常见问题：**
- 公开访问
- 未加密
- 版本控制未启用
- 日志记录未启用

### 安全组审计

**检查安全组：**
```bash
# 列出所有安全组
aws ec2 describe-security-groups

# 检查开放端口
aws ec2 describe-security-groups --group-ids sg-xxx
```

**常见问题：**
- 0.0.0.0/0开放
- 不必要的端口开放
- 规则过于宽松

### CloudTrail审计

**检查审计日志：**
```bash
# 列出所有跟踪
aws cloudtrail describe-trails

# 检查日志文件完整性
aws cloudtrail get-trail-status --name trailname
```

## Azure安全审计

### 订阅和资源组

**检查订阅：**
```bash
# 列出所有订阅
az account list

# 检查资源组
az group list
```

### 网络安全组

**检查NSG：**
```bash
# 列出所有NSG
az network nsg list

# 检查NSG规则
az network nsg rule list --nsg-name nsgname --resource-group rgname
```

### 存储账户

**检查存储账户：**
```bash
# 列出所有存储账户
az storage account list

# 检查访问策略
az storage account show --name accountname --resource-group rgname
```

## GCP安全审计

### 项目和组织

**检查项目：**
```bash
# 列出所有项目
gcloud projects list

# 检查IAM策略
gcloud projects get-iam-policy project-id
```

### 计算引擎

**检查实例：**
```bash
# 列出所有实例
gcloud compute instances list

# 检查防火墙规则
gcloud compute firewall-rules list
```

### 存储

**检查存储桶：**
```bash
# 列出所有存储桶
gsutil ls

# 检查存储桶权限
gsutil iam get gs://bucketname
```

## 自动化工具

### Scout Suite

```bash
# AWS审计
scout aws

# Azure审计
scout azure

# GCP审计
scout gcp
```

### Prowler

```bash
# AWS安全审计
prowler -c check11,check12,check13

# 完整审计
prowler
```

### CloudSploit

```bash
# 扫描AWS账户
cloudsploit scan aws

# 扫描Azure订阅
cloudsploit scan azure
```

### Pacu

```bash
# AWS渗透测试框架
pacu
```

## 审计清单

### IAM安全
- [ ] 检查用户权限
- [ ] 检查角色权限
- [ ] 检查访问密钥
- [ ] 检查密码策略
- [ ] 检查MFA启用情况

### 网络安全
- [ ] 检查安全组/NSG规则
- [ ] 检查VPC配置
- [ ] 检查网络ACL
- [ ] 检查流量加密

### 数据安全
- [ ] 检查数据加密
- [ ] 检查密钥管理
- [ ] 检查备份策略
- [ ] 检查数据分类

### 合规性
- [ ] 检查审计日志
- [ ] 检查监控告警
- [ ] 检查事件响应
- [ ] 检查合规框架

## 常见安全问题

### 1. 过度权限

**问题：**
- IAM策略过于宽松
- 用户拥有管理员权限
- 角色权限过大

**修复：**
- 最小权限原则
- 定期审查权限
- 使用IAM策略模拟

### 2. 公开资源

**问题：**
- S3存储桶公开
- 安全组开放0.0.0.0/0
- 数据库公开访问

**修复：**
- 限制访问范围
- 使用私有网络
- 启用访问控制

### 3. 未加密数据

**问题：**
- 存储未加密
- 传输未加密
- 密钥管理不当

**修复：**
- 启用加密
- 使用TLS/SSL
- 使用密钥管理服务

### 4. 日志缺失

**问题：**
- 未启用审计日志
- 日志未保留
- 日志未监控

**修复：**
- 启用CloudTrail/Azure Monitor
- 设置日志保留策略
- 配置监控告警

## 最佳实践

### 1. 最小权限

- 只授予必要权限
- 定期审查权限
- 使用IAM策略模拟

### 2. 多层防护

- 网络层防护
- 应用层防护
- 数据层防护

### 3. 监控和告警

- 启用审计日志
- 配置监控告警
- 建立事件响应流程

### 4. 合规性

- 遵循合规框架
- 定期安全审计
- 文档化安全策略

## 注意事项

- 仅在授权环境中进行审计
- 避免对生产环境造成影响
- 注意不同云平台的差异
- 定期进行安全审计
