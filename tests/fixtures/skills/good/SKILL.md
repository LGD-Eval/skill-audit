---
name: sample-good
description: 生成月度账单报告并自动发送邮件，支持批量任务与失败重试。当用户说「帮我出账单」时使用。触发词：账单、月报。
version: 1.0.0
license: MIT
allowed-tools: Read, Write
platforms: [windows, macos, linux]
tags: [报表, 自动化]
read_when:
  - 用户要求生成账单
---
# Sample Good

## 何时用
用户要求出账单时。

## 何时不用
仅查询历史、不需要生成新文件时。

## 用法
运行脚本并检查输出目录。注意：会覆盖同名文件（不可逆），请先备份。
