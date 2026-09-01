---
name: jargon-buster
description: 识别并翻译输入内容中最晦涩的技术术语或行业黑话。Use when the user is confused by jargon-heavy docs, specs, or error messages and wants plain-language translations of technical terms. Trigger on phrases like "术语太多", "看不懂这些词", "jargon", "行话", or when the user pastes dense technical text and asks what it means.
disable-model-invocation: true
---

# 技术术语粉碎机

分析输入内容（$ARGUMENTS），识别出其中最晦涩、最容易让人迷惑的 3 个技术术语或行业黑话。

## 每个术语的输出格式

- **术语名称**
- **人话翻译**：用一句大白话解释它到底是什么。
- **为什么需要它**：用简单的话说明它解决了什么痛点（如果不使用它会怎样）。
- **代码/场景示例**：给出一个具体的代码片段或业务场景，展示这个术语在"使用前"和"使用后"的区别。

选择真正让人困惑的术语，而不是显而易见的词。优先挑选那些"字面意思"和"实际含义"差距最大的词。
