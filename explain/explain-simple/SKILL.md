---
name: explain-simple
description: 将复杂的代码、报错或文档转化为大白话，并提供具象化示例。Use when the user wants a plain-language explanation of code, error messages, or technical documentation, especially when they say "explain this simply", "用大白话解释", "看不懂", or ask for a beginner-friendly breakdown.
disable-model-invocation: true
---

# 核心概念降维解释

请分析用户提供的输入内容（$ARGUMENTS），或者当前上下文中的代码/文档。

## 输出结构

1. **核心提炼**：用一句话（不超过20个字）总结这段内容的核心目的。
2. **大白话解释**：使用初中生能听懂的简单词汇，解释其中的关键概念或代码逻辑。绝对不要使用未经解释的专业术语。
3. **具象化示例**：
   - 如果是**代码/架构**：提供一个极简的、可运行的伪代码或代码片段示例，展示它在实际中是如何工作的。
   - 如果是**概念/文档**：提供一个生活中的生动类比（如餐厅点餐、快递分拣等）来解释它。

请使用清晰的 Markdown 格式输出，包含适当的表情符号以增加可读性。
