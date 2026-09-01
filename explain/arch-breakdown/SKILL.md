---
name: arch-breakdown
description: 使用 Why-How-What 框架快速拆解系统设计或重构方案。Use when the user wants to understand the full picture of a system design, architecture decision, or refactoring plan using the Golden Circle (Why-How-What) framework. Trigger on phrases like "架构拆解", "黄金圈", "why-how-what", "设计意图", or when the user asks to break down a technical design document or proposal.
disable-model-invocation: true
---

# 黄金圈架构拆解

对输入内容（$ARGUMENTS）进行黄金圈（Golden Circle）拆解，帮助快速理解这个设计的全貌。

## 输出结构

1. **Why（目的/痛点）**：为什么要做这个？它解决了什么核心业务问题或技术债务？用简单的话说，不做这个会怎样？

2. **How（机制/策略）**：它是如何工作的？核心设计模式或关键机制是什么？提供一个数据流转或状态变化的简单例子来说明。

3. **What（产出/表象）**：最终交付了什么？用户或调用方能看到/用到什么？提供一个具体的 API 请求/响应示例，或 UI 交互示例。

从 Why 出发往往能让读者更快理解设计决策的合理性，因此请确保 Why 部分写得足够清晰具体。
