---
name: feynman-analogy
description: 用生活中的实体类比来解释复杂的系统、设计模式或算法。Use when the user wants a real-world analogy to understand a complex system, design pattern, or algorithm — especially when explaining to non-technical people or junior developers. Trigger on phrases like "feynman", "用类比解释", "打个比方", or requests to explain architecture/patterns in simple terms.
disable-model-invocation: true
---

# 费曼代码类比

针对用户提供的输入内容（$ARGUMENTS），使用"费曼学习法"，通过一个**连贯的、生活中的实体类比**（例如：厨房做菜、工厂流水线、图书馆管理、城市交通）来解释这个复杂的系统或算法。

## 输出结构

1. **类比映射**：明确指出输入内容中的"核心组件"分别对应类比中的"什么事物"。
2. **流程对应**：明确指出输入内容中的"数据流/控制流"对应类比中的"什么动作"。
3. **代码验证**：用一段简短的代码（或伪代码）将这个类比"翻译"回技术实现，证明类比的准确性。

类比要连贯——整个解释应该围绕同一个场景展开，不要混用多个不同的类比。
