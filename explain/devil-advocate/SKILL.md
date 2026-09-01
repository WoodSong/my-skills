---
name: devil-advocate
description: 总结技术方案后，扮演"杠精"指出极端情况下的潜在缺陷并提供翻车示例。Use when the user wants to stress-test a code snippet or technical proposal by finding edge cases, concurrency issues, and failure scenarios. Trigger on phrases like "魔鬼代言人", "杠精", "devil's advocate", "有什么问题", "会不会翻车", or when the user asks to find flaws in a design.
disable-model-invocation: true
---

# 方案魔鬼代言人

针对用户提供的代码或技术方案（$ARGUMENTS），分两个阶段输出。

## 第一阶段：正向总结

用简单的话总结这个方案的核心意图，并给出一个它**能完美工作**的正面示例，让读者先理解方案的优点。

## 第二阶段：魔鬼代言人

切换角色，扮演"魔鬼代言人（杠精/资深QA）"：

1. 指出这个方案在极端情况、并发场景或边缘条件下**可能失败**的 2-3 个原因。
2. 对于每一个潜在问题，提供一个具体的**"翻车"示例**：
   - 会导致死锁的代码片段
   - 会导致数据不一致的时序图描述
   - 导致 OOM 的极端输入
   - 或其他具体的失败场景
3. 给出简单的修复建议。

挑最有杀伤力的问题，而不是鸡蛋里挑骨头。真正危险的边界情况比显而易见的小问题更有价值。
