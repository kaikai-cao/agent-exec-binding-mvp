# D4：Agent 执行绑定与持久化恢复集成核查

## 1. 阶段目标

核查 MVP 授权机制与 E4.8.3 持久化执行机制的集成情况，重点确认：

1. 父级授权能否正确绑定到子级执行授权。
2. 操作身份、上下文、请求摘要和授权随机数能否贯穿执行链。
3. 全局预算能否在持久化执行过程中保持一致。
4. 执行中断后能否恢复已有状态，避免重复消费预算或重复产生模拟工具结果。
5. Gateway 回执与原始工具回执能否得到验证。

## 2. D4.1：集成链路核查

已核查 MVP 与 E4.8.3 的关键源码及测试。

当前集成链路：

MVP Parent Grant → IntegrationCoordinator → Child LeaseGrant → ExecutionBindingGateway → DurableCounterBroker → E483MockFinanceAdapter。

Coordinator 验证父级授权后，生成与父级授权摘要、Nonce、Operation ID 绑定的 Child LeaseGrant，再交由持久化 Gateway 执行。

执行完成后，Coordinator 验证 Gateway Receipt 和原始 MVP Tool Receipt，并写入 Parent AuditChain。

## 3. D4.2：持久化与恢复机制核查

确认底层已有以下机制：

- Child Grant 关键字段可确定性重建。
- DurableCounterBroker 使用 SQLite Journal 和文件计数器模拟器记录预算状态。
- ExecutionJournal 持久化操作状态、授权绑定、预算序号及回执。
- Gateway 能够识别已提交操作、恢复已有工具结果，并对无法确认的状态采取 INDETERMINATE 处理。
- Adapter 使用 SQLite 持久化模拟工具结果及原始回执。

同时发现 D1 集成层此前缺少完整对象栈重建后的恢复测试。

## 4. D4.3：D1 对象栈重建恢复验证

新增两个恢复测试：

1. `test_process_restart_recovers_after_tool_effect_before_receipt`
2. `test_process_restart_recovers_after_gateway_receipt_commit`

测试重建 Parent Gateway、Adapter、Broker、ExecutionBindingGateway 和 Coordinator，再使用相同授权及操作请求恢复执行。

### 场景一：工具结果已持久化，Gateway Receipt 尚未提交

验证结果：

- 中断发生后，模拟工具结果持久化记录数量为 1。
- 预算计数为 1。
- 重建对象栈后，使用相同操作请求恢复。
- 恢复后 Journal 状态为 COMMITTED。
- 模拟工具结果记录数量仍为 1。
- 预算计数仍为 1。

### 场景二：Gateway Receipt 已提交，Parent AuditChain 尚未更新

验证结果：

- 中断发生后，Journal 状态为 COMMITTED。
- 已从 Journal 读取持久化的 Gateway Receipt。
- 重建对象栈后，使用相同操作请求恢复。
- 恢复调用返回原先持久化的 Gateway Receipt。
- 模拟工具结果记录数量仍为 1。
- 预算计数仍为 1。
- Parent AuditChain 得到更新，签名验证通过。

## 5. 测试结果

| 测试范围 | 结果 |
|---|---:|
| D1 集成测试 | 9/9 通过 |
| MVP 原有回归测试 | 80/80 通过 |

测试环境及执行结果来自本地实验记录。

## 6. 证据边界与未解决问题

本阶段结果不能解释为已经证明任意真实外部工具的 exactly-once 执行能力。

具体限制：

1. Adapter 包装的是只读 MockFinanceTool，SQLite 记录数量不能代表任意外部系统的真实副作用次数。
2. D4.3 是同一 Python 进程内的完整对象栈重建，不是独立 OS 进程退出后的端到端恢复测试。
3. Parent AuditChain 仍是内存实现，尚未验证其自身的持久化恢复。
4. FileBackedCounter 是软件模拟器，不是 TPM NV Counter 或其他硬件可信计数器。
5. SQLite 幂等工具测试不能直接推论任意外部 API、数据库或支付系统具有 exactly-once 语义。

## 7. 阶段结论

D4 阶段目标基本完成。

已有证据表明：MVP 授权绑定机制能够与 E4.8.3 持久化预算及执行状态管理机制集成；在两个关键中断窗口下，完整 D1 对象栈重建后能够恢复执行状态，避免重复消费预算和重复写入模拟工具结果。

**D4 验收状态：通过，附带上述证据边界。**

当前新增测试及本记录属于本地工作区内容，尚未推送到远程 GitHub 分支。本阶段不提交、不推送。

## 8. D5 后续计划

进入 D5：独立进程恢复验证。

保持现有架构和协议不变，使用独立 OS 进程模拟执行中断和重新启动，优先验证：

- 工具结果已持久化、Gateway Receipt 未提交；
- Gateway Receipt 已提交、上层审计未完成；
- 重启后预算不重复消费；
- 重启后不重复产生模拟工具结果；
- 已提交回执能够恢复。

D5 继续区分模拟环境验证与真实外部工具的执行语义，不将工程测试结果扩大解释为普遍安全保证。
