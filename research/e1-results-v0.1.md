# Agent Execution Binding — E1 阶段实验结果 v0.1（冻结）

**状态：** **E1 阶段结果冻结（R3 数据首次落地）**。用户已于 2026-11-12 完成 E1 阶段结果验收，判定**通过**。
**日期：** 2026-11-12
**配套基线（冻结，不回改）：** `threat-model-v0.1.md`、`security-properties-v0.1.md`、`attack-experiment-matrix-v0.1.md`
**本文件与基线的关系：** 基线 v0.1 冻结的是**怎么做、记什么、怎么判**，其 §8 结果表与 §9 结论模板在冻结时全空，**本版不回填、不回改基线**；R3 实际数据单独落在本文，供后续研究报告引用。若后续实验与 v0.1 预期不符，以 **v0.2 修订**，不回改 v0.1。
**本轮约束：** 未改代码、未改既有测试、未改 README、未改三份 v0.1 基线、未碰 Halo2、未跑实验、未提交、未推送。仅新增本文件。

---

## 0. 冻结范围与表述纪律

1. **「通过」的含义**：用户明确说明，该验收是**基于实验记录的结果验收，不是独立审查本地测试实现**；本文件不把验收结论写成「实现已被独立审查」或「安全性质已被证明」。
2. **四组计数禁止合并**：E1.1 / E1.2 / E1.3-a / E1.3-b 是四种不同攻击能力（ATK-A1 / A2 / A3 / A4）、不同拒绝层、不同 $N$ 定义，**不得求和、不得合成「总体攻击成功率」**。
3. **三率分离**：E1 四组全部为**执行前预防性**场景（$ASR=0$、$PR=1$），副作用发生数为 0，故 **$DR$ 分母为 0，记为「不适用」**；完整三率口径保留给 E2。
4. **不称统计显著性**：每臂 10 次独立 Grant / nonce 只用于验证稳定性，**不构成统计显著性证明**，不换算 p 值或置信区间。
5. **证据等级**：本文为 **R3（本阶段新实验）**；上一阶段 80/80 与四组变异反证是 **R2**，仅作交叉引用，**不冒充本阶段结论**；基线中的静态核对为 R0/R1。
6. **结论口径**：只写「在当前实现、单进程内存状态、mock 只读工具、无 LLM 接入的研究原型与测试条件下」；不外推为生产系统、分布式部署或端到端 ZK 系统。

---

## 1. 四组实验原始结果（R3）

### 1.1 E1.1 — 请求替换 `Sales → Finance`（ATK-A1 / P1、P3）

注入点：`ToolCall.args["where"]["department"] = "Finance"`，Grant 仍绑定 Sales；10 次独立 Grant / nonce。
测试入口：`test_request_tampering_after_authorization_denied`（扩为 10 次）、`test_e1_1_adapter_counter_detects_a_real_execution`（计数器有效性自检）。

| Run | Adapter execute | Gateway | Audit `decision` | `reason` | 拒绝层 |
| --- | --- | --- | --- | --- | --- |
| 1–10（逐次） | 0 | DENY (`AuthorizationError`) | DENY | `request differs from the authorized request` | `request_hash` L452–453 |

**原始计数**：`0/10` 越权执行、`10/10` Gateway 拒绝、`10/10` `DENY` 审计、`10/10` request hash mismatch；10 个 nonce 互不相同；`AuditChain.verify()` 全部 `True`。

**变量隔离证据**（本组最关键）：`policy.check(tampered)` 单独调用 **10/10 通过**，即 Finance 仍是 `Policy-compliant`；`nonce_consumed=false` 10/10，拒绝位置钉在 L452（早于 L465 策略复核与 L476 nonce 消费）。审计中的 `request_hash` 记录的是被篡改请求，且不等于 Grant 绑定哈希。
**排除假阴性**：同一 `_CountingTool` 在良性请求下 `execute_count=1`、`ALLOW_EXECUTED`，证明 `0` 是真实的「未执行」而非计数器未接上。

> **结论**：`Policy-compliant ⇏ Grant-authorized`。即使替换后的请求符合一般策略，也不能替换已签发 Grant 绑定的具体请求。

### 1.2 E1.2 — 上下文替换 `tenant_id`（ATK-A2 / P2）

原始上下文 `session_id=S1`、`task_id=T1`、`tenant_id=tenant:example`（记为 A，demo policy 允许）；仅把 `tenant_id` 改为 `tenant:B`；`ToolCall`、`session_id`、`task_id` 全程不变。10 次独立 Grant / nonce。
测试入口：`test_e1_2_baseline_context_matches_grant`、`test_e1_2_tenant_substitution_denied_10_runs`。

**良性对照（1 次）**

| Adapter execute | Gateway | Audit `decision` | receipt.context_hash == Grant.context_hash | `AuditChain.verify()` |
| --- | --- | --- | --- | --- |
| 1 | ALLOW | `ALLOW_EXECUTED` | True | True |

**攻击运行（10 次）**

| Run | Adapter exec | Gateway | Audit `decision` | `reason`（实测） | 拒绝层 | Nonce consumed |
| --- | --- | --- | --- | --- | --- | --- |
| 1–10（逐次） | 0 | DENY | DENY | `execution context differs from authorized context` | `context_hash` L454–455 | No |

**原始计数**：`0/10` 越权执行、`10/10` `request_hash` 检查通过、`10/10` `context_hash` 层拒绝、`10/10` Gateway 拒绝、`10/10` 审计 `DENY`、`0/10` nonce 被消费；10 个 nonce 互不相同；`AuditChain.verify()` `10/10`。

**变量隔离证据**：`request_hash == digest(call)` 为 True，说明 L452 通过、拒绝发生在更靠后的 L454–455；单独调用 `policy.check(篡改上下文)` 返回 `tenant context does not match policy`，**但 Gateway 未到达 L465**。拒绝原因由**只读探测先取实测值**、再写断言，未复制 E1.1 的字符串。

> **结论（按用户限定）**：在当前实现和测试条件下，替换 `tenant_id` 会被 Context Hash 绑定机制检测并在 Adapter 执行前拒绝。**本组只验证 `tenant_id`，不声称 `session_id` / `task_id` 已分别完成验证。**

### 1.3 E1.3-a — 顺序重放（ATK-A3 / P4）

同一 Grant 原样提交两次（不重签、不换 nonce、不改请求与上下文）；10 组独立 Grant / nonce。
测试入口：`test_e1_3_a_sequential_replay_10_groups`。

| Group | Call 1 | Call 2 | `reason`（实测） | 拒绝层 | Adapter exec | Audit 顺序 | Chain |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1–10（逐组） | ALLOW（1 row） | DENY | `grant replay detected` | L477→L478（nonce 原子块 L476–480） | 1 | `ALLOW_EXECUTED → DENY` | OK |

**原始计数**：`10/10` 首次成功、`10/10` 第二次拒绝、Adapter 总执行 **10**（每组恒 1）、**重放导致的额外执行 0**；nonce 首次后已消费 `10/10`；`AuditChain.verify()` `10/10`。第二次提交时验签 / `request_hash` / `context_hash` / `policy.check` 均通过，故拒绝只可能落在 nonce 层。

### 1.4 E1.3-b — 并发重放（ATK-A4 / P4）

每组两线程共享完全相同的 Grant / ToolCall / Context，使用**测试侧阻塞 Adapter**（`_BlockingCountingTool`，Event 同步 + 计数锁，不依赖固定 `sleep` 制造竞争）；10 组独立 Grant / nonce。
测试入口：`test_e1_3_b_concurrent_replay_10_groups`。

| Group | Outcomes（实测） | `reason`（实测） | 重叠证据 | Adapter exec | Audit 顺序 | Chain |
| --- | --- | --- | --- | --- | --- | --- |
| 1–10（逐组） | T1 ALLOW / T2 DENY | `grant replay detected` | Yes | 1 | `DENY → ALLOW_EXECUTED` | OK |

**「Yes」的操作化定义（10/10 满足）**：T1 已进入 `Adapter.execute()` 且尚未释放时 T2 才提交；且 T2 在 `release` 之前已拿到结果。断言按 `sorted(outcomes) == [ALLOW, DENY]`，**未写死线程身份**。
**原始计数**：每组恰好 1 成功 + 1 拒绝、Adapter 总执行 **10**、重复执行 **0**；nonce 已消费 `10/10`；`AuditChain.verify()` `10/10`。

**只读核对结论（实施前）**：原 `test_replay_denied` 只断言「第二次抛异常」，无计数 / reason / 审计 / nonce 校验；现有 `_GatedNonceSet` 阻塞的是 `set.__contains__`（nonce 尚未消费、首次执行尚未开始），验证的是 check-and-consume 原子性，**不能覆盖「首次执行进行中被重放」**，故新增阻塞 Adapter 夹具，原有并发测试全部保留未动。

> **审计观测**：顺序场景为 `ALLOW_EXECUTED → DENY`，并发场景为 **`DENY → ALLOW_EXECUTED`**（T1 阻塞在 Adapter 内，成功后才写审计）。两者 decision 集合相同且链有效，审计如实反映并发时序。
> **表述边界**：本轮用 Event 同步确定重叠时序而非 sleep 窗口，但**不宣称严格证明并发原子性**；顺序与并发分别统计，未合并成单一比例。

### 1.5 汇总（仅并列展示，禁止合并）

| 实验 | 攻击能力 | 独立实例数 | 越权 / 额外执行 | 拒绝层 | $ASR$ | $PR$ | $DR$ |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E1.1 | ATK-A1 | 10 | `0/10` | `request_hash` L452 | 0 | 1 | 不适用 |
| E1.2 | ATK-A2 | 10 | `0/10` | `context_hash` L454–455 | 0 | 1 | 不适用 |
| E1.3-a | ATK-A3 | 10 组（每组调 2 次） | 额外执行 `0` | nonce L477 | 0 | 1 | 不适用 |
| E1.3-b | ATK-A4 | 10 组（每组 2 线程） | 重复执行 `0` | nonce L477 | 0 | 1 | 不适用 |

**测试规模**：E1.1 10 次 / E1.2 10 次 / E1.3-a 10 组 / E1.3-b 10 组。Python 全量测试演进：`60/60`（E1.1 后）→ `62/62`（E1.2 后）→ **`64/64`（E1.3 后，29 / 21 / 14）**；定向：E1.1 `25/25`、E1.2 `-k e1_2` `2/2`、E1.3 `-k e1_3` `2/2`。`git diff --check` clean。

---

## 2. 三条证据链（用户阶段验收结论）

| # | 证据链 | 支撑实验 | 判定 |
| --- | --- | --- | --- |
| 1 | **授权请求不可被替换**：即使 Finance 在通用 Policy 层面允许，也不能把已签发的 Sales 请求替换成 Finance | E1.1 | `Policy-compliant ≠ Grant-authorized` |
| 2 | **授权上下文不可被替换**：即使 `ToolCall` 完全不变，替换租户上下文仍在进入 Adapter 前被拒 | E1.2 | 授权绑定从请求内容扩展到执行上下文 |
| 3 | **Grant 不能被重复使用**：nonce 的 check-and-consume 阻止顺序重放，也阻止首次执行尚未结束时的并发重放 | E1.3-a / b | `SuccessfulUses(g) ≤ 1`（在当前实例内） |

**方法学增量（用户指出）**：本阶段不只验证拒绝结果，还把**拒绝发生的位置、Adapter 是否执行、nonce 是否消费、审计记录是否有效**同时纳入观测。E1.3-b 的阻塞 Adapter 建立了 `T1 已进入执行 → T2 随后提交 → T2 在 T1 释放前得到拒绝` 的确定时序，比固定等待时间的测试更有说服力。

---

## 3. 必须保留的研究边界

| # | 边界 | 说明 |
| --- | --- | --- |
| B1 | **并发原子性范围** | 只验证**当前 Gateway 实例内**的 nonce 原子消费；不可外推到多进程、多实例或分布式部署。对应 G4 / G6、S1 假设。 |
| B2 | **上下文覆盖范围** | 只实际验证 `tenant_id`；`session_id` / `task_id` 未分别验证；`ExecutionContext` 无 `user` 字段（G9），主体在 `ToolCall.agent_id`。 |
| B3 | **Adapter 信任边界** | E1 只证明 Gateway 能在调用 Adapter **前**拒绝特定授权绑定攻击，**不证明恶意 Adapter 无法偏离授权内容**。此前的 Adapter mutation 实验已显示 Receipt 检查是**执行后检测**，副作用不可撤销（U1 未闭合）。 |
| B4 | **未执行的设计臂**（本卷宗补充登记） | 冻结基线的 `E1.1-c`（策略复核隔离测试）、`E1.2` 的 session/task 分字段、`E1.2-b` TOCTOU 漂移复跑均**未在 E1 阶段实施/复跑**；见 §4。它们仍是 R0 定义或 R2 引用，**不是本阶段 R3 结论**。 |

> **不可让步表述**：**审计系统记录了攻击，不代表系统阻止了攻击。** E1 全部为执行前预防性，未出现 `RECEIPT_INVALID` / `OUTCOME_UNKNOWN` 场景；该结论留给 E2。

---

## 4. 设计基线（v0.1）与实际执行的映射 / 偏差

**本卷宗不回改基线**，仅登记差异，供研究报告如实说明「设计 vs 执行」。

| 冻结基线臂（v0.1 §2） | 实际执行 | 状态与差异 |
| --- | --- | --- |
| E1.1-a 阴性对照 | 由 `test_e1_1_adapter_counter_detects_a_real_execution` 的良性请求承担 | 等效覆盖（计数器自检 + `ALLOW_EXECUTED`），但未以「10 次误拒率」形式单独统计 |
| E1.1-b 请求绑定 | E1.1，10 次 | ✅ 一致 |
| **E1.1-c 策略复核隔离** | **未实施** | ❌ 无 R3 数据。需受控夹具（Issuer 私钥直签、`request_hash` 绑定 Legal），基线 §3.6 规格仍有效，留待后续或 v0.2 |
| E1.2-a 三字段分别替换 | E1.2，仅 `tenant_id`，10 次 | ⚠️ 范围缩小，与 B2 一致 |
| E1.2-b TOCTOU 漂移 | **本阶段未复跑** | ⚠️ 仅有上一阶段 R2 变异反证；本阶段未产出 R3 |
| E1.3 顺序重放 | E1.3-a，10 组 | ✅ 一致（并补齐计数 / reason / 审计 / nonce / 链校验） |
| **E1.4 并发重放** | **以 E1.3-b 名义完成**，10 组 | ✅ 结果达成，但**方案更换**：未复用 `_GatedNonceSet` 的固定等待窗口，改用测试侧阻塞 Adapter + Event 同步，验证的是「首次执行进行中被重放」这一不同时序；与基线 §6 描述不是同一实验 |

**命名说明**：用户逐轮下发的执行方案把并发重放并入 E1.3（`-b`），本卷宗沿用**实际执行编号**；基线中的 `E1.4` 编号继续保留在冻结文档中，二者不互相覆盖。若将来写论文，需统一编号并说明方案变更。

---

## 5. 仓库状态（阶段节点快照）

| 项目 | 状态 |
| --- | --- |
| E1.1 / E1.2 / E1.3-a / E1.3-b | 已完成，结果验收通过 |
| 良性对照、计数器自检、变量隔离证据 | 已覆盖（§1.1 / §1.2） |
| 审计链完整性 `AuditChain.verify()` | 四组全部通过 |
| 生产代码修改 | **无**（`agent_exec_binding.py` mtime 仍为 2026-11-11 21:20:13） |
| 测试侧改动 | 仅 `tests/test_agent_exec_binding.py`，累计新增 5 个测试 + 2 个夹具（`_CountingTool`、`_BlockingCountingTool`）；该文件 24 → 29 个测试 |
| README / 冻结文档更新 | **暂缓**（README 仍写上阶段 `80/80`；三份 v0.1 基线与本文件的 §8/§9 空表均未回填） |
| Git 提交与推送 | **暂缓**；HEAD 仍 `610b280`；工作树 6 个 `M` + `?? research/` |
| Halo2 / Rust 侧 | 本阶段未涉及 |

---

## 6. E2 交接：三种安全能力的静态分层（**R1，不是本轮实验结论**）

用户提出的 E2 主线：*如果 Planner 与 Gateway 都正确完成授权，但 Adapter 在执行时偏离授权内容，现有机制能提供什么保证？* 下表仅为**源码级静态核对**（`agent_exec_binding.py` L439–564、相关测试），供用户设计 E2 对照实验时定夺，**本轮未跑任何 E2 实验、未写实验方案**。

| 能力 | 发生位置（源码） | 能观测到什么 | 不能观测到什么 |
| --- | --- | --- | --- |
| **预防 Prevention** | Adapter 调用前：验签 → 绑定/策略检查 → nonce 原子消费（L439–480） | Planner 侧 ATK-A1/A2/A3/A4 在 `tool.execute`（L502）之前被拒 | Adapter 拿到快照后**实际用于查询的参数** `e`（U1 / `Bind(e,r)` 未闭合） |
| **检测 Detection（执行后）** | receipt 验签 + `expected_receipt_bindings` 逐字段比对（L518–551） | 「Adapter 自签 receipt 声明」与 Gateway 钉住的绑定值是否自洽；不一致 → `RECEIPT_INVALID` | 独立性有限：`output_hash` 是 Gateway 拿 **Adapter 返回的 output** 算的（L532），receipt 也由 Adapter 自签；Gateway 只能验证「receipt 与返回输出自洽」，**不能验证「返回输出 = 实际读取的数据」**（G3，声明级检测） |
| **事后审计 Post-hoc audit** | `_record` 四态 + `AuditChain` 哈希链签名（L506–511 / L544–551 / L553–562） | `DENY` / `ALLOW_EXECUTED` / `OUTCOME_UNKNOWN` / `RECEIPT_INVALID` 区分；链可验证 | `RECEIPT_INVALID` **缺 `grant_hash` / `receipt_hash` / `output_hash`**（G1、G2），无法定位是哪份失效 receipt；副作用已发生且不可撤销 |

**现有 R2 交叉引用（非 R3）**：`test_adapter_receives_snapshot_and_cannot_shift_binding` 中 Adapter 把 `where.department` 改成 Finance 后**确实返回了 Finance 行 `amount=3400`**，调用方对象未被污染，审计为 `RECEIPT_INVALID` 且无 `ALLOW_EXECUTED` / `DENY`；`test_invalid_receipt_records_receipt_invalid`、`test_tool_exception_records_outcome_unknown` 覆盖另两种终态。**这正是 B3 边界的既有证据，不得写成「越权执行被阻止」。**

**E2 设计前需用户定夺的控制变量（登记，不预设结论）**

1. **「偏离」与「证据偏离」必须分开注入**：若 Adapter 只改参数而用 `super().execute()` 自签，receipt 的 `request_hash` 会随之改变 → 被 `RECEIPT_INVALID` 检出；但若 Adapter 按 Gateway 钉住的绑定值**恶意自签一份自洽 receipt** 并返回越权行（在攻击者持有 tool_sk 的模型下），静态推断 L524–537 的绑定比对仍可能通过 → 记为 `ALLOW_EXECUTED`。**该推断目前是 R1，未经实测**；E2 若不设置这一臂，就无法区分「偏离被检测」与「偏离因证据恰好不自洽才被检测」。
2. **副作用度量必须落在 Adapter 侧**：MVP 的 mock 工具**只有只读访问、无写操作**，「副作用」= 返回越权行，不得外推为写操作或可撤销；计数与留痕需同时记录 `executions`、`executed_rows`、`Adapter 实际使用的 args`。
3. **三率口径切换**：E2 才启用完整 `ASR / PR / DR`；`RECEIPT_INVALID` 只计 DR，**绝不计入 PR**；E1 与 E2 的 ASR **不得合并**。
4. **nonce 语义**：L480 在执行前消费，`RECEIPT_INVALID` / `OUTCOME_UNKNOWN` 后 nonce 保留，同 Grant 无法重试；E2 需说明这对「失败后处置」的影响。
5. **P5/P6 的 R3 判定**：冻结基线 §4 中 P5-③、P6-③/④ 明确留待 E1（DENY 场景）与 E2（Adapter 偏离场景）分别产出；本卷宗只补齐 E1 侧，E2 侧仍为空。

> **分工纪律**：按用户确立的「用户负责设计阶段实验、AI 负责执行并反馈结果」，本文件**不给出 E2 实验方案**，等用户下发 E2 的具体执行要求与验收标准后再实施。

---

## 7. 变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| **v0.1（冻结 E1 结果）** | **2026-11-12** | 首次落地 E1 的 R3 原始计数：E1.1 / E1.2 / E1.3-a / E1.3-b 四组结果、三条证据链、B1–B4 研究边界、基线与实际执行的映射偏差表、阶段仓库快照、E2 三能力静态分层与待定夺控制变量。**不回改 v0.1 基线、不改 README、不改代码、不提交推送。** |
