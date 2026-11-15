# Agent Execution Binding — 攻击模型 v0.1

**状态：** **v0.1 定稿（冻结研究基线）**。依据用户 2026-11-12 的五项决定完成修订后冻结。**不是**安全证明，**不是**实现报告。
**日期：** 2026-11-12（初稿与定稿同日）
**范围：** 单进程 Python 执行基线 `agent_exec_binding.py`；不涉及 Halo2 / Rust 电路、不涉及端到端 ZK 集成。
**冻结时约束：** 未改代码、未改既有文档、未跑实验、未提交、未推送。后续按「根据实际实验不断修正」原则以 **v0.2** 修订，**不回改 v0.1 基线定义与预期值**。

**本版依用户决定冻结的五项事项：**

| 编号 | 决定 | 落实位置 |
| --- | --- | --- |
| **D1** | G8 选 (a)：保持实现，授权定义为「已签发 Grant 绑定的具体请求」，**不收紧 Sales 策略、不改代码** | §3.2 |
| **D2** | 采用 `ARM-` / `ATK-` 双前缀：防御机制分层与攻击能力是两个正交维度 | §4、§9 |
| **D3** | P5/P6 判定标准原则上采纳，补充可观测性要求（区分审计完整性与故障分类，不能只看是否有日志） | `security-properties-v0.1.md` §4 |
| **D4** | E1.1-c 增加对照臂，但必须明确控制变量（构造签名有效且 `request_hash` 匹配 Legal 的 Grant） | `attack-experiment-matrix-v0.1.md` §3 |
| **D5** | 每臂至少 10 次独立 nonce；报告原始计数；不包装成统计显著性 | `attack-experiment-matrix-v0.1.md` §0 / §1.2 |

---

## 0. 证据等级约定（防止把「定义」写成「结论」）

本文所有断言必须带下列等级之一。后续实验产出结论时，只能升级等级，不能跨级引用。

| 等级 | 含义 | v0.1 冻结时状态 |
| --- | --- | --- |
| **R0** | 研究定义 / 模型假设，无实现、无实验 | 本文主体 |
| **R1** | 仓库中存在对应代码路径（静态核对源码，未执行） | 本文已核对 |
| **R2** | 上一阶段已实测（测试 / 变异反证），**E1 阶段未复跑** | 引用上阶段记录，需显式标注 |
| **R3** | 本研究阶段新实验产出 | **v0.1 冻结时为空，结果位留待 E1 填写** |

> 关键纪律：`R2` 不得写成「本实验验证」；`R0` 不得写成「系统保证」。
> 「检测到了」不得写成「攻击被阻止」。二者在 §6 分开定义。
> **审计系统记录了攻击，不代表系统阻止了攻击。**

---

## 1. 研究系统与执行链（R0 + R1）

### 1.1 抽象执行链

```
  LLM / Agent Planner  ──(ToolCall, untrusted)──►  Security Gateway
        不可信                                        可信执行控制点
                                                          │
   Trusted Issuer ──(SignedGrant)────────────────────────┤
   独立签发授权，不由 Planner 决定                          │ 快照后的请求 / Grant / Context
                                                          ▼
                                              Tool Executor / Adapter
                                                    条件可信
                                                          │
                                                          ▼
                                              External Resources
                                              （DB / 服务 / 文件系统）
                                                          │
                                              SignedReceipt ──► Audit Storage
```

### 1.2 与仓库实现的对应（R1）

| 抽象组件 | 仓库对应物 | 当前实际形态 |
| --- | --- | --- |
| LLM / Planner | 测试夹具 `good_call()` / `ToolCall` | **LLM 未接入**；由固定夹具代替，以隔离协议行为 |
| Trusted Issuer / Authority | `GrantIssuer` + `Policy` | Ed25519 签名；`issue()` 内先 `policy.check()` 再签名 |
| Security Gateway | `ToolGateway` | 快照、验签、复核 policy、nonce 原子消费 |
| Tool Adapter | `MockFinanceTool` | 同进程 mock；自签 receipt |
| External Resource | `MockFinanceTool.records` | 内存中的合成记录，含敏感字段 `id_number`，无真实 DB / 无写操作 |
| Audit Storage | `AuditChain` | 内存签名哈希链，单进程 |
| Grant | `SignedGrant` | 绑定 `request_hash`、`context_hash`、`policy_hash`、`tool_schema_hash`、`nonce`、有效期、`issuer_id` |
| Receipt | `SignedReceipt` | 绑定 `request_hash`、`policy_hash`、`context_hash`、`nonce`、`output_hash` |

### 1.3 研究模型与研究主线（R0）

> **Issuer 向 Gateway 提供可验证授权；Planner 不拥有授权签发权。**
> **Agent 可以提出执行请求，但不能自行决定自己有权执行什么。**

推论：一次工具调用是否合法，**不**由 Planner 的自然语言意图、自我声明或请求「看起来是否合法」决定；由 Gateway 对「实际将交给执行的字节」独立重算授权判定决定。§3 给出可判定形式。

**研究主线（用户 2026-11-12 确立，后续所有实验围绕此问题）：**

> 当 Planner 不可信时，**密码学授权绑定究竟能够阻止哪些越权行为，又在哪个执行边界上失效？**

因此本研究的不是「代码有没有写对」，也不是简单的「Planner 把允许访问的部门改成不允许访问的部门」，而是：

> **Planner 能否在一次已经签发的授权中，擅自替换实际请求，即使替换后的请求本身仍符合系统的一般策略？**

该问题直接决定 §3.2 的两个术语区分与 E1.1 的三臂控制变量设计。

---

## 2. 信任假设（R0）

| 组件 | 信任级别 | 当前假设 | 假设失效条件 / 对应实验位 |
| --- | --- | --- | --- |
| LLM / Planner | 不可信 | 可能幻觉、被 Prompt Injection 攻击、主动构造恶意请求 | 常态；ATK-A1 / ATK-A2 |
| Issuer | 可信 | 正确执行授权策略，私钥不泄露 | 明文排除（§5） |
| Security Gateway | 可信 | 正确执行验证逻辑，内部状态受保护 | 明文排除（§5） |
| Tool Adapter | 条件可信 | 基准实验诚实执行；另设恶意/故障 Adapter 实验 | ATK-A6；**本模型最弱环节** |
| External Resource | 不完全可信 | 可能返回错误、异常或恶意数据 | `OUTCOME_UNKNOWN` 路径 |
| Audit Storage | 条件可信 | 需验证记录的完整性与一致性 | ATK-A5；`AuditChain.verify()` |

**补充假设（R0，必须在论文中显式列出，否则 §3 的判定式不成立）：**

- **S1 状态单调性**：`used_nonces` 在 Gateway 进程内单调增长、检查与消费原子、且发生在任何工具调用之前。当前实现是**单进程内存 set**（`README.md` 已声明非 crash-safe、非跨副本共享）。
- **S2 时间源**：`now` 由调用方注入（测试）或 `time.time()`（生产路径）；有效期判定依赖该值可信。
- **S3 密钥分布**：Issuer / Tool / Audit 的公钥已安全配置到 Gateway；`expected_issuer_id` 显式配置且非空。
- **S4 策略来源**：`Policy` 是预配置的结构化封闭策略，**无自然语言策略编译器**；「意图 → 策略」的翻译过程不在本研究范围内。
- **S5 同进程边界**：Issuer / Gateway / Tool / Audit 运行在同一 Python 进程；不存在网络传输、跨进程可信执行环境或 TEE。

---

## 3. 信任边界的精确定义（本文核心判断，R0）

### 3.1 不信任「组件」，信任「可判定谓词」

「我们应该信任什么」若回答成「信任 Issuer 和 Gateway」，是不可证伪的组件级陈述。研究上可操作的答案是给出一个**只做字节比较与封闭检查、完全不解释自然语言意图**的判定式：

$$
\begin{aligned}
\operatorname{Legit}(r, c, g, S, t) :=&
\ \operatorname{Verify}_{pk_I}\big(g.\sigma,\ \operatorname{canon}(g.p)\big) \\
&\wedge\ g.p.\text{issuer\_id} = \text{expected\_issuer\_id} \\
&\wedge\ g.p.\text{agent\_id} = r.\text{agent\_id} \\
&\wedge\ H(\operatorname{canon}(r)) = g.p.\text{request\_hash} \\
&\wedge\ H(\operatorname{canon}(c)) = g.p.\text{context\_hash} \\
&\wedge\ g.p.\text{policy\_hash} = H(\operatorname{canon}(\pi))
\ \wedge\ \pi.\operatorname{check}(r, c) = \text{pass} \\
&\wedge\ r.\text{tool\_id} = g.p.\text{tool\_id}
\ \wedge\ \texttt{tool.SCHEMA\_HASH} = g.p.\text{tool\_schema\_hash} \\
&\wedge\ t \in [\text{issued\_at}, \text{expires\_at}) \\
&\wedge\ \operatorname{FreshAndConsume}(g.p.\text{nonce}, S) \\
&\wedge\ \operatorname{Bind}(\text{exec\_bytes},\ r)
\end{aligned}
$$

其中 `canon` = `canonical_json`，`H` = `sha256_hex`，`S` = Gateway 重放状态，$\pi$ = `Policy`。
**每一个合取项都是字节相等、集合成员或闭式检查；没有任何一项读取「意图」**（R1：与 `ToolGateway.execute()` 的检查顺序一致）。

### 3.2 两个必须分开的术语：Policy-compliant 与 Grant-authorized（R0，D1 冻结）

该类攻击依赖验证者**解释语义**（「这个请求看起来是查销售数据」）。而一旦授权是「对 `H(canon(r))` 的签名」，则「看起来」没有操作含义：`r` 任一字节变化都会改变摘要，判定失败。

**正式定义（本项目的两个基础区分，不得互换）：**

| 术语 | 定义 | 判定式 | 判定者 |
| --- | --- | --- | --- |
| **Policy-compliant**（策略合规） | 请求落在**一般策略约束**的包络内 | $\pi.\operatorname{check}(r,c)=\text{pass}$ | Issuer 签发期 + Gateway 复核 |
| **Grant-authorized**（授权一致） | 请求与**本次已签发 Grant 所绑定的具体请求**逐字节相同 | $H(\operatorname{canon}(r)) = g.p.\text{request\_hash}$ | Gateway 执行前 |

- **本研究的「授权范围」取 `Grant-authorized`**（决定 D1）。`Policy-compliant` 是更弱的必要条件，不是充分条件。
- 二者由**两个不同的检查**实现，位于 Gateway 检查序列的不同位置（R1：`request_hash` 在 L452，$\pi.\operatorname{check}$ 在 L465；**绑定检查在前**）。
- 因此，一个 `Policy-compliant` 但非 `Grant-authorized` 的请求**必须被拒绝**；若仅做策略检查（README `ARM-A1`），它会通过。

> **本仓库最值得写进论文的观测（R1，待 R3 实验确认）：**
> demo policy 的 `allowed_filter_values = {"department": ("Sales", "Finance")}`，即 **Finance 查询本身是 `Policy-compliant` 的**。
> 但 `test_request_tampering_after_authorization_denied` 把 `where.department` 从 `Sales` 改成 `Finance` 后仍被拒绝，拒绝理由是
> `"request differs from the authorized request"`（`request_hash` 比较），**不是** policy 白名单。
>
> 由此得到两类必须分开的替换（决定 D4 的依据）：
> - `Sales → Finance`：两个值都 `Policy-compliant`，但请求哈希不同 → 应因 **Grant 绑定不匹配** 被拒（E1.1-b）。
> - `Sales → Legal`：替换值非 `Policy-compliant`，**同时**与原 Grant 请求哈希不匹配 → 两处都会拒绝，**不能混为一个结论**；
>   要观察策略检查是否独立生效，必须构造 `request_hash` 与 Legal 请求匹配的受控 Grant（E1.1-c）。

**✅ 决定 D1（G8 已结案）：** 保持当前实现，**不为迁就叙述示例而修改策略代码**。
早期叙述中「Issuer 只授权 Sales」是简化示例，与 demo policy 不符；现以本节的 `Grant-authorized` 定义为准，模型与实现已对齐。
早期曾考虑的选项 (b)（收紧 policy 为 Sales only）**已排除**：它会改变代码，且会把 E1.1-b 的拒绝层从 `request_hash` 移到 policy，从而**破坏本项目最有价值的基础区分**。G8 在 §7 关闭。

### 3.3 信任清单与一条未闭合假设

| 编号 | 信任对象 | 性质 | 当前 MVP 是否成立 |
| --- | --- | --- | --- |
| **T1** | Issuer 对**显式、规范、封闭**授权陈述的签名（不是对意图签名） | 密码学 | R1 成立（Ed25519，无形式化证明） |
| **T2** | Gateway 对**将交付执行的实际字节**重算判定，fail-closed，状态原子 | 实现 | R1 成立 |
| **T3** | 这些字节与实际执行之间的**绑定** | 证据 | ⚠️ **仅检测性**：靠 adapter 自签 receipt 事后比对 |
| **U1** | Adapter 确实执行了被绑定的快照 | **假设** | ❌ **未闭合**；ATK-A6 已构造反例（R2） |

- 对 Planner：**零信任**。Planner 的输出是**数据**，不是证据；既不信其意图，也不信其自我声明，也不信其结构「看起来合法」。
- 对 Adapter：**不宣称信任**。基准实验假设诚实，但 U1 是我们**明确承认尚未解决的问题**，不是已被满足的性质。

### 3.4 由此产生的研究问题（R0）

> 密码学绑定应止于 **Agent → Gateway**，还是应延伸到 **Gateway → 实际工具执行环境**？
> 当前 MVP 只完成前者（预防性）+ 对后者的**事后检测**。
> 若要求预防性覆盖后者，需要执行方能就其「实际执行的操作」产生可独立验证的证据；这属于后续研究方向，**本版不声称已解决、也不声称与现有 Halo2 电路对接**。

---

## 4. 攻击者能力（R0）

**命名空间（决定 D2 已冻结）：** 攻击能力统一用 `ATK-A*`，README §"First experiment matrix" 的防御机制分层统一用 `ARM-A0..A3`。二者是**两个正交维度**（攻击能力驱动 vs 防御层递进），不是同一组实验。

| 编号 | 攻击能力 | 具体行为 | 作用位置 | 相对副作用时序 | 仓库证据点（R1） |
| --- | --- | --- | --- | --- | --- |
| ATK-A1 | 请求操纵 | 改 `ToolCall` 的 `operation` / `args`（fields、where、limit） | Gateway 入口 | 执行前 | `test_request_tampering_after_authorization_denied` |
| ATK-A2 | 上下文操纵 | 替换 `session_id` / `task_id` / `tenant_id`；或校验后二次读时漂移 | Gateway 入口 / 校验中 | 执行前 | `test_context_substitution_denied`、`test_context_snapshot_is_used_for_policy_and_adapter` |
| ATK-A3 | 授权重放 | 重复使用已消费 Grant | Gateway 状态 | 执行前 | `test_replay_denied` |
| ATK-A4 | 并发竞争 | 多线程同时使用同一 Grant | Gateway 状态 | 执行前 | `test_concurrent_replay_only_executes_once`、`test_concurrent_replay_test_detects_missing_lock` |
| ATK-A5 | 数据篡改 | 改 Receipt、执行结果、审计条目 | 执行后 / 审计 | 执行后 | `test_invalid_receipt_records_receipt_invalid`、`test_audit_tampering_detected` |
| ATK-A6 | 工具侧偏离 | Adapter 执行与 Gateway 授权请求不一致的操作 | Adapter 内部 | **执行中（副作用已发生）** | `test_adapter_receives_snapshot_and_cannot_shift_binding` |

**攻击者的「不知道」**：Issuer 私钥、Tool 签名私钥、Audit 签名私钥、Gateway 内存状态。
**攻击者的「能构造」**：任意 `ToolCall` / `ExecutionContext` / `SignedGrant` 对象，包括带自定义 `__contains__` / `get` / 属性 getter 的可变映射对象（R1：`MutatingPayload`、`ShiftingContext`、`ShiftingReceipt`、`_GatedNonceSet` 均已作为夹具存在）。

> ⚠️ **E1.1-c 的受控夹具属于测试构造，不是攻击者能力**：它需要用 Issuer 私钥签名一个策略会拒绝的 Grant。
> 该能力**不属于**上述攻击者模型（Issuer 私钥为攻击者所不知道），因此 E1.1-c 是**策略检查的隔离测试**，**不是**真实攻击场景，其结论不可写成「攻击被阻止」。见实验矩阵 §3.5。

---

## 5. 明确排除的范围（R0）

用户给定、本版沿用：

1. Issuer 私钥已泄露；
2. Gateway 本身被完全攻破；
3. OS 内核或密码学底层实现被攻破；
4. 外部数据库自身权限控制完全失效。

结合仓库现状补充排除（R1）：

5. **自然语言策略编译器**：`Policy` 是预配置结构化对象；
6. **LLM 实际接入与 Prompt Injection 成功率**：Planner 未连接，测试用固定夹具；
7. **跨副本持久化重放状态**：`used_nonces` 为单进程内存 set，非 crash-safe；
8. **审计存储的持久化 / 抗尾删除 / 抗恶意 Gateway 写入假条目**：`AuditChain` 为内存签名链；
9. **数据库内容真实性、完整性、新鲜性**：receipt 只认证工具声明；
10. **网络传输、可用性、时延攻击**；
11. **ZK 关系与 Halo2 电路**：Python 执行路径不使用零知识证明，Rust 侧电路与 Python 授权信封未集成。

> 排除项 2 与 8 存在**耦合**：审计签名私钥与 Gateway 同进程，若排除 2 不成立，则 P5/P6 的审计结论一并失效。此依赖需在 v0.2 显式建模。

---

## 6. Tool Adapter 边界 —— 本模型最重要的一条结论（R0 + R2）

上一阶段已完成的实验（**R2，上阶段记录，E1 阶段未复跑**）：Adapter 把 `call.args["where"]` 改为 Finance 后，**越权查询确实执行并返回了 Finance 记录**；Gateway 随后通过 receipt 绑定比对才发现偏离，审计记为 `RECEIPT_INVALID`，不记为 `DENY`、也不记为 `ALLOW_EXECUTED`。

由此确立四条不可让步的表述纪律：

| 概念 | 定义 | 判定信号 |
| --- | --- | --- |
| **阻止（prevention）** | 越权请求**未到达工具 / 未产生副作用** | 审计 `DENY`，工具执行次数 = 0 |
| **检测（detection）** | 越权操作**已执行**，事后被发现 | 审计 `RECEIPT_INVALID` / `OUTCOME_UNKNOWN`，工具执行次数 ≥ 1 |
| **攻击成功（ASR 分子）** | 越权操作实际产生了副作用 | 工具执行次数 ≥ 1 且返回越权结果 |
| **审计记录** | 系统写下了一条终态条目 | **与上述三者正交**：记录了 ≠ 阻止了 |

- ✅ 可以说：Gateway 能**检测**某些 Adapter 行为偏离（receipt-binding）。
- ❌ 不能说：当前方案能**抵御任意恶意 Tool Adapter**，或能**阻止**其副作用。
- ❌ 不能把「检测率」计入「阻止率」，也不能把 `RECEIPT_INVALID` 记为「攻击被拒绝」。
- ❌ **审计系统记录了攻击，不代表系统阻止了攻击**（用户 2026-11-12 明确要求写入）。
- 副作用一旦发生，事后检测**无法撤销**。因此 P1/P3 对 Planner 是预防性的，对 Adapter 只有检测性（见 `security-properties-v0.1.md` §2）。

> **实验排期（用户决定）：** ATK-A6 / ATK-A5 相关的 Adapter 偏离与 Receipt 篡改实验**不进入第一阶段**，
> 在 E1.1–E1.4 基础攻击实验有清楚结果后**单独推进（E2）**。但 U1 未闭合这一结论在 v0.1 **保留**，不因实验延后而弱化。

---

## 7. v0.1 已知缺口（R1，供后续修订，本版不修）

| 编号 | 缺口 | 影响性质 | 处置 |
| --- | --- | --- | --- |
| G1 | `RECEIPT_INVALID` 审计条目**不含 `receipt_hash`** | P5 部分满足 | v0.2 待定 |
| G2 | `RECEIPT_INVALID` / `OUTCOME_UNKNOWN` 不含 `grant_hash`、`output_hash` | P5 | v0.2 待定 |
| G3 | `output` 由 Adapter 返回，`output_hash` 也由 Adapter 签名声明，Gateway 无法独立确认「返回行 = 实际读取行」 | P5 / U1 | 研究问题 |
| G4 | `used_nonces` 内存单进程，非 crash-safe、非跨副本 | P4（仅在 S1 下成立） | 明确列为假设 |
| G5 | `AuditChain.verify()` 能检出条目修改，未覆盖尾部删除/截断；审计签名私钥与 Gateway 同进程 | P5 | 明确列为假设 |
| G6 | `_GatedNonceSet` 的 0.2s 停顿是**实测竞争窗口**，非严格确定性调度证明 | P4 证据强度 | 实验方法学说明（E1.4） |
| G7 | 模块 docstring 仍含 `executes exactly the bound request`，与「Adapter 可偏离」存在张力 | 表述一致性 | 已知遗留，待授权后修 |
| ~~G8~~ | ~~`Policy` 允许 Sales 与 Finance，与叙述示例不一致~~ | — | **已关闭（D1）**：不改代码；以 §3.2 的 `Grant-authorized` 定义为准，该「偏差」正是研究对象 |
| G9 | `ExecutionContext` 只有 `session_id / task_id / tenant_id`，**无 `user` 主体维度**；主体标识在 `ToolCall.agent_id` | P2 / E1.2 覆盖度 | v0.1 以三字段替代，见实验矩阵 §4；扩展需改代码 |

---

## 8. 与既有文档的关系（R1）

| 文档 | 定位 | 本文关系 |
| --- | --- | --- |
| `README.md` | 项目现状与对外承诺 | 本文引用其 L20（Adapter 边界）、L38（Python 路径非 ZK）、L40（内存状态）、L42（LLM 未接入）、L104（测试不构成安全有效性声明）；**本版不修改** |
| `docs/data_access_threat_model.md` | **Step 2 批量计划 / 数据访问**的威胁模型 | 作用域不同（批量计划 vs 单调用执行绑定）；并存，不替代 |
| `docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md` | Halo2 目标关系规格 | 目标规格，非当前实现；本文不引用其结论作为实现证据 |
| `research_brief.md` | 早期研究选题简报 | 本文聚焦于其中的「运行时执行绑定」子问题 |
| `README.md` §"First experiment matrix" | `ARM-A0..A3` 防御机制分层 | 与本文 `ATK-A*` 攻击能力**正交**，按 D2 分前缀 |

> 本文是**新增的一层研究卷宗**，不修改、不覆盖上述任何文件。

---

## 9. 命名空间总表（R0，D2 冻结）

| 前缀 | 含义 | 取值 |
| --- | --- | --- |
| `ATK-A*` | 攻击能力 | A1–A6（本文 §4） |
| `P*` | 安全性质 | P1–P7（`security-properties-v0.1.md`） |
| `E1.*` | **第一阶段基础攻击实验臂** | E1.1-a/b/c、E1.2-a/b、E1.3、E1.4（执行序：E1.1 → E1.2 → E1.3 → E1.4） |
| `E2.*` | **后续单独阶段**：Adapter 偏离 / 信任边界 | ATK-A6 为主；ATK-A5 归属待后续确认 |
| `ARM-A*` | 防御机制分层实验臂（README 已有） | A0–A3 |
| `D*` | 用户决定 | D1–D5（本文头部） |
| `G*` | 已知缺口 | G1–G7、G9；G8 已关闭（本文 §7） |
| `S*` | 补充信任假设 | S1–S5（本文 §2） |
| `T* / U*` | 信任对象 / 未闭合假设 | T1–T3、U1（本文 §3.3） |
| `R*` | 证据等级 | R0–R3（本文 §0） |

---

## 10. 变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v0.1 draft | 2026-11-12 | 初稿：系统模型、信任假设与 S1–S5、Legit 判定式、ATK-A1–A6、排除范围、Adapter 边界、G1–G8 缺口、命名空间总表。未跑实验、未改代码。 |
| **v0.1 定稿（冻结）** | **2026-11-12** | 依用户 D1–D5 修订：新增研究主线与 D1–D5 决定表；§3.2 正式定义 `Policy-compliant` / `Grant-authorized` 并关闭 G8（明确不改策略代码）；§4 冻结 `ARM-`/`ATK-` 双前缀并声明 E1.1-c 夹具不属攻击者能力；§6 补充「记录了 ≠ 阻止了」及 E2 排期；新增 G9（上下文无 user 维度）；§9 更新实验臂范围与执行序。**仍未跑实验、未改代码、未改既有文档、未提交推送。** |
