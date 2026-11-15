# Agent Execution Binding — E 阶段（E1 + E2）集中验收与结果卷宗 v0.1（冻结）

**状态：** **E 阶段实验结果冻结**。用户已于 2026-11-12 完成 E1 与 E2 两阶段结果验收，均判定**通过**；E2.2 被指定为本轮实验终点。
**日期：** 2026-11-12
**范围：** E1（授权绑定与重放防护）+ E2（Adapter Deviation / 执行证据独立性）。
**配套冻结基线（不回改）：** `threat-model-v0.1.md`、`security-properties-v0.1.md`、`attack-experiment-matrix-v0.1.md`、`e1-results-v0.1.md`。
**与基线的关系：** v0.1 三份基线冻结的是「怎么定义、怎么做、怎么判」，其 §8 结果表与 §9 结论模板保持空白；`e1-results-v0.1.md` 冻结 E1 的 R3 数据。本卷宗是**阶段级汇总归档**：E1 部分引用前者逐 run 原始记录并给出汇总，E2 部分的 R3 数据**首次落地成文档**。若后续与 v0.1 预期不符，以 **v0.2 修订**，不回改 v0.1。
**本轮约束：** 未改生产代码、未改测试、未改 README、未改四份冻结文档、未碰 Halo2、未新增实验（仅复跑全量测试作归档时点核查）、未提交、未推送。**仅新增本文件。**

---

## 0. 冻结范围与表述纪律

1. **「通过」的含义**：用户明确说明，验收是**基于实验记录的结果验收，不是独立审查本地测试实现**；本卷宗不写成「实现已被独立审查」或「安全性质已被证明」。
2. **计数禁止合并**：E1 四组（ATK-A1/A2/A3/A4）与 E2 三臂（ATK-A6 的三种证据策略）是不同攻击能力、不同拒绝层、不同 $N$；E2.0 为良性控制组，不进入任何攻击指标分母。**不得求和、不得合成「总体攻击成功率」；E2.1 与 E2.2 不得混成一个 ASR。**
3. **指标口径**：沿用冻结 v0.1（§1.1 / §7）；$\operatorname{UER}$ 是 E2 阶段新增**辅助指标**，不取代 ASR、不回写 v0.1。
4. **三率分离**：`RECEIPT_INVALID` 只计 DR，**绝不计入 PR**；`AuditChain.verify()` 通过只证明哈希链结构完整，**不等于 DR，也不等于语义正确**。
5. **不称统计显著性**：每臂 10 次独立 Grant / nonce 只验证稳定性，不换算 p 值或置信区间。
6. **证据等级**：R0 定义 / R1 静态核对 / R2 上阶段实测 / R3 本阶段新实验。上一阶段 `80/80` 与四组变异反证是 R2，只作交叉引用，**不冒充本阶段结论**。
7. **结论口径**：只写「在当前实现、单进程内存状态、mock 只读工具、无 LLM 接入的研究原型与指定测试夹具下」；不外推为生产系统、分布式部署或端到端 ZK 系统。

---

## 1. 指标定义与互斥结果分类

### 1.1 冻结 v0.1 三率（原文口径，`attack-experiment-matrix-v0.1.md` §1.1 / §7）

$$
\operatorname{ASR} = \frac{\#\{\text{越权副作用实际发生}\}}{N}, \qquad
\operatorname{PR} = \frac{\#\{\text{未执行且被 }\texttt{DENY}\}}{N}, \qquad
\operatorname{DR} = \frac{\#\{\text{副作用发生后被 }\texttt{RECEIPT\_INVALID}/\texttt{OUTCOME\_UNKNOWN}\text{ 标记}\}}{\#\{\text{越权副作用实际发生}\}}
$$

- $\operatorname{DR}$ 是**条件率**，不得与 $\operatorname{PR}$ 相加或互换；E1 四组的 $\operatorname{DR}$ 分母为 0，记为「不适用」；完整三率口径保留给 E2。
- 用户 2026-11-12 明确拍板：**不回改 v0.1**，不把 ASR 改成「未被检测的成功执行」。理由是「事后检测不会让已经发生的未授权执行变成没有成功」——「攻击是否造成未授权执行」与「系统是否发现」必须分别测量。

### 1.2 E2 新增辅助指标（来源：E2 阶段口径拍板，**不回写 v0.1**）

$$
\operatorname{UER} = \frac{\#\{\text{已执行且未被检测}\}}{N}
$$

### 1.3 每次尝试的互斥分类（A/B/C/D）

| 类别 | 发生情况 | ASR | PR | DR 分母 |
| --- | --- | --- | --- | --- |
| A 执行前阻止 | 未授权副作用未发生，Gateway 提前拒绝 | 0 | 计入 | 否 |
| B 执行后检测 | 副作用已发生，最终正确识别 | 1 | 不计入 | 是 |
| C 执行后未检测 | 副作用已发生，系统未识别 | 1 | 不计入 | 是 |
| D 其他 / 无法判定 | 异常、观测不完整或执行结果不确定 | 暂不判定 | 不计入 | 不计入 |

D 类**必须单独报告**，不得为凑比例强行归入成功或失败。分类逻辑实现于 `test_e2_2_self_consistent_malicious_receipt_10_runs`，测试**不预设 Gateway 一定接受**。

### 1.4 三种安全能力（用户定义，用于解释而非相加）

| 能力 | 要回答的问题 | 当前机制的边界 |
| --- | --- | --- |
| 预防 Prevention | 能否阻止未授权执行发生？ | Gateway 能在调用 Adapter 前拒绝请求，但无法仅凭调用前绑定保证 Adapter 后续忠实执行 |
| 检测 Detection | 执行偏离能否被发现？ | 当前 Receipt 能检测部分绑定不一致，但依赖 Adapter 提供的证据 |
| 事后审计 Audit | 发生偏离后能否留下可信、完整的记录？ | AuditChain 能保护已有记录的完整性，不等于记录本身能证明实际数据访问行为 |

---

## 2. E1 结果汇总（R3；逐 run 原始记录见 `e1-results-v0.1.md`）

| 实验 | 攻击能力 | 独立实例 | 越权 / 额外执行 | 拒绝层（实测 reason） | ASR | PR | DR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E1.1 请求替换 Sales→Finance | ATK-A1 | 10 | `0/10` | `request_hash` L452–453 `request differs from the authorized request` | 0 | 1 | 不适用 |
| E1.2 上下文替换 tenant_id | ATK-A2 | 10 | `0/10` | `context_hash` L454–455 `execution context differs from authorized context` | 0 | 1 | 不适用 |
| E1.3-a 顺序重放 | ATK-A3 | 10 组（每组 2 次调用） | 额外执行 `0` | nonce L477 `grant replay detected` | 0 | 1 | 不适用 |
| E1.3-b 并发重放 | ATK-A4 | 10 组（每组 2 线程） | 重复执行 `0` | nonce L477 `grant replay detected` | 0 | 1 | 不适用 |

**三条证据链**：① `Policy-compliant ≠ Grant-authorized`（E1.1：Finance 在通用策略层 10/10 仍合法，却因 Grant 绑定被拒）；② 授权绑定从请求内容扩展到执行上下文（E1.2：`request_hash` 10/10 通过、仅 `tenant_id` 被换）；③ `SuccessfulUses(g) ≤ 1`（E1.3-a/b，含首次执行进行中被重放的确定时序）。

**方法学增量**：四组均同时观测拒绝位置、Adapter 是否执行、nonce 是否消费、审计终态与 `AuditChain.verify()`；E1.3-b 用 Event 同步的阻塞 Adapter 建立 `T1 已进入执行 → T2 提交 → T2 在 T1 释放前得到拒绝` 的确定时序，不以固定 `sleep` 窗口宣称原子性。

**E1 边界（B1–B4，详见 `e1-results-v0.1.md` §3）**：单实例 nonce 原子性、不可外推多进程 / 分布式；只验证 `tenant_id`（`ExecutionContext` 无 `user` 字段）；E1 不证明恶意 Adapter 无法偏离授权；`E1.1-c` 策略复核隔离、session/task 分字段、`E1.2-b` TOCTOU 复跑**未实施**，仍属 R0 定义或 R2 引用。

---

## 3. E2 结果（R3 首次落地成文档）

### 3.0 测量工具与三类独立观测

E2 全部臂共用三类**来源分离**的记录；前两类来自测试侧被动探针（`_QueryProbe` / `_ObservedWhere` / `_ObservedRow` / `_ProbedTool`），钩住 `MockFinanceTool.execute()` 真实发生的 `where.items()`、`row.get(key)`、`row[key]`，**不读 Receipt、不读 output、不读 grant payload，不从 Adapter 声明反填**：

| 记录 | 采集内容 | 来源 |
| --- | --- | --- |
| `actual_query_log` | 实际过滤条件、比较键、比较事件数、扫描行数 | 探针：真实过滤比较 |
| `actual_result_log` | 实际投影行数、部门分布、结果摘要 | 探针：真实结果投影 |
| `gateway_observation` | Adapter 提交证据副本、独立验签与哈希重算、Gateway 结果、Audit、nonce、执行次数 | Adapter 返回边界 `deepcopy` 副本 + 异常 / 审计 / 状态 |

**探针有效性（E2.0 前置反证）**：把 `where` 改为 Finance 后探针记录随真实执行变化、未回显授权值；把该次 Receipt 换成无效签名后两类日志**逐字段不变**（独立于 Receipt）；`observe=False` 变异体使 `result_summary()["row_count"]=0`、E2.0 核心断言失败（有区分力）；`dict` 子类包装不改变 `canonical_json` 字节，`request_hash` 10/10 仍匹配。**`comparison_events=5` 而非 6**（`all()` 短路）佐证记录的是真实列表推导轨迹，而非硬编码回显。

### 3.1 E2.0 Honest Adapter Baseline（良性控制组，10 次）

| Run | `actual_query_log` | `actual_result_log` | `gateway_observation` |
| --- | --- | --- | --- |
| 1–10（逐次一致） | `{year:2026, department:Sales}` / `[department, year]` / `5` 事件 / 扫描 `3` 行 | `1` 行 `{Sales:1}` / `Sales, 2026, 1200` | 返回 `1` 行 Sales/1200 / 验签通过 / `request_hash` 匹配 / `ALLOW_EXECUTED` / 链有效 / exec `1` / nonce 已消费 |

`10/10` 正常执行、**0/10 误拒**、10 个 nonce 互不相同；控制变量（`request_hash` / `context_hash` / `policy_hash` / `tool_schema_hash` / 数据集部门集合）`10/10` 一致。**E2.0 不进入 ASR / PR / DR / UER 分母。**

### 3.2 E2.1 Detectable Adapter Deviation（10 次，ATK-A6 如实报告）

Adapter 用 Finance 覆盖 `where`，走正常查询与投影路径，`super().execute()` 使 Receipt **如实绑定偏离后的请求**，由同一把合法 `tool_sk` 签名；Gateway 收到的证据副本在**返回边界**以 `deepcopy` 保存（live 对象原样返回，未改变实际提交对象）。

| Run | 真实查询 / 真实结果（探针） | Receipt 声明 | 验签 / 八项绑定 | Gateway 结果 | Audit / nonce / exec |
| --- | --- | --- | --- | --- | --- |
| 1–10（逐次一致） | Finance 条件 / `1` 行 `Finance/3400` | `H_receipt = H_Finance ≠ H_authorized` | 通过 / **唯一失配 `request_hash`** | 抛 `AuthorizationError("tool receipt is invalid or not bound to this execution")`，无正常返回 | `RECEIPT_INVALID` / 已消费 / `1` |

**固定哈希（截断前缀）**：`H_authorized = 1dc027a4…`、`H_Finance = H_receipt = 3a3558fc…`、`H_output = 1cafc253…`（Finance 越权数据）。
**排除竞争解释**：`H_receipt = H_Finance request`（测试侧独立构造 Finance `ToolCall` 计算）`10/10`，证明 Receipt 是如实按偏离请求生成，而非任意失配；`output_hash` 因 Gateway 用 Adapter 返回的越权 output 自算而必然相等 → **检测依赖「Adapter 让证据诚实跟随偏离」，不是 Gateway 观测到了实际查询**。

| 分类 | 计数 | 指标 | 值 |
| --- | --- | --- | --- |
| B 执行后检测 | 10 | ASR | **1.0** |
| A 执行前阻止 | 0 | PR | **0** |
| C 执行后未检测 | 0 | DR | **1.0** |
| D 其他 | 0 | UER | **0** |

> **不可让步**：Finance 数据已被查询；`RECEIPT_INVALID` 不计入 PR。**检测成功不等于阻止成功。**

### 3.3 E2.2 Self-consistent Malicious Receipt（10 次，本阶段核心反例）

唯一变量改为 **Receipt 生成策略**：Adapter 仍实际执行 Finance 查询，丢弃诚实 Receipt，用同一把合法 `tool_sk` 重签一份 `request_hash = H_authorized` 的 Receipt，`output_hash` 仍取实际返回的 Finance 结果。`policy_hash` / `nonce` / `context_hash` / `tool_id` / `tool_schema_hash` / `status` 均按授权侧填写。

| Run | `actual_query_log` / `actual_result_log` | Receipt 声明 | 验签 / 八项绑定 | Gateway 结果 | Audit / nonce / exec |
| --- | --- | --- | --- | --- | --- |
| 1–10（逐次一致） | Finance 条件 / `1` 行 `Finance/3400` | `H_receipt = H_authorized`、`H_output = H_Finance output` | 通过 / **失配项 `[]`** | **RETURNED，返回 Finance 数据** | `ALLOW_EXECUTED` / 链有效 / 已消费 / `1` |

三组同时成立的对照（用户指定的核心发现）：

$$
H_{\text{actual query}} = H_{\text{Finance}}, \qquad
H_{\text{receipt}} = H_{\text{authorized}}, \qquad
H_{\text{output}} = H_{\text{Finance output}}
$$

- 探针独立证实真实过滤条件为 Finance、真实投影为 `Finance/3400`（`comparison_events=5`、`scanned_rows=3`）；**被丢弃的诚实 Receipt 确实绑定 `H_Finance`**，证明 Adapter 走的是正常执行路径后主动改声明，不是绕过查询。
- 测试侧按 L524–537 独立重算 Gateway 八项绑定，失配项恒为 `[]` `10/10`；`verify_receipt` 用 `env["tool_sk"].public_key()` 对提交副本 `10/10` 通过。**这不是伪造签名，而是合法密钥持有者对真实执行作出不真实声明。**
- 审计把越权数据记为 `ALLOW_EXECUTED`（`request_hash` 为 Sales、`output_hash` 却是 Finance 数据的哈希），`AuditChain.verify()` `10/10` 通过 → **审计链结构完整但语义错误**（P5 结构层 / 语义层分离的正面证据）。

| 分类 | 计数 | 指标 | 值 |
| --- | --- | --- | --- |
| C 执行后未检测 | 10 | ASR | **1.0** |
| A 执行前阻止 | 0 | PR | **0** |
| B 执行后检测 | 0 | DR | **0** |
| D 其他 | 0 | UER | **1.0** |

### 3.4 E2 阶段验收汇总（用户表，原样归档）

| 实验 | Adapter 行为 | Gateway 结果 | ASR | PR | DR | UER |
| --- | --- | --- | --- | --- | --- | --- |
| E2.0 | 正常执行、如实报告 | 正常接受 | 不计入 | 不计入 | 不计入 | 不计入 |
| E2.1 | 执行 Finance、如实报告 | 执行后检测 | 1.0 | 0 | 1.0 | 0 |
| E2.2 | 执行 Finance、虚假报告 | 接受越权结果 | 1.0 | 0 | 0 | 1.0 |

**规模**：30 次独立运行（E2.0 为良性控制组）、20 次越权执行实验；E2.1 `10/10` 执行后检测、E2.2 `10/10` 执行后未检测；E2.0 不纳入攻击指标分母，E2.1 与 E2.2 **不合并成单一 ASR**。

**三组对照的唯一变量**：原始 `ToolCall` / `ExecutionContext` / Policy / Gateway / Adapter 身份与签名密钥 / 数据集全部固定，每次独立 Grant 与 nonce；只有 **Adapter 的行为及 Receipt 生成方式**改变 → E2.0 良性无误拒、E2.1 偏离且如实报告（`DR=1.0`）、E2.2 偏离但虚假报告（`DR=0`、`UER=1.0`）。

---

## 4. 阶段研究结论

**核心结论（用户凝练）**

> **Adapter-Controlled Execution Evidence Is Insufficient for Verifiable Agent Authorization**
>
> 由执行者自主生成的执行证据不足以支撑可验证的 Agent 授权执行。

| # | 层次 | 支撑实验 | 判定 |
| --- | --- | --- | --- |
| 1 | 执行前授权绑定有效 | E1 | Gateway 能拒绝原始请求与 Context 的替换攻击、顺序与并发重放 |
| 2 | 执行后证据一致性检查有效但有局限 | E2.1 | Adapter 如实报告偏离时 Gateway 能检测（`DR=1.0`） |
| 3 | 执行证据缺乏独立性 | E2.2 | Adapter 通过自洽虚假 Receipt 使 Gateway 接受实际越权结果（`UER=1.0`） |

**两个必须分开的属性**：

- **签名完整性 ≠ 执行真实性**：签名证明谁签署了声明，不能证明声明描述的执行行为确实发生过。
- **审计完整性 ≠ 审计真实性**：`AuditChain.verify()` 通过是 P5 结构层结论，不能替代语义正确性；E2.2 即结构通过、语义错误的实例。

> **不得**把上述结论写成「一个已经解决的密码学研究问题」，**不得**声称 Halo2 已解决执行真实性。E 阶段只完成了**能力上限的定位与可重复反例的构造**，比「Agent 存在越权风险」更有价值之处在于明确定位了信任缺口。

---

## 5. 适用边界（必须在研究报告中如实写出）

| # | 边界 | 说明 |
| --- | --- | --- |
| B1 | 并发原子性范围 | 只验证当前 Gateway 实例内 nonce 原子消费；不外推多进程 / 多实例 / 分布式（G4 / G6、S1） |
| B2 | 上下文覆盖范围 | E1.2 只验证 `tenant_id`；`session_id` / `task_id` 未分别验证；Context 无 `user` 字段（G9） |
| B3 | 未执行的设计臂 | `E1.1-c` 策略复核隔离、session/task 分字段、`E1.2-b` TOCTOU 复跑未实施，仍为 R0 / R2 |
| B4 | 探针是夹具级观测 | `_QueryProbe` 只钩指定测试路径的真实读取，**不能证明任意恶意 Python 代码无法绕过探针**，更不等于 Gateway 具备独立数据访问监督能力 |
| B5 | 副作用定义 | mock 工具只有只读查询、无写操作；「副作用」= 返回越权行 `Finance/3400`，不外推为写操作或可撤销性；`execute_count` 单独不构成副作用证据 |
| B6 | Gateway 无独立执行观测来源 | L532 的 `output_hash` 输入仍是 Adapter 返回的 output，Receipt 由 Adapter 自签 → 闭环自证；Gateway 只能验证「声明与返回输出自洽」，不能验证「返回输出 = 实际读取数据」（G3、U1 未闭合） |
| B7 | E2.2 结论范围 | 只在**当前受控测试夹具**中证明 Gateway 无法区分自洽虚假声明与真实执行；**不得**声称任意恶意 Adapter 都能绕过所有部署环境下的安全机制 |
| B8 | 审计结构 vs 语义 | `AuditChain.verify()` 通过 ≠ DR ≠ 语义正确；「审计记录了攻击」≠「系统阻止了攻击」 |
| B9 | 统计与合并纪律 | 10 次独立 nonce 只验证稳定性，不构成统计显著性；E1 四组 / E2 三臂计数禁止合并 |
| B10 | Halo2 / Rust 侧 | **E 阶段全部实验未涉及 Halo2**；Python 侧结论不得写成端到端 ZK 系统结论 |

---

## 6. 设计基线（v0.1）与实际执行的偏差登记

本卷宗**不回改基线**，仅登记差异，供研究报告如实说明「设计 vs 执行」。

| 冻结 v0.1 设计 | 实际执行 | 差异 |
| --- | --- | --- |
| §7 只留「E2（Adapter 偏离 / 信任边界）」预留位，无子臂编号 | E2.0 / E2.1 / E2.2 三臂 | 编号为 E 阶段新增；「E2.3 的结果判定」按用户统一视为 **E2.2**，不再保留 E2.3 编号 |
| §7 预期 `RECEIPT_INVALID` → `ASR=1, PR=0, DR=1` | E2.1 实测一致；E2.2 新增 `ASR=1, PR=0, DR=0, UER=1` | 基线未预见自洽 Receipt 分支；**不回改预期值**，以本卷宗 R3 为准 |
| §1.1 三率（ASR / PR / DR） | 三率**原样沿用** + 新增 UER 辅助指标 | 用户拍板不回改 v0.1、UER 不取代 ASR |
| 方案初稿「E2.0 单次基线」 | E2.0 改为 10 次独立 Grant / nonce | D5「每臂 ≥10 次」优先；按用户拍板执行 |
| E1.1-c / E1.4 等 | 见 `e1-results-v0.1.md` §4 | 并发重放以 E1.3-b 名义完成，并更换为阻塞 Adapter 方案 |

> 若写论文，需统一编号并说明「设计 vs 执行」的方案变更；以 **v0.2 修订**，不回改 v0.1。

---

## 7. 原始数据与可复现入口

**测试入口**（均在 `tests/test_agent_exec_binding.py`，全部真实存在）：

| 阶段 | 测试名 |
| --- | --- |
| E1.1 | `test_request_tampering_after_authorization_denied`、`test_e1_1_adapter_counter_detects_a_real_execution` |
| E1.2 | `test_e1_2_baseline_context_matches_grant`、`test_e1_2_tenant_substitution_denied_10_runs` |
| E1.3 | `test_e1_3_a_sequential_replay_10_groups`、`test_e1_3_b_concurrent_replay_10_groups` |
| E2.0 | `test_e2_0_honest_baseline_10_runs`、`test_e2_0_query_probe_captures_real_filter_and_is_receipt_independent`、`test_e2_0_probe_mutation_breaks_result_observation` |
| E2.1 | `test_e2_1_detectable_adapter_deviation_10_runs` |
| E2.2 | `test_e2_2_self_consistent_malicious_receipt_10_runs` |

**逐次原始 JSON 标记**：`E1_1_RESULTS`、`E1_2_BASELINE`、`E1_2_RESULTS`、`E1_3_A_RESULTS`、`E1_3_B_RESULTS`、`E2_0_RESULTS`、`E2_1_RESULTS`、`E2_2_RESULTS`、`E2_2_CLASSIFICATION`（由测试 `print` 输出；10 行逐次数值一致、nonce 互不相同）。

**复现命令**（仓库根目录，使用 `.venv`）：

```
./.venv/Scripts/python.exe -m unittest discover -s tests -k e2_2 -v
./.venv/Scripts/python.exe -m unittest discover -s tests -v
```

**控制变量**：原始 `ToolCall`（Sales / `year=2026` / `fields` / `limit=5`）、`ExecutionContext`（S1 / T1 / `tenant:example`）、demo policy、Gateway 配置、Adapter 身份与 `tool_sk`、固定 3 行数据集（Sales/2026/1200、Finance/2026/3400、Sales/2025/900）全程不变；每次独立 Grant 与 nonce。E2.1 / E2.2 的 Adapter 局部类分别为 `_DeviatingProbedTool`、`_SelfConsistentProbedTool`，均继承 E2.0 的 `_ProbedTool`，不复制查询与投影逻辑。

---

## 8. 阶段节点仓库集中核查快照（2026-11-12 归档时点）

| 项目 | 状态 |
| --- | --- |
| Python 全量测试（本轮复跑，**非新实验**） | **`Ran 69 tests … OK`**（0.471s；`test_agent_exec_binding` 34 / `test_data_access` 21 / `test_plan_batch` 14） |
| `git diff --check` | clean |
| HEAD | `610b280`（未提交、未推送） |
| 工作树 | 6 个 `M`（README、生产代码、3 份 docs、测试文件）+ `?? research/` |
| 累计 `git diff --stat` | 6 files changed, 2014 insertions(+), 107 deletions(-) |
| 生产代码 | **E 阶段全程未修改**；`agent_exec_binding.py` mtime `2026-11-11 21:20:13`，sha256 `7ca84580…` |
| 四份冻结基线 | 归档时点内容指纹（sha256 前 8 位）：`threat-model` `8d761d90`、`security-properties` `8d5cce37`、`attack-experiment-matrix` `44a87fe0`、`e1-results` `b903182e`；**本轮未回改** |
| README | 仍写上阶段 `80/80`（Python 59 + Rust 21）；当前 Python 已为 69。**按用户决定暂缓更新，留待阶段统一同步** |
| 测试侧累计 | `tests/test_agent_exec_binding.py` 24 → 34 个测试（E1 新增 5、E2 新增 5）；E2 新增 4 个探针类 + 2 个局部 Adapter 类 |
| Halo2 / Rust | E 阶段未涉及 |

---

## 9. 后续三阶段路线（**登记，不实施**）

| 阶段 | 内容 | 本轮状态 |
| --- | --- | --- |
| 一 · E 阶段正式归档 | 整理 E1/E2 结果、原始数据、指标定义与适用边界，形成独立结果卷宗；保留 v0.1 威胁模型与安全属性文档，不回改冻结基线 | **本卷宗完成** |
| 二 · 独立执行证据设计 | 研究如何让执行证据不再完全由 Adapter 自己产生；用户列出的方向：执行参数与授权声明的独立绑定、数据访问层的可信观测、执行结果的可验证承诺、执行身份与授权身份的分离、**Halo2 能证明什么以及不能证明什么** | 仅登记方向，**本轮不设计、不引入 Halo2** |
| 三 · 反例驱动增强实验 | 不能只设计「看起来更安全」的方案：必须**重新构造 E2.2 攻击**，让增强机制面对同样的恶意 Adapter，再比较是否真正降低 $\operatorname{UER}$ | 仅登记，未实施 |

> 按用户决定：**暂时把 E2.2 作为本轮实验终点**；不扩展 Halo2、不修改生产代码，直到用户下发下一阶段设计。工作分工保持「用户设计阶段实验、AI 执行并反馈、阶段节点集中核查仓库」。

---

## 10. 变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| **v0.1（冻结 E 阶段结果）** | **2026-11-12** | 首次把 E1+E2 汇总为阶段级结果卷宗：指标定义与 A/B/C/D 互斥分类、E1 四组汇总、E2 三组 R3 数据首次落地（含三类独立观测、固定哈希对照、指标）、核心结论与两个属性区分、B1–B10 边界、基线偏差登记、复现入口、阶段节点仓库快照、后续三阶段路线。**不回改 v0.1 基线、不改 README、不改代码、不改测试、不提交推送。** |
