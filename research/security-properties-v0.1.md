# Agent Execution Binding — 安全性质定义 v0.1

**状态：** **v0.1 定稿（冻结研究基线）**。**这些性质是研究目标，不代表已全部得到证明或已被实现满足。**
**日期：** 2026-11-12（初稿与定稿同日）
**配套文档：** `threat-model-v0.1.md`（攻击者 / 信任边界 / D1–D5 决定）、`attack-experiment-matrix-v0.1.md`（实验设计与结果位）
**冻结时约束：** 未改代码、未跑实验、未提交、未推送。证据等级沿用 `threat-model-v0.1.md` §0（R0 定义 / R1 静态核对 / R2 上阶段实测 / R3 本研究阶段新实验，**v0.1 冻结时 R3 为空**）。
**本版依据：** 用户决定 **D3** —— P5/P6 判定标准原则上采纳，补充可观测性要求，**区分审计完整性与故障分类，不能只看是否有日志**。§4 据此重写。

---

## 0. 记号、判定对象与「实际执行」的测量口径（R0）

| 记号 | 含义 |
| --- | --- |
| $r$ | 将交付执行的请求（canonical 字节） |
| $c$ | 执行上下文 `ExecutionContext` |
| $g$ | `SignedGrant`，$g.p$ 为其 payload，$g.\sigma$ 为签名 |
| $\pi$ | `Policy` |
| $S$ | Gateway 重放状态（`used_nonces`） |
| $H(\cdot)$ | `sha256_hex(canonical_json(\cdot))` |
| $e$ | 工具实际执行的操作字节（**Gateway 不可直接观测**） |
| $\rho$ | `SignedReceipt` |

**「实际执行」的操作化定义（本研究的关键测量约定）：** 在 MVP 中，以 **Tool Adapter 的 `execute()` 被真实调用的次数** 与 **其返回的 `executed_rows`** 作为副作用的观测量，而**不**以 Gateway 的返回码或审计 decision 作为观测量。理由见 `test_concurrent_replay_only_executes_once` / `test_adapter_receives_snapshot_and_cannot_shift_binding` 均直接对 Adapter 侧计数或留痕（R1）。

**「副作用」在 MVP 中的含义：** 读取 `records` 并返回行。当前 mock 工具**没有写操作**，因此所有「副作用」都是只读数据访问；不得外推为「无副作用」或「可撤销」。

**两类作用时序（不可混用）：**

| 类型 | 定义 | 判定信号 |
| --- | --- | --- |
| **预防性（preventive）** | 判定发生在 Adapter 执行之前，越权操作未产生副作用 | 工具执行次数 = 0 |
| **检测性（detective）** | 判定发生在 Adapter 执行之后，副作用已产生 | 工具执行次数 ≥ 1，且审计状态为 `RECEIPT_INVALID` / `OUTCOME_UNKNOWN` |

**攻击者分层：** 每个性质必须分别标注对 **Planner** 与对 **Adapter** 的满足情况。二者不互推（§3）。

---

## 1. 统一判定式（R0，引自 `threat-model-v0.1.md` §3.1）

$$
\operatorname{Legit}(r,c,g,S,t) = \operatorname{Verify}_{pk_I}(g.\sigma,\operatorname{canon}(g.p))
\wedge g.p.\text{issuer\_id}=\text{expected}
\wedge H(\operatorname{canon}(r))=g.p.\text{request\_hash}
\wedge H(\operatorname{canon}(c))=g.p.\text{context\_hash}
$$
$$
\wedge\ g.p.\text{policy\_hash}=H(\operatorname{canon}(\pi))
\wedge \pi.\operatorname{check}(r,c)=\text{pass}
\wedge r.\text{tool\_id}=g.p.\text{tool\_id}
\wedge \texttt{tool.SCHEMA\_HASH}=g.p.\text{tool\_schema\_hash}
$$
$$
\wedge\ t\in[\text{issued\_at},\text{expires\_at})
\wedge \operatorname{FreshAndConsume}(g.p.\text{nonce},S)
\wedge \operatorname{Bind}(e,r)
$$

其中 $\operatorname{Bind}(e,r)$ 是当前 MVP 的**薄弱环节**：Gateway 只能把「自己交给 Adapter 的快照」当作 $r$，把「Adapter 自签的 receipt 声明」当作 $e$ 的证据；**无法独立观测 $e$**。见 `threat-model-v0.1.md` §3.3 的 U1。

> **顺序事实（R1，D4 实验设计的依据）：** Gateway 内 `request_hash` 比较在 $\pi.\operatorname{check}(r,c)$ **之前**，二者又在 `FreshAndConsume` **之前**。
> 因此若只替换请求而沿用原 Grant，拒绝会落在绑定层，**测不到策略检查是否独立生效**；见实验矩阵 §3.5。

---

## 2. 七项安全性质（R0 定义 + R1/R2 现状）

### P1 授权完整性 Authorization Integrity

> 原式：$\operatorname{Execute}(r)\Rightarrow \operatorname{Authorized}(r,g)$

- **可操作定义**：任何到达 Adapter 并产生返回行的请求 $r$，必须落在本次已签发、已验签、未过期、未消费的 Grant 所绑定的授权集合内。
- **验证条件（oracle）**：构造越权请求 → 断言 `AuthorizationError` 且 **Adapter 执行次数 = 0**；并检查 rejection reason 来自授权链而非偶然异常。
- **作用类型**：对 Planner **预防性**；对 Adapter **仅检测性**（ATK-A6 反例，R2）。
- **MVP 现状（R1）**：由 `request_hash` 比较、`issuer_id` 校验、policy 复核、`tool_id` / `SCHEMA_HASH` 比较、`expires_at` 判定共同实现；双点检查（Issuer `issue()` 内 `policy.check()` + Gateway 复核）。
- **相关测试（R1）**：`test_request_tampering_after_authorization_denied`、`test_write_operation_denied_before_grant`、`test_sensitive_field_denied_before_grant`、`test_filter_widening_denied_before_grant`、`test_row_limit_escalation_denied_before_grant`、`test_expired_grant_denied`、`test_tool_schema_drift_denied`、`test_custom_issuer_id_is_accepted_when_configured`。
- **已知缺口**：
  - **D1（G8 已关闭）**：授权集合定义为 **`Grant-authorized`**（与已签发 Grant 绑定的具体请求逐字节相同），**不是** `Policy-compliant` 的策略包络。demo policy 同时允许 Sales 与 Finance 是本项目的研究对象，**不是缺陷，不修改策略代码**（威胁模型 §3.2）。
  - U1：Adapter 侧偏离无预防性保证。
  - 排除项 2（Gateway 被攻破）一旦不成立，P1 全部失效。

### P2 上下文完整性 Context Integrity

> 原式：$C_{verify}=C_{execute}$

- **可操作定义**：Gateway 用于 `policy.check()` 与 `context_hash` 比较的对象，与 Adapter 收到的上下文对象，必须来自**同一次入口快照**；调用方持有的对象不得被二次读取。
- **验证条件**：传入一个「首次读取忠实、后续读取投毒」的上下文对象 → 断言调用方对象 `reads == 1`、Adapter 收到的是重建的 `ExecutionContext`、receipt 的 `context_hash` 等于 Grant 的 `context_hash`。
- **作用类型**：对 Planner **预防性**。
- **MVP 现状（R1）**：`json_snapshot(context.as_dict())` → `ExecutionContext(**context_data)` 重建；`context_hash` 覆盖 `session_id / task_id / tenant_id` 三字段，故任一字段替换都会被拒（policy 本身只校验 `tenant_id`）。
- **相关测试（R1）**：`test_context_substitution_denied`、`test_context_snapshot_is_used_for_policy_and_adapter`。
- **已知缺口**：
  - 上下文是从调用方 `as_dict()` 派生的，**没有独立可信来源**；若调用方在入口前就伪造上下文且 Issuer 也据此签发，Gateway 无法识别「真实租户」。这属于 S4 / 排除项 2 的边界。
  - **G9**：`ExecutionContext` 无 `user` 主体维度（仅 `session_id / task_id / tenant_id`）；主体标识实际在 `ToolCall.agent_id`。E1.2 以三字段覆盖，「user 维度」列入 v0.2 待扩展（需改代码）。

### P3 请求完整性 Request Integrity

> 原式：$R_{execute}=R_{authorized}$

- **可操作定义**：Adapter 实际用于查询的 `args`（fields / where / limit）必须与 Grant 绑定的请求逐字段一致；Gateway 交出的请求对象与调用方对象**无共享可变状态**。
- **验证条件**：Adapter 内修改 `call.args` → 断言 (a) 越权行确实被返回（副作用发生）、(b) 调用方原对象未被污染、(c) 审计为 `RECEIPT_INVALID` 而非 `DENY` / `ALLOW_EXECUTED`。
- **作用类型**：对 Planner **预防性**；对 Adapter **仅检测性**。
- **MVP 现状（R1）**：入口 `json_snapshot`、Adapter 侧 `ToolCall(... args=json_snapshot(call_data["args"]))`、`expected_receipt_bindings` 中的 `request_hash` 与 `output_hash` 比对。
- **相关测试（R1）**：`test_adapter_receives_snapshot_and_cannot_shift_binding`、`test_executed_rows_and_bindings_match_authorized_request`、`test_grant_payload_snapshot_blocks_mutating_mapping`、`test_receipt_is_verified_and_used_from_one_snapshot`。
- **已知缺口**：G3 —— `output` 与 `output_hash` 都由 Adapter 提供并自签，Gateway 只能验证「receipt 与返回输出自洽」，不能验证「返回输出 = 实际读取的数据」。故 P3 对 Adapter 是**声明级**检测，不是执行级证明。

### P4 防重放 Replay Resistance

> 原式：$\operatorname{SuccessfulUses}(g)\le 1$

- **可操作定义**：同一 `nonce` 的 Grant，无论串行还是并发，**Adapter 真实执行次数 ≤ 1**；且「检查 + 消费」必须是原子操作并在调用 Adapter **之前**完成。
- **验证条件**：串行两次 / 双线程并发 → 断言 `executions == 1`、`ALLOW == 1`、`DENY == 1`、审计 `ALLOW_EXECUTED == 1`；并以**移除锁的变异体**证明该断言有区分力。
- **作用类型**：对 Planner **预防性**。
- **MVP 现状（R1）**：`with self._nonce_lock:` 内检查并 `add`，发生在 `self.tool.execute()` 之前；工具异常时 nonce 仍保留（不回滚），故实际满足的是更强的 $\operatorname{ToolInvocations}(g)\le 1$，代价是失败后需重新签发 Grant。
- **相关测试（R1）**：`test_replay_denied`、`test_concurrent_replay_only_executes_once`、`test_concurrent_replay_test_detects_missing_lock`（变异反证）、`test_tool_exception_records_outcome_unknown`。
- **已知缺口**：
  - G4：`used_nonces` 单进程内存，非 crash-safe、非跨副本；P4 仅在 **S1** 假设下成立。
  - G6：并发竞争窗口由 `_GatedNonceSet` 的 0.2s 停顿构造，是**实测可复现窗口**，不是严格确定性的调度证明；论文中应表述为「带确定性门的并发反证」，不得写成「形式化并发正确性证明」。

### P5 审计绑定完整性 Audit Binding Integrity（D3 收紧后名称）

> 原式（用户给定）：审计记录能够关联授权、请求、执行结果和最终状态。
> **判定标准：** 见 §4.1（用户四条要求 + 可观测性要求）。

- **可操作定义**：每条终态审计条目必须可关联 $\langle g, r, \rho, \text{output}, \text{nonce}, \text{decision}, t\rangle$，且 `decision` 必须与**真实执行过程**一致；`AuditChain.verify()` 对**已存在的**记录提供哈希链与签名完整性。
- **作用类型**：**检测性**（事后）。
- **MVP 现状（R1）**：四类终态 `DENY` / `ALLOW_EXECUTED` / `OUTCOME_UNKNOWN` / `RECEIPT_INVALID`；`AuditChain` 为带签名的哈希链，`append()` / `verify()` 均加锁。
  - `ALLOW_EXECUTED` 含 `policy_hash / request_hash / grant_hash / receipt_hash / output_hash / nonce / timestamp` —— **完整**。
  - `DENY` 仅含 `reason / request_hash / timestamp`。
  - `OUTCOME_UNKNOWN` / `RECEIPT_INVALID` 仅含 `reason / request_hash / nonce / timestamp` —— **缺 `grant_hash`、`receipt_hash`、`output_hash`**（G1、G2）。
- **相关测试（R1）**：`test_audit_tampering_detected`、`test_audited_grant_hash_is_pinned_before_adapter_runs`、`test_executed_rows_and_bindings_match_authorized_request`。
- **已知缺口**：G1、G2、G5（尾部删除未覆盖、审计签名私钥与 Gateway 同进程）、`grant_hash` 在 Adapter 运行前固定这一 TOCTOU 防护仅覆盖 happy path。
- **结论口径**：P5 在当前 MVP 为**部分满足**，且只对 `ALLOW_EXECUTED` 满足。**不得**写成「审计完整」；**有日志 ≠ 审计绑定完整**。

### P6 故障可观测性 Failure Observability（D3 收紧后定义）

> 原式（用户给定）：执行异常、Receipt 验证失败等情况必须被区分记录，不能将未知执行结果伪装成普通拒绝。
> **判定标准：** 见 §4.2（用户四条要求 + 可观测性要求）。

- **可操作定义**：`DENY`（未执行）、`ALLOW_EXECUTED`（已执行且证据有效）、`OUTCOME_UNKNOWN`（已尝试执行、结果未知）、`RECEIPT_INVALID`（已执行、证据无效）四态互斥且可区分，且**分类必须与真实执行过程一致**；异常路径下 nonce 保留、异常文本与工具输出不得写入审计。
- **作用类型**：**检测性**（事后记录），但状态区分本身发生在 Gateway 控制流内。
- **MVP 现状（R1）**：`RECEIPT_INVALID` 与 `OUTCOME_UNKNOWN` 独立于 `DENY`；`except Exception` 路径不写入异常文本或工具输出；nonce 在异常后仍留在 `used_nonces` 中，重放被拒。
- **相关测试（R1）**：`test_tool_exception_records_outcome_unknown`、`test_invalid_receipt_records_receipt_invalid`、`test_adapter_receives_snapshot_and_cannot_shift_binding`。
- **已知缺口**：`RECEIPT_INVALID` 不含 `receipt_hash`（G1），故「哪一份无效 receipt 触发了失败」不可关联；Gateway 在工具异常时重新抛出原始异常（未包装），调用方看到的错误类型不受控；Gateway 进程崩溃则无任何条目写入 —— 这是 S1 / 排除项 2 的边界。
- **结论口径**：满足状态区分，但**不满足字段齐全**；且**「如实记录了攻击」不等于「攻击被阻止」**。

### P7 密码学不可伪造性 Cryptographic Unforgeability

> 原式（用户给定）：在签名算法安全假设成立的前提下，攻击者不能伪造 Issuer 的有效授权。

- **可操作定义**：攻击者无法在不知道 Issuer 私钥的情况下，构造出通过 `Verify_{pk_I}(σ, canon(p))` 且 `issuer_id` / `policy_hash` / `request_hash` 等为自选值的 payload；且验签所用字节与后续所有读取所用的字节相同。
- **验证条件**：替换签名为无效字节 → `DENY`；使用可变 payload 映射（多次 `get("nonce")` 返回不同值）→ 断言所有消费、receipt、审计都使用**同一次快照**里的真实 nonce。
- **作用类型**：**预防性**（对 Planner）。
- **MVP 现状（R1）**：Ed25519（`cryptography` 实现），`canonical_json` 固定签名字节；`canonical_payload` 在入口取一次，`json_snapshot` 阻断 TOCTOU。
- **相关测试（R1）**：`test_forged_grant_signature_denied`、`test_grant_payload_snapshot_blocks_mutating_mapping`、`test_custom_issuer_id_is_accepted_when_configured`。
- **已知缺口**：这是**对底层算法安全假设的引用**，不是本项目给出的证明；无形式化验证、无密钥轮换 / 吊销机制；Issuer 私钥泄露属排除项 1。Ed25519 ≠ ZK：Python 执行路径不使用零知识证明。

---

## 3. 性质之间的依赖与不可互推（R0）

| 关系 | 说明 |
| --- | --- |
| **P7 ⇏ P1** | 签名不可伪造只保证「Grant 是 Issuer 签的」；若 Gateway 不做 `request_hash` 比较，合法 Grant 仍可被配到越权请求上。二者由不同检查实现。 |
| **Policy-compliant ⇏ Grant-authorized** | 策略合规不蕴含授权一致；这正是 E1.1-b 要验证的核心区分（D1）。 |
| **P1 ⇏ P2 / P3** | 授权范围正确，不保证校验时上下文 / 执行时请求是同一对象（TOCTOU）。这是上一阶段 N1/N2/N3 快照闭环要解决的问题。 |
| **P4 需要 S1** | 「最多一次」依赖状态原子性；移除 `_nonce_lock` 的变异体（R2）直接使 P4 失效，而 P1/P2/P3/P7 仍可通过。 |
| **P5 ⇏ P6** | 记录可关联 ≠ 状态可区分；一条「完整绑定」的 `DENY` 记录也可能把未知执行结果伪装成拒绝。 |
| **P6 ⇏ P5** | 状态可区分 ≠ 字段齐全；`RECEIPT_INVALID` 就是有状态、缺 `receipt_hash` 的例子（G1）。 |
| **P5 / P6 ⇏ 阻止** | 审计写入只是观测；`RECEIPT_INVALID` 出现时副作用**已经发生**。审计记录了攻击，不代表系统阻止了攻击。 |
| **检测 ⇏ 阻止** | 所有针对 Adapter 的性质（P1/P3 的 Adapter 侧、P5、P6）都是检测性。 |
| **R2 ⇏ R3** | 上一阶段实测不构成「本研究阶段实验结论」；E1 需独立产出 R3 数据。 |

---

## 4. P5 / P6 判定标准（D3 采纳，v0.1 冻结）

### 4.0 判定原则（用户 2026-11-12 补充）

1. **两个性质必须分开判定**：P5 问「记录能否关联回完整执行过程」（**审计完整性**）；P6 问「终态分类是否与真实执行过程一致」（**故障分类**）。
2. **不能只看「是否有日志」**。判定分两层：
   - **结构层**：字段是否齐全、哈希链是否可验证、篡改能否发现；
   - **语义层**：`decision` 是否与 `executions` / `executed_rows` / 副作用事实一致。
   只有结构层通过而语义层错误，仍判 **P5/P6 不满足**。
3. **审计记录与阻止能力正交**：一条准确记录 `RECEIPT_INVALID` 的日志是 P6 的**正面**证据，同时是「攻击未被阻止」的**正面**证据。二者不得互相抵消。
4. 下表「当前 MVP」列均为 **R1 静态核对**；语义层条目需 E1/E2 实验补 **R3** 数据后才能给最终结论。

### 4.1 P5 审计绑定完整性 —— 用户四条要求逐条判定

| # | 用户要求 | 可写成 pass/fail 的判定条件 | 层 | 当前 MVP（R1） |
| --- | --- | --- | --- | --- |
| P5-① | **能关联到唯一授权 Grant** | 终态条目含 `grant_hash`，且该 hash 指向**验签那一刻**的 Grant（而非 Adapter 后续改写对象）；`nonce` 唯一 | 结构 | ⚠️ 仅 `ALLOW_EXECUTED` 满足；`test_audited_grant_hash_is_pinned_before_adapter_runs` 覆盖 happy path |
| P5-② | **能关联到对应请求及执行结果** | 含 `request_hash`；若工具已运行还应含 `receipt_hash` 与 `output_hash` | 结构 | ⚠️ `request_hash` 四类均含；`receipt_hash`/`output_hash` 仅 `ALLOW_EXECUTED`（G1、G2） |
| P5-③ | **最终状态与实际执行过程一致** | `decision` 与 Adapter 侧 `executions` / `executed_rows` 一致：`executions=0` ⇒ `DENY`；`executions≥1` 且证据有效 ⇒ `ALLOW_EXECUTED`；证据无效 ⇒ `RECEIPT_INVALID` | **语义** | ✅ 现有测试逐场景覆盖（R1）；**需 E1/E2 的 R3 系统性计数确认** |
| P5-④ | **篡改关键审计字段能被发现** | 改任一 `event` 字段后 `AuditChain.verify()` 返回 `False` | 结构 | ✅ `test_audit_tampering_detected`；❌ 尾部删除/截断未覆盖（G5） |

**细化检查项（保留初稿的字段级清单，供逐项打勾）：**

| 编号 | 条件 | 状态 | 对应上表 |
| --- | --- | --- | --- |
| P5-a | 每条终态条目可定位唯一 `nonce` | ✅（`DENY` 早于 nonce 取值时为 `None` 的边界需另测） | ① |
| P5-b | 每条终态条目含 `request_hash` | ✅ | ② |
| P5-c | 每条终态条目含 `grant_hash` | ❌ 仅 `ALLOW_EXECUTED` | ① |
| P5-d | 每条终态条目含 `receipt_hash`（若工具已运行） | ❌ G1 | ② |
| P5-e | 每条终态条目含 `output_hash`（若产生输出） | ❌ G2 | ② |
| P5-f | `AuditChain.verify()` 对已存在条目 `True`、篡改后 `False` | ✅ | ④ |
| P5-g | 尾部删除 / 截断可被检出 | ❌ G5 | ④ |
| P5-h | 条目描述的是验签那一刻的 Grant | ✅ happy path | ① |

**P5 结论口径（R0，D3 冻结）**：③ 语义层现有证据为正面但缺 R3 系统计数；① ② ④ 结构层仅部分满足（P5-c/d/e/g 不满足）→ **部分满足**，且只对 `ALLOW_EXECUTED` 完整。**不得**写成「审计完整」或「因为有日志所以满足」。

### 4.2 P6 故障可观测性 —— 用户四条要求逐条判定

| # | 用户要求 | 可写成 pass/fail 的判定条件 | 层 | 当前 MVP（R1） |
| --- | --- | --- | --- | --- |
| P6-① | **授权阶段拒绝与执行阶段异常可区分** | `DENY` 仅出现在 `executions=0`；`OUTCOME_UNKNOWN` / `RECEIPT_INVALID` 仅出现在工具已被调用之后；两者不得交叉 | **语义** | ✅ `test_tool_exception_records_outcome_unknown`、`test_invalid_receipt_records_receipt_invalid` |
| P6-② | **`OUTCOME_UNKNOWN` 不被错误记录为成功或失败** | 工具抛异常时审计 `decision == "OUTCOME_UNKNOWN"`，且 `ALLOW_EXECUTED` / `DENY` 计数均为 0；异常文本不入审计 | 结构 + 语义 | ✅ |
| P6-③ | **`RECEIPT_INVALID` 不被误认为执行前拒绝** | 工具已执行且 receipt 无效时，`decision == "RECEIPT_INVALID"`，且该次审计序列中**无 `DENY`**、无 `ALLOW_EXECUTED` | **语义** | ✅ `test_adapter_receives_snapshot_and_cannot_shift_binding` |
| P6-④ | **Adapter 已产生副作用、但 Receipt 后续验证失败，必须如实记录** | 同时记录：越权 `executed_rows` 非空（副作用发生）+ `RECEIPT_INVALID`（证据失败）+ nonce 保留；**不得**因「检测到了」而把该次记为成功或拒绝 | **语义 + 表述** | ✅ 状态级如实记录；❌ 缺 `receipt_hash`（G1），无法定位是哪份 receipt |

> **P6-④ 的不可让步结论（用户明确要求写入）：**
> **审计系统记录了攻击，不代表系统阻止了攻击。**
> 该场景下 `ASR=1`、`PR=0`、`DR=1`；`RECEIPT_INVALID` 是检测信号，**不是**拒绝信号。副作用已发生且不可撤销（U1 未闭合）。

**细化检查项：**

| 编号 | 条件 | 状态 | 对应上表 |
| --- | --- | --- | --- |
| P6-a | 四态互斥且各自有独立写入路径 | ✅ | ① |
| P6-b | 工具异常记为 `OUTCOME_UNKNOWN`，不记为 `DENY` / `ALLOW_EXECUTED` | ✅ | ② |
| P6-c | 工具已执行但 receipt 无效记为 `RECEIPT_INVALID`，不记为 `DENY` | ✅ | ③ |
| P6-d | 异常路径下 nonce 保留，重放仍被拒 | ✅ | ④ |
| P6-e | 异常文本 / 工具输出不写入审计条目 | ✅ | ② |
| P6-f | 每条终态条目含 `grant_hash` / `receipt_hash` 以便定位失效证据 | ❌ G1 / G2 | ④ |
| P6-g | Gateway 进程崩溃时结果可观测 | ❌ 未覆盖（S1 边界） | ① |

**P6 结论口径（R0，D3 冻结）**：① ② ③ 满足；④ 状态级满足、字段级不满足（P6-f）→ **部分满足**。

> P5 与 P6 的 R3 判定数据由 E1（P5-③ 的 `DENY` 场景）与 E2（P6-③/④ 的 Adapter 偏离场景）分别产出；
> 按用户决定 **E2 单独推进**，因此 v0.1 冻结时 P6-④ 的 R3 列保持为空。

---

## 5. 性质 × 攻击 × 证据 对应表（R0/R1/R2，R3 待测）

| 性质 | 主要攻击 | 预防/检测 | 对 Planner | 对 Adapter | 对应测试（R1） | 变异反证（R2，上阶段） |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | ATK-A1 | 预防 / 检测 | ✅ | ⚠️ 仅检测 | `test_request_tampering_after_authorization_denied` 等 8 项 | 未在 E1 阶段复跑 |
| P2 | ATK-A2 | 预防 | ✅ | ❌ | `test_context_substitution_denied`、`test_context_snapshot_is_used_for_policy_and_adapter` | 回退 Context 快照 → 对应测试失败 |
| P3 | ATK-A1、ATK-A6 | 预防 / 检测 | ✅ | ⚠️ 仅检测 | `test_adapter_receives_snapshot_and_cannot_shift_binding` 等 4 项 | 回退 Receipt / Grant 快照 → 对应测试失败 |
| P4 | ATK-A3、ATK-A4 | 预防 | ✅ | ❌ | `test_replay_denied`、`test_concurrent_replay_only_executes_once` | 移除 `_nonce_lock` → `test_concurrent_replay_test_detects_missing_lock` |
| P5 | ATK-A5、ATK-A6 | 检测 | — | ⚠️ 部分 | `test_audit_tampering_detected`、`test_audited_grant_hash_is_pinned_before_adapter_runs` | 回退 Grant Hash 固定 → 对应测试失败 |
| P6 | ATK-A5、ATK-A6 | 检测 | — | ⚠️ 部分 | `test_tool_exception_records_outcome_unknown`、`test_invalid_receipt_records_receipt_invalid` | 未在 E1 阶段复跑 |
| P7 | ATK-A1（伪造 Grant） | 预防 | ✅ | ❌ | `test_forged_grant_signature_denied`、`test_grant_payload_snapshot_blocks_mutating_mapping` | 未在 E1 阶段复跑 |

> 表中「✅」= 当前实现**预防性**满足；「⚠️ 仅检测」= 副作用可发生、仅能事后发现；「❌」= 无独立保证；「部分」= 见 §4。

---

## 6. 声明（R0）

1. P1–P7 是**研究定义**，不是定理；本文件不提供任何形式化证明、安全归约或生产级安全声明。
2. 单元测试通过只说明原型行为符合预期；**不构成**安全性有效性（security effectiveness）的证据（`README.md` L42 / L104 已有同口径声明）。
3. 本文不涉及 Halo2 / Rust 电路；Python 执行路径不使用零知识证明，Rust 侧电路未与 Python 授权信封集成。
4. 「检测」与「阻止」在本文全篇分离；任何实验结论不得把 `RECEIPT_INVALID` 计为「攻击被阻止」。
5. **P5 判审计完整性，P6 判故障分类**；二者均不得仅以「有日志」判定通过。
6. **v0.1 冻结时未执行 E1 实验**，所有 R2 标注均为上一阶段记录的引用，R3 结果位为空。

---

## 7. 变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v0.1 draft | 2026-11-12 | 初稿：记号与测量口径、Legit 判定式、P1–P7 逐项可操作定义/验证条件/作用类型/MVP 现状/缺口、性质依赖表、P5-P6 判定标准提案、性质×攻击×证据表。未跑实验、未改代码。 |
| **v0.1 定稿（冻结）** | **2026-11-12** | 依 D3 重写 §4：P5 更名「审计绑定完整性」、P6 明确为故障分类；二者按用户四条要求逐条给出 pass/fail 条件，新增 §4.0「结构层 / 语义层」判定原则与「不能只看是否有日志」；写入「审计记录了攻击 ≠ 阻止了攻击」及 `ASR=1/PR=0/DR=1` 口径。依 D1 更新 P1 缺口（G8 关闭，授权集合 = `Grant-authorized`）；P2 新增 G9（上下文无 user 维度）；§1 补充 Gateway 检查顺序事实；§3 新增 `Policy-compliant ⇏ Grant-authorized`、`P5/P6 ⇏ 阻止` 两条不可互推。**仍未跑实验、未改代码、未改既有文档、未提交推送。** |
