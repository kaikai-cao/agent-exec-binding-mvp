# R2.8-P2 — 执行授权、持久化防重放与历史效果恢复：最小修复与对照实验报告

**任务性质：** 工程基线强化 + 可重复对照实验；**不是**新密码学构造，不以论文创新为预设目标。
**研究问题：** 普通系统工程机制能否修复 R2.8-P0/P1 复现的四项缺陷（E1 授权绕过、E2 日志尾部截断、E5 跨实例重放、E6 效果与审计不一致），以及是否出现必须由新密码学机制才能满足的安全性质。
**底线声明：** 不声称普遍意义的 exactly-once；不声称跨存储原子性；不把"签名有效"描述成"数据真实"；不把"日志可验证"描述成"日志一定完整"；不把"工具回执"描述成"外部效果一定真实"；不把 UNKNOWN 描述成安全完成。

---

## 1. 实验环境与基线门禁（Phase 0）

| 项目 | 值 |
|---|---|
| 仓库 | `kaikai-cao/agent-exec-binding-mvp` |
| 本地目录 | `D:\Research\agent-exec-binding-mvp` |
| 固定上一轮提交（基线 SHA） | `d422d334f14ce59d6fc0c316dc6951460835531e` |
| 基线父提交 / main | `f3048571268642696616d9f38c536d9449106918`（未动） |
| 基础分支 | `r2-8-p0-p1-boundary-audit`（本地与远端 HEAD 均为基线 SHA，已核验） |
| 新工作分支 | `r2-8-p2-minimal-hardening`（创建前本地/远端均不存在，从基线创建） |
| Python / 依赖 | 仓库 `.venv`（Python 3.14）+ `cryptography`；标准库 `sqlite3`，无新增第三方依赖 |
| 操作系统 | Windows 11 |
| 实验日期 | 2026-11-26 |

### 1.1 门禁检查逐项结果

| 检查项 | 结果 |
|---|---|
| 工作区 `git status --short`（建分支前） | clean |
| 本地审计分支 HEAD == 基线 SHA | 是 |
| 远端审计分支 HEAD == 基线 SHA（`ls-remote`，是） | 是 |
| main 保持原状态 | 是（`f304857`） |
| P2 目标分支创建前不存在 | 是 |
| 原始回归 `python -m unittest discover -s tests -v` | `Ran 75 tests … OK` |

无任何基线不一致；未执行 reset / 清理 / 强推。

### 1.2 测试结果汇总

| 运行 | 命令 | 结果 |
|---|---|---|
| 新建 P2 测试 | `python -m unittest discover -s tests -p "test_r2_8_p2.py" -v` | `Ran 18 tests … OK` |
| 全量回归 | `python -m unittest discover -s tests -v` | `Ran 93 tests … OK`（75 原始 + 18 新增，0 failure / 0 error） |

**结果口径：** 测试通过表示"修复后行为被观察到"或"缺陷对照行为被复现"，测试数量本身不构成安全结论。P0/P1 六个缺陷复现测试（`test_r2_8_boundary.py`）原样保留、未修改、仍全部通过，作为旧基线。

---

## 2. 设计原则：opt-in 强化 + 双轨并存

本轮最重要的设计决策是**所有修复均为显式启用（opt-in）**：

- 基线类 `MockFinanceTool`、`ToolGateway.execute()`、`AuditChain.verify()` **完全不改**（`agent_exec_binding.py` 的 diff 为 647 行新增、0 行删除/修改），因此 P0/P1 的六个缺陷复现测试继续成立，构成可比较的"修复前"列。
- 修复路径通过新类/新方法提供：`VerifyingTool`（E1）、`CheckpointWitness` + `verify_audit_with_checkpoint()`（E2）、`NonceRegistry` + `HardenedToolGateway`（E5/E6）、`ExecutionLedger` + `ExecutionReconciler`（E6），由 `make_hardened_environment()` 装配。

这保证了"必须同时保留旧基线与修复后版本的可比较结果"，且不允许用修复覆盖掉缺陷证据。

---

## 3. 四项修复的实现与证据

### 3.1 E1 — 工具端独立授权验证

**实现：** 新增 `VerifyingTool(MockFinanceTool)`。工具在构造时**自身持有**可信 issuer 公钥与期望 issuer id / policy hash，**不接受调用者提供的公钥或策略**。执行前独立做九项校验：①Ed25519 签名 ②issuer 身份 ③principal ④tool id ⑤tool schema hash ⑥request hash ⑦context hash ⑧授权有效窗口 ⑨policy 绑定 + nonce 格式与一次性消费状态（与 E5 共用同一 `NonceRegistry`，避免网关与适配器双重消费导致正常请求失败）。

| 测试 | 修复前（P0/P1 基线） | 修复后（P2） | 证据 |
|---|---|---|---|
| 伪造签名直连 Adapter | 可执行、返回 `id_number`、签发有效回执 | **拒绝**（`invalid grant signature`，execute_count=0） | `E1_P2_FORGED` |
| 合法签名但请求被替换 | — | **拒绝**（`request hash mismatch`） | `E1_P2_SWAPPED` |
| schema 不一致 | — | **拒绝**（`schema hash mismatch`） | `E1_P2_LEGIT`（schema_rejected=true） |
| context 不一致 / 过期 | 过期经网关拒绝，Adapter 自身不验 | Adapter 独立**拒绝**（`context hash mismatch` / `not currently valid`） | `E1_P2_CONTEXT_EXPIRY` |
| 合法 Grant 精确请求 | 可执行 | **放行**（execute_count=1，工具记录一条 ACCEPT） | `E1_P2_LEGIT` |

**边界：** 工具端验证阻止"伪造授权的直连调用"，但**不是**对所有可能执行旁路的证明。若攻击者能替换工具对象本身、其可信公钥，或调用比 Adapter 更底层的函数，则不在该机制覆盖范围。E1 成立前提（能否远程触达 Adapter）本轮仍未测试，仍记为条件性。

### 3.2 E2 — 外部审计检查点

**实现：** 新增 `CheckpointRecord`（绑定 last_seq / last_entry_hash / log_id / version）、`CheckpointWitness`（序号不得倒退、同一序号不接受不同 head hash）、`UnavailableCheckpointWitness`（服务不可用），以及 `verify_audit_with_checkpoint()`。验证时把日志末尾与外部 checkpoint 比较，返回四态之一：`COMPLETE` / `INCOMPLETE`（有未锚定额外记录）/ `DIVERGED`（缺已锚定终端记录、head 篡改或链断裂）/ `UNVERIFIED`（witness 不可用或无锚点）。checkpoint 独立于 `AuditChain.entries` 存储。

| 测试 | 修复前 | 修复后 | 证据 |
|---|---|---|---|
| 正常链 | verify=True | `COMPLETE` | `E2_P2_NORMAL` |
| 追加未锚定记录 | 无此概念 | `INCOMPLETE`（非 COMPLETE） | `E2_P2_NORMAL` |
| 尾部删 1 / 删 2 | 仍 `verify=True`（漏检） | `DIVERGED` / `DIVERGED`（普通 verify 仍 True，说明检查点必要性） | `E2_P2_TAIL` |
| 中间删除 | 检出 | `DIVERGED` | `E2_P2_MISC` |
| 篡改 head | 检出 | `DIVERGED` | `E2_P2_MISC` |
| 检查点回退 / 同序号异 hash | 无此机制 | 均拒绝（`CheckpointError`） | `E2_P2_MISC` |
| witness 不可用 | 无此机制 | `UNVERIFIED`（不确定态，非 COMPLETE） | `E2_P2_MISC` |

**信任假设：** 参考实现 `CheckpointWitness` 是进程内对象，**只验证协议逻辑**，不能冒充真实独立部署的外部见证服务。真实部署需由独立可信主体或独立存储保护检查点；否则持有日志与检查点同一写权限的攻击者仍可同时回滚两者。

### 3.3 E5 — SQLite 持久化 nonce 消费

**实现：** 新增 `execution_ledger.py` 的 `NonceRegistry`：nonce / grant_hash / request_hash / principal / consumed_at 一条一行，`BEGIN IMMEDIATE` + UNIQUE 主键在单事务内原子消费；`force_commit_error` 测试钩子验证提交失败无半完成状态。`HardenedToolGateway` 用该注册表替代网关内存集合，且工具端共享同一注册表（identical duplicate 在工具侧接受、在网关侧拦截，避免双重消费失败）。

| 测试 | 修复前 | 修复后 | 证据 |
|---|---|---|---|
| 单实例重复请求 | 第二次重放成功 | 拒绝 | `E5_P2_REPLAY` |
| 新 Gateway 实例重放 | 成功 | 拒绝（nonce_count=1, execute_count=1） | `E5_P2_REPLAY` |
| SQLite 关闭并重开 | 无持久化 | 重开后仍在，重复消费返回 identical duplicate（非新消费） | `E5_P2_REOPEN` |
| 两个/四个 Gateway 并发消费 | 无原子保证 | 4 个独立连接仅 1 个成功（wins=1, rows=1） | `E5_P2_CONCURRENT` |
| 事务提交失败 | 无此语义 | 抛错、库内 0 行、重试可成功（无半状态） | `E5_P2_COMMIT_FAIL` |
| 不同 nonce 独立消费 | — | 3 行独立；同 nonce 换绑定触发 `NonceConflict` | `E5_P2_DISTINCT` |

**重放成功次数：0**（所有重放尝试均被拒）。**信任假设：** 原子性限于同一 SQLite 文件的单事务；WAL + busy_timeout 缓解但不等于分布式事务。防重放的前提是所有执行路径都查询同一注册表；绕过注册表的调用路径不在保证内。

### 3.4 E6 — 执行效果与审计恢复（本轮重点）

**实现：** `ExecutionLedger` 持久化状态 `INTENT → EXECUTING → COMPLETED`，失败转 `OUTCOME_UNKNOWN`，确认后转 `RECONCILED`（终态不可降级）。`HardenedToolGateway.execute()` 在**任何副作用之前**先写 INTENT，再消费 nonce，再调用工具。`VerifyingTool` 把 nonce→执行结果及签名 Receipt 持久化到 `ToolResultStore`，并提供 `query_execution(nonce)` 查询接口。`ExecutionReconciler` 对缺终态的记录：查询工具状态 → 校验 Receipt 签名 → 三方绑定（工具输出摘要 == 工具报告 hash == Receipt hash，且 request/context/policy/tool/schema/nonce 全部匹配已存意图）→ 写补偿审计 `ALLOW_EXECUTED_RECONCILED` → 转 `RECONCILED`；**全程不重新执行工具**。工具无法确认效果时保持 `OUTCOME_UNKNOWN`。

五项故障注入 + 边界：

| 故障点 | 修复前 | 修复后 | 证据 |
|---|---|---|---|
| 最终审计写入失败 | 效果已发生、无终态审计、无恢复记录 | 意图保留、状态 OUTCOME_UNKNOWN；对账后 `RECONCILED`（execute_count=1，未重放副作用），写入 `ALLOW_EXECUTED_RECONCILED` | `E6_P2_RECOVER` |
| 恢复过程中审计再次失败 | — | 保持 OUTCOME_UNKNOWN，`RECONCILE_UNKNOWN`，未宣称成功 | `E6_P2_RECOVERY_FAIL` |
| Intent 写入后、工具执行前崩溃 | — | 有意图、execute_count=0；对账返回 UNKNOWN | `E6_P2_INTENT_CRASH` |
| 工具完成效果+Receipt 后、返回前崩溃 | — | 可恢复：对账 `RECONCILED`、execute_count=1（未重复执行） | `E6_P2_CRASH_AFTER_EFFECT` |
| 工具 STARTED 但无 Receipt | — | 效果不可判定，保持 UNKNOWN | `E6_P2_STARTED_NO_RECEIPT` |
| 工具无查询/幂等能力 | — | 明确返回 UNKNOWN（不冒充成功） | `E6_P2_NO_QUERY` |

**恢复实验统计：** 可确认效果的场景（最终审计失败、效果后崩溃）恢复成功率 **2/2**；保持 UNKNOWN 的场景 4 类（恢复审计失败、intent 后崩溃、STARTED 无回执、无查询能力），均为**预期不确定**，非失败。**错误接受次数：0**（无未绑定 Receipt 被接受）。**OUTCOME_UNKNOWN 数量：** 4 类场景保持不确定。

**保证边界：** 恢复依赖外部工具提供"按幂等键持久化结果 + 状态查询"两个能力；二者缺一即返回 UNKNOWN。补偿记录是对账证据，**不是**把原 `ALLOW_EXECUTED` 重放出来，也不构成跨存储原子性或 exactly-once。

---

## 4. 对照实验汇总表（E1–E6 修复前后）

| 测试 | P0/P1 基线 | P2 修复后 |
|---|---|---|
| E1 伪造 Grant 直连 | 可执行（条件性） | 拒绝（工具端独立验签+九项绑定） |
| E2 尾部截断 | verify 通过（漏检） | `DIVERGED`（检测）；额外记录 `INCOMPLETE` |
| E3 中间删除 | 检出 | 检出（保持，`DIVERGED`） |
| E4 效果后异常 | `UNKNOWN` + nonce 保留 + 拒重放 | 保持；并可由对账接口处理（本轮未改变其正确语义） |
| E5 重启重放 | 可重放 | 拒绝（跨实例/重开/并发） |
| E6 最终审计失败 | 无恢复记录 | 保留意图 + 可恢复 / 明确 UNKNOWN |

## 5. 量化指标

| 指标 | 值 |
|---|---|
| 新增测试数量 | 18（`tests/test_r2_8_p2.py`） |
| 原始测试通过情况 | 75/75 OK（未修改） |
| 全量回归 | 93/93 OK |
| 恢复成功率（可确认效果场景） | 2/2 |
| 重放成功次数 | 0 |
| 错误接受次数 | 0 |
| OUTCOME_UNKNOWN 场景数 | 4（均预期） |
| 网关执行一次延迟 | 约 7.5 ms（单样本，冷启动量级，非性能结论） |
| nonce 原子消费延迟 | 约 0.7 ms（单样本，SQLite 本地文件） |
| SQLite 信任假设 | 单文件单事务原子；所有执行路径须查同一库；文件写权限即信任边界 |
| Witness 信任假设 | 参考实现为进程内逻辑验证；真实部署需独立可信主体/存储 |

> 延迟为单次测量，仅说明量级；本轮不是性能研究，不据此声称相对其他方案的普遍性能优势。

---

## 6. 研究判断（Phase 3）

**1. E1 能否通过 Adapter 端授权验证解决？**
能解决"伪造授权直连 Adapter"这一具体缺陷：把验签与请求/上下文/工具绑定下沉到持有可信公钥的工具端即可。但**不能**被描述为对所有执行旁路的整体证明——能替换工具对象/密钥或调用更底层的地方仍可绕过，且能否远程触达 Adapter 未验证。这是信任边界设计，不是证明系统问题。

**2. E2 是否只需要外部可信检查点？**
就"检测尾部截断/未被锚定记录"这一性质而言，外部检查点是最小充分机制：把最新已确认 head 锚定在日志之外，验证时比较即可。但检查点本身的可信度、可用性与分发是独立的工程/部署问题（进程内 witness 只验证协议逻辑，不是真实独立见证）。检查点把"日志可验证"从"局部前缀自洽"提升为"与已确认 head 一致"，仍不证明"绝对无遗漏"（只能证明未被移出已锚定区间）。

**3. E5 是否可以通过标准持久化事务解决？**
可以。SQLite UNIQUE + 单事务原子消费即解决本 MVP 的单实例/重启/并发重放，无需新机制。前提是共享同一持久存储且所有路径都消费；跨数据库/跨地域的分布式防重放需要更强的分布式共识或中心化服务，超出本轮范围。

**4. E6 是否能够依靠执行意图、幂等键和状态查询实现可恢复语义？**
在"工具提供幂等键 + 持久化结果 + 状态查询"的前提下，可以实现**可恢复（recoverable）语义**：对账确认效果后补写证据、不重复执行；无法确认时明确 UNKNOWN。这是补偿/对账语义，**不是 exactly-once，也不是跨存储原子性**。工具不具备上述能力时，机制退化为 UNKNOWN，不提供虚假保证。

**5. 哪些保证仍依赖外部服务配合？**
- E6 恢复：依赖工具按 nonce/幂等键持久化结果、提供可验证 Receipt、暴露可信状态查询；依赖工具端真正按幂等键去重。
- E2：依赖检查点由独立可信主体保管且可及时查询。
- E5：依赖所有执行路径访问同一持久注册表。
- 普遍前提：签名密钥/检查点/数据库写权限的保管属于信任假设，机制本身不解决密钥泄露。

**6. 是否出现了任何现有机制无法满足的安全性质？**
**没有。** 四项缺陷均落入普通系统工程与已有机制的覆盖范围：工具端验签、外部检查点、持久化事务、意图-收据-对账。未发现需要新证明关系/新密码学原语才能闭合的性质。

---

## 7. 停止条件与总体结论

- E6 未依赖真实外部系统无法提供的能力：所需接口（幂等键、状态查询）在 Mock Tool 中实现；若外部工具不具备，则按规则保留 UNKNOWN 并停止扩大范围——本轮已按此执行，未接入真实支付/外部数据库。
- 四项问题均可由现有系统机制解决，**正式记录：MOER 历史执行证据宽泛命题 = NO-GO**。本结论只针对该宽泛命题及四项工程缺陷，不扩展到所有 Agent 安全研究；不得据此引入新密码学模块来"保留方向"。
- 未新增 Halo2/PLONK/Groth16 电路；未接入 LLM/MCP/真实支付；未改 main；未删除上一轮测试与报告；未修改禁止文件（`data_access.py`、`plan_batch.py`、`zk-v2-host/`）。

---

## 8. 文件修改边界核对

| 操作 | 文件 | 说明 |
|---|---|---|
| 修改（仅新增代码，0 删除/改写） | `agent_exec_binding.py` | opt-in 新增 hardened 类/函数；基线类未改 |
| 新增 | `execution_ledger.py` | `NonceRegistry` / `ExecutionLedger` / `ToolResultStore` |
| 新增 | `tests/test_r2_8_p2.py` | 18 个 P2 测试 |
| 新增 | `docs/r2_8_p2_execution_report.md` | 本报告 |
| 未修改 | `data_access.py` / `plan_batch.py` / `zk-v2-host/` / P0-P1 测试与报告 | 符合边界 |
