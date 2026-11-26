# R2.8-P0/P1 — Agent 真实执行边界审计报告

**任务性质：** 只读审计 + 缺陷复现；本轮不修复、不改业务实现、不扩架构、不引入新密码学机制。
**研究问题：** 当前系统能否证明每一次被授权的操作确实经过授权网关，并在完成后留下完整、可独立验证的执行记录？

---

## 1. 实验环境

| 项目 | 值 |
|---|---|
| 仓库 | `kaikai-cao/agent-exec-binding-mvp` |
| 本地目录 | `D:\Research\agent-exec-binding-mvp` |
| 固定基线 | `main` @ `f3048571268642696616d9f38c536d9449106918` |
| 工作分支 | `r2-8-p0-p1-boundary-audit`（从 `origin/main` 创建） |
| Python | 3.14.7（仓库 `.venv`） |
| 依赖 | `cryptography==46.0.7`（`requirements.txt`: `cryptography>=42.0,<47.0`） |
| 操作系统 | Windows 11 (10.0.26320-SP0) |
| 实验日期 | 2026-11-26 |
| 新增文件 | `tests/test_r2_8_boundary.py`、`docs/r2_8_p0_p1_execution_report.md` |

### 1.1 基线门禁（Phase 0）

| 检查 | 结果 |
|---|---|
| 工作区 `git status --short`（建分支前） | clean |
| `origin/main` | `f3048571268642696616d9f38c536d9449106918`，与固定基线一致 |
| 目标分支创建前是否已存在 | 本地无、远端无 |
| 建分支方式 | `git switch -c r2-8-p0-p1-boundary-audit origin/main` |
| 原始回归测试 | `Ran 69 tests … OK`（0 failure / 0 error） |

> 说明：切换分支前仓库 checkout 在另一研究分支 `research/r1-model-b-feasibility`（HEAD `9f6b36b`），工作区 clean。本轮未修改、未推送该分支，也未触碰 `main`。

### 1.2 测试运行结果（Phase 2）

| 运行 | 命令 | 结果 |
|---|---|---|
| 仅新增测试 | `python -m unittest discover -s tests -p "test_r2_8_boundary.py" -v` | `Ran 6 tests … OK` |
| 全量回归 | `python -m unittest discover -s tests -v` | `Ran 75 tests … OK`（69 原始 + 6 新增，0 failure / 0 error） |

**结果分类口径：** 测试脚本运行成功（exit 0）；E1/E2/E5/E6 缺陷复现成功 = 实验通过，**不是**系统安全通过；E3/E4 保护行为符合预期 = 对应安全行为通过。测试数量不作为安全结论。

---

## 2. 六项实验结果

### E1 — 直接绕过 ToolGateway

| 字段 | 内容 |
|---|---|
| 攻击目标 | `agent_exec_binding.py` 的 `MockFinanceTool.execute()` |
| 前置条件 | 调用者持有 Adapter 对象引用（进程内/同信任域），不经 `ToolGateway.execute()` |
| 执行方法 | 构造 `fields=["id_number","year","department","amount"]`、`where={"year":2026}` 的请求；用**伪造的** `SignedGrant`（signature=`"forged-signature"`, policy_hash=`FORGED-POLICY-HASH`）直接调用 `tool.execute()` |
| 预期 Oracle | `E1 = CONDITIONAL_BYPASS_REPRODUCED` |
| 实际结果 | 返回 2 行，均含 `id_number`：`SENSITIVE-001`、`SENSITIVE-002`；工具仍签发回执，`verify_receipt()=True`，且回执原样携带伪造的 `policy_hash` |
| 是否复现 | **是**（`CONDITIONAL_BYPASS_REPRODUCED`） |
| 证据 | `test_e1_direct_adapter_bypass`；`E1_EVIDENCE` JSON |
| 成立条件与限制 | 仅在调用者能直接访问 Adapter 对象时成立。Adapter 完全不验 Grant 签名，只从 `grant.payload` 读 `policy_hash`/`nonce` 用于回执。**不代表**已证明远程攻击者可获得该对象访问权；本轮未测试任何进程外/网络路径。 |

### E2 — 审计日志尾部截断

| 字段 | 内容 |
|---|---|
| 攻击目标 | `AuditChain.verify()` |
| 前置条件 | 能删除 `AuditChain.entries` 尾部条目（进程内可变列表） |
| 执行方法 | 写 3 条有效记录并确认原链 `verify()=True`；`pop()` 删除最后 1 条再验；再 `pop()` 删除 1 条（累计 2 条）再验 |
| 预期 Oracle | `E2 = TAIL_TRUNCATION_REPRODUCED` |
| 实际结果 | 原始 3 条 `verify=True`；删 1 条后剩 2 条 `verify=True`；删 2 条后剩 1 条仍 `verify=True` |
| 是否复现 | **是**（`TAIL_TRUNCATION_REPRODUCED`） |
| 证据 | `test_e2_audit_tail_truncation`；`E2_EVIDENCE` JSON |
| 成立条件与限制 | `verify()` 从 `seq=0`、前序哈希 `"0"*64` 逐条正向校验，合法前缀始终自洽。哈希链只保证**已存在条目**的局部完整性，**不**证明日志未被截尾。根因是缺少外部锚定的 head/计数承诺。 |

### E3 — 审计日志中间事件删除

| 字段 | 内容 |
|---|---|
| 攻击目标 | `AuditChain.verify()` |
| 前置条件 | 能删除中间条目 |
| 执行方法 | 写 3 条（`seq=[0,1,2]`），删除 `seq=1`，再验 |
| 预期 Oracle | `E3 = MIDDLE_DELETION_DETECTED` |
| 实际结果 | 原链 `verify=True`；删除后剩余 `seq=[0,2]`，`verify=False`（`body["seq"] != index`） |
| 是否复现 | 保护机制有效（`MIDDLE_DELETION_DETECTED`） |
| 证据 | `test_e3_audit_middle_deletion`；`E3_EVIDENCE` JSON |
| 成立条件与限制 | 序号连续性检查能发现中间删除。注意这与 E2 不矛盾：E3 保护删除造成的不连续，E2 无法发现尾部整体缺失。 |

### E4 — 工具产生效果后异常退出

| 字段 | 内容 |
|---|---|
| 攻击目标 | `ToolGateway.execute()` 的异常路径语义 |
| 前置条件 | 使用测试专用 Tool Adapter：先增加模拟效果计数器，再抛异常 |
| 执行方法 | 正常签发 Grant → 执行 → Adapter 注入效果后抛 `RuntimeError` → 检查审计、nonce、重放 |
| 预期 Oracle | `E4 = UNKNOWN_OUTCOME_HANDLING_VERIFIED` |
| 实际结果 | 异常正确传播；审计仅记录 `OUTCOME_UNKNOWN`（无 `DENY`）；nonce 已消费；同一 Grant 再次执行被拒 `DENY: grant replay detected` |
| 是否复现 | 保护机制有效（`UNKNOWN_OUTCOME_HANDLING_VERIFIED`） |
| 证据 | `test_e4_effect_then_exception`；`E4_EVIDENCE` JSON |
| 成立条件与限制 | 这是 mock 效果注入（内存计数器），**不是**实际支付或真实外部服务实验。系统正确地把不确定结果记为 UNKNOWN 并保留不可重放性；但 UNKNOWN 本身意味着"效果是否发生"在审计层无法判定。 |

### E5 — Gateway 重启后的 Grant Replay

| 字段 | 内容 |
|---|---|
| 攻击目标 | 网关进程内 nonce 防重放集合 `used_nonces` |
| 前置条件 | 能新建一个 `ToolGateway` 实例（新 `AuditChain`），但沿用相同 issuer/tool key、policy、tool 配置；Grant 仍在有效期内 |
| 执行方法 | 正常执行一次 → 新建 Gateway 与 AuditChain → 用**同一 Grant**、相同有效时间 `now=1_800_000_001`（`expires_at=1_800_000_030`）再次执行 |
| 预期 Oracle | `E5 = REPLAY_AFTER_RESTART_REPRODUCED` |
| 实际结果 | 两次执行均成功返回相同行、回执均有效；新网关的 `used_nonces` 初始为空，重放后仅含该 nonce |
| 是否复现 | **是**（`REPLAY_AFTER_RESTART_REPRODUCED`） |
| 证据 | `test_e5_replay_after_gateway_restart`；`E5_EVIDENCE` JSON |
| 成立条件与限制 | 防重放状态仅为单进程内存 `set`，未持久化。不得把单进程内存集合描述为跨进程/跨实例的防重放保证。本轮模拟的是"网关实例与审计链均新建"，未测试真实进程崩溃恢复。 |

### E6 — 效果完成但最终审计写入失败

| 字段 | 内容 |
|---|---|
| 攻击目标 | `ToolGateway.execute()` 的 `ALLOW_EXECUTED` 终态写入 |
| 前置条件 | 测试专用 `AuditChain`：`ALLOW_EXECUTED` 写入抛 `OSError` 模拟持久化失败，其余事件正常；测试专用 CountingTool 记录效果 |
| 执行方法 | Grant 验证成功 → 工具执行成功（效果计数器+1）→ Receipt 签名与绑定验证成功 → `ALLOW_EXECUTED` 写入失败 → Gateway 抛异常 |
| 预期 Oracle | `E6 = EFFECT_WITHOUT_FINAL_AUDIT_REPRODUCED` |
| 实际结果 | 工具已执行（效果计数=1）；Receipt 有效；`failed_events=["ALLOW_EXECUTED"]`；持久化审计 `decisions=[]`，无 `ALLOW_EXECUTED`；`recovery_record_identifying_effect=None`；Gateway 抛 `OSError` |
| 是否复现 | **是**（`EFFECT_WITHOUT_FINAL_AUDIT_REPRODUCED`） |
| 证据 | `test_e6_effect_without_final_audit`；`E6_EVIDENCE` JSON |
| 成立条件与限制 | mock 效果计数器，**不是**真实外部支付。系统把该故障以异常上抛，但没有留下任何识别该效果的成功审计记录，也没有 OUTCOME_UNKNOWN（因工具本身未抛异常）。存在"效果已发生 / 最终审计缺失 / 无恢复记录"的不一致窗口。 |

---

## 3. 缺陷汇总

### 3.1 确认的实现缺陷（复现成功）

| # | 缺陷 | Oracle | 本质 |
|---|---|---|---|
| E2 | 审计链尾部截断不可检测 | `TAIL_TRUNCATION_REPRODUCED` | 哈希链无外部锚定 head/计数承诺，合法前缀自洽 |
| E5 | 新 Gateway 实例可重放旧 Grant | `REPLAY_AFTER_RESTART_REPRODUCED` | nonce 防重放仅为进程内存集合，未持久化 |
| E6 | 效果完成但最终审计写入失败无恢复记录 | `EFFECT_WITHOUT_FINAL_AUDIT_REPRODUCED` | 效果、Receipt、审计三者非原子；无补偿记录 |

### 3.2 条件性缺陷

| # | 缺陷 | Oracle | 条件 |
|---|---|---|---|
| E1 | 直接调用 Adapter 可绕过网关读取未授权字段，且签发看似有效的回执 | `CONDITIONAL_BYPASS_REPRODUCED` | 仅当调用者能直接访问 Adapter 对象；Adapter 不验 Grant 签名、不校验字段白名单 |

### 3.3 已有保护机制有效

| # | 保护 | Oracle |
|---|---|---|
| E3 | 中间删除因序号断裂被发现 | `MIDDLE_DELETION_DETECTED` |
| E4 | 工具异常记为 `OUTCOME_UNKNOWN`、nonce 保留、拒绝重放、不误记为 DENY | `UNKNOWN_OUTCOME_HANDLING_VERIFIED` |

### 3.4 未能验证的项目

| 项 | 原因 |
|---|---|
| 进程外/网络攻击者能否触达 Adapter（E1 前提） | 本轮为进程内单元审计，未接入网络/LLM/MCP |
| 真实进程崩溃后的状态恢复行为（E5） | 用新建 Gateway+AuditChain 模拟，未做真实 crash/restore |
| 真实外部支付/服务的一致性窗口（E4/E6） | 使用内存效果计数器 mock，非真实副作用 |
| 跨实例审计链连续性 / 外部见证锚定 | 当前系统无此机制，无对象可测 |

---

## 4. 研究判断

**1. 哈希链是否解决了日志完整性问题？**
部分解决。`AuditChain.verify()` 能发现中间删除/篡改（E3）与内容改动，但无法发现尾部截断（E2）——合法前缀始终自洽。完整性保证限于"已存在条目之间的局部一致性"，不等于"日志未被删减"。要证明无遗漏需外部锚定的 head（透明日志/签名计数/公开可验证承诺）。

**2. nonce 内存集合是否解决了持久化重放问题？**
没有。`used_nonces` 是网关实例内存 `set`（E5），进程重启或被替换即丢失。它只提供单进程内的重放防护，不构成跨进程/跨实例的持久化防重放保证，也无法支持崩溃后的状态恢复判定。

**3. 工具效果和审计事件是否存在不一致窗口？**
存在，且有两个已复现的具体窗口：
- E4：效果已发生但异常退出 → 只记 `OUTCOME_UNKNOWN`，效果是否发生无法从审计判定（保护正确，但语义不确定）。
- E6：效果已发生、Receipt 有效，但最终 `ALLOW_EXECUTED` 写入失败 → 无成功审计记录、无恢复记录。
根因是"工具副作用 / Receipt 签发 / 终态审计写入"三者之间无原子性或补偿机制。本报告不声称存在跨存储原子性保证，也不声称 exactly-once。

**4. 当前工具网关是否构成真正不可绕过的执行边界？**
不构成不可绕过边界。E1 表明 `ToolGateway` 只是调用路径上的一层校验；`MockFinanceTool.execute()` 本身不验证 Grant 签名/字段白名单，任何持有 Adapter 引用的调用者都能直接读取越权字段并获得工具签发的有效回执。网关是"约定调用入口"，不是强制信任边界。E1 的成立前提（能否拿到 Adapter 引用）本轮未证实可从远程达成，故记为条件性缺陷。

**5. 这些问题是否能由普通系统工程和已有机制解决？**
大部分可以，且不需新密码学构造：
- E2 → 外部锚定审计 head / 签名序号计数 / append-only 透明日志 + 周期性见证。
- E5 → 持久化 nonce 消费状态（带事务的存储）、或让 Verifier/工具服务端校验 nonce 单一消费。
- E6 → 以 Receipt 为事实源的补偿记录 / 两阶段确认 / 先写意图后写完成并对账。
- E1 → 把 Adapter 设为不可直接调用（封装在信任边界内）、工具服务端强制验签。
这些属于系统工程/架构强化，不是新的密码学问题。

**6. 哪些问题仍然值得继续研究？**
- **效果与审计的原子性语义**：E4/E6 暴露的"不确定结果"如何在不依赖同步存储事务的前提下，给出可独立验证的执行历史判定。这是可信执行证据问题，但现有基线（签名收据 + 远程证明 + 审计链 + 补偿对账）已有明确工程路径，本轮证据不足以支撑独立密码学贡献。
- **可独立验证的完整日志**：无外部锚定时尾部缺失不可判定，可用透明日志/见证解决，属成熟机制。
- **强制执行边界**：Adapter 直连绕过是信任边界设计问题，不是证明系统问题。

**结论：** 本轮六项测试确认的是现有 MVP 在"历史执行证据"上的具体、可复现的边界条件；这些缺口的修补路径落在普通系统工程与已有机制，**未发现必须由新密码学机制才能解决的安全性质**。按任务包边界，本轮不进行修复，也不据此宣称任何密码学创新。是否进入 R2.8-P2 由研究负责人裁决。

---

## 5. 停止条件声明

本轮未执行修复、未接入 LLM/MCP、未连接真实支付或外部服务、未新增 Halo2 电路。所有缺陷均有可重复的测试证据（六个 unittest 用例，全量回归 75 tests OK）。
