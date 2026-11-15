# Agent Execution Binding — 攻击实验矩阵 v0.1

**状态：** **v0.1 定稿（冻结实验设计基线）**。**本版冻结时未执行任何实验，未产生任何 R3 数据；「实际结果」列全部留空。**
**日期：** 2026-11-12（初稿与定稿同日）
**配套文档：** `threat-model-v0.1.md`（ATK-A* / 信任边界 / D1–D5 / G* 缺口）、`security-properties-v0.1.md`（P1–P7 / 判定标准）
**冻结时约束：** 未改代码、未改既有测试、未碰 Halo2、未跑实验、未提交、未推送。本文只定义「怎么做、记什么、怎么判」。

**本版依用户决定冻结的修订：** D1（授权 = `Grant-authorized`，不改策略代码）、D2（`ARM-` / `ATK-` 双前缀）、D3（P5/P6 判定分离）、**D4（E1.1-c 控制变量，本版核心修订）**、D5（≥10 次独立 nonce，原始计数，不称统计显著性）。
**实验排期按用户决定调整：** 第一阶段为 **E1.1 → E1.2 → E1.3 → E1.4**（并发重放纳入第一阶段）；**Adapter 偏离（ATK-A6）不进入第一阶段，作为 E2 单独推进**。

---

## 0. 实验纪律与命名空间（R0）

1. **一次一项**：第一阶段按序做 E1.1 → E1.2 → E1.3 → E1.4；不得顺带修代码或补文档承诺。
2. **先核对后实施**：下一步先核对 E1.1 的**测试入口、攻击注入点、预期执行次数、观测字段**（§3.7 已给出核对结论），再实施。
3. **三率分离**：攻击成功率 / 检测率 / 阻止率**分别统计**，禁止把「检测到了」计为「攻击被阻止」。
4. **控制变量**：凡要验证某一层检查是否独立生效，必须让**所有更靠前的检查全部通过**（D4，§3.3 / §3.6）。
5. **必须有变异反证**：每个臂必须指定「移除哪项安全机制 → 哪条断言必须失败」；若变异体下断言仍通过，该臂**无区分力**，结论无效。
6. **证据等级不跨级**：上一阶段测试结果记为 **R2（上阶段实测、E1 阶段未复跑）**，不得冒充 R3 结论。
7. **重复次数（D5）**：每臂至少 **10 次独立 nonce / 独立授权**；**报告原始计数**（如 `0/10`、`10/10`）；记录实际执行次数、拒绝原因、审计状态；**不把 10 次重复称为统计显著性证明**，只用于验证稳定性。

**命名空间（D2 冻结，避免撞名）：**

| 前缀 | 含义 | 本文使用 |
| --- | --- | --- |
| `ATK-A*` | 攻击能力 | ATK-A1 … ATK-A6 |
| `P*` | 安全性质 | P1 … P7 |
| `E1.*` | 第一阶段实验臂（执行序固定） | E1.1-a/b/c → E1.2-a/b → E1.3 → E1.4 |
| `E2.*` | 后续单独阶段（Adapter 偏离 / 信任边界） | 本阶段不做 |
| `ARM-A*` | README 已有的**防御机制分层**实验臂 | ARM-A0 … ARM-A3 |
| `D*` / `G*` / `R*` | 用户决定 / 已知缺口 / 证据等级 | D1–D5、G1–G9、R0–R3 |

> ⚠️ **命名冲突已按 D2 解决**：`README.md` §"First experiment matrix" 的 `A0–A3` 是**防御机制分层**（无 gateway / 仅 policy / 签名 Grant / +receipt+audit），
> 与 `ATK-A1–A6` 的**攻击能力**在 A1/A2/A3 上撞名。二者是**正交维度**（攻击能力驱动 vs 防御层递进），分别加 `ATK-` / `ARM-` 前缀，不是同一组实验；§10 给出合并方式。

**研究主线（贯穿全部实验）：** 当 Planner 不可信时，密码学授权绑定究竟能**阻止**哪些越权行为，又在**哪个执行边界**上失效？实验结论必须回答「哪一层阻止了 / 哪一层只是检测到」，而不是只报「通过 / 拒绝」。

---

## 1. 指标定义（R0，必须在每个臂逐项记录）

用户指定的 5 项必记指标，操作化如下：

| # | 指标 | 操作化定义 | 本仓库的测量方式 |
| --- | --- | --- | --- |
| M1 | **攻击是否成功** | 越权请求实际到达 Tool Adapter 并产生返回行 | 包裹 `tool.execute` 计数 `executions`；记录 `executed_rows` |
| M2 | **是否发生实际副作用** | 同上，但显式标注「只读访问 / 无写操作」 | `executions ≥ 1` 且返回行含越权数据 |
| M3 | **Gateway 是否检测到攻击** | 出现 `DENY`（预防）或 `RECEIPT_INVALID` / `OUTCOME_UNKNOWN`（检测） | 读 `audit.entries[-1]["event"]["decision"]` |
| M4 | **审计是否准确记录** | decision 正确 + 绑定字段与预期一致 + `AuditChain.verify()` 为 `True` | 逐字段断言 + 链式校验 |
| M5 | **变异体区分力** | 移除对应机制后，该臂的核心断言**必须失败** | 定点变异（临时替换，跑完还原，不改仓库文件） |

### 1.1 三率（必须分开，R0）

记 $N$ 为该臂的攻击实例总数（**每次使用独立新 Grant / nonce**，D5）：

$$
\operatorname{ASR} = \frac{\#\{\text{越权副作用实际发生}\}}{N},\qquad
\operatorname{PR} = \frac{\#\{\text{未执行且被 } \texttt{DENY}\}}{N},\qquad
\operatorname{DR} = \frac{\#\{\text{副作用发生后被 } \texttt{RECEIPT\_INVALID}/\texttt{OUTCOME\_UNKNOWN} \text{ 标记}\}}{\#\{\text{越权副作用实际发生}\}}
$$

- 在「执行 / 未执行」二分下 $\operatorname{PR} + \operatorname{ASR} = 1$；**$\operatorname{DR}$ 是条件率，不得与 $\operatorname{PR}$ 相加或互换**。
- `RECEIPT_INVALID` 计入 DR 的分子，**绝不**计入 PR 的分子。
- **第一阶段的口径说明**：E1.1–E1.4 全部为「执行前预防性」场景，预期 `ASR=0`、`PR=1`、`executions=0`，因此 **DR 的分母为 0，记为「不适用」**。三率完整口径保留给 E2（Adapter 偏离）使用。
- **E1.1-a 是阴性对照（benign call），不进入攻击实例分母 $N$**；它用于观测误拒率（false deny rate，README L117）与基线 `ALLOW_EXECUTED`。

### 1.2 必记原始字段（D5，用户明确要求）

每个实例至少记录并在结果表汇总：

| 字段 | 说明 |
| --- | --- |
| `nonce` | 每次独立，不复用 |
| `executions` | **Adapter 侧实际调用次数**，不以 Gateway 返回状态代替 |
| `executed_rows` | 实际返回行（用于判定副作用） |
| `reason` | 审计条目的拒绝原因字符串（**用于定位是哪一层拒绝**） |
| `decision` | 审计终态 |
| `原始计数` | 形如 `0/10 越权执行`、`10/10 被 DENY`；**不换算成 p 值 / 置信区间** |

### 1.3 重复与配对（D5 冻结）

- 每臂 $\ge 10$ 次独立实例（不同 nonce、不同 Grant）；并发臂 E1.4 每轮 race 用一个独立 Grant，10 次 = 10 轮 race。
- 口径与上一阶段变异反证采用的 10 次重复一致（**R2，上阶段记录，本阶段未复跑**）。
- `README.md` L117 要求 paired seeds 与显式预期；本阶段为**确定性单元测试**（无随机策略、无模型输出），以「不同 nonce + 固定夹具」配对。结论中须说明该配对**不等价于**统计意义上的随机种子配对，也不构成统计显著性证明。

---

## 2. 实验组 E1 总表（R0，执行序固定）

| 序 | 臂 | 攻击能力 | 请求 / Grant | 主要验证性质 | 预期观察（R0，未验证） | 类型 | 变异体 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | **E1.1-a** | 无（阴性对照） | Sales / Sales | 基线 | `ALLOW_EXECUTED`；`executions=1`；无误拒 | 对照 | — |
| 1 | **E1.1-b** | ATK-A1 | Finance / Sales | P1、P3（**Grant 绑定**） | `DENY`，`reason="request differs from the authorized request"`；`executions=0` | 预防性 | 移除 `request_hash` 校验 |
| 1 | **E1.1-c** | 无（隔离测试） | Legal / **Legal** | P1（**策略复核**独立生效） | `DENY`，`reason="filter is not allowed: department"`；`executions=0` | 预防性（隔离） | 移除 Gateway `policy.check` 复核 |
| 2 | **E1.2-a** | ATK-A2 | 替换 tenant / session / task | P2 | `DENY`；`executions=0` | 预防性 | 移除 `context_hash` 校验 |
| 2 | **E1.2-b** | ATK-A2（时间维） | `ShiftingContext` 二次读投毒 | P2 | 上下文只读一次；Adapter 收到重建对象 | 预防性 | 回退 Context 快照 |
| 3 | **E1.3** | ATK-A3 | 同一 Grant 用两次 | P4 | 工具**实际执行次数恒为 1** | 预防性 | 移除 / 延后 nonce 消费 |
| 4 | **E1.4** | ATK-A4 | 双线程竞争同一 Grant | P4 | 每轮 `executions=1`、`ALLOW=1`、`DENY=1` | 预防性 | 移除 `_nonce_lock`（`_NoOpLock`） |

> **不进入第一阶段（用户决定）：** ATK-A6 Adapter 偏离、ATK-A5 Receipt / 审计篡改 → **E2 单独推进**（§7）。
> 理由：涉及信任边界 U1，应在基础攻击实验有清楚结果后再单独研究；且避免与 E1 的 ASR 统计重复计数。

---

## 3. E1.1 请求替换 —— 核心控制变量（R0，D1 + D4 冻结）

### 3.1 研究问题与前置条件（R0 + R1）

**本组要回答的不是**「Planner 把允许访问的部门改成不允许访问的部门」，而是：

> **Planner 能否在一次已经签发的授权中，擅自替换实际请求，即使替换后的请求本身仍符合系统的一般策略？**

`make_demo_environment()` 下，由 `GrantIssuer.issue()` 对
`ToolCall(operation="read", args={"fields":["year","department","amount"], "where":{"year":2026,"department":"Sales"}, "limit":5})`
签发 Grant；`context = ExecutionContext("session-001","task-001","tenant:example")`。
`MockFinanceTool.records` 中 Sales 行 `amount=1200`、Finance 行 `amount=3400`，并含敏感字段 `id_number`。

**术语（D1，威胁模型 §3.2）：**

| 术语 | 定义 | 判定式 |
| --- | --- | --- |
| `Policy-compliant` | 请求落在一般策略包络内 | $\pi.\operatorname{check}(r,c)=\text{pass}$ |
| `Grant-authorized` | 请求与本次已签发 Grant 绑定的具体请求逐字节相同 | $H(\operatorname{canon}(r))=g.p.\text{request\_hash}$ |

**本研究的「授权」取 `Grant-authorized`；保持当前实现，不收紧 Sales 策略、不改代码。**

### 3.2 三臂控制变量表（D4，用户给定，冻结）

| 实验臂 | 请求 | Grant 绑定 | Policy | 主要观察 |
| --- | --- | --- | --- | --- |
| **E1.1-a** | `Sales` | `Sales` | 允许 | 正常基线（阴性对照） |
| **E1.1-b** | `Finance` | `Sales` | 允许 | **请求绑定**是否阻止替换 |
| **E1.1-c** | `Legal` | **`Legal`** | 拒绝 | **策略检查**是否独立生效 |

- `Sales → Finance`：两个值都 `Policy-compliant`，但请求哈希不同 → 应因 **Grant 绑定不匹配** 被拒，**与策略无关**。
- `Sales → Legal`：替换值非 `Policy-compliant`，**同时**与原 Grant 请求哈希不匹配 → 两处都会拒绝，**不能混成一个结论**。

### 3.3 关键设计约束：三种拒绝位置必须分开（R1 静态核对）

Gateway 检查顺序（`agent_exec_binding.py`，R1）：验签 L439 → `issuer_id` L444 → `agent_id` L446 → policy id/version/hash L448–451 → **`request_hash` L452–453** → `context_hash` L454–455 → tool/schema L458–459 → 有效期 L460–463 → **$\pi.\operatorname{check}$ L465** → **nonce 原子消费 L476** → `tool.execute` L502。

> **因此：若直接把原授权请求从 Sales 改成 Legal（沿用原 Grant），请求哈希也会变，拒绝会落在 L452 的绑定层，
> 即使系统拒绝了，也完全不能说明策略检查起了作用。** 这正是 E1.1-c 必须构造受控 Grant 的原因。

| 拒绝位置 | 触发条件 | 是否有 `DENY` 审计 | reason / 异常 | 现有测试覆盖（R1） |
| --- | --- | --- | --- | --- |
| **① Issuer 签发期** | `issuer.issue(policy, legal_call, ...)` | ❌ 无（Gateway 未调用） | `AuthorizationError("filter is not allowed: department")` 直接抛出（L230 → L184） | `test_filter_widening_denied_before_grant` |
| **② Gateway 绑定层** | Sales Grant + Finance 请求 | ✅ `DENY` | `"request differs from the authorized request"`（L453） | `test_request_tampering_after_authorization_denied` |
| **③ Gateway 策略复核层** | **Legal Grant + Legal 请求** | ✅ `DENY` | `"filter is not allowed: department"`（L184 → L467 `_deny(str(exc))`） | **无现成测试，需新增受控夹具** |

**纪律：**
- E1.1-c 的主结果**只能**来自位置 ③；**不得把位置 ①（Issuer 拒绝）误报成 Gateway 拒绝**。
- 位置 ① 仅作为**前置条件验证/对照**记录（确认 Issuer 确实不会签 Legal），不计入 E1.1-c 的 $N$。
- 若 E1.1-c 实测 `reason == "request differs from the authorized request"`，说明 `request_hash` 未与 Legal 匹配，**该臂无效，必须重做**，不得当成策略检查的证据。

### 3.4 E1.1-a：正常基线（阴性对照，预防性基线）

| 项 | 内容 |
| --- | --- |
| 性质 | P1/P3 的阴性对照；**不计入 ASR 分母 $N$** |
| 步骤 | ① 用原始 Sales 请求签发 Grant；② `gateway.execute(call, context, grant, now=NOW+1)`；③ 包裹 `tool.execute` 计 `executions`；④ 读审计末条与 `AuditChain.verify()` |
| 对应现有测试（R1） | `test_valid_request_executes_and_receipt_verifies` |
| **预期（R0）** | `ALLOW_EXECUTED`；`executions=1`；返回 `[{"year":2026,"department":"Sales","amount":1200}]`；无 `id_number`；receipt 验签通过；审计链有效 |
| 观测 | 误拒率（应 `0/10` 误拒）、`receipt.payload["request_hash"] == grant.payload["request_hash"]` |
| 变异体 | 无（对照臂不设变异体）；若基线本身失败，整个 E1.1 结论无效 |

### 3.5 E1.1-b：请求绑定是否阻止替换（预防性，ATK-A1）

| 项 | 内容 |
| --- | --- |
| 攻击能力 / 性质 | ATK-A1 / P1、P3（`Grant-authorized`） |
| 注入点 | `ToolCall.args["where"]["department"]` 在 `gateway.execute()` **之前**被改为 `"Finance"`；Grant 仍绑定 Sales |
| 步骤 | ① 原始请求签发；② 构造 `tampered`（仅改 department）；③ 包裹 `tool.execute` 计数；④ 调用 gateway；⑤ 读 `reason` / `decision` / `AuditChain.verify()`；⑥ 换独立 nonce 重复 ≥10 次 |
| 对应现有测试（R1） | `test_request_tampering_after_authorization_denied`（**需在其上补 Adapter 侧计数与 reason 断言**） |
| **预期（R0）** | `AuthorizationError`；`DENY`；`reason == "request differs from the authorized request"`（**位置 ②**）；`executions=0`；`executed_rows=[]`；`ASR=0`、`PR=1`、`DR` 不适用；原始计数 `0/10 越权执行`、`10/10 被 DENY` |
| 关键结论 | Finance 本身 `Policy-compliant`；被拒**只可能**来自 Grant 绑定，故本臂直接验证 `Policy-compliant ⇏ Grant-authorized` |
| 变异体 | 移除 L452 的 `request_hash` 校验 → 期望 `assertRaises(AuthorizationError)` **失败**且 `executions ≥ 1` |
| M5 判据 | 变异体下核心断言失败 ⇒ 有区分力 |

### 3.6 E1.1-c：Gateway 策略检查隔离测试（D4 核心修订）

> **定位（必须写入结论）：** 这是 **Gateway 策略复核层的隔离测试**，**不是攻击实验**。
> 夹具需要用 Issuer 私钥签名一个策略会拒绝的 Grant，该能力**不在攻击者模型内**（威胁模型 §4：攻击者不知道 Issuer 私钥）。
> 故本臂**不计入 ASR / PR 统计**，其结论只能写成「策略复核独立生效 / 不生效」。

**受控夹具构造规格（R0 定义；下一轮实施时在测试侧新增，不改产品代码）：**

`legal_call`：仅把 `where.department` 改为 `"Legal"`，其余保持与基线一致——
`operation="read"`、`fields=["year","department","amount"]`、`where={"year":2026,"department":"Legal"}`（`year=2026` 为 `required_filters`，必须保留）、`limit=5`、`agent_id` / `tool_id` / `resource` 不变。

`payload`（与正常 Grant 同形，**原 `Policy` 对象不修改**）：

| 字段 | 取值 | 目的 |
| --- | --- | --- |
| `issuer_id` | `"issuer-1"` | 通过 L444 |
| `agent_id` | `"agent:finance-assistant"` | 通过 L446 |
| `policy_id` / `policy_version` | `"finance-read-sales-2026"` / `1` | 通过 L448 |
| `policy_hash` | `env["policy"].policy_hash`（**原 policy**） | 通过 L451 |
| **`request_hash`** | **`digest_object(legal_call.as_dict())`** | **← 控制变量关键：让 L452 通过，才能到达策略层** |
| `context_hash` | `digest_object(env["context"].as_dict())` | 通过 L455 |
| `tool_id` / `tool_schema_hash` | `MockFinanceTool.TOOL_ID` / `env["tool"].SCHEMA_HASH` | 通过 L459 |
| `nonce` | 每次新随机 | 独立性（D5） |
| `issued_at` / `expires_at` | `NOW` / `NOW+30` | 通过 L460–463 |
| `signature` | `base64.b64encode(env["issuer_sk"].sign(canonical_json(payload)))` | 通过 L439–441 验签 |

**为什么不能用 `GrantIssuer.issue()`：** `issue()` 在 L230 先执行 `policy.check(call, context)`，Legal 会在签发期被拒（位置 ①）。因此必须用**受控测试夹具**以 Issuer 私钥直接构造签名 Grant，绕过签发期检查；这正是「隔离」的含义。

**静态核对结论（R1，源码级，本版未执行）：**

| 检查 | 结果 |
| --- | --- |
| 验签 / issuer_id / agent_id / policy id·version·hash | ✅ 全部通过（payload 与原 policy 一致） |
| **`request_hash`（L452）** | ✅ **通过**（绑定的是 Legal 请求）→ 控制变量成立 |
| `context_hash` / tool·schema / 有效期 | ✅ 通过 |
| **$\pi.\operatorname{check}(legal_call, c)$（L465）** | ❌ `where.department="Legal"` 不在 `allowed_filter_values["department"]=("Sales","Finance")` → L184 `AuthorizationError("filter is not allowed: department")` → L467 `_deny(str(exc))` |
| `nonce` 消费（L476） | **未发生**（在策略复核之后） |
| `tool.execute`（L502） | **未调用** |

**预期观测（R0）：**

| 字段 | 预期 |
| --- | --- |
| `decision` | `DENY` |
| `reason` | **`"filter is not allowed: department"`**（位置 ③；若出现 `"request differs from the authorized request"` 则本臂无效） |
| `executions` | `0`；`executed_rows=[]` |
| `audit.request_hash` | 等于 `digest_object(legal_call.as_dict())` |
| `used_nonces` | **不含**该 nonce（策略复核在消费之前） |
| `AuditChain.verify()` | `True` |
| 原始计数 | `0/10 执行`、`10/10 策略层拒绝`；**不计入 ASR/PR** |

| 项 | 内容 |
| --- | --- |
| 对应现有测试（R1） | **无**。位置 ① 的 `test_filter_widening_denied_before_grant` 是 Issuer 签发期拒绝，**不能作为本臂证据** |
| 实施要求 | 下一轮新增**受控测试夹具 + 测试**（测试侧新增，不改产品代码、不改既有测试断言） |
| 变异体 | 移除 Gateway L465 的 `policy.check()` 复核 → 期望 `DENY` 断言**失败**且 `executions ≥ 1`（因 Legal 请求已通过绑定层） |
| M5 判据 | 变异体下核心断言失败 ⇒ 证明「策略复核」是独立的第二道检查 |
| 表述纪律 | 结论只能写「Gateway 策略复核独立生效」；**不得**写成「Planner 的 Legal 攻击被阻止」 |

### 3.7 E1.1 实施前核对表（用户要求「先核对再实施」，R1 静态核对结论）

| 臂 | 测试入口 | 攻击 / 夹具注入点 | 预期 `executions` | 必记观测字段 |
| --- | --- | --- | --- | --- |
| E1.1-a | `test_valid_request_executes_and_receipt_verifies`（现有） | 无 | **1** | `decision=ALLOW_EXECUTED`、`rows`、`request_hash`、`audit.verify()` |
| E1.1-b | `test_request_tampering_after_authorization_denied`（现有，**需补计数与 reason 断言**） | `ToolCall.args["where"]["department"] = "Finance"`（Gateway 入口前） | **0** | `executions`、`executed_rows`、`reason="request differs from the authorized request"`、`decision=DENY`、`audit.verify()` |
| E1.1-c | **需新增受控夹具**（现有测试无覆盖；位置 ① 的测试不可用） | `SignedGrant.payload.request_hash` 固定为 Legal；注入点在 **Grant 构造**，不是请求替换 | **0** | `executions`、`reason="filter is not allowed: department"`、`decision=DENY`、`audit.request_hash`、`used_nonces`、`audit.verify()` |

**核对结论（R1）：** a、b 有现成测试入口，但 b 需补 Adapter 侧计数与 reason 断言才能满足 M1/M3/D5；**c 无现成入口，必须新增受控夹具**。三臂的 `executions` 期望值分别为 `1 / 0 / 0`。下一步据此实施，不在本版执行。

---

## 4. E1.2 上下文替换（R0）

### 4.1 E1.2-a：静态上下文替换（预防性，ATK-A2）

| 项 | 内容 |
| --- | --- |
| 性质 | P2（$C_{verify}=C_{execute}$） |
| 步骤 | ① 用 `("session-001","task-001","tenant:example")` 签发；② 分别替换 `tenant_id` / `session_id` / `task_id` 后调 gateway；③ 包裹 `tool.execute` 计数；④ 记录各自的 `reason`、`decision`；⑤ 每字段各 ≥10 次独立 nonce |
| 对应现有测试（R1） | `test_context_substitution_denied`（现覆盖 `session_id` 替换） |
| **预期（R0）** | `DENY`；`executions=0`；`reason == "execution context differs from authorized context"`（L455）；`ASR=0`、`PR=1` |
| 分层观测 | 三字段均被 `context_hash` 覆盖；仅 `tenant_id` **同时**被 `Policy.check` L154 校验。但 `context_hash`（L454）在策略复核（L465）之前，故静态替换**只会**落在绑定层；需记录 reason 证实这一点 |
| 变异体 | 移除 `context_hash` 校验 → 期望 `assertRaises(AuthorizationError)` **失败** |

> **⚠️ G9（R1 实现事实）：** `ExecutionContext` 只有 `session_id / task_id / tenant_id`，**没有 `user` 字段**。
> 用户提到的「替换 user」在当前实现中无对应字段；主体标识实际在 `ToolCall.agent_id`（Grant 也有 `agent_id`，Gateway L446 校验，替换会被 `"grant principal does not match request"` 拒绝），但它**不属于执行上下文**。
> 本阶段以 `tenant / session / task` 三字段覆盖 P2；「user 维度」登记为 G9，列入 v0.2 待扩展（需改代码），**本阶段不擅自扩展上下文模型**。

> **同类控制变量提示（R0，提案，待用户确认是否增设 E1.2-c）：** 与 E1.1-c 同构——若要单独观察 `Policy.check` 的 tenant 校验是否独立生效，
> 必须构造 `context_hash` 与「替换后上下文」匹配的受控 Grant，否则拒绝只会落在 L455 的绑定层。本阶段**不增设**该臂，仅记录该设计约束。

### 4.2 E1.2-b：校验中二次读漂移 / TOCTOU（预防性）

| 项 | 内容 |
| --- | --- |
| 攻击能力 / 性质 | ATK-A2（时间维） / P2 |
| 步骤 | ① 构造 `ShiftingContext`：`as_dict()` 首次忠实、后续把 `tenant_id` 改为 `tenant:attacker`；② 包裹 `tool.execute` 记录 Adapter 收到的 `type(context)` 与 `as_dict()`；③ 调用 gateway；④ 断言 `tracked.reads == 1`、receipt 的 `context_hash == grant.payload["context_hash"]` |
| 对应现有测试（R1） | `test_context_snapshot_is_used_for_policy_and_adapter` |
| **预期（R0）** | 正常执行；`reads = 1`；Adapter 收到重建的 `ExecutionContext`、未见 `tenant:attacker`；`decision = ALLOW_EXECUTED`；`executions = 1` |
| 变异体 | 回退「从快照重建 Context」→ 直接传调用方对象 ⇒ `reads > 1`、Adapter 看到 `tenant:attacker`，期望断言**失败**（**R2**：上阶段已做过该反证，本阶段未复跑） |
| 注意事项 | 该臂「攻击成功」定义为「Gateway 二次读取到被投毒的上下文」，而非「越权执行成功」；需单独说明，避免与 E1.2-a 的 ASR 口径混用 |

---

## 5. E1.3 授权重放（R0）

| 项 | 内容 |
| --- | --- |
| 攻击能力 / 性质 | ATK-A3 / P4（$\operatorname{SuccessfulUses}(g)\le 1$） |
| 步骤 | ① 同一 Grant 连续两次 `gateway.execute(...)`（`now` 取 `NOW+1`、`NOW+2`）；② **包裹 `tool.execute` 计 `executions`**；③ 读两次审计 `decision` / `reason` 与 `AuditChain.verify()`；④ 换独立 Grant/nonce 重复 ≥10 次 |
| 对应现有测试（R1） | `test_replay_denied` |
| **预期（R0）** | 第一次 `ALLOW_EXECUTED`，第二次 `AuthorizationError` / `DENY`（`reason="grant replay detected"`）；**`executions = 1`**；`used_nonces` 恰含该 nonce；审计链有效；原始计数 `1/10`（每轮总执行次数均为 1） |
| 关键观测 | 用户明确要求「工具实际执行次数是否始终为 1」——计数必须在 **Adapter 侧**，不能只统计 Gateway 的 `ALLOW` 次数 |
| 变异体 | (i) 移除 nonce 消费；或 (ii) 把消费移到 `tool.execute()` 之后 ⇒ 第二次也执行，`executions = 2`，期望断言**失败** |
| 边界补充 | `test_tool_exception_records_outcome_unknown` 显示工具异常后 nonce 仍保留、重放被拒；这使 P4 实际满足更强的 `ToolInvocations(g) ≤ 1`，代价是失败后必须重签 Grant |

---

## 6. E1.4 并发重放（R0，按用户决定纳入第一阶段）

| 项 | 内容 |
| --- | --- |
| 攻击能力 / 性质 | ATK-A4 / P4 |
| 步骤 | ① 每轮用**独立新 Grant / nonce** 构造一对并发请求（复用 `_run_race(lock_enabled=True)` 的双线程 + `_GatedNonceSet` + `Barrier` 结构）；② 包裹 `tool.execute` 计 `executions`；③ 记录两线程结果、审计 decisions、`AuditChain.verify()`；④ 重复 ≥10 轮（= 10 个独立 nonce） |
| 对应现有测试（R1） | `test_concurrent_replay_only_executes_once`、`test_concurrent_replay_test_detects_missing_lock`（变异反证） |
| **预期（R0）** | 每轮 `executions = 1`；`ALLOW = 1`、`DENY = 1`；审计 `ALLOW_EXECUTED = 1`、`DENY = 1`；`AuditChain.verify()` 为 `True`；原始计数 `10/10 轮仅一次执行` |
| 变异体 | `lock_enabled=False`（`_NoOpLock` 替换 `_nonce_lock`）⇒ `executions = 2`、`ALLOW = 2`，期望 `assertEqual(executions, 1)` **失败** |
| **证据强度（G6）** | `_GatedNonceSet` 的 0.2s 停顿是**实测竞争窗口**，用于打开确定性 TOCTOU 窗口；10 轮重复只验证**稳定性**，**不构成**统计显著性证明，也不构成形式化并发正确性证明。结论须写「带确定性门的并发反证」 |
| 与 E1.3 的关系 | 共享同一 nonce 机制，但 E1.4 检验**原子性**而非单纯「消费一次」；两者结论分别记录，不互相替代 |

---

## 7. 后续阶段 E2（用户决定：**不进入第一阶段**）

| 臂 | 攻击能力 | 性质 | 对应现有测试（R1） | 预期观察 |
| --- | --- | --- | --- | --- |
| E2（Adapter 偏离 / 信任边界） | **ATK-A6** | P3、P5、P6、U1 | `test_adapter_receives_snapshot_and_cannot_shift_binding` | 检测偏离；**不能假设副作用可被阻止** |
| 归属待后续确认 | ATK-A5 | P5、P6 | `test_invalid_receipt_records_receipt_invalid`、`test_audit_tampering_detected` | 识别验证失败，审计状态准确 |

> **排期纪律：** Adapter 偏离涉及信任边界 U1，按用户决定在 E1.1–E1.4 有清楚结果后**单独推进**；ATK-A5 归属待后续确认。
> **统计纪律：** E2 的 `RECEIPT_INVALID` 场景才启用完整三率（`ASR=1`、`PR=0`、`DR=1`），且**不重复计入 E1 的 ASR**。
> **表述纪律：** 只能写「检测到偏离」，不能写「阻止了越权执行」；**审计系统记录了攻击，不代表系统阻止了攻击**（D3 / 威胁模型 §6）。

---

## 8. 结果记录表（**v0.1 冻结时为空，待 E1 实施后填写**）

每行一个臂；「实际」列在冻结时一律为 `待测`。**必须报告原始计数，不得只报百分比。**

| 臂 | N（独立 nonce） | M1 攻击成功 | M2 副作用 | M3 检测 | M4 审计准确 | M5 变异体区分力 | 拒绝原因 `reason` | 审计状态 `decision` | 原始计数 | `executions` | ASR | PR | DR | 证据等级 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E1.1-a（对照） | 待测 | — | 待测 | — | 待测 | — | — | 待测 | 待测 | 待测 | 不计入 | 不计入 | 不计入 | R3 待产出 |
| E1.1-b | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 不适用 | R3 待产出 |
| E1.1-c（隔离） | 待测 | 不计入 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 不计入 | 不计入 | 不适用 | R3 待产出 |
| E1.2-a | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 不适用 | R3 待产出 |
| E1.2-b | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 不适用 | R3 待产出 |
| E1.3 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 不适用 | R3 待产出 |
| E1.4 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 不适用 | R3 待产出 |

**上阶段遗留观测（R2，仅作交叉引用，不得填入上表）：**
上一阶段记录了全量 80/80（Python 24/21/14 + Rust 11/10）、定向 24/24，以及回退 Context 快照 / Grant Hash 固定 / Receipt 快照 / nonce 锁的四组变异反证均使对应测试失败。**E1 阶段未复跑，不作为本研究阶段的实验结论。**

---

## 9. 结论模板（**v0.1 冻结时不产生结论**）

实验执行后按下列句式填写，禁止提前使用：

> 在 E1 的各 $N\ge10$ 次独立 nonce 实例中，报告原始计数（`0/10`、`10/10` 形式），**不称为统计显著性证明**。
> 对 E1.1-b：`Finance` 请求为 `Policy-compliant` 但非 `Grant-authorized`，观测到越权执行 `__/10`、`DENY __/10`，
> `reason = "request differs from the authorized request"`，故 **Grant 请求绑定**独立阻止了「在已签发授权内替换请求」。
> 对 E1.1-c：受控夹具使绑定层通过，观测到策略层拒绝 `__/10`，`reason = "filter is not allowed: department"`，
> 故 **Gateway 策略复核**独立生效；该臂为隔离测试，不计入 ASR。
> 对 E1.2 / E1.3 / E1.4：分别报告上下文一致性、串行重放、并发原子性的原始计数与变异体区分力。
> 结论须明确「哪一层**阻止**、哪一层只是**检测到**」；第一阶段全部为执行前预防性，`DR` 不适用。
> 上述结论仅适用于单进程内存状态（S1）、无 LLM 接入（S4）、mock 只读工具的研究原型，不外推为生产或端到端 ZK 系统。
> **U1（Gateway → 执行环境）未在第一阶段验证，留待 E2 单独研究。**

---

## 10. 与 README `ARM-A0..A3` 分层实验的关系（D2，R0）

| 维度 | 本文 `E1.*` | README `ARM-A0..A3` |
| --- | --- | --- |
| 组织方式 | 按**攻击能力**组织 | 按**防御机制逐层递增**组织 |
| 单元 | 一次攻击实例 / 一个隔离夹具 | 一整套 Gateway 配置 |
| 主指标 | ASR / PR / DR 三率分离 + 原始计数 | ASR、误拒率、时延、字节数、审计校验成本 |
| 关系 | 可正交：同一攻击在多个防御臂下各跑一次 | 承载 E1 攻击的执行环境 |

**合并方式（提案，待用户确认）：** 后续可把 E1 的每个攻击臂在 `ARM-A0`（无 Gateway，作为攻击成功率上界）与 `ARM-A2/A3`（当前实现）下各跑一次，得到「机制增量」曲线；`ARM-A1`（仅 policy check）恰好可验证 §3.2 的判断 —— **Sales→Finance 替换在仅策略检查时应成功**。
本阶段**不**执行该合并，也不修改 README 的既有矩阵。

---

## 11. 变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v0.1 draft | 2026-11-12 | 初稿：实验纪律与命名空间、5 项指标与三率、E1.1–E1.3 逐臂步骤/预期/变异体、`policy-compliant ≠ authorized` 判断、E2 预留位、空白结果表与结论模板。未跑实验、未改代码。 |
| **v0.1 定稿（冻结）** | **2026-11-12** | 依用户 D1–D5 修订，核心为 **D4/E1.1-c 控制变量**：① 重构 E1.1 为 a 基线 / b 请求绑定 / c 策略检查隔离三臂（用户给定控制变量表），撤销原「E1.1-b = Adapter 侧替换」并移入 E2；② 新增 §3.3 三种拒绝位置判别表与 Gateway 检查顺序；③ 新增 §3.6 受控夹具构造规格（签名有效且 `request_hash` 匹配 Legal）与 R1 静态核对结论，明确 Issuer 拒绝不得误报成 Gateway 拒绝、该臂不计入 ASR；④ 新增 §3.7「实施前核对表」（测试入口 / 注入点 / 预期执行次数 / 观测字段）；⑤ 按用户排期把 E1.4 并发重放纳入第一阶段、E2（Adapter 偏离）单独推进；⑥ D5 落实为 ≥10 次独立 nonce、原始计数 `0/10`/`10/10`、不称统计显著性，结果表新增 `reason` / `decision` / 原始计数列；⑦ 标注 G9（上下文无 user 维度）与 E1.2 同类控制变量提示；⑧ D1 关闭 G8，明确不改策略代码。**仍未跑实验、未改代码、未改既有测试、未提交推送。** |
