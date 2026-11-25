# AE-ZK-R1.2 — 预注册配额承诺模型可行性与研究价值裁决

日期：2026-11-25
状态：研究设计文档；**不实现代码、不生成 proof、不运行性能实验**
标记：`[FACT]` 源码/规格/原文直接支持；`[INFERENCE]` 由事实与模型推导；`[REC]` 设计建议；`[OPEN]` 暂无法确认。

---

## 0. 基线与结论摘要

### 0.1 实际基线 `[FACT]`

| 对象 | 远端实际 SHA |
| --- | --- |
| `main`（V1 基线） | `f3048571268642696616d9f38c536d9449106918` |
| `feat/step3-2b-plan-root-circuit`（冻结） | `48169bc7d0d6dbaf231fb0d2944a8d85035c9e9c` |
| `design/step3-2c-integration-contract` | `774037d4fc2165dda23e99ff590b465cdf73cfbd` |
| 本分支 | `research/r1-model-b-feasibility`，从上述 V1 SHA 新建，远端此前不存在 |

开始前已核验：远端 main SHA 与基线一致、新分支本地与远端均不存在、工作区干净。切换基线后，`*.bak*` 类历史备份文件因 V1 `.gitignore` 缺少 design 分支的忽略规则而变为 untracked；未删除、未暂存，仅在本地 `.git/info/exclude` 镜像该忽略规则以保持状态可判读。本分支提交中只有本文件。

### 0.2 摘要结论 `[INFERENCE]/[REC]`

- Model A（V1 / 3.2C-0）中，Gateway 不需要知道精确 `B,L`；V1 已由 Authority 完成私有 allowlist、单步上限与累计预算检查，并由 Ed25519 Grant 背书（`data_access.py:255-271,301-328`）。当前 Step 3.2B proof 没有证明 `B,L` 来自注册策略，不能消除 Authority 策略真实性信任（`plan_quota_circuit.rs:103-146,164,1152-1159`；`v0.2:338`）。
- Model Bq 有一个**可形式化的独立性质**：Policy Owner 一次注册策略承诺后，Gateway 可在不逐计划获得 Policy Owner 决策签名的前提下，验证任意 Prover 给出的计划证明满足该承诺的预算 opening。这是 V1 在“相同信任假设（签发者不在每份计划在线）”下无法直接提供的。
- 但该性质**不等于完整策略授权**：Bq 只承诺预算三元组，不承诺资源/字段/过滤 allowlist；Prover 必须知道 witness；nonce、撤销与持久化消费尚未落实到电路与网关；与 zk-Guard-R 的隐藏策略承诺原型差异仍属场景级。
- 模型选择：**只保留 Bq 作为候选**；Bfull 本轮判定不值得继续（电路复杂度与 zk-Guard-R 重叠、范围过大）。
- 整体裁决见第 9 节：**CONDITIONAL HOLD**。不进入 Step 3.2C。

---

## 1. 三种模型的严格区分

### 1.1 Model A：当前 V1 / Step 3.2C-0 `[FACT]`

- Authority 逐计划读取私有 `DataAccessPolicy`（`data_access.py:133-145`），检查 allowlist 与 `L`（255-271）、累计 `B`（301-308），签 Ed25519 Grant（313-328）。
- Grant 含 `policy_id/version`、加盐 SHA-256 策略承诺、计划根、身份、schema、时间、nonce，**不含 B/L 明文**（239-242,313-327）。
- Gateway 不持 `DataAccessPolicy`（424-437），但自查签名、身份、有效期、schema、计划根 inclusion、顺序/nullifier、工具回执与结果行数（451-528）。
- Step 3.2B 电路接收调用方传入的 `budget, limit, blinding`（`plan_quota_circuit.rs:103-146`），`C_quota=Poseidon(D_QUOTA,B,L,r)`（164），八个 instance 被约束（1152-1159）；`zk-v2-host` 全仓无 `policy_commitment/policy_id` 绑定；冻结规格 `v0.2:60,62-75,338` 明确承认缺少注册机制。
- 契约 `F.0:429-438` 把 Authority 与 Prover 放入同一受信任边界，`F.1.6:451` 明确 Gateway 不检查 `C_quota` 与 `policy_commitment_sha256` 的关系。

`[INFERENCE]` Model A 的结论不能夸大：proof 可能检出 Authority 软件中的配额算术错误，但不能防止 Authority 故意或错误地选择比真实策略更宽松的 `B,L`。

### 1.2 Model Bq：只绑定预算的预注册承诺模型 `[REC]`

- 策略参数：`P_q=(B,L,N_max)`，`N_max≤16`。
- Policy Owner 注册一次版本化承诺；Prover 持有 opening，为具体计划生成证明；Gateway 验证承诺、证明、上下文与逐步执行绑定。
- 明确边界：**这不是完整 `DataAccessPolicy` 授权**，只覆盖预算三元组。V1 的 `private_policy_dict()` 还包含资源/字段/过滤字段/过滤值 allowlist 与 `max_plan_actions`（`data_access.py:202-217`）。

### 1.3 Model Bfull：完整私有策略承诺模型 `[REC]/[INFERENCE]`

- 目标：对完整私有策略结构建立版本化承诺，电路内证明每个动作满足 allowlist 与累计预算。
- 代价：需要集合成员关系/查找论证、策略结构规范化、版本化与撤销，电路规模显著上升；与 zk-Guard-R 已实现的“隐藏策略向量 + MiMC-Merkle 策略根 + ZK 策略检查”高度重叠（见第 7 节）。
- 裁决：**本轮不值得作为主线继续**。`[OPEN]` 若未来出现明确需要隐藏完整 allowlist 的场景，再单独立项。

### 1.4 选择结果 `[REC]`

唯一候选为 **Bq**；Bfull 不继续；禁止把 Bq 的“易实现”与 Bfull 的“完整策略”混成一个不可实现的混合方案。

---

## 2. 信任边界

### 2.1 角色与信任表 `[FACT]/[INFERENCE]/[REC]`

| 角色 | 职责 | 必须信任什么 | 不应该信任什么 |
| --- | --- | --- | --- |
| Policy Owner | 注册版本化 `C_qpol` 与元数据签名；维护撤销/epoch | 策略来源与注册正确性、签名密钥 | 不应负责每份计划的在线正确性裁决 |
| Prover | 用 `(B,L,N_max,r_policy,...)` 生成计划 proof | 其掌握 witness 的事实；证明协议正确执行 | 不应被信任为“证明正确性的唯一依据”；不应被宣称对预算保密 |
| Planner / Agent | 提交计划与动作 | 仅作为不可信输入方 | 不应决定预算、版本或绕过验证 |
| Gateway | 验证 proof、nonce、注册状态、逐步 inclusion、原子消费 | 身份认证、最新注册/撤销状态、原子执行状态 | 不应依赖 Prover 口头声明；不能被绕过 |
| Tool Adapter | 执行获准动作并签 Receipt | 必须完整校验进入工具边界的参数 | 不应自行扩大权限；Receipt 不等于数据库真实性 |

### 2.2 Prover 的信息边界 `[FACT]/[INFERENCE]`

标准 Halo2/Groth16 ZK proof 不会向证明者隐藏其自己使用的 witness。因此：

1. Gateway 对 B/L 的隐私：可由 ZK + 承诺隐藏性提供，但须给出显式泄漏函数（第 6 节）。
2. Prover 对 B/L 的隐私：**不提供**。第三方 Prover 持有 opening 就可能泄露。
3. Agent 对 B/L 的隐私：若 Agent 担任 Prover，则不提供；若 Agent 只是 Planner，则可隐藏（但可见 `max_rows` 下界）。
4. 外部观察者对策略结构的隐私：只隐藏承诺 opening；版本、时间、计划规模、执行顺序仍可见。

`[REC]` 若坚持 Prover 也不可信于保密，需要 MPC/TEE/分布式证明等架构，超出本轮范围；不得用普通 Halo2 声称实现。

### 2.3 在线依赖 `[FACT]/[INFERENCE]`

- Policy Owner：`[REC]` 注册后可离线；不再逐计划作策略决策签名。
- Prover：`[REC]` 每份计划仍需在线生成 proof，成为新的可用性依赖。
- Gateway：`[FACT]` 仍需当前时间、身份、schema、注册状态；`[REC]` 需要最新策略版本/撤销 epoch；`[FACT]` V1 的进程内 nullifier 不等于持久化跨网关原子状态（`data_access.py:435-437,479-490`）。
- 关键区分：**不需要每份计划的 Policy Owner 决策签名**，不等于**每份计划不需要在线证明服务**。

---

## 3. `C_qpol` 精确定义与证明关系

### 3.1 元数据摘要 `[REC]`

```
H_meta = SHA-256( canonical_json({
  "policy_id": <id>,
  "version": <positive int>,
  "tenant_id": <id>,
  "tool_schema_digest_sha256": <exact V2 schema digest>,
  "relation_version": "r1-model-bq-v1",
  "commitment_format": "poseidon-qpol-v1",
  "domain": "agent-exec-binding/r1-bq"
}) )
(meta_hi, meta_lo) = limbs_be128(H_meta)
```

`limbs_be128` 沿用 v0.2 的前 16 字节为 hi、后 16 字节为 lo、不模约减的规则（`v0.2:283`；`lib.rs:89-100`）。

### 3.2 承诺 `[REC]`

```
C_qpol = Poseidon^ConstantLength(7)(
    D_QPOL, B, L, N_max, meta_hi, meta_lo, r_policy
)
```

`D_QPOL` 需新域标签，不得复用 `D_QUOTA`（`lib.rs:24`）或 `D_POLICY` 未定义名。Policy Owner 签名 `(policy_id, version, tenant_id, H_meta, C_qpol, epoch, expires_at)`；Gateway 只接受 pin 的已签注册记录。

### 3.3 每份计划 proof 的约束 `[REC]`

见证包含 `(B,L,N_max,r_policy,r_quota, words[16][14], active[16], ctx_limbs, schema_limbs, nonce_limbs)`。约束：

1. `Poseidon(D_QPOL,B,L,N_max,meta_hi,meta_lo,r_policy) = C_qpol`（公共）；
2. `Poseidon(D_QUOTA,B,L,r_quota) = C_quota`（可选保留，逐计划盲化；与 1 使用同一 B/L）；
3. `∀i: 1≤m_i≤L`，其中 `m_i=words[i][13]`；
4. `Σ_i m_i≤B`，活动前缀连续，非活动槽为 padding；
5. `1≤n≤N_max≤16`；
6. `R_plan=root(16 个 Poseidon 叶，四层)`，`C_statement` 绑定 `C_qpol/C_quota/R_plan/n/H_ctx/H_schema/H_nonce`；
7. 动作编码与固定深度 Merkle 关系使用与 Step 3.2B 相同宿主 primitive（`lib.rs:102-252`），但属于**新电路版本**，不改 v0.2。

### 3.4 allowlist 的明确处理 `[FACT]/[REC]`

- V1 的 `private_policy_dict()` 包含资源/字段/过滤字段/过滤值 allowlist 与 `max_plan_actions`（`data_access.py:202-217`）；Bq 的 `C_qpol` **不包含**这些。
- 因此 Bq 不能宣称等价于 V1 完整策略授权。`[REC]` 两种合法处理：
  - **Bq-a**：把这些规则定义为公开、版本化、由 Gateway 独立执行的规则集，并纳入 `H_meta`；此时与 B0 的语义比较必须注明 allowlist 不再是私有 witness。
  - **Bq-b**：保留 V1 的私有 allowlist 检查作为独立 Authority 步骤；此时 Bq 只减少“预算策略决策”的在线依赖，不减少“allowlist 决策”的在线依赖，禁止声称去中心化完整策略授权。
- 本轮选择 **Bq-a** 作为同语义比较基线；Bq-b 只作为退化情形记录。

---

## 4. 公共声明、nonce 与防重放

### 4.1 公共声明清单与 nonce 选择 `[REC]`

每份 Bq proof 的公共声明至少包含：

| 项 | 编码/位置 | 验证方检查 |
| --- | --- | --- |
| `C_qpol` | Poseidon field-hex，公共实例 | 等于 Gateway pin 的已签注册承诺 |
| `C_quota`（可选） | Poseidon field-hex，公共实例 | 与 `C_qpol` 使用同一 B/L；逐计划盲化 |
| `meta_hi, meta_lo` | `H_meta` 的 128-bit big-endian limbs | 由已签 `(policy_id,version,tenant,schema digest,relation version,format,epoch)` 重算 |
| `R_plan` | Poseidon field-hex，公共实例 | 等于逐步 inclusion 使用的根 |
| `action_count` / `n` | field + 整数 claim | `1≤n≤N_max≤16` |
| `H_ctx_hi, H_ctx_lo` | 128-bit limbs | 由当前 principal/tenant/session 重算 |
| `H_schema_hi, H_schema_lo` | 128-bit limbs | 等于 Gateway 的精确 schema digest |
| `H_nonce_hi, H_nonce_lo` | nonce digest 的 128-bit limbs | 等于 Gateway 本次 challenge 的重算值 |

Policy Owner 签名覆盖的 `policy_id/version/tenant` 通过 `H_meta` 进入电路；不另设可被替换的顶层 claim。采用 **nonce digest 作为独立公共输入并纳入 statement**：

```
preimage_nonce = b"request-nonce:r1-bq:v1\0" || nonce_raw[32]
H_nonce = SHA-256(preimage_nonce)
(H_nonce_hi, H_nonce_lo) = limbs_be128(H_nonce)
```

Gateway 生成 32 字节 CSPRNG nonce，解码后逐字节计算上述值；`H_nonce_hi/lo` 作为新公共输入（建议 index 8/9），并进入 `C_statement`。验证时 Gateway 重算并与实例比较；证明在另一 nonce 下会因实例不同而失败。

`[FACT]` R1.1 已指出当前 3.2C 契约的 proof 不绑定 `plan_nonce`，可在新 Grant 中复用（`774037d:262`）；本设计修正该缺口。

### 4.2 版本、撤销与状态 `[REC]/[FACT]`

- `policy_id/version/tenant/schema digest/relation version/commitment format/epoch` 进入 `H_meta`。
- Gateway 在执行时检查最新注册状态：未撤销、 epoch 匹配、未过期；快照需有界有效期并带 Policy Owner 签名。
- `nonce` 必须持久化、原子消费；proof 内绑定只提供密码学不可重包装，不提供跨网关原子性（`data_access.py:435-437,479-490`）。
- 身份认证来源仍是 Gateway 本地 principal/tenant/session 校验，不由 proof 提供。
- 工具调用实际参数必须与已验证动作一致；工具边界完整中介条件未满足时，任何 ZK 性质都不成立。

---

## 5. 可证伪安全性质 P1–P5

| 性质 | 攻击者能力 | 安全实验/判定条件 | 依赖假设 | 当前状态 | 仍缺什么 |
| --- | --- | --- | --- | --- | --- |
| **P1 Registered Quota Soundness** `[REC]` | 恶意 Prover 选更宽松 B/L 或使用未注册承诺 | 给定已注册未撤销 `C_qpol`，接受 proof ⇒ 存在其 opening 且满足预算约束；换承诺即拒绝 | 承诺绑定/隐藏、SNARK soundness、Gateway pin 正确 | 设计可定义；Step 3.2B 不满足 | 新电路、注册协议、撤销检查 |
| **P2 Plan-Step Binding** `[FACT]/[REC]` | Planner 改动作/重排/替换槽位 | 执行动作须等于已授权计划第 i 叶；`proof.index==step` | 规范编码、Merkle binding、Gateway 检查 | V1 SHA-256 Merkle 已提供同构性质（`plan_batch.py:50-61,149-190`） | ZK 版新增的只是与预算承诺同证明，不是 hash 替换本身 |
| **P3 Challenge-Bound Replay Resistance** `[REC]` | 重包装 proof 到新请求；二次消费 nonce | 同一 proof 在新 `nonce` 实例下验证失败；已消费 nonce 二次提交失败 | nonce 实例绑定 + 持久原子状态 | 设计已选唯一编码 | 持久化存储、跨网关事务 |
| **P4 Verifier-Side Quota Privacy** `[REC]` | Gateway 从 proof/公开声明恢复 B/L | 除显式泄漏函数外不可区分；泄漏函数含第 6 节各项 | ZK、承诺隐藏、随机数不复用 | 设计可定义；仅对 Gateway | 对 Prover/Agent 不提供；需精确证明与随机数纪律 |
| **P5 Policy-Version / Context / Schema Binding** `[REC]` | 跨版本、跨租户、跨 schema、跨 context 迁移 proof | 实例中含 `H_meta`/ctx/schema；任一不同即拒绝 | 公共输入绑定、规范 JSON、签名 pin | V1 已由签名绑定身份/context/schema（`data_access.py:313-328`） | Bq 需把 version/epoch 纳入 `H_meta` 并电路绑定 |

---

## 6. 隐私与执行边界（修正 R1.1）`[FACT]/[INFERENCE]`

| 可见/不可见项 | Model A (V1) | Model Bq | 说明 |
| --- | --- | --- | --- |
| 每步完整动作含 `max_rows` | 可见（`data_access.py:76-80,443`） | 可见 | 预算下界 `B≥Σm_i`、`L≥max m_i` 可直接推断 |
| 精确 B/L | 不可见 | 对 Gateway 不可见；对 Prover 可见 | 不得统称策略隐私 |
| 确定性 Poseidon root | 无（SHA-256 root） | 有 | binding，不自动 hiding（`lib.rs:239-295`） |
| 低熵动作字典枚举 | 存在 | 存在 | Rust 固定 ID 表规模小；未执行动作可被枚举推断 |
| 稳定政策承诺跨计划关联 | V1 承诺逐计划随机 salt（`data_access.py:310`） | Bq 承诺长期稳定 | 新增可关联性，必须写入泄漏函数 |
| `C_quota` 与 `C_qpol` 同时公开 | 无 `C_qpol` | 有 | 若 `r_quota` 重用会产生额外关联；`[REC]` 每计划独立 |
| Receipt 真实性 | 工具签名声明 | 同 | 不证明数据库结果真实/完整/最新 |
| 工具边界完整中介 | V1 依赖 Gateway | Bq 同样依赖 | proof 不阻止绕过 |
| nullifier 原子性 | 进程内集合 | 进程内不够 | 持久化/多网关事务仍为工程前提 |

`[INFERENCE]` 允许声明：“Gateway 不直接获得 B/L witness，且 proof 不公开未执行动作完整清单”；不允许声明：“完整策略隐私/计划隐私”。

---

## 7. 相关工作（限定范围，按指定四项核查）

| 工作 | 已提供什么 | 实际实现/实验 | 仍为设计描述 | 与 Bq 的关系 | 不能宣称 | 具体差异 |
| --- | --- | --- | --- | --- | --- | --- |
| **CVA** *Cryptographically verifiable authorization for autonomous AI agents*（Front. Comput. Sci. 8, 2026；DOI `10.3389/fcomp.2026.1966725`）`[FACT]` | 形式化 `R_CVA=BindPrincipal∧BindRequest∧BindContext∧SatisfyPolicy`，并另列 gateway stateful `Fresh(n,t,N)`；明确 `Authorization Request Binding ≢ Runtime Execution Binding` | Groth16/bn128/Circom/snarkjs PoC：Poseidon 主体绑定、`SHA256(plan)=hplan` 计划级请求绑定、静态算术策略满足、网关外部 nonce 控制；作者称非完整 CVA 验证、无对比 benchmark、无独立电路审计 | Context binding（原文“not implemented in the current prototype”）、runtime execution binding（open）、显式 `pid_j` policy binding（partial）、完整安全归约、多主体委派 | 都把计划与 proof 绑定；Bq 增加“注册预算承诺 opening”与累计 `max_rows` 关系 | 不能声称首次把 Agent 请求或计划与 ZK proof 绑定 | CVA PoC 无多步累计预算、无逐步 Merkle inclusion、无注册策略承诺 opening 验证 |
| **AgentCap**（arXiv `2611.00729v1`，2026-10-31；NeurIPS 2026 workshop non-archival）`[FACT]` | MCP wrapper + policy engine + authorization gateway + Ed25519/JWT capability + 会话内衰减委托 + trust score + 审计 + 静态 surface analyzer | AgentDojo 97 benign/949 attacked、InjecAgent 1054 attacked/51 clean、593 项机制测试、10k 次延迟中位 issuance 66.9μs / verification 79.9μs / 三层委托 151.4μs；全部 <0.2ms | `workflow` 仅静态分析；跨域委托、持久记忆 provenance 为未来工作；策略/provenance 标签是安全配置 | 强非 ZK 基线：逐调用授权、参数 provenance、预算与有效期衰减 | 不能声称逐调用 capability 或工具边界授权由我们首创 | 无 ZK；`budget` 是 token 剩余调用预算，不是签名多步计划的累计预留行数；无注册策略承诺 |
| **zk-Guard-R**（Sensors 2026, 26(16), 5045；DOI `10.3390/s26165045`）`[FACT]` | 隐藏策略向量承诺、MiMC-Merkle policy/attribute/data root、nonce 绑定、Solidity verifier、IPFS 网关计量 | Go + gnark 0.14.0 BN254/Groth16：425,574 R1CS、3.12s prove、0.73ms verify、641MB peak heap、241,942 gas；Kubo 测试接受 40 合法、拒绝 20 stale replay 与 180 flood | 完整 reverse-Polish bytecode interpreter 明确“design-level component and is not used to support the measured timing claims”；ARM/Android 未测；仅 gnark 后端 | 最接近的隐藏策略承诺 + proof + nonce + gateway 原型 | 不能声称首次组合隐藏策略承诺、Merkle、ZK 与 nonce | 场景是 IoT/IPFS 数据访问，无 Agent 多步计划、无累计预留行预算、无逐步位置绑定；其策略向量非本场景 allowlist |
| **`draft-das-execution-finality-ai-interoperability-05`**（个人 Internet-Draft，2026-09，2027-03-23 到期）`[FACT]` | EP-14 aggregate-budget control：`sum(cost(successful_act_i)) <= protected_budget`；Finality Sink / Effectuation Boundary；EP-8/9/13 实际效果重建、commit-time equality、完整中介 | 无实现实验；文档明确不要求特定密码套件 | 整个架构是标准讨论 pattern；无 ZK/SNARK 构造 | 概念信号：累计预算本身不是新颖性；finality sink 与工具边界思想互补 | 不能称其为 IETF 标准，不能称其提供 ZK 方案 | 无电路、无承诺、无证明系统；只提供执行最终性约束语言 |

`[INFERENCE]` 综合：四项工作中没有与 Bq 完全等价的“注册预算承诺 + 有限多步计划累计 `max_rows` + 逐步位置绑定 + challenge 绑定”的已实现系统；但 CVA 与 zk-Guard-R 已覆盖大量组成性质，Bq 的增量必须是**可形式化且可实验**的，不能只靠场景替换。

本轮未发现需要补充的新的直接等价工作；未扩展为大规模综述。

---

## 8. 基线与未来实验设计 `[REC]`

| 基线 | 核心方案 | 语义要求 |
| --- | --- | --- |
| B0 | V1：Authority 逐计划检查 + Ed25519 Grant + SHA-256 Merkle + 进程内 nullifier | 完整私有 allowlist + B/L |
| B1 | 逐调用 capability / tool-boundary authorization（AgentCap 类） | 每次调用独立授权；budget 为 token 剩余额度 |
| B2 | Model Bq：一次注册 `C_qpol` + 一份计划 proof + 逐步 Poseidon inclusion + challenge/nonce 绑定 | 与 B0 同语义需采用 Bq-a（allowlist 公开且 Gateway 独立执行）；否则只能与“预算专用”基线比较 |

`[INFERENCE]` 若 B2 只验证 B/L，而 B0 还验证私有 allowlist，不能直接做同语义性能比较。

未来指标（本轮只设计，不测量）：策略注册耗时；每份计划授权/证明生成耗时；proof verification 耗时；每步 inclusion verification 耗时；N 步总延迟；proof/VK/PK 大小；电路约束规模；Policy Owner 在线负担；Prover 在线可用性与信任负担；多 Gateway 状态消费开销；不同 `N∈{1,2,4,8,16}` 下成本变化。冷/热启动分开，setup 不计入 online latency。

---

## 9. GO / HOLD / NO-GO 裁决

### 9.1 GO 条件核对 `[FACT]/[INFERENCE]`

1. 形式化 V1 per-plan signature 在相同信任假设下无法提供的性质：**部分满足**（P1 可定义，但尚未电路化）。
2. Policy Owner 只注册、不逐计划在线决策：**满足**于 Bq。
3. Prover witness 可见性与信任边界明确：**满足**（明确知道 B/L，不声称对其保密）。
4. allowlist 未纳入关系的处理明确：**满足**于 Bq-a；Bq-b 退化。
5. nonce/version/context/schema 绑定完整：**设计满足**，实现未完成。
6. 相对 CVA/zk-Guard-R/AgentCap 差异具体：**部分满足**（差异存在但属场景级，尚未实验）。
7. 公平可复现 B0/B1/B2 实验：**未满足**（本轮明确不跑实验）。
8. 实际部署理由：**未满足**（只是设计可能性，尚无部署驱动证据）。

### 9.2 NO-GO 条件核对 `[INFERENCE]`

- 仍依赖 Policy Owner 逐计划在线判断：Bq 不触发；Bq-b 触发（故不采用 Bq-b 作为主张）。
- Prover 必须知道预算却声称对其保密：**不触发**（本设计明确不声称）。
- allowlist 仍依赖逐计划 Authority 却声称完全去中心化：**不触发**（Bq-a 明确公开规则；Bq-b 不主张）。
- 最终性质等价于 V1 签名背书：**不触发**（离线注册 + 任意计划验证是不同信任假设）。
- 核心构造只是 CVA/zk-Guard-R 场景化重复：`[OPEN]` 尚未被证伪，是最大风险。
- 计划根/执行边界没有更强保证：**部分触发**（P2/P3 与 V1 同构，新增仅在 P1）。
- 需 MPC/TEE/分布式证明：**不触发**（前提是不追求 Prover 侧保密）。

### 9.3 最终裁决

证据不足以 GO，也未触发必须立即停止的 NO-GO 条件。按任务要求给出唯一结论：

**CONDITIONAL HOLD。**

解除条件（全部满足才允许从 HOLD 转 GO）：完成 Bq-a 的 `C_qpol` 新电路关系与公开输入设计；把 challenge nonce、policy version/epoch、context、schema 写入同一 statement 并给出字节级编码；形式化 P1 与 zk-Guard-R policy-vector soundness 的差异；完成 B0/B1/B2 同语义实验协议与最小验证性实验；明确 allowlist 公开化后的部署合理性。否则停止该 ZK 实现路线。

本轮不启动 Step 3.2C，不修改 Step 3.2B 或 v0.2 冻结规格，不把设计可能性描述为已实现能力。
