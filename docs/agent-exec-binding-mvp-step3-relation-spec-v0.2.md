# Step 3 — Halo2 约束关系规格（v0.2）

状态：完整关系设计规格（v0.2）。本文定义目标协议的公共输入、
私有见证、承诺关系及电路约束。

实现状态说明：当前 Rust/Halo2 原型仅实现固定三动作配额子关系。
16 叶计划 Merkle Root、完整 Statement Commitment、可变动作数量、
非活动槽位及动作 Schema 兼容性等约束尚未全部纳入 Halo2 电路。
详见 `zk-v2-host/README_STEP3_2.md`。

因此，本文描述的是目标关系规格，不应被理解为当前电路
已经完整实现的功能。

## 0. 本版结论

v1 电路只证明“隐藏的单步上限与计划级预留行数总额”关系，不证明私有资源/字段/filter allowlist。

采用一个独立的 ZK 协议版本 `data-query-v2-poseidon`：

- 旧 `data-query-v1`：Ed25519 + SHA-256 完整策略承诺 + SHA-256 Merkle Tree，继续作为基线；
- 新 `data-query-v2-poseidon`：Ed25519 授权信封 + Poseidon 配额承诺 + Poseidon 计划 Merkle Tree + Halo2 计划级证明。

v2 的电路公共 `R_plan` 必须与执行网关验证每个步骤 Inclusion Proof 使用的 Poseidon 根完全相同。不能出现“电路证明 Poseidon Root、执行却只校验 SHA-256 Root”的双根脱节。

## 1. 研究场景与语义

Agent 提交一份有序、有限、只读数据查询计划：

\[
A=(a_0,a_1,\ldots,a_{n-1}),\quad 1\le n\le16.
\]

每个动作包含固定数据查询 schema 下的资源、过滤条件、返回字段和预留最大行数 \(m_i\)。\(m_i\) 是该步骤获准返回的最大行数，不是实际返回行数。

隐藏配额策略为：

\[
P_q=(B,L),
\]

其中 \(B\) 是计划累计预留行数上限，\(L\) 是单步预留行数上限。

电路要证明：

\[
1\le m_i\le L,\qquad \sum_{i=0}^{n-1}m_i\le B.
\]

这里的累计量是各步骤 `max_rows` 的总和。重复或重叠查询仍重复计数；它不是唯一记录数、唯一用户数或差分隐私预算。

## 2. 承诺对象：明确区分两种 commitment

现有 Python `policy_commitment()` 对 `policy.private_policy_dict()` 整体做 SHA-256 加盐承诺，包含字段/过滤白名单、`max_rows_per_action`、`aggregate_row_budget` 和 `max_plan_actions`。保留它作为 v1 基线，不改其语义。

v2 新增单独的配额承诺：

\[
C_q=H_{\text{quota}}(B,L,r),
\]

其中 \(r\) 是均匀随机采样的 Pasta `pallas::Base` 域元素，仅由授权方/证明者持有。

因此：

- `C_policy_sha256`：旧基线的完整策略承诺；
- `C_quota_poseidon`：v2 电路实际验证的 \((B,L)\) 承诺。

不能把二者称为同一个 commitment。v2 证明不验证字段和过滤 allowlist；这些仍由当前可信授权方做确定性检查。

## 3. Halo2 / Poseidon 参数

目标依赖与 Orchard 工程线一致：`halo2_proofs 0.4.0`、`halo2_gadgets 0.6.0`、直接依赖 `halo2_poseidon 0.2.0`，字段取 `pasta_curves::pallas::Base`。`halo2_poseidon` 虽是 `halo2_gadgets` 的依赖，但本项目若直接调用 host primitive，仍应在自己的 `Cargo.toml` 中显式声明直接依赖。

采用 Zcash Halo2 `halo2_poseidon::P128Pow5T3`：

- field：Pallas Base；
- state width \(T=3\)，rate \(RATE=2\)；
- S-box：\(x^5\)；
- full rounds：8；
- partial rounds：56；
- 电路端使用 `halo2_gadgets::poseidon::Pow5Chip` / `Hash` gadget；
- host 端使用同一 `halo2_poseidon` primitive 计算承诺、动作叶和 Merkle 根。

各类 hash 使用固定长度域 `ConstantLength<L>`，并在消息首元素放入不同的数值 domain tag。这样 host 端和电路端使用相同的 field、Poseidon 参数、消息长度、domain tag 和元素顺序。

参考源码：

- <https://github.com/zcash/halo2/blob/main/halo2_poseidon/src/p128pow5t3.rs>
- <https://github.com/zcash/halo2/blob/main/halo2_poseidon/src/lib.rs>
- <https://github.com/zcash/halo2/blob/main/halo2_gadgets/src/poseidon.rs>
- <https://github.com/zcash/halo2/blob/main/halo2_gadgets/src/poseidon/pow5.rs>

## 4. 固定动作编码

不把任意字符串、JSON 或 Python 字典直接放进电路。v2 使用固定整数 ID。所有 ID 从 1 开始，0 只用于规范 padding。

### 4.1 ID 表

**Resource ID**

| ID | 资源 |
|---:|---|
| 1 | `sales_records` |
| 2 | `support_metrics` |

**Selected-field ID**（按字段名字典序分配，和当前 `DataQueryAction` 排序一致）

| ID | 字段 |
|---:|---|
| 1 | `category` |
| 2 | `quarter` |
| 3 | `region` |
| 4 | `revenue_cents` |
| 5 | `ticket_count` |

**Filter-field ID**

| ID | 字段 |
|---:|---|
| 1 | `category` |
| 2 | `quarter` |
| 3 | `region` |

**Filter-value ID**（在同一字段内部按字典序分配）

| ID | 字段和值 |
|---:|---|
| 1 | `category=account` |
| 2 | `category=billing` |
| 3 | `category=technical` |
| 4 | `quarter=2026-Q3` |
| 5 | `quarter=2026-Q4` |
| 6 | `region=east` |
| 7 | `region=north` |
| 8 | `region=south` |
| 9 | `region=west` |

**固定版本常量**

- `DATA_QUERY_SCHEMA_ID = 2`；只代表本版固定 read-only query schema，不替代公共输入中的真实 schema digest。
- v2 必须定义独立的 `DATA_QUERY_TOOL_SCHEMA_V2`（协议/工具版本字段为 2，显式限制 filters ≤ 2、selected_fields 1..3、只读操作和固定资源字段集合），并以当前 `canonical_json` 规则计算新的 `DATA_QUERY_SCHEMA_HASH_V2`。不能复用现有 `DATA_QUERY_SCHEMA_HASH`：它来自 `DATA_QUERY_TOOL_SCHEMA` version 1。v1 的 schema hash 与 SHA-256 执行基线保持不变。
- `MAX_PLAN_ACTIONS = 16`。
- `MAX_FILTERS_PER_ACTION = 2`。
- `MAX_SELECTED_FIELDS = 3`。

**固定工具 schema 兼容集合**（这是公开工具 schema 的结构检查，不是私有 policy allowlist 证明）：

| Resource ID | 可选 selected-field IDs | 可用 filter-field IDs |
|---:|---|---|
| 1 (`sales_records`) | {2, 3, 4} | {2, 3} |
| 2 (`support_metrics`) | {1, 2, 5} | {1, 2} |

Filter field/value 的静态编码兼容关系：category ID 1 只配 value IDs {1,2,3}；quarter ID 2 只配 {4,5}；region ID 3 只配 {6,7,8,9}。Host encoder 和 circuit 都必须拒绝不兼容组合。

Host encoder 还必须拒绝超过 2 个 filters 或 3 个 selected fields 的动作；现有 Python `DataQueryAction` 对象本身并未完整表达这些 v2 固定上限，不能假定构造对象时已替电路做完检查。

### 4.2 Canonical action message

每个活动动作编码为恰好 14 个 Pasta field 元素：

\[
\begin{aligned}
M_i=[&D_{ACTION},2,i,resource_i,filterCount_i,\\
&filterField_{i,0},filterValue_{i,0},filterField_{i,1},filterValue_{i,1},\\
&fieldCount_i,field_{i,0},field_{i,1},field_{i,2},m_i].
\end{aligned}
\]

规范规则：

1. `step` 必须等于动作槽位下标 \(i\)，即 0 到 15；
2. `filterCount` 为 1 或 2；过滤字段按 ID 严格递增；未使用过滤槽位的 field/value ID 均为 0；
3. `fieldCount` 为 1 到 3；输出字段 ID 按 ID 严格递增；未使用字段槽位为 0；
4. resource、field、filter-field、filter-value ID 必须落在上表定义范围内；
5. 本版可额外检查固定工具 schema 的资源/字段兼容性，但这只是公开 schema 检查，不等于证明私有 policy allowlist；
6. `max_rows` 必须在 1 到 65535 之间。

动作叶：

\[
Leaf_i=H_{ACTION}(M_i)=Poseidon_{P128Pow5T3}^{ConstantLength(14)}(M_i).
\]

### 4.3 活动槽位与规范 padding

电路固定使用 16 个叶子，不使用奇数层 duplicate-last 规则。

- 活动槽位为 \(i<n\)，且必须对应 step \(i\)；
- 非活动槽位 \(i\ge n\) 的所有动作 witness 字段必须为 0；
- 非活动叶子为：

\[
Pad_i=Poseidon^{ConstantLength(2)}(D_{PAD},i).
\]

- 活动叶子使用 `Leaf_i`。
- 用固定的二叉结构对 16 个叶子计算 4 层 Merkle Tree。

父节点：

\[
Node(l,r)=Poseidon^{ConstantLength(3)}(D_{NODE},l,r).
\]

最终根：

\[
R_{plan}=MerkleRoot_{16}(Leaf_0,\ldots,Leaf_{n-1},Pad_n,\ldots,Pad_{15}).
\]

因此 v2 执行端必须用相同 Poseidon 规则验证 4 层 Inclusion Proof；SHA-256 tree 继续仅供 v1 baseline 使用。

所有 Poseidon 输出在 grant / JSON 中使用 Pasta `PrimeField::to_repr()` 的规范 32-byte 表示编码为 hex；不得对 field 元素做模约减或自行反转字节序。host 端与 gadget 端必须共享测试向量。

## 5. 配额承诺与数学关系

配额承诺固定为 4 个 field 元素：

\[
C_q=Poseidon^{ConstantLength(4)}(D_{QUOTA},B,L,r).
\]

固定数值 domain tag（作为 `pallas::Base` 元素）：

| Tag | 数值（十六进制） | 用途 |
|---|---|---|
| `D_QUOTA` | `0x51554F54415F5632` | 配额承诺 |
| `D_ACTION` | `0x4143544E5F5632` | 动作叶 |
| `D_NODE` | `0x4E4F44455F56325F` | Merkle 父节点 |
| `D_PAD` | `0x5041445F56325F5F` | 非活动叶子 |
| `D_STATEMENT` | `0x53544154454D5432` | 公共声明绑定 |

完整关系：存在私有见证 \(B,L,r,A\)，使得：

1. `C_q` 与隐藏配额 \((B,L)\) 的 Poseidon 承诺一致；
2. 由固定动作编码和规范 padding 计算出的 Poseidon Merkle 根等于公共 \(R_{plan}\)；
3. 活动槽位恰为前 \(n\) 个，\(1\le n\le16\)；
4. 每个活动动作的 \(m_i\) 满足 \(1\le m_i\le L\)；
5. \(S=\sum_{i=0}^{15}active_i\cdot m_i\)，且 \(S\le B\)。

## 6. 整数范围约束的具体实现目标

Pallas Base 是有限域。不能仅写 field inequality 或把域元素直接当作整数比较。

范围：

- \(B\)：32-bit，且非零；
- \(L\)：16-bit，且非零；
- 活动 \(m_i\)：16-bit，且非零；
- 活动槽位计数 \(n\)：5-bit，且由 16 个活动位求和得到；
- 累计值 \(S\)：20-bit；最大值 \(16\times65535=1,048,560<2^{20}\)。

建议使用 bit-decomposition 与差值见证表达非负比较：

- 对活动动作，见证 \(d_i=L-m_i\)，约束 \(L=m_i+d_i\)，并对 \(d_i\) 做 16-bit range check；
- 见证 \(d_B=B-S\)，约束 \(B=S+d_B\)，并对 \(d_B\) 做 32-bit range check；
- 结合 \(B,L,m_i\) 本身的范围约束，保证这些等式具有整数语义而不是有限域回绕。

活动位 \(active_i\) 为布尔值，约束前缀连续：`active[0]=1`，对 \(i>0\) 约束 `active[i] * (1 - active[i-1]) = 0`，并约束 \(n=\sum active_i\)。非活动槽位的动作字段必须为 0。

非零约束可用 inverse witness：对需非零的 \(x\)，引入 \(x^{-1}\) 并约束 \(x\cdot x^{-1}=1\)。实现时应统一封装并测试，不能遗漏 `B/L/m_i` 的零值拒绝。

## 7. 公共输入、私有见证与授权信封

### 7.1 公共输入顺序（v2 初版）

1. `C_quota_poseidon`；
2. `R_plan_poseidon`；
3. `n`；
4. `H_ctx_hi`；
5. `H_ctx_lo`；
6. `H_schema_hi`；
7. `H_schema_lo`；
8. `C_statement`。

`H_ctx` 和 `H_schema` 当前是 32-byte SHA-256 digest。进入 Pasta field 时分别拆成两个 128-bit limb：前 16 bytes 按 big-endian 解析为 `hi`，后 16 bytes 按 big-endian 解析为 `lo`。不允许把 256-bit digest 直接模约减成单个 field element。电路必须计算并约束：

\[
C_{statement}=Poseidon^{ConstantLength(8)}(D_{STATEMENT},C_q,R_{plan},n,H_{ctx,hi},H_{ctx,lo},H_{schema,hi},H_{schema,lo}).
\]

`C_statement` 也作为公共输入。这样 context/schema limbs 不只是未使用的 instance 值，而是实际进入电路约束；授权信封签署全部 8 个声明值，验证端核对 proof instance 与信封一致。

### 7.2 私有见证

- \(B,L,r\)；
- 16 个动作槽位的固定编码字段；
- 活动位、范围分解位、比较差值及 inverse witnesses；
- Merkle 中间节点（或由电路内部计算）。

### 7.3 外层授权信封

Ed25519 信封继续负责认证授权方并绑定：协议版本、policy ID/version、上述所有公共输入（包括 `C_statement`）、principal/tenant/session、tool schema digest、plan nonce、issued_at、expires_at。

验证端必须同时检查：

- Ed25519 签名有效；
- proof 的公共输入与签名信封完全一致；
- 当前 context/schema 与信封一致；
- grant 在有效期内；
- 逐步执行时使用相同 `R_plan_poseidon` 的 Inclusion Proof，并检查 step 顺序和 nullifier 一次性消费。
- 每个执行动作还必须满足 `0 <= action.step < n`，并提供恰好 4 层的 Poseidon Inclusion Proof；不能把非活动 padding 叶当作有效动作。

`plan_nonce` 与时间戳由外层签名信封做 freshness 管理，不进入本版算术关系；因此证明证明的是配额与计划承诺关系，不负责时效或一次性消费。

## 8. v1 证明边界

说明：本节描述的是协议设计中 v1 证明范围，不代表当前
Rust/Halo2 原型的实际证明范围。当前原型仅实现固定三动作
配额子关系，具体边界以 `zk-v2-host/README_STEP3_2.md` 为准。

电路证明：计划中每步的预留行数、隐藏单步上限 L、隐藏总预算 B，以及被公开承诺的有序计划根之间满足约束。

v1 不证明：

- 私有字段/资源/filter allowlist；
- 数据库返回内容真实、完整、最新或正确来源；
- 工具确实执行了查询或没有伪造回执；
- 查询组合不泄漏敏感信息；
- differential privacy；
- 多网关之间 nullifier 的原子一致性。

私有 allowlist 的校验仍由可信授权方在签发前执行。授权方仍是信任根：ZK 证明的是计划符合 `C_quota` 中承诺的 B/L，不证明授权方没有把一个比组织真实意图更宽松的 B/L 放入承诺。若要证明配置来自组织事先注册的策略，还需先有不可任意替换的策略承诺注册机制。未来若要把 allowlist 也纳入 ZK，需要定义单独的私有策略承诺结构与集合成员关系，不应混入本版配额电路。

## 9. 必须先完成的测试向量

### 正常边界

1. `n=1, m_0=1, L=1, B=1` 接受；
2. `n=1, m_0=65535, L=65535, B=65535` 接受；
3. `n=16, all m_i=65535, L=65535, B=1,048,560` 接受；
4. 当前 demo 的 `m=(2,2,1), L=3, B=5, n=3` 接受。

### 必须拒绝

5. `n=0`、`n=17`；
6. `B=0` 或 `L=0`；
7. 任一活动 `m_i=0` 或 `m_i=65536`；
8. 任一活动 `m_i>L`；
9. `sum(m_i)>B`；
10. `B=2^32`；
11. 活动槽位不构成前缀；
12. 非活动槽位出现任意非零字段；
13. filter/field count 超范围、ID 越界、重复或乱序；
14. 动作修改、重排、step 不匹配导致根不一致；
15. 错误 domain tag、错误 padding 或错误 Poseidon 参数导致根/承诺不匹配；
16. context/schema limbs 与授权信封不一致。

另需离线 host/gadget 一致性向量：同一组输入分别由 host Poseidon primitive 和 Halo2 gadget 计算，输出必须逐字节一致。

## 10. 实施顺序

| 工作项                            | 当前状态                |
| ------------------------------ | ------------------- |
| v0.2 关系规格                      | 已形成设计规格             |
| Poseidon Host 编码与配额承诺          | 已实现                 |
| 固定深度 16 叶 Poseidon 计划树         | 已实现 Host 参考实现       |
| Statement Commitment 与公共输入编码   | 已实现 Host 参考实现       |
| 固定三动作 Halo2 配额电路               | 已实现原型，MockProver 测试 |
| 完整计划根与 Statement Commitment 约束 | 待实现                 |
| 可变动作数量与非活动槽位约束                 | 待实现                 |
| 动作 Schema 兼容性约束                | 待实现                 |
| 证明与 Python 授权信封绑定              | 待实现                 |
| 证明接入执行网关                       | 待实现                 |
| 端到端安全性与性能评估                    | 待实现                 |

在 host/gadget 一致性测试通过前，不开始性能优化，也不宣称完成 ZK 授权系统。
