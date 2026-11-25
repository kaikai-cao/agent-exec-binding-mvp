# Step 3.2C-0 — Halo2 与 Python Gateway 集成契约（设计，不实现）

状态：接口与信任模型设计稿。本文只回答 Step 3.2C 开始前必须定清的契约问题；**不实现代码、不生成真实 proof、不启动性能实验、不宣称新颖性，也不把设计完成描述成代码已实现**。

基线：`kaikai-cao/agent-exec-binding-mvp` @ `48169bc7d0d6dbaf231fb0d2944a8d85035c9e9c`（Step 3.2B 已封存并在独立临时目录全量克隆复现：`cargo fmt --check` 通过，`cargo test --locked` 53 passed / 0 failed）。本轮仅新增本文件。

标记约定：

- `[FACT]`：可从指定源码位置直接核对的既有行为；
- `[REC]`：本设计提出的推荐契约，尚未实现；
- `[OPEN]`：必须由人类决策者定夺、本轮不擅自修改冻结规格的未决问题。

---

## 0. 结论摘要

Step 3.2C 不能只是给现有 Ed25519 Grant 增加一个 proof 字段。至少存在四个阻断项：

1. V1 Python 授权/执行使用 SHA-256 Merkle 根；V2 电路使用固定 16 叶 Poseidon 根，二者不能互认。`[FACT: data_access.py:300,476；plan_batch.py:50-61,101-186；zk-v2-host/src/lib.rs:254-338]`
2. Python `DataQueryAction` 接受的字符串资源/字段/任意短过滤值比 Rust 编码器的固定枚举更宽；Python 授权通过不代表 V2 电路可编码。`[FACT: data_access.py:82-117；zk-v2-host/src/lib.rs:102-159,166-237]`
3. 现有 `H_schema` 是 v1 schema digest；v0.2 §4.1 明确要求 V2 定义独立的 `DATA_QUERY_SCHEMA_HASH_V2`。本勘误已把 O2（v2 schema digest）固定为契约要求，O1（复用 v1 hash）不再是可选方案。`[FACT: data_access.py:49-65；docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:147-148]`
4. `C_quota` 只承诺 `(B,L,r)`，不证明其与 SHA-256 `policy_commitment` 或私有 allowlist 的关系。`[FACT: data_access.py:239-242；docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:58-75]`

因此采用版本边界：V1 保持冻结；另建 V2 独立授权路径，Rust 作为唯一的 Poseidon / 编码 / proof 后端。

---

## 1. 源码事实清单

| ID | 事实 | 代码位置 |
| --- | --- | --- |
| F1 | `data_access.py` 自述为 Ed25519 基线，明确不是 ZK 实现，并复用 SHA-256 Merkle。 | `data_access.py:1-6` |
| F2 | V1 授权方构造 `plan_batch.MerkleTree`，把 `tree.root` 写入 `plan_root` claim。 | `data_access.py:300,322` |
| F3 | V1 Gateway 用 `MerkleTree.verify(action, inclusion_proof, plan_root)` 逐步验包含。 | `data_access.py:474-477` |
| F4 | V1 Merkle 叶/父节点是 `SHA-256(0x00‖u32(index)‖canonical_json)` 与 `SHA-256(0x01‖left‖right)`，奇数宽度 duplicate-last。 | `plan_batch.py:50-61,101-126` |
| F5 | V2 Host 的叶/父/padding 是 Poseidon：`Poseidon^14(M_i)`、`Poseidon^3(D_NODE,l,r)`、`Poseidon^2(D_PAD,i)`；固定 16 叶四层。 | `zk-v2-host/src/lib.rs:69-71,239-252,254-295` |
| F6 | V2 `verify_inclusion` 用 Poseidon 根、`action_count`、4 个 sibling，并检查 `proof.index == action.step`。 | `zk-v2-host/src/lib.rs:314-338` |
| F7 | Python 动作仅校验资源/字段名为正则、filters 至少 1 个且字段不重复、selected_fields 至少 1 个且不重复、值是非空字符串 ≤128 字符。 | `data_access.py:82-117` |
| F8 | Rust `encode_action` 固定资源 2 个、filter field 3 个、selected field 5 个、filter value 9 个；filters 1..2、selected 1..3；拒绝不兼容组合。 | `zk-v2-host/src/lib.rs:102-159,166-237` |
| F9 | Rust 32-byte digest 拆分为两个大端 128-bit limb，不模约减；字段规范序列化为 `hex(to_repr())`。 | `zk-v2-host/src/lib.rs:77-100` |
| F10 | V2 公共输入顺序固定为 `C_quota,R_plan,n,H_ctx_hi,H_ctx_lo,H_schema_hi,H_schema_lo,C_statement`。 | `zk-v2-host/src/lib.rs:407-423`；`docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:272-289` |
| F11 | `plan_context_hash` 的 preimage 仅含 `principal,tenant_id,session_id`。 | `plan_batch.py:319-325` |
| F12 | `agent_exec_binding.py` 的另一套 context 含 `task_id`，与 D1 数据访问路径不同。 | `agent_exec_binding.py:99-109,246-275` |
| F13 | 现有 `DATA_QUERY_TOOL_SCHEMA` 的 `version=1`，`DATA_QUERY_SCHEMA_HASH = object_digest(...)`。 | `data_access.py:49-65` |
| F14 | v0.2 规格要求 v2 另建 `DATA_QUERY_TOOL_SCHEMA_V2` / `DATA_QUERY_SCHEMA_HASH_V2`，不得复用 v1 hash。 | `docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:147-148` |
| F15 | `PlanQuotaCircuit::from_plan` 已接收动作、B、L、blinding、context digest、schema digest，并返回电路与 8 个 host 计算实例。 | `zk-v2-host/src/plan_quota_circuit.rs:101-146` |
| F16 | `from_plan` 逐槽检查 `step==index` 并调用 Rust `encode_action`；私有 witness 字段不公开。 | `zk-v2-host/src/plan_quota_circuit.rs:50-62,101-121` |
| F17 | 当前 `main.rs` 只打印 demo 实例和 inclusion proof，blinding 是固定 fixture，明确不得用于真实授权。 | `zk-v2-host/src/main.rs:11-17,31-37` |
| F18 | 全仓库检索 `create_proof`/`verify_proof`/`keygen_vk`/`keygen_pk`/`Params::new`/`Blake2b` 均无匹配；真实 proof API 尚未接入。 | 在基线 `48169bc` 全仓 `*.rs/*.py/*.md` grep |
| F19 | `DataAccessAuthorization` 持有 `issuer_policy` 与 salt，注释要求永不发给 agent 或 gateway。 | `data_access.py:221-228` |
| F20 | V1 Gateway 的 nullifier 消费使用进程内 `set` + `Lock`，注释承认真实部署需要共享持久事务状态。 | `data_access.py:435-437,481-490`；`plan_batch.py:444-445` |
| F21 | Halo2 0.4 `create_proof` / `verify_proof` / `keygen_vk` / `keygen_pk` 的签名如下文 E 节所列；`Params::new(k)` 本地生成。 | `halo2_proofs-0.4.0/src/plonk/prover.rs:34-47`、`verifier.rs:67-79`、`keygen.rs:189-198,251-259`、`poly/commitment.rs:35-38` |
| F22 | Pallas Base = `Fp` = Vesta Scalar；因此以 `pallas::Base` 为电路 scalar 时 PLONK 曲线参数应为 `vesta::Affine`。 | `pasta_curves-0.6.0/src/pallas.rs:6-9`、`vesta.rs:6-9`；`halo2_proofs-0.4.0/src/plonk/keygen.rs:193-197` |

---

## 2. 数据流图（推荐，未实现）

```mermaid
flowchart TD
    subgraph Issuing[Trusted issuing boundary — full plan exists ONLY here]
        A[Python V2 Authority: full DataQueryAction plan + private DataAccessPolicy]
        A -->|1. per-action private allowlist check; B=aggregate_row_budget, L=max_rows_per_action| B[Rust backend: encode_action / PoseidonPlanTree]
        B -->|2. 14-element words, R_plan, n; B/L + CSPRNG r as private witness| C[Halo2 Prover: from_plan + create_proof]
        C -->|3. proof bytes| B
        B -->|4. R_plan, n, 8 field-hex instances, per-step inclusion proofs| A
        A -->|5. confirm R_plan/n/instances match the checked plan; then sign| D[Ed25519 V2 Grant issuer]
    end
    D -->|6. Grant + ProofBundle + inclusion proofs — NO full plan to Gateway| Caller[Caller / Agent]
    Caller -->|7. Grant + ProofBundle + pinned vk_id| E[Python V2 Gateway: register plan]
    E -->|8. signature / context / schema / time / n / vk pin / proof_bundle_digest, then verify_proof| F[Rust backend verifier]
    F -->|9. Ok(()) accept / Err reject| E
    E -->|10. cache validated-plan record| G[(Validated plan cache)]
    Caller -->|11. per step: current DataQueryAction + its inclusion proof| E
    E -->|12. verify_inclusion against same R_plan, 4 Poseidon siblings| F
    F -->|13. true / false / Err| E
    E -->|14. ordered nullifier consume, freshness rechecked| H[(Durable nullifier store)]
    E -->|15. execute| I[MockReadOnlyDataTool / 未来真实工具]
    I -->|16. signed receipt with action_leaf_poseidon| E

    subgraph Verifying
        E
        F
        G
        H
    end
```

`[REC]` Rust 后端是唯一的密码学编码、Poseidon、Merkle 与 proof 实现位置；Python 不复制 Poseidon 或字段序列化逻辑。**完整计划清单只存在于 Authority / Prover 的受信任签发边界内；Gateway 不接收、也不重建完整计划。**

---

## A. 协议版本边界

### A.1 `[FACT]` 既有 V1

- `TOOL_ID = "data.query.v1"`，V1 明确是 Ed25519 + SHA-256 基线。`[data_access.py:1-6,37]`
- 授权方使用 `plan_batch.MerkleTree` 生成 `plan_root`。`[data_access.py:300,322]`
- 执行网关使用 `MerkleTree.verify` 验证 SHA-256 inclusion proof。`[data_access.py:474-477]`
- 现有测试覆盖该路径；本轮不改 `data_access.py`、`plan_batch.py` 及其测试。

### A.2 `[REC]` 新增 V2

- 使用独立模块/类，例如 `data_access_v2.py` 与 `DataAccessAuthorityV2` / `DataAccessGatewayV2`，不静默替换 V1。
- V2 的 Grant、`ProofBundle`、逐步 `InclusionProofV2` 必须引用同一个 Poseidon `R_plan`，其唯一合法来源是 Rust `PoseidonPlanTree::root()`。`[zk-v2-host/src/lib.rs:254-295]`
- V2 Grant 标记 `protocol = "data-query-v2-poseidon"`、`grant_version = 2`；V1 的 `grant_version = 1` 继续由 V1 路径处理。`[data_access.py:314,458]`
- V2 不得出现 SHA-256 `plan_root` 字段；若历史上存在同名字段，必须改名或拒绝，避免误用。

### A.3 `[OPEN]`

- V1 与 V2 是否共存于同一 Python 包、是否共享 `AuthorizationError`、是否共享工具执行器，需要后续实现任务决定；本设计只要求行为隔离和数据隔离。

---

## B. 规范动作编码

### B.1 `[FACT]` Python 侧更宽

`DataQueryAction.__post_init__` 接受任意匹配 `^[a-z][a-z0-9_]{0,63}$` 的 resource/filter field/selected field，过滤值可为任意 ≤128 字符字符串，selected/filter 数量下限为 1，但没有 v2 的 2/3 上限。`[data_access.py:43-44,82-117]`  
`DataAccessPolicy` 的 allowlist 是通用字符串集合，与 Rust 固定 ID 表不是同一套对象。`[data_access.py:134-217]`

### B.2 `[FACT]` Rust 侧固定编码

`encode_action` 生成 14 元素消息：`[D_ACTION,2,step,resource_id,filter_count,ff0,fv0,ff1,fv1,field_count,f0,f1,f2,max_rows]`；未使用槽位为 0。`[zk-v2-host/src/lib.rs:166-237]`  
动作叶、padding、父节点与根都由同一 Host primitive 计算。`[zk-v2-host/src/lib.rs:239-295]`

### B.3 `[REC]` Python → Rust 转换表

| Python `DataQueryAction` | Rust 函数 / 常量 | V2 允许值 | 失败处理 |
| --- | --- | --- | --- |
| `resource` | `resource_id()` `lib.rs:102-108` | `sales_records`→1；`support_metrics`→2 | 任何其它字符串拒绝 |
| `filters[i][0]` | `filter_field_id()` `lib.rs:121-128` | `category`→1；`quarter`→2；`region`→3 | 未知字段拒绝 |
| `filters[i][1]` | `filter_value_id()` `lib.rs:130-143` | `category={account,billing,technical}`→{1,2,3}；`quarter={2026-Q3,2026-Q4}`→{4,5}；`region={east,north,south,west}`→{6,7,8,9} | 未知值拒绝 |
| `filters` 数量 | `encode_action()` `lib.rs:176-178` | 1..=2 | 0 或 >2 拒绝 |
| `selected_fields` | `selected_field_id()` `lib.rs:110-119` | `category`→1；`quarter`→2；`region`→3；`revenue_cents`→4；`ticket_count`→5 | 未知字段拒绝 |
| `selected_fields` 数量 | `encode_action()` `lib.rs:179-181` | 1..=3 | 0 或 >3 拒绝 |
| resource ↔ selected | `selected_field_allowed()` `lib.rs:145-151` | resource 1→{2,3,4}；resource 2→{1,2,5} | 不兼容拒绝 |
| resource ↔ filter field | `filter_field_allowed()` `lib.rs:153-159` | resource 1→{2,3}；resource 2→{1,2} | 不兼容拒绝 |
| 去重与排序 | `encode_action()` `lib.rs:183-215` | 按 numeric ID 严格递增；重复拒绝 | Python 侧数组顺序不再作为规范顺序 |
| `step` | `encode_action()` `lib.rs:167-169`；`PoseidonPlanTree::new()` `lib.rs:260-269` | 槽位下标 0..15，活动槽位必须 `step == i` | 跳位/错位拒绝 |
| `max_rows` | `encode_action()` `lib.rs:172-174` | 1..=65535 | 0 或 65536 拒绝 |
| 16 槽 padding | `padding_leaf()` `lib.rs:243-248`；`PoseidonPlanTree::new()` `lib.rs:260-270` | 非活动槽位 14 元素全 0，叶子为 `Poseidon^2(D_PAD,i)` | 不得把 padding 当动作 |

### B.4 `[REC]` 拒绝规则

V2 授权阶段必须调用 Rust `encode_action` / `PoseidonPlanTree::new` / `PlanQuotaCircuit::from_plan` 做一次完整转换；任一步返回 `Err` 或 `Result::Err` 时，直接拒绝该计划，**不得签发 V2 Grant**。Gateway 在执行每步时用同一 Rust 函数重新编码，防止传输层改动动作。`[zk-v2-host/src/plan_quota_circuit.rs:101-121]`

公开工具 schema 的结构兼容性检查只说明动作能被固定编码，不证明私有 allowlist。`[docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:313-323]`

---

## C. Digest 与公共输入契约

### C.1 `[FACT]` `H_ctx`

完整 preimage 为 JSON 对象：

```json
{"principal": "<principal>", "tenant_id": "<tenant_id>", "session_id": "<session_id>"}
```

经 `canonical_json`（`sort_keys=True, separators=(",",":"), ensure_ascii=False`, UTF-8）后做 SHA-256，得到 32-byte digest。`[plan_batch.py:32-47,319-325]`  
不得使用 `agent_exec_binding.py` 中含 `task_id` 的 `ExecutionContext` 替换。`[agent_exec_binding.py:99-109,246-275]`

### C.2 `[FACT]/[REC]` `H_schema` — 固定为 V2 schema digest（O2）

现有 `DATA_QUERY_SCHEMA_HASH` 是对 `DATA_QUERY_TOOL_SCHEMA`（`version=1`）的 `object_digest`。`[data_access.py:49-65]`  
v0.2 §4.1 明确要求：V2 必须定义独立的 `DATA_QUERY_TOOL_SCHEMA_V2`（协议/工具版本字段为 2，显式限制 filters ≤ 2、selected_fields 1..3、只读操作和固定资源字段集合），并以现有 `canonical_json` 规则计算新的 `DATA_QUERY_SCHEMA_HASH_V2`，**不得复用 v1 hash**。`[docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:147-148]`

`[REC]` 本勘误据此把 O2 固定为契约要求：O1（复用 v1 `DATA_QUERY_SCHEMA_HASH`）不再是 V2 的可选实施方案。V2 的 `H_schema` 必须来自 `DATA_QUERY_SCHEMA_HASH_V2`；V1 的 schema hash 与 SHA-256 执行基线保持不变。V2 Grant 中该字段统一命名为 `tool_schema_digest_sha256`。`[OPEN]` 仍需人类确认的是 `DATA_QUERY_TOOL_SCHEMA_V2` 对象的最终内容；机制本身沿用 `canonical_json` / `object_digest`，不引入新算法，也不修改冻结规格。

### C.3 `[FACT]` 128-bit limb 与字段序列化

`digest_to_limbs()` 将 32-byte digest 的前 16 字节按大端解析为 `hi`，后 16 字节为 `lo`，各自 `<2^128`；不模约减。`[zk-v2-host/src/lib.rs:89-100]`  
字段规范序列化为 `hex::encode(to_repr())`，即 32-byte hex。`[zk-v2-host/src/lib.rs:77-79]`

`[REC]` Python 只传 32-byte hex 字符串；Rust 后端负责解析为非规范表示拒绝的 `Fp`。禁止十进制字符串、禁止把 digest 模约减成单个 field、禁止第二种字段序列化。

### C.4 `[FACT]/[REC]` 八个公共输入

| index | 名称 | 源 | 编码 |
| --- | --- | --- | --- |
| 0 | `C_quota` | `quota_commitment(B,L,r)` `[lib.rs:340-353]` | 32-byte hex |
| 1 | `R_plan` | `PoseidonPlanTree::root()` `[lib.rs:254-295]` | 32-byte hex |
| 2 | `n` | `active` 求和；`PlanQuotaCircuit::from_plan` 同时返回 `[plan_quota_circuit.rs:101-146]` | field hex；另有整数 claim `action_count` |
| 3 | `H_ctx_hi` | `digest_to_limbs(H_ctx)[0]` `[lib.rs:91-100]` | 32-byte hex |
| 4 | `H_ctx_lo` | `digest_to_limbs(H_ctx)[1]` | 32-byte hex |
| 5 | `H_schema_hi` | `digest_to_limbs(H_schema)[0]` | 32-byte hex |
| 6 | `H_schema_lo` | `digest_to_limbs(H_schema)[1]` | 32-byte hex |
| 7 | `C_statement` | `statement_commitment()` `[lib.rs:389-405]` | 32-byte hex |

签名信封必须绑定全部 8 个值。`[docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:289,300]`  
Gateway 在计划注册时必须检查 `action_count == public_instances[2] == n` 且 `1 <= n <= 16`；它此时没有完整动作清单，不校验 `len(encoded_actions)`。逐动作的规范编码只在单步执行时由 Rust `verify_inclusion` 对当前动作验证（见 F.2）。

---

## D. Ed25519 授权信封

### D.1 `[REC]` V2 Grant schema

签名方式与 V1 一致：Ed25519 对 `canonical_json(claims)` 签名，signature 用 hex 表示。`[data_access.py:328,454]`  
V2 claims 至少包含：

```json
{
  "protocol": "data-query-v2-poseidon",
  "grant_version": 2,
  "policy_id": "<policy_id>",
  "policy_version": 1,
  "policy_commitment_sha256": "<sha256-policy-commitment-hex>",
  "principal": "<principal>",
  "tenant_id": "<tenant_id>",
  "session_id": "<session_id>",
  "tool_schema_digest_sha256": "<DATA_QUERY_SCHEMA_HASH_V2-hex>",
  "context_digest_sha256": "<H_ctx-hex>",
  "plan_root_poseidon": "<R_plan-field-hex>",
  "action_count": 3,
  "plan_nonce": "<64-lowercase-hex-chars-encoding-32-bytes>",
  "issued_at": 0,
  "expires_at": 0,
  "vk_id": "<pinned-vk-id: ops-deployment-identifier>",
  "public_instances": {
    "format": "pallas-base-32-byte-hex-v1",
    "values": [
      {"index": 0, "name": "C_quota", "field_hex": "..."},
      {"index": 1, "name": "R_plan", "field_hex": "..."},
      {"index": 2, "name": "n", "field_hex": "..."},
      {"index": 3, "name": "H_ctx_hi", "field_hex": "..."},
      {"index": 4, "name": "H_ctx_lo", "field_hex": "..."},
      {"index": 5, "name": "H_schema_hi", "field_hex": "..."},
      {"index": 6, "name": "H_schema_lo", "field_hex": "..."},
      {"index": 7, "name": "C_statement", "field_hex": "..."}
    ]
  },
  "proof_bundle_digest_sha256": "<sha256-of-canonical-proof-bundle-payload-hex>"
}
```

`policy_commitment_sha256` 继续是 SHA-256 私有策略承诺，不声称等于 `C_quota`。`[data_access.py:239-242；docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:58-75]` V2 Grant/ProofBundle/Receipt 的完整字段命名表见 D.4。

`[REC]` `C_quota` 在本 schema 中**只**作为签名 claims 的 `public_instances.values[0]`（`index = 0`、`name = "C_quota"`、`field_hex`）出现；Grant 不设顶层 `C_quota` claim，不得维护重复字段。

### D.2 `[REC]` proof 是独立传输对象

推荐 `ProofBundle` 独立传输，不把 proof 字节放进签名 claims：

```json
{
  "proof_format": "halo2-0.4.0-pallas-base-v1",
  "proof_hex": "...",
  "vk_id": "<same-as-grant>",
  "circuit_id": "plan-quota-16-leaf-statement-binding-v1",
  "k": 13,
  "public_instances_digest_sha256": "<sha256-of-canonical-8-values>"
}
```

`[REC]` `proof_bundle_digest_sha256 = hex(SHA-256(canonical_json(proof_bundle_payload)))`；`public_instances_digest_sha256 = hex(SHA-256(canonical_json(values)))`。两者都使用 `plan_batch.canonical_json` 的同一规则。`[plan_batch.py:32-47]`

为避免循环引用：`proof_bundle_payload` **不包含自身 digest 字段**；`proof_hex` 使用唯一的小写 hex 表示；`circuit_id`、`k`、`vk_id`、`proof_format`、`public_instances_digest_sha256` 等安全相关元数据全部进入被摘要的 payload。`[REC]`

`[REC]` Grant 签署 `proof_bundle_digest_sha256` 的语义边界：它把 Grant 精确绑定到某一 ProofBundle，可检出传输过程中的 proof 替换、防止 Grant 收到另一份不同 proof bundle。**它不能单独实现 nonce 绑定，也不能保证同一份 proof 在不同 Grant 之间不可复用。** 本电路八个 public instances 不含 `plan_nonce`，因此相同 instances 对应的有效 proof 可以在一份新 Grant 中再次被签署和引用；freshness/replay 控制由 `plan_nonce`、`expires_at`、`step_nullifier` 负责。若未来要求 proof 本身对每个 nonce 密码学绑定，必须单独修改公共输入或证明关系，本轮不声称已实现。该字段不在 v0.2 八个 public instances 中，不改变电路关系。

### D.3 `[FACT]/[REC]` 一致性检查

- V1 Gateway 已检查 principal/tenant/session/schema/有效期/action_count。`[data_access.py:458-475]`
- V2 额外检查：`vk_id` 匹配部署 pin、`proof_bundle_digest_sha256` 匹配、8 个实例格式与顺序正确、`n == action_count`、`R_plan` 与实例 1 相同、`C_statement` 与实例 7 相同。
- 任何检查失败均在调用工具前拒绝。

### D.4 `[REC]` V2 统一字段命名表

V2 Grant、ProofBundle 与 Receipt 必须使用同一套字段名，不得混用 `tool_schema_hash` / `tool_schema_digest` / `schema_hash` 或语义不明的 `action_hash`。V1 字段名与行为不修改。

| 语义 | 字段 | 出现的对象 |
| --- | --- | --- |
| 协议标识 | `protocol` | Grant |
| 授权版本 | `grant_version` | Grant |
| 私有策略承诺 | `policy_commitment_sha256` | Grant |
| Context 摘要 | `context_digest_sha256` | Grant |
| 工具 Schema 摘要 | `tool_schema_digest_sha256` | Grant |
| Poseidon 计划根 | `plan_root_poseidon` | Grant、Inclusion Proof、Receipt |
| 动作数量 | `action_count` | Grant |
| 授权随机数（32 字节；Grant JSON 中为恰好 64 个小写 hex 字符） | `plan_nonce` | Grant |
| 验证密钥部署标识 | `vk_id` | Grant、ProofBundle、Cache |
| 八个公共输入 | `public_instances` | Grant |
| ProofBundle 摘要 | `proof_bundle_digest_sha256` | Grant、ProofBundle、Cache |
| Inclusion Proof 根 | `plan_root_poseidon` | Inclusion Proof |
| Receipt 动作叶 | `action_leaf_poseidon` | Receipt |
| 辅助 Action 摘要 | `action_json_digest_sha256` | Receipt（仅日志/追踪） |
| 逐步消费标识 | `step_nullifier` | Receipt、Nullifier store |

`plan_nonce` 必须以解码后的原始 32 bytes 参与 V2 `step_nullifier` 的 SHA-256 preimage，V2 的唯一字节级派生规则见 F.2 第 5 步；V1 `step_nullifier` 算法及 `nullifier:v1:` 前缀不变。

---

## E. Prover 与 Verifier 接口

### E.1 `[FACT]` 当前状态

仓库中没有 `create_proof` / `verify_proof` / `keygen_vk` / `keygen_pk` / `Params::new` 调用；只有 MockProver 测试与 demo 输出。`[F18；zk-v2-host/src/main.rs:1-40]`  
`Cargo.toml` 固定 `halo2_proofs = "=0.4.0"`、`halo2_gadgets = "=0.6.0"`、`halo2_poseidon = "=0.2.0"`、`pasta_curves = "=0.6.0"`，不得在本轮改依赖。`[zk-v2-host/Cargo.toml:9-16]`

### E.2 `[FACT]` Halo2 0.4 实际 API

```rust
pub fn keygen_vk<C, ConcreteCircuit>(
    params: &Params<C>,
    circuit: &ConcreteCircuit,
) -> Result<VerifyingKey<C>, Error>
where
    C: CurveAffine,
    C::Scalar: FromUniformBytes<64>,
    ConcreteCircuit: Circuit<C::Scalar>;
```
`[halo2_proofs-0.4.0/src/plonk/keygen.rs:189-198]`

```rust
pub fn keygen_pk<C, ConcreteCircuit>(
    params: &Params<C>,
    vk: VerifyingKey<C>,
    circuit: &ConcreteCircuit,
) -> Result<ProvingKey<C>, Error>
```
`[keygen.rs:251-259]`

```rust
pub fn create_proof<C, E, R, T, ConcreteCircuit>(
    params: &Params<C>,
    pk: &ProvingKey<C>,
    circuits: &[ConcreteCircuit],
    instances: &[&[&[C::Scalar]]],
    rng: R,
    transcript: &mut T,
) -> Result<(), Error>
```
`[prover.rs:34-47]`

```rust
pub fn verify_proof<'params, C, E, T, V>(
    params: &'params Params<C>,
    vk: &VerifyingKey<C>,
    strategy: V,
    instances: &[&[&[C::Scalar]]],
    transcript: &mut T,
) -> Result<V::Output, Error>
```
`[verifier.rs:67-79]`

`Params<C>::new(k)` 直接本地构造。`[poly/commitment.rs:35-38]`  
由于电路 scalar 是 `pallas::Base = Fp = vesta::Scalar`，参数类型取 `Params<vesta::Affine>`。`[F22]`

**RNG 契约（`[FACT]`，已核对锁定依赖与 0.4.0 源码）：**

- `create_proof` 的 RNG 参数是 `mut rng: R`，trait bound 为 `R: Rng`，其中 `Rng` 指 `rand_core::Rng`。`[halo2_proofs-0.4.0/src/plonk/prover.rs:2,34-47]` 在 `rand_core 0.10` 中 `Rng: TryRng<Error = Infallible>`。`[rand_core-0.10.1/src/lib.rs:49]`
- 本仓库锁定 `rand_core 0.10.1`、`rand 0.10.3`、`getrandom 0.4.3`；halo2 0.4.0 `Cargo.toml` 声明 `rand_core = "0.10"`、`rand = "0.10"`（可选，`sys_rng` feature）。`[zk-v2-host/Cargo.lock:328-341,126-128；halo2_proofs-0.4.0/Cargo.toml:175-183]` **不要混用其他 major 的 `rand_core` trait 类型**，否则 `Rng` bound 不成立。
- 系统 CSPRNG 取 `rand::rngs::SysRng`（即 `getrandom::SysRng`）。它实现的是 `TryRng`（`Error = getrandom::Error`），不是 `Infallible`，因此不能直接满足 `Rng`；halo2 0.4.0 自身测试用 `rand_core::UnwrapErr(SysRng)` 包装后传入。`[halo2_proofs-0.4.0/src/plonk/prover.rs:740-741,772-788；getrandom-0.4.3/src/sys_rng.rs:36-37；rand_core-0.10.1/src/unwrap_err.rs:30-33]`
- `UnwrapErr` 在底层 OS 取数失败时会 panic。`[rand_core-0.10.1/src/unwrap_err.rs:36-42]` 因此 `[REC]` 在签发边界初始化时必须**先显式探测系统熵源**（例如先 `SysRng` 取种子成功再构造证明 RNG），失败则拒绝签发并记录错误，不允许静默降级；证明 RNG 与 blinding 取数都在 Rust 侧完成，不经过命令行或日志。
- `[REC]` 当前 Cargo.lock 已含可用的 `rand` / `rand_core` / `getrandom`，本轮不新增依赖；若未来要用可移植 PRNG，再单独评估 `chacha20` crate，并仍以 `Rng` bound 为准。禁止把 demo fixture、`main.rs:14` 固定 blinding、时间戳、普通 `rng` 别名或未经审查的 `thread_rng` 当密码学 blinding 来源。

### E.3 `[REC]` 参数、VK/PK、缓存与分发

- `k = 13` 来自 Step 3.2B 的实测电路尺寸。`[zk-v2-host/IMPLEMENTATION_NOTES_STEP3_2B.md:103-106]`
- `[FACT]` `without_witnesses` 是 `Circuit` trait 的**实例方法** `fn without_witnesses(&self) -> Self`，不是静态函数；`blank()` 是模块私有方法，外部模块不可直接调用。`[halo2_proofs-0.4.0/src/plonk/circuit.rs:480；plan_quota_circuit.rs:65-75,327-328]` 需先 `use halo2_proofs::plonk::Circuit;`，再由已构造的电路实例取无 witness 电路。示意（接口层成立）：

```rust
use halo2_proofs::plonk::Circuit; // trait import，否则 without_witnesses 不可调用

let (circuit, public_instances) = PlanQuotaCircuit::from_plan(
    &actions, budget, limit, blinding, context_digest, schema_digest,
)?;
let keygen_circuit = circuit.without_witnesses(); // &self 实例方法
let vk = keygen_vk(&params, &keygen_circuit)?;
let pk = keygen_pk(&params, vk, &keygen_circuit)?; // 注意 keygen_pk 取得 vk 所有权
```

- `[FACT]` `Params<C>` 提供 `write<W: io::Write>` / `read<R: io::Read>` 的字节读写。`[halo2_proofs-0.4.0/src/poly/commitment.rs:169,184]` 但 `VerifyingKey` 没有内建 serde，也没有可从 VK 字节计算稳定指纹的 API。`[halo2_proofs-0.4.0/src/plonk/keygen.rs:189-259]`
- `[REC]` 本 MVP 的 `vk_id` 采用**运维配置固定标识**，由部署方写入 Gateway 的 pinned 配置，绑定：`circuit_id`、Halo2 版本、曲线类型、`k`、参数生成版本、部署使用的 VK/参数制品版本。这不是密码学上从 VK 字节算出的指纹；两者必须区分，不声称存在或已生成后者。Gateway 不接受来自 Grant 的 `vk_id` 自行更新。`[OPEN]` VK / PK 的跨进程字节分发与摘要方式留待实现阶段定义。

### E.4 `[REC]` witness 与 blinding

`PlanQuotaCircuit::from_plan(actions, B, L, blinding, context_digest, schema_digest)` 是唯一推荐的 witness 构造器；它已经调用 Rust `encode_action` 和 `digest_to_limbs`，并返回与电路一致的 8 个实例。`[plan_quota_circuit.rs:101-146]`

`[REC]` `C_quota = Poseidon(D_QUOTA, B, L, r)` 的见证归属必须固定：

- Authority/Prover：`B = policy.aggregate_row_budget`，`L = policy.max_rows_per_action`，由 Authority 从真实私有策略中取出；**不允许接受 Agent 或外部调用方自行指定的 B/L**。生成电路 witness 时必须使用这两个准确值。`[data_access.py:137-145]`
- `r` 用系统 CSPRNG（见 E.2）在 Rust 端按拒绝采样生成合法 `Fp`，保证均匀且非 fixture；不得使用 `main.rs:14` 的固定 demo 值。`[docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:68；zk-v2-host/src/main.rs:11-14]`
- Authority 负责确保签名 Grant 中作为 `public_instances.values[0]` 的 `C_quota` 对应这份策略中的 B/L，并确保 proof 使用这同一公共实例。

`[REC]` 本 MVP 的推荐信任模型：**Authority 与 Rust Prover 后端处于同一受信任签发边界，Rust 后端是 Authority 的密码学执行组件。** 必须明确：若未来把 Prover 作为独立且不受信任的外部服务，仅靠当前电路不能证明它使用了 Authority 策略中准确的 B/L；届时必须增加额外的策略绑定机制，不能沿用“Authority 已经确保”的模糊表述。B/L 本身不是 allowlist 的证明。

### E.5 `[REC]` proof 创建/验证调用形态

一个 proof、一个 circuit、一个 instance column。实例切片按 Halo2 类型 `&[&[&[Fp]]]` 构造：

```rust
let instances: [&[Fp]; 1] = [host_instances.as_slice()];
let instance_ref: &[&[&Fp]] = &[&instances];
// create_proof(&params, &pk, &[circuit], instance_ref, rng, &mut write)
// verify_proof(&params, &vk, SingleVerifier::new(&params), instance_ref, &mut read)
// SingleVerifier::Output = ()：Ok(()) 表示接受，Err(Error::ConstraintSystemFailure) 等表示拒绝；无 bool=false 结果
```

transcript 选用 `Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>` 与 `Blake2bRead<&[u8], vesta::Affine, Challenge255<vesta::Affine>>`。`[halo2_proofs-0.4.0/src/transcript.rs:66,143,260]`

错误 classification（`[REC]`）：

| 错误 | 触发 | Gateway 行为 |
| --- | --- | --- |
| `EncodeError` | Rust `encode_action` 拒绝动作 | 签发前拒绝；执行时拒绝 |
| `PublicInputMismatch` | Grant 实例与 Host 重算不一致 | 拒绝，不调用 verifier |
| `ProofInvalid` | `verify_proof`（`SingleVerifier`）返回 `Err`；`Ok(())` 为接受 | 拒绝 |
| `VkMismatch` | `vk_id` 与 pin 不一致 | 拒绝 |
| `GrantInvalid` | Ed25519 / 上下文 / 时间 / schema 不一致 | 拒绝 |

### E.6 `[REC]` Python ↔ Rust 通信方式比较

| 方案 | 优点 | 成本/风险 | 结论 |
| --- | --- | --- | --- |
| CLI 子进程 | 实现与调试最简单；进程隔离；Windows 上无扩展编译 | 每次启动重新构造 Params/PK/VK；Halo2 0.4 无内建 serde；私钥 witness 不能走命令行参数 | 适合单步测试，不适合作最终 V2 主路径 |
| 长期运行本地 worker | Params/PK/VK 常驻；避免 serde；可用 stdin/stdout 长度前缀 JSON 或 Windows named pipe；进程边界仍清晰 | 需要进程生命周期、帧协议、崩溃恢复与本地 ACL | **推荐**：适合当前 Windows MVP |
| PyO3 | 类型化 API、最低调用延迟 | 需要 Rust 扩展工具链与 maturin/setuptools-rust；Windows ABI/版本耦合；把密码学实现拉进 Python 进程 | 暂不推荐 |

`[REC]` 推荐 worker 暴露四个逻辑命令：`encode_plan`、`prove`、`verify`、`verify_inclusion`；全部使用 JSON over stdio/named pipe，stdin 传私有 witness，不经过命令行参数或日志。`prove` 的 RNG 与 blinding 在 worker 进程内按 E.2 生成，初始化失败即返回错误，不由 Python 侧传入种子。

---

## F. Gateway 执行流程

### F.0 `[REC]` 前置：Authority / Prover 签发阶段（Gateway 之外）

1. Authority 收到**完整** `DataQueryAction` 计划与私有 `DataAccessPolicy`。
2. Authority 对完整计划逐项执行私有 allowlist 检查（资源、字段、过滤字段、过滤值、行数）。`[data_access.py:245-331]`
3. Authority 把完整计划交给 Rust Host，由 Rust 统一完成规范动作编码、`PoseidonPlanTree`、`R_plan` 与逐步 Inclusion Proof 生成。`[zk-v2-host/src/lib.rs:166-295]`
4. Halo2 Prover 对同一计划生成真实 proof（witness 见 E.4）。
5. Authority 确认 Host 返回的 root、action count 与 proof public instances 一致后，签发 Ed25519 Grant。**Authority 必须保证它签署的 `R_plan` 对应其实际检查通过的那份计划，而不是接受任意 Prover 返回的 root。**
6. Authority 将 Grant、ProofBundle 和后续逐步所需 Inclusion Proof 交付给调用方。

完整计划清单只在本阶段流转；Gateway 不接收完整计划。

### F.1 `[REC]` 操作 1：注册/验证完整计划授权

输入（**不含完整计划清单**）：V2 Grant、`ProofBundle`、当前 principal/tenant/session、当前工具 schema digest、当前时间、部署配置中的 pinned `vk_id`。

步骤：

1. 验证 Ed25519 签名与 `grant_version=2`。V1 已有相同基线检查。`[data_access.py:454-459]`
2. 检查 principal/tenant/session/`tool_schema_digest_sha256` / `issued_at` / `expires_at`。`[data_access.py:460-473]`
3. 验证 Grant 中全部八个 public instances 的格式、顺序与 field-hex 编码。
4. 检查 `plan_root_poseidon == public_instances[1]`；检查 `action_count == public_instances[2] == n` 且 `1 <= n <= 16`。**Gateway 此时不重建 Merkle Tree。**
5. 从已验证 claims 重算 `H_ctx` / `H_schema`（instances 3..6），并由公开实例重算 `C_statement`，检查其与 instances[7] 一致。`[zk-v2-host/src/lib.rs:389-405]`
6. `C_quota` 的唯一来源是 Grant 签名覆盖的 `public_instances.values[0]`：必须验证其 `index == 0`、`name == "C_quota"`，并检查 `field_hex` 符合 C.3 的 32-byte 小写 field-hex 编码；Halo2 verifier 使用的第 0 个公共输入必须是这一已签名值。不新增顶层 `C_quota` claim，不要求维护重复字段。**Gateway 不重算 `C_quota`**：其输入 `(B,L,r)` 是私有见证，Gateway 不知道也无法重算；Gateway 不检查、也不声称 `C_quota` 与 SHA-256 `policy_commitment_sha256` 存在任何关系。该隐藏承诺由 Authority 在受信任签发边界内从私有策略取出 B/L，并确保 proof 与签名 Grant 使用相同的公共实例；`C_statement` 的输入全部公开，二者不可混为一谈。
7. 检查 `vk_id` 与部署 pin 一致、`proof_bundle_digest_sha256` 与 Grant 签名字段一致、`public_instances_digest_sha256` 与 8 个值一致。
8. 调用 Rust `verify_proof`（`SingleVerifier`）；`Err` 则拒绝，仅 `Ok(())` 视为成功。
9. 成功后写入 validated-plan cache，记录绑定 `grant_digest_sha256`、`proof_bundle_digest_sha256`、`vk_id`、`public_instances_digest_sha256`、`context_digest_sha256`、`tool_schema_digest_sha256`、`expires_at`。缓存只表示“完整 proof 验证通过”，不表示 freshness 已永久有效，也不含任何 nullifier 消费结果。

### F.2 `[REC]` 操作 2：执行单步

输入：V2 Grant、`ProofBundle` 或 validated-plan handle、`DataQueryAction`、`InclusionProofV2`、上下文与时间。

步骤：

1. **每次执行都重新检查** Ed25519 签名、当前 principal/tenant/session、`tool_schema_digest_sha256` 与 `now < expires_at`；命中 cache 时仍逐项校验缓存记录与当前 Grant、ProofBundle、8 个实例、VK pin 一致。缓存命中不能绕过这些检查。
2. 若未命中 cache，先执行 F.1；不允许跳过 proof 验证直接执行。
3. 用 Rust `verify_inclusion(action, n, proof, instances[1])` 验证当前动作属于同一个 Poseidon 根；`Ok(true)` 通过，`Ok(false)` 或 `Err` 拒绝。`[zk-v2-host/src/lib.rs:314-338]`
4. 检查 `proof.index == action.step` 且 `0 <= action.step < n`，恰好四层 sibling，Rust 规范编码成功；拒绝 padding 叶。`[zk-v2-host/src/lib.rs:297-300,314-338]`
5. 以 V2 域分离规则派生 `step_nullifier`，**以下字节规则是唯一允许的编码**；Python 与 Rust 必须逐字节一致，不允许自行选择其他分隔符、整数宽度、端序或文本表示：

   - `protocol`：必须严格等于 ASCII 字符串 `data-query-v2-poseidon`。
   - `plan_nonce`：必须是 32 字节随机值；Grant JSON 中以恰好 64 个小写十六进制字符表示，解析时解码为原始 32 bytes；大写、空白、长度错误或非法 hex 一律拒绝。参与哈希的是解码后的 32 字节原始值，不是 64 字符 hex 文本。
   - `action.step`：无符号 32-bit 整数，取值范围 `0..=15`，采用 4 字节 big-endian 编码；参与哈希的不是十进制字符串。

   ```
   preimage =
       b"nullifier:data-query-v2-poseidon:v1\0"
     || b"data-query-v2-poseidon\0"
     || plan_nonce_raw[32]
     || uint32_be(action.step)

   step_nullifier = lowercase_hex(SHA-256(preimage))
   ```

   顺序固定为 prefix → protocol → nonce → step；preimage 首段以 `\0` 结束（不是冒号），`nullifier:data-query-v2-poseidon:v1:` 仅作域标签。输出是 SHA-256 的 32-byte digest，以 64 个小写 hex 字符表示。本规范使用 SHA-256，不新增 Poseidon nullifier 算法。该域与 V1 的 `nullifier:v1:` 分离，V1 `step_nullifier` 算法及前缀完全不变。`[plan_batch.py:332-333；data_access.py:479-490]` 按 step 顺序原子消费；当前进程内存锁不等于跨进程/多网关持久原子，真实部署前仍需持久化事务状态。`[F20]`
6. 调用工具并验证签名回执；V2 Receipt 必须以 `action_leaf_poseidon`（与该 Inclusion Proof 对应的 Poseidon action leaf）作为执行动作的权威密码学绑定；若保留 SHA-256 辅助日志摘要，另用 `action_json_digest_sha256`，且不得用于 V2 Merkle inclusion 验证。回执另绑定 `grant_digest_sha256`、`plan_root_poseidon`、step、`step_nullifier`、result digest、`context_digest_sha256`、`tool_schema_digest_sha256`。`[data_access.py:403-418,499-528]` V2 不得使用语义不明的 `action_hash`。

### F.3 `[REC]` 完整 proof 是否每步重复验证

不重复。缓存只缓存**已成功完成的完整 Halo2 proof 验证结果**，不缓存 nullifier 消费结果，也不替代 Grant 的 freshness 检查。确认计划授权有效后缓存该结果；每步仍做签名/身份/上下文/schema/有效期重检 + 缓存记录一致性校验 + Poseidon inclusion proof + nullifier 原子消费。理由：完整 proof 证明的是整份计划的算术关系，重复验证不增加语义保证，只增加成本。`[REC]`

缓存键/记录至少绑定 F.1 第 9 步的全部字段：`grant_digest_sha256`、`proof_bundle_digest_sha256`、`vk_id`、`public_instances_digest_sha256`、`context_digest_sha256`、`tool_schema_digest_sha256`、`expires_at`。缓存命中**不能绕过**：当前时间有效期检查、当前 principal/tenant/session 匹配、每步 Inclusion Proof、nullifier 消费。`now >= expires_at` 时失效。`[REC，基于 data_access.py:470-473 的时间检查与 F20 的 nullifier 边界]` VK pin 发生变更时旧缓存记录失效或按旧 VK 版本隔离，不得跨 pin 复用。`[REC]`

---

## G. 信任边界

- `[FACT]` `DataAccessAuthority` 仍是可信私有 allowlist 检查者；它按策略检查资源、字段、过滤字段、过滤值及行数，并用 Ed25519 签名。`[data_access.py:245-331]`
- `[FACT]` `C_quota` 只承诺 `(B,L,r)`；不证明 B/L 与 SHA-256 `policy_commitment_sha256` 等价，也不证明私有 allowlist。`[docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:58-75；data_access.py:239-242]` `[REC]` 本 MVP 由 Authority 在同一受信任签发边界内从真实策略取 B/L，并确保 proof 与签名 Grant 的 `public_instances.values[0]` 使用同一 `C_quota`；Gateway 不重算该隐藏承诺，也不检查其与 `policy_commitment_sha256` 的关系，只校验签名覆盖的实例 0 的格式（`index = 0`、`name = "C_quota"`、field-hex）并确保 verifier 使用同一已签名值。
- `[FACT]` 公开工具 schema 兼容性是结构检查，不是私有 allowlist 的 ZK 证明。`[docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:313-323]`
- `[REC]` 证明生成方知道其使用的私有 witness `(B,L,r,words,active,limbs)`；verifier 只看到约束成立，不获得 witness 真实性之外的保证。`[zk-v2-host/src/plan_quota_circuit.rs:50-62]`
- `[REC]` Gateway 必须执行 proof 验证；只检查 Ed25519 签名不构成 ZK 验证。Gateway 不持有完整计划，也不重建 `R_plan`；它依赖 Authority 已在签发前检查过完整计划并保证 `R_plan` 对应之。
- `[FACT]` 工具回执是工具服务自己的签名声明，不证明外部数据库查询真实、完整、最新。`[data_access.py:362-418,499-528]`
- `[FACT]` nullifier 当前是单进程内存集合；多网关原子消费与持久化仍是独立工程问题。`[data_access.py:435-437,481-490；plan_batch.py:444-445]` `[REC]` V2 使用与 V1 域分离的 nullifier 派生规则（preimage 首段 `b"nullifier:data-query-v2-poseidon:v1\0"`，唯一字节规则见 F.2 第 5 步），V1 的 `nullifier:v1:` 前缀与算法不变。
- `[FACT]` 本方案不证明不存在数据出口绕行、不证明查询组合不泄漏敏感信息、不提供差分隐私。`[docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md:313-338]`
- `[FACT]` 电路不证明 Ed25519 签名有效性、nonce/expiry、数据库执行结果或真实 Halo2 proof 已生成。`[zk-v2-host/README_STEP3_2B.md:71-83,121-136]`

---

## H. 风险与验收矩阵

| # | 负向场景 | 预期拒绝点 | 必须绑定的证据 |
| --- | --- | --- | --- |
| 1 | SHA-256 Root 冒充 Poseidon Root | V2 字段 `plan_root_poseidon` 必须为 field-hex，且 `plan_root_poseidon == instances[1]`；Gateway 不重建根 | `PoseidonPlanTree::root()` `[lib.rs:254-295]` |
| 2 | 动作编码不可表达 | 签发前 Rust `encode_action` / `from_plan` 返回 `Err` | `lib.rs:102-237`；`plan_quota_circuit.rs:101-121` |
| 3 | proof 与签名信封 public inputs 不一致 | Gateway 步骤 F.1.4-F.1.5，调用 verifier 前拒绝 | Grant `public_instances` + `raw_public_inputs` `[plan_quota_circuit.rs:149-203]` |
| 4 | context digest 改变 | 从已验证 claims 重算 `plan_context_hash`，与 instances 3/4 比较 | `plan_batch.py:319-325` |
| 5 | schema digest 改变 | 与 pin 的 `DATA_QUERY_SCHEMA_HASH_V2` 及 instances 5/6 比较；O2 已固定，O1 不允许 | `data_access.py:49-65`；规格 §4.1 `147-148`；`lib.rs:89-100` |
| 6 | 错误 proof | `verify_proof`（`SingleVerifier`）返回 `Err`；仅 `Ok(())` 接受 | `verifier.rs:67-79,49-63` |
| 7 | 错误 VK | pinned `vk_id`（部署标识）不一致，拒绝；不依赖不存在的 VK 指纹 API | `keygen.rs:189-198`；`Params::write/read` `[commitment.rs:169,184]` |
| 8 | action 修改 / 重排 / 无效 step | Rust 重新编码 + `verify_inclusion` 失败 | `lib.rs:297-338` |
| 9 | proof 正确但 grant 签名无效 | `Ed25519 verify` 失败，先于 proof 验证 | `data_access.py:454-456` |
| 10 | nonce replay / V1-V2 串域重放 | V2 `step_nullifier` 按 F.2 第 5 步唯一字节规则派生（preimage 首段 `b"nullifier:data-query-v2-poseidon:v1\0"`），与 V1 `nullifier:v1:` 域分离；已消费则拒绝；域分离不等于跨网关原子消费 | `[REC F.2]`；`plan_batch.py:332-333；data_access.py:481-490` |
| 11 | expired grant | `now >= expires_at` 拒绝 | `data_access.py:470-473` |
| 12 | Gateway 只信任签名、不验证 proof | 代码路径要求 validated-plan cache 只能由 F.1 的 `verify_proof` 成功后写入 | `[REC F.1/F.2]` |
| 13 | proof 被重复验证或未绑定缓存记录 | 缓存记录绑定 grant/proof_bundle/vk/instances/context/schema/expiry；不匹配或 VK pin 变更则失效；缓存不绕过 freshness 与逐 step nullifier | `[REC F.3]` |
| 14 | `n` 与 `action_count` 不一致 | 签发前和 Gateway 均比较三者 | `plan_quota_circuit.rs:101-146；data_access.py:474-475` |
| 15 | padding 叶被当作有效动作 | `proof.index >= action_count` 或 `step != index` 拒绝 | `lib.rs:297-300,323-325` |
| 16 | V2 Receipt 误用 SHA-256 辅助摘要做 Merkle 验证 | 权威字段为 `action_leaf_poseidon`；`action_json_digest_sha256` 仅供日志 | `[REC G/F.2]`；`data_access.py` `action_digest()` |
| 17 | 同一 proof 跨不同 nonce/Grant 复用并被误当作 nonce 绑定 | `proof_bundle_digest_sha256` 只绑定 proof 字节；freshness 由 nonce/expiry/nullifier 控制，不声称 proof 绑定 nonce | `[REC D.2]` |

---

## 9. 未决问题

1. `[OPEN C.2]` `DATA_QUERY_TOOL_SCHEMA_V2` 对象的最终字段内容（版本=2、filters ≤ 2、selected_fields 1..3、只读、固定资源字段集合）；机制已按规格 §4.1 固定为 O2，需人类确认对象内容。
2. `[OPEN D.2]` `proof_bundle_digest_sha256` 的精确 payload 规范化与 hex 规则；其安全语义已限定为 proof 绑定，**不是 nonce anti-replay**。若未来要求 proof 绑定 nonce，需改公共输入/证明关系。
3. `[OPEN E.3]` `vk_id` 运维 pin 的具体取值与绑定清单；Halo2 0.4 无 VK serde、无稳定指纹 API，`Params` 有 write/read 可用；不声称存在密码学指纹。
4. `[OPEN E.2/E.6]` Rust worker 的帧协议、本地 ACL、进程监管、崩溃恢复，以及系统熵源初始化失败的具体处理策略；推荐 Windows named pipe 或长度前缀 stdio。
5. `[OPEN F.2/F.3]` 持久化 nullifier 存储与多网关原子性不属于本轮，但进入真实部署前必须解决；缓存只缓存 proof 验证结果，不绕过 freshness 与逐 step nullifier。
6. `[OPEN C/E.4]` 是否把 `C_quota` 与 SHA-256 `policy_commitment_sha256` 做额外绑定；当前电路和规格均无此关系，不能宣称已有。若未来 Prover 独立于 Authority，还需额外的 B/L 策略绑定机制。
7. `[OPEN]` 每份计划只生成一个 proof；是否支持批量证明或逐次证明属于后续 Step 3.3 对照实验，不在本契约中承诺。

---

## 10. 交付状态

- 本文件是设计文档；未修改 Python、Rust、测试、Cargo 依赖、Step 3.2B 规格或实现。
- 未生成真实 proof；未启动 Step 3.2C 实现；未启动性能实验。
- 不作新颖性声明；不把设计完成描述成代码已实现。
- Step 3.2B 继续按已封存状态处理；其 README 中关于“独立复现待完成”的历史文字不在本轮修改范围内，独立复现已由本轮任务验收记录另行确认。
