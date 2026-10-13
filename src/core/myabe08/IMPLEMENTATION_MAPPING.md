# Current status — Phase 3A

当前 **PHASE_3A_ALGEBRA_CORE_ONLY**。下方 Phase 1 内容保留为当时的审计快照；其中“encoding/backend 未实现”的描述不再代表当前基础层状态。最新 exact byte contract、FusePos、确定性重构及 algebra-only boundary 见 [IMPLEMENTATION_PROFILE_V1.md](IMPLEMENTATION_PROFILE_V1.md)。算法规范及历史源码未修改。

Phase 2A 按用户授权完成 repository profile closure：typed TLV tags/大端/显式 composite、固定行载荷、SHA256、contextual HMAC、分域 row BLAKE2b 与 AF nonce、GCM-SIV/HKDF DEM、py_ecc 8.0.0 BLS12-381 adapter、严格 group/profile/SysID 验证和固定 TEST vectors。只更新基础层，不接通八算法。

原 G0 的 encoding/H0/KDF/nonce/FusePos closure、G1 的 backend 基础检查和 G3 的 AF correctness 已落实；AuthorizedSubset 的纯 LSSS 重构也通过 Phase 2B gate。G2 的 Ed25519 credential/capability 协议未实现，G4 的代数 core 已验证、完整协议仍未接通，其余 G5–G9 仍未完成。

基础 adapter 真实可用与完整方案 profile 可用分开：`backend_status=FOUNDATION_V1_IMPLEMENTED`，scheme `implementation_status=NOT_IMPLEMENTED`，BENCHMARK_READY=NO。本机 AESGCMSIV 对空明文有明确限制，adapter fail closed，不替换为 GCM，详见新 profile 文档。

Phase 1 scaffold 中旧 encoding/AF/LSSS placeholder 检查已迁移为实际正负例；八主算法、TEE、完整 PolicyEncode 的未实现边界仍受测试。未删除旧目录测试、未改历史计数约束。

Phase 2A 记录：MYABE08 定向 129 passed；全库 267 passed。Phase 2B：MYABE08 定向 162 passed；全库 300 passed；均 0 failed / 0 skipped。Phase 3A 增加真实 BLS12-381 algebra core，八个 public protocol methods 仍未实现。myabe08 外修改 0；详见 V1 文档。

---

# Historical Phase 1 mapping (snapshot)

# MYABE-08 — Phase 1 Implementation Mapping + Clean Scaffold

**状态：PHASE_1_SCAFFOLD_ONLY；BENCHMARK_READY=NO。**

本目录只冻结 Python 接口、结构化数据类型、信任域和待实现边界。八个主算法、PolicyEncode、AuthorizedSubset、AF、TEE 协议、canonical encoding 和 backend 均未实现，调用明确抛出 `NotImplementedError` 的子类。没有 MYABE-08 correctness、security 或性能完成声明。

## 1. 规范来源、快照与证据冲突

- 唯一算法规范：[ABE-Scheme-08.md](../../../../../Doc/ABE-Scheme-08.md)。方案全名：**My-ABE: Occurrence-aware Type-III ABE with TEE-assisted Contextual Dual-side Anonymity and Privacy-Preserving Access-time Revocation**。
- 本次读取日期：2026-09-22；规范文件 SHA-256：`d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`。
- 被审计仓库 HEAD：`db551156e3c4f76a8d6de3d84d178549c3c25b59`；起始工作区干净。
- 辅助导航：[实际存在的目录与源码梳理报告](../../../../../Doc/My-ABE_Scheme_目录与源码梳理报告.md)。用户所述“目录与源代码梳理报告.md”按此实际文件读取；报告不是算法规范。
- 参考旧代码、现有测试和实验设计；绝不为复用而改写 08 公式。未修改规范原文，未复制不存在的历史 08 证据。

### 1.1 必须保留的 source/evidence gap

规范开头和末尾仍有“待重新验证”陈述，但 §8.1、§8.3、§9.1 写有 BLS12-381/SGX/23 项测试等已执行状态。它还指向 `Code/myabe08/`、根级 `experiments/RAW_SCHEMA.md`、`experiments/environment.{json,md}`、`BLOCKER.md`、`DESIGN_ISSUE.md` 等外部证据。

本次仓库没有 `Code/myabe08/` 或根级 `experiments/`，也没有既有 `src/core/myabe08/`。现存的是 `src/experiments/` 下的历史五套实验。**规范的算法/协议条款仍为唯一依据；无法在本仓库定位的实现状态声明，不作为当前分支已完成的证据。** 本阶段按用户要求建立软件模拟接口，不探测或部署 SGX，不继承文档中的硬件型号、性能和证明结论。

更具体地，§8.2 将 canonical TLV 和 FusePos 的精确字节规则委托给缺失模块及 RAW_SCHEMA。这会阻塞逐字节兼容实现。已明确的固定宽度、PRF/KDF/AEAD 名称、段长度规则均已记录；未知的 tag 编号、字段端序细节、hash-to-curve suite/DST、seed mixing 和 domain 字节规则不得从 05.3 猜出。

因此 `encoding.py` 仅有接口。本阶段不声称编码同值性、无歧义解析或规范测试向量已验证；Phase 2 必须恢复所引用规则或在规范来源中明确补充，再实现，不能由代码自行成为新的算法规范。

## 2. Normative algorithms and entities

八个主算法严格为：

1. `Setup → setup`
2. `KeyGen → keygen`
3. `Encrypt → encrypt`
4. `Rev → rev`
5. `RevStateUpt → rev_state_upt`
6. `TEEAuthorize → tee_authorize`
7. `Transform → transform`
8. `FinalDec → final_dec`

内部过程：`PolicyEncode → lsss.policy_encode`、`AF.Build → ProtectedPayloadAF.build`、`AF.Query → ProtectedPayloadAF.query`、`AuthorizedSubset → lsss.authorized_subset`。

`PrivacyKeyUpt`、`RevKeyUpt`、`KUNodes`、Cover、周期树更新不属于 08 API。它们只能出现在明确标记的历史对照说明中。

| 实体 | 长期或本地状态 | 边界 |
| --- | --- | --- |
| Authority/KGC | α、a、credential signing key，注册表、DO namespace、内部撤销 handle 和 pending/committed 序列 | 管理授权后排队 Rev；收到可信 Ack 才确认生效；临时 z 须清理 |
| DO | 消息、明文策略、namespace 发布钥、PolicyContextID/Version | 经私有策略会话请求令牌；独立生成 s 和完整 r_j；发布认证 |
| DU | credential、认证私钥、RK=z⁻¹、user-carried sealed blob、ReqState | possession proof 绑定认证公钥；RK 不发给 enclave；最终本地解密 |
| CSP host | CT、公开 PP、临时 Auth、随机 nonce 消费记录 | AF/LSSS/TA；无 UID、长期 K0、μ、稳定撤销 handle、credential/blob digest |
| Anonymous Authorization Enclave | Ktok、Krev、sk_cap、sealing secret、exact RevSet、版本/请求管理状态；临时解封 μ/K0 | 验证、当前状态协调、全 certified 属性 tokenization、随机化和 T0；无 RK、MSK、α/a、消息 |

`Credential`、`SealedUserBlob` 和 `UserBaseState` 不是 CSP wire 类型。Opaque blob 本身会泄露 equality，所以不能公开作为文件名、缓存键或日志标签。Dataclass 的 `repr=False` 只降低误打印风险，**不提供保密、内存隔离或可靠清零**；也不得对包含私有状态的对象直接 `asdict()` 后发送或写日志。

## 3. Module architecture and API freeze

```text
MyABE08 orchestration (eight algorithm ports, all unavailable)
  ├─ profile / crypto       separate pairing and TEE profiles, strict backend ports
  ├─ types / encoding      trust-domain DTOs; canonical wire is unresolved
  ├─ credential            certified attributes, possession, sealing/channel ports
  ├─ state                 exact-state snapshots and linearizable transaction ports
  ├─ tee                   independent EmulatedAnonymousAuthorizationEnclave
  ├─ lsss                  policy/context binding and deterministic feasible subset
  ├─ af                    protected-payload segmented XOR (no PStore/locator)
  └─ metrics               explicit unobserved counters; no fabricated measurements
```

`tee.py` 不继承 `MyABE08`。新包只依赖标准库及本包相对导入，不导入 Charm、py_ecc、cryptography 或历史方案；库是否存在不影响 scaffold 的可导入性，也不自动启用任何算法。

### 3.1 文件职责

| 文件 | 责任 | 本阶段已实现 / 未实现 |
| --- | --- | --- |
| `__init__.py` | 公共类、profile 名称、scaffold/benchmark 状态 | 可导入；状态明确为未完成 |
| `errors.py` | contract/profile、未实现、协议拒绝、同步/重放/AF 失败异常 | 异常与统一未实现抛出函数 |
| `profile.py` | 两个 pairing 名称、独立 emulated TEE、规范 primitive 标识 | 冻结逻辑描述、未知名称拒绝；backend 不可执行 |
| `types.py` | 明确角色/群方向/状态/输入输出 dataclass | 结构构造和有限 shape 校验；非密码验证 |
| `encoding.py` | canonical Encode/Decode 与固定 AF 行载荷接口 | 全部未实现，不沿用旧 wire |
| `crypto.py` | PairingBackend、AuthEnc、ContextualPRF、KDF ports | Protocol only；无具体 backend 或密码操作 |
| `credential.py` | credential verifier、PoP、attested channel、sealing 和 DO session | Protocol only；无允许全部通过的假 verifier |
| `state.py` | fresh current-head 事务、Ack commit、可信时钟、原子请求状态 | 仅契约；无本地异步替代 freshness |
| `lsss.py` | PolicyEncode、AuthorizedSubset | 明确抛未实现异常 |
| `af.py` | 独立 build/query | 明确抛异常，query 也不伪造 miss |
| `tee.py` | provision、DO tokenization、RevStateUpt、authorize | 软件模拟接口，实际软件协议也未实现 |
| `scheme.py` | 八个主算法与结构化返回类型 | 明确抛异常；setup 拒绝未验证 backend |
| `metrics.py` | TEE/AF/CSP 和实际 operation counter schema | `None` 表示未观测，NOT_EXECUTED；无计时 |
| `tests/` | import、profile、shape、placeholder、架构边界 | scaffold-level regression，不是 crypto correctness |

### 3.2 Scheme contract

以下为类型摘要，完整 keyword-only 参数以 `scheme.py` 为准。状态显式传入/返回，没有隐藏的大 dict 状态。

| 方法 | 主要输入与辅助依赖 | 返回结构 |
| --- | --- | --- |
| `setup` | security_parameter、c_max、绑定 measurement 的 provisioning channel；profile 在构造时选择 | `SetupResult(PP, MSK, KGCState, TEEState)` |
| `keygen` | PP、MSK、KGCState、TEEState、UID、认证属性、公钥、validity、provisioning channel | `KeyGenerationResult(Credential, RecoveryKey, SealedUserBlob, KGCState, TEEState)` |
| `encrypt` | PP、bytes 消息、PolicyInput、PolicyContext、DataID、DOSession | `Ciphertext` |
| `rev` | KGCState、UID、revoke/activate、管理授权 | `RevocationResult(protected update, pending KGCState)` |
| `rev_state_upt` | PP、TEEState、protected update、认证机密通道 | `RevocationStateResult(TEEState, Ack)` |
| `tee_authorize` | PP、TEEState、Cred、Blob、TEERequest、channel、PoP、coordinator、clock | `AuthorizationResult(Auth, internal TEEState)` |
| `transform` | PP、CT、Auth、CSPState、atomic request store、clock | `TransformResult(PartialCiphertext, CSPState)` |
| `final_dec` | PP、PartialCiphertext、RK、DU RequestState、client request store、clock | plaintext bytes，未来协议拒绝抛异常 |

返回聚合类型是**进程内编排契约，不是一个通用网络 envelope**。例如 `KeyGenerationResult.tee_state` 不送 DU，`.recovery_key` 不送 TEE；`AuthorizationResult` 只把 `.authorization` 发给 CSP。将整个结果对象发送给任何单个角色均违反契约。

未来错误约定：主算法的规范 ⊥ 映射到 `ProtocolRejectedError`；AF 认证失败映射到 `AFQueryResult(hit=False, rows=())`；构建耗尽为 `AFBuildError`。**Phase 1 的 unavailable 不等于 ⊥/miss**，必须始终抛出 `AlgorithmNotImplementedError`，避免吞掉缺失实现。

当前 API 使用不可变 tuple/FrozenSet 和 frozen dataclass 表达快照，属性为 `Attribute(namespace,name,value)`，版本为整数、validity/expiry 为 UTC 整数秒。它们是显式的 Python scaffold 约定，不声称已经得到规范 wire 兼容验证。字符串规范化、大小上限、field tags/端序和实际序列化仍由规范补全决定。群元素 wrapper 存的是待验证编码，不是“已验证点”；构造 DTO 不能跳过后续 canonical/subgroup/SysID/profile 检查。

### 3.3 关键数据对象与信息流

| 类型 | 应包含的内容 | 明确排除 |
| --- | --- | --- |
| `PublicParameters` | G1/G2/g1ᵃ/g2ᵃ/gTᵅ、KGC/cap 公钥、AF/crypto/profile metadata | μ、z、长期用户状态 |
| `MasterSecretKey` | α、a、sk_KGC | Ktok/Krev/cap key 不混作 MSK |
| `KGCState` | 注册/namespace、内部 handle、pending/committed 版本和摘要 | 不发布为 CSP 状态 |
| `TEEState` | 独立秘密、exact handle set、credential versions/digests、请求签发与 Ack 记录 | α/a、MSK、RK、z、plaintext M |
| `UserBaseState` | SysID/UID/μ/K0、credential digest/version/schema/profile | RK；只经内部 unseal 得到 |
| `RecoveryKey` | 群/profile/SysID binding 与 z⁻¹ | μ、K0 |
| `PolicyEncoding` | DO 临时矩阵、完整行序 token/Q/rank | 不存入 CT/AF |
| `ProtectedAnonymousFilter` | fixed slots、metadata | PStore、token list、token→row/locator 映射 |
| `CiphertextHeader` | Hdr_AF/context/DataID、唯一 C、c_max、全部 core/AF digest、KEMDEMInfo | rev_version、c_star、UID |
| `Ciphertext` | C_i、D_j、A、AF、DEM、header、publication/certificate | 明文 rho、C 的重复副本、用户撤销组件 |
| `TEERequest` | header/pub/cert/DEM digest、context、nonce、hint、expiry | Cred/Blob/UID 不是 host 请求字段，私有参数分开 |
| `AuthorizationBundle` | 排序去重 token/Ktau、K1q、T0q | K0q、μq、δq、长期标识 |
| `SignedCapability` | SysID、header/context/bundle digest、rev_version、nonce、expiry、signature | UID/handle、credential/blob digest |
| `PartialCiphertext` | T0q、TA、header、DEM、publication、完整 Auth | 不持有长期 TK |

## 4. Repository reuse audit matrix

“As-is”指不改变该纯工具函数语义即可提取的候选，不表示本阶段已复制或引入依赖。**本阶段实际 runtime reuse 为 0，历史导入为 0。** “Adapt”表示概念或工程结构可参考；08 实现仍按规范重写边界。所有历史目录保持原样。

| Component | Existing source | Reusable as-is? | Reusable with adaptation? | Must rewrite? | Reason | MYABE-08 target module | Security/measurement caveat |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Occurrence ABE core（algebra reference） | `src/core/fxabe_05_3_exp/scheme.py` Encrypt/Transform | No | Yes，局部代数推导 | Yes，完整算法 | 旧 K0 含路径 β，旧撤销 2 pairings，长期 tokens；新 K0/公开 g2ᵃ/μq/T0 分工不同 | `scheme.py`、`tee.py` | 不继承 `3+t_I` 或旧安全陈述 |
| LSSS（utility/algebra） | `fxabe_05_3_exp/lsss.py` | No | Yes，消元结构 | Yes，backend-neutral 验证边界 | 旧实现依赖 Charm ZR/MSP；需确定性行序、去零和重构等式检查 | `lsss.py` | Charm 的 int 零测试不能推广到其他 scalar backend |
| Protected AF graph（utility reference） | `fxabe_05_3_exp/fx.py` | No | Yes，peeling/reverse XOR 思路 | Yes，payload/position/wire | 旧是 20-byte j+check 加外部 AES-GCM PStore；08 槽直接存完整固定宽度 GCM-SIV 载荷 | `af.py` | 不能只改类名；旧 three-lane hash 不能充当缺失 single-mixing 规则 |
| Old encoding/KDF（utility reference） | `fxabe_05_3_exp/encoding.py`、`crypto.py` | No | Yes，typed length-frame 设计经验 | Yes | 旧 epoch/domain、tuple/list 合并、AES-GCM、不同 posting 长度和 KDF | `encoding.py`、`crypto.py` | 不继承旧 wire、不能 GCM 替代 GCM-SIV |
| Dual-epoch scheme（NOT reusable as protocol） | `src/core/fxabe_rev/scheme.py` | No | 只参考错误路径/计量 | Yes | tree path、KU、C_rev 和 `2+2r` 不属于 08 | `scheme.py`、`state.py` | 不把旧成功/撤销测试改名为 08 测试 |
| Tree revocation（NOT reusable） | `fxabe_rev/revocation.py` | No | No，仅历史比较 | Yes | exact RevSet + online current-state 取代 KUNodes/Cover/epoch KU | `state.py`、`tee.py` | 不产生 public KU，不更新 CT/RK/AF |
| Composed index（utility reference） | `fxabe_rev/filters/{base,fxabf}.py` | No | Yes，有限构建与分项统计思路 | Yes | base 的 pstore ids 会保留映射；08 不需要 locator/PStore | `af.py` | 泄露边界与历史 index_v2 组合索引不同 |
| Static retrieval（utility/test pattern） | `fxabe_rev/retrievals/{base,xor_core,fxabf_retrieval}.py` | No | Yes，定宽槽/失败/无 retained map 检查 | Yes | 历史 `j||check` 不等于 AuthEnc(Mtau)；position/wire 不同 | `af.py`、tests | 不继承短 check 误接受结论 |
| FXDACP core（historical only） | `src/core/fxdacp/scheme.py` | No | 仅分阶段工程参考 | Yes | `1+2r`、无 TEE、旧 MSK 加密接口和 OPRF | `scheme.py` | 正确性不能迁移到新 g2ᵃ/μq 公式 |
| Historical OPRF（NOT main token） | `fxdacp/oprf.py`、`fxabe_rev/oprf.py` | No | 仅未来 Exp4 baseline | Yes | 08 为 enclave HMAC contextual PRF，非属性盲 OPRF | `crypto.py`、`tee.py` | baseline 单列收费，不计入主算法 |
| Canonical attribute utilities | `fxdacp/encoding.py` | No | Yes，类型/长度防拼接模式 | Yes | 08 context/domain 与待明确 attribute normalization 不同 | `encoding.py` | 不把 str coercion 当成属性规范化 |
| Prototype OPRF/ABF/certificate（NOT reusable） | `src/core/dacp/components/` | No | 只参考 adapter 分层 | Yes | prototype hash signature、GT envelope、ABF 不能满足 08 | `credential.py`、`af.py`、`crypto.py` | 未实现 verifier 不能默认返回 True |
| Real Ed25519 adapter（utility pattern） | `dacp/components/signature.py` | No，协议层不直接复用 | Yes，底层 API 调用方式 | Yes，08 消息域/独立钥/上下文 | 08 credential、publication、cap 均有新 signed transcript | `credential.py`、`crypto.py` | 相同 primitive 不代表兼容 signed bytes |
| AES envelope（NOT reusable instance） | `dacp/components/symmetric.py` | No | 只参考接口/错误处理 | Yes | 旧 AES-GCM 与 08 deterministic AF nonce 的要求不同 | `crypto.py` | nonce 重用风险由 GCM-SIV profile 处理，不能替换算法 |
| Local protocol/roles（engineering reference） | `dacp/protocol/{roles,transport,wire}.py` | No | Yes，消息分层和测量思路 | Yes | host 日志/长期 TK 流程不符合 08 私有边界；无 attestation/linearization | `credential.py`、`tee.py`、`state.py` | opaque 数据不自动隐藏 equality；普通 replay set 非并发事务 |
| FABEO official baseline（baseline code） | `src/core/fabeo22cp/__init__.py` | Yes，保持其历史实现不变 | Yes，未来共同 backend adapter | 不重写历史文件 | baseline 应保持可追溯；08 g2ᵃ/T0 等不能塞入 FABEO | 未来独立实验 adapter，非当前主包 | 原始 Charm/MNT224 与 BLS12-381 不可直接计时对比 |
| Index comparison（benchmark infrastructure/test pattern） | `src/experiments/index_v2/{benchmarks,analysis,tests}` | No，schema 不同 | Yes，工作负载身份/失败保留/公平性审计 | Yes，08 schema/validators | 旧 validator 断言 `2+2r` 且计 locator/PStore | 未来 Exp3/4/5 | composed vs retrieval 区分须保留，历史样本不是 08 样本 |
| 05.3 operations（benchmark infrastructure/test pattern） | `src/experiments/perf_05_3/{scripts,workloads,tests}` | No，整体不能复用 | Yes，真实计数、warmup、分项、失败保留 | Yes，08 counters/gates | 旧 row 默认 MNT224/成功，旧 `3+t_I` 和 revocation 数据不适用 | `metrics.py`；未来 Exp1/2/3/5 | 不预填成功，不以理论计数填实际计数 |
| End-to-end/statistics（benchmark infrastructure） | `src/experiments/global_exp/src/{adapters,statistics,common}.py` | `percentile` 等纯工具可原样提取 | Yes，统计和环境记录 | Yes，workflow/timing schema | 原 adapters 绑定旧方案；summary 还依赖本套 common | 未来实验公共层 | 保留分位数/尾部与样本单位；计量包括在线协调和 Auth 转发 |
| Revocation suite（test pattern only） | `src/experiments/rev_exp/src/{revocation,experiments,planning}.py` 与 tests | No | 仅采样/负例/plan 验证模式 | Yes | 撤销分布/树 Cover/KU/dual-vs-coupled 不是 exact RevSet 当前状态协议 | 未来 Exp6/7 | 不能复用 tree cost 或将历史重复样本改作 08 数据 |

### 4.1 可复用层次的结论

- **Algebra reuse**：05.3 的 occurrence 抵消推导及“先重构后聚合”结构；需要重新审计每一密钥/公开参数/状态公式。
- **Utility reuse**：有限域消元、严格行号解析、剥离队列、反向 XOR、规范字节大小与纯统计函数的设计经验。除纯统计小函数外，密码与 wire 相关代码均需 adaptation 或重写。
- **Benchmark infrastructure reuse**：工作负载指纹、环境快照、独立重复、raw/summary 分层、保留失败/异常值；本阶段不创建运行器或结果。
- **Test pattern reuse**：重复属性、后续 occurrence、超界、篡改、失败关闭、计数 hook、批次身份一致性；测试结论不能继承。
- **NOT reusable**：树撤销主协议、旧 token 算法作为主 profile、长期 CSP TK、旧 `C_rev`/KU、PStore/locator 结构、旧 wire/domain、旧 benchmark 数值与旧安全声明。

## 5. Formula and invariant migration

### 5.1 Pairing migration table

| Historical implementation | Historical invariant | MYABE-08 status |
| --- | --- | --- |
| FXDACP | `1+2r` | historical only |
| FXABERev | `2+2r` | historical only |
| FXABE05.3 | `3+t_I` | algebra/reference only |
| MYABE-08 | `2+t_I` | normative target, not yet validated |

08 成功且非空重构的分工必须是 **TEE=1、CSP=1+t_I、whole system=2+t_I、FinalDec=0**。只统计 ABE pairing terms；Ed25519 不增加配对。Multi-pairing 优化不能减少记账中的数学 pairing terms。AF/LSSS 不满足的请求可能已经花掉 1 次 TEE pairing，失败成本必须另计。Phase 1 的测试未执行或验证这些公式。

### 5.2 新代数逐项映射

| 项 | MYABE-08 normative target | 历史差异 / 目标责任 |
| --- | --- | --- |
| PP/MSK | PP 新增 `g2^a`，MSK=`(α,a,sk_KGC)`；Ktok/Krev/sk_cap 独立 provision | 不继承 OPRF κ/树 secret；`types/crypto/scheme` |
| K0 / μ / z / RK | 独立非零 z、μ；K0=`g2^(zα+aμ)`；RK=`z^-1` | K0 不再是减 β 的路径分量；μ/K0 仅 TEE、RK 仅 DU |
| Token | `HMAC_Ktok(Encode("MYABE-TOK",SysID,ctx_priv,x))` | 无 OPRF/epoch/role/session/nonce 输入；`crypto/tee` |
| Context | `ctx_priv=Hctx(Encode("PRIV",SysID,PolicyContextID,PolicyVersion))` | policy version 不是撤销/key epoch；随机 context ID 至少 256-bit |
| Qτ | 正规 `H0(τ) ∈ G1` | 不能 `g1^Hash(τ)`；suite/DST 待补全 |
| c(i) / c_max | 完整策略中同 token 的 occurrence rank；超界拒绝；固定 c_max 个 D | 不能在 J/I 重编号；不发布 c_star |
| s / r_j | 每个新 CT fresh nonzero s 和全部 r_1…r_cmax | 禁止跨 CT 缓存随机量；未使用 slot 也发布 |
| C_i / D_j | `C_i=(g1^a)^λ_i · Qτ_i^(-r_c(i))`；`D_j=g2^r_j` | 共享 slot 的代数经验可参考，不能继承旧 security proof |
| C / E | `C=g1^s`；`E=(gT^α)^s`；C 只存在 header 一处 | 删除 C_rev、用户专属撤销分量 |
| δq / μq | fresh nonzero δq；μq=μ+δq，拒绝 μq=0 | 每请求，非旧隐私纪元更新 |
| K1q / Kτq | `g2^μq` / `Qτ^μq` | CSP 只拿临时包，不装长期 TK |
| K0q | `K0·(g2^a)^δq`，拒绝单位元；不输出 | TEE 不需 a/z/s；`tee` |
| T0q | `e(C,K0q)=gT^((zα+aμq)s)` | TEE 1 term；发布认证防任意 C oracle |
| J / φ | J=命中完整列表并集；`φ(i_j)=(τ,j)` | 冲突行拒绝，j 保留完整列表 rank |
| I / ω / k | 固定行序消元；验证 `Σω_i A_i=(1,0,…)`，删零系数；k=|I| | 可行解不保证最小 k/t_I |
| C_I / t_I | C_I=`{c(i):i∈I}`；t_I=|C_I|，1≤t_I≤min(k,c_max) | 不等于 |J| 或 matched token 数 |
| TA | `X=ΠC_i^ω_i`；`Y_j=Π Kτ_i,q^ω_i`；`TA=e(X,K1q)Π_j e(Y_j,D_j)=gT^(aμq s)` | CSP 1+t_I terms；`scheme.transform` |
| FinalDec | `E=(T0q/TA)^RK`；绑定同一 ctx_CT/KDF/AD | 1 GT exp，0 pair；先验证本地 ReqState/cap/publish/T0 |
| RevState | exact RevSet、monotonic version、在线 current-head、原子 Ack | 无 ciphertext/token/RK 更新；不生成 KU/Cover |

群方向固定：C_i/C/Qτ/Kτq 属于 G1；D_j/K0/K0q/K1q/g2ᵃ 属于 G2；T0/TA/E 属于 GT。Wrapper 只表达此类型约定；真正群方向与 subgroup validation 尚未实现。

## 6. Protected AF and ciphertext binding contract

主 profile 保留文档标识 `MYABE05.3-SEGMENTED-XOR-V1`，**名称相近不代表旧实现的 wire 兼容**。规范要求：

- `segmentLength=max(4,floor((3u+5)/2))`，`m_AF=3*segmentLength`。
- 三个连续、不相交 segment，从一个 seeded mixing 输出获得位置；精确 mixing 规则目前缺失，不能复制旧独立 lane hash 充数。
- `Mτ` 是 uint32 h 加 c_max 个 uint32 槽；0 是 bot；`0<h≤c_max`，`1≤i1<…<ih≤ell≤2^32-1`；其余槽全为 0。
- 固定明文宽度 `4(c_max+1)`，AuthEnc 为 AES-256-GCM-SIV、128-bit tag；槽宽 `4(c_max+1)+16`，无单独 nonce 存储。
- token-specific row key：domain-separated BLAKE2b-256(ctx_AF,τ)；96-bit nonce 从相同 context/token 经独立域派生。确切字节规则和 domain 标识待恢复。
- `ADτ=Encode("AF-row",ctx_AF,TokCtx(τ),meta_AF)`；`TokCtx=Hctx(Encode("AF-TOKEN",τ))`；meta 至少绑定 profile/ell/u/c_max/m/seed。
- 先找到成功 seed、冻结 metadata，再生成受 metadata 绑定的载荷和逆序赋值。最多 32 次 fresh-seed 尝试，失败抛出，不输出部分结构。
- Build 的 token maps/queue/stack 仅临时存在；最终 `ProtectedAnonymousFilter` 只有 slots 和 metadata。
- Query 验证格式/宽度、AuthEnc、严格解析、h/行范围/严格递增/bot；失败为 miss，而不是未经验证的 XOR 值。
- 没有 PStore、locator 或独立 `τ→row` 表。持有查询 token 的 CSP 可推导该行钥，因此不能单靠 AuthEnc 声称抵抗其伪造；必须验证已认证的完整 AF digest。

上下文依赖顺序必须保持：

```text
ctx_priv -> Hdr_AF -> ctx_AF -> successful seed/meta -> Filter_AF
         -> Hdr_CT (complete core AND entire AF digest)
         -> ctx_CT -> fresh DEM nonce/Csym -> DO publication signature
```

`meta_AF` 不包含数组 digest，避免自引用。C 唯一位于 header。Ciphertext 不包含 rev_version。AF 显式复用同一 context/输入时可能跨 CT 重用；不能宣称 row AD 单独隔离这些 CT，具体 CT 绑定依赖完整 header/发布签名。

DEM 是独立 AES-256-GCM-SIV：HKDF-SHA256(salt=ctx_CT, IKM=canonical E, info=`MYABE-DEM`, L=32)，fresh nonce，AD=`Encode("DEM",ctx_CT)`。Credential、publication、cap 均为独立 Ed25519 密钥/消息域。

## 7. TEE emulation boundary and state semantics

`EMULATED_TEE_PROFILE` 与 pairing profile 分开。当前仅有软件模拟**接口**，不是可运行的 enclave 协议。不声称 SGX isolation、hardware TEE security、side-channel resistance、真实 enclave transition/sealing latency 或 SGX throughput。

后续软件模拟必须明确实现并测试：

1. channel/challenge 绑定、credential 签名/validity/当前版本、认证公钥 possession proof；失去可信时间则拒绝。
2. unseal 后 SysID/schema/profile/UID/credential digest/version 一致；旧 credential/blob 拒绝；被窃 credential 无私钥也拒绝。
3. KGC 注册的 DO namespace/certificate、完整 header/publication digest、context、C 的 subgroup/非单位元及尺寸检查。
4. 每请求 fresh nonce 的在线 current-head **事务许可**；缺更新、版本跳跃、回滚、冻结或不可达拒绝；`version_hint` 不作可信来源。
5. exact RevSet lookup；已撤销者在 token/TK/T0 输出之前拒绝。仅完整 credential S_id 参与 tokenization，DU 无自选属性 oracle。
6. 独立 CSPRNG 采样 δq；拒绝 μq=0、K0q=1；K0q/μq/δq 不出 enclave。
7. 唯一 TEE pairing 后签发绑定 header/context/version/nonce/expiry/Bq 的 cap；TEE nonce 原子签发、CSP nonce 原子消费、DU 本地响应约束。
8. 所有错误 fail closed，不以通道 stub、布尔 verified 标志、普通文件 seal、异步推送或本地版本缓存替代可信服务。

### 7.1 撤销事务状态机

`Rev` 校验管理授权和注册目标，分配下一个版本并生成机密认证 Δ，状态为 pending。`RevStateUpt` 检查 SysID、来源、前态摘要和 next version，exact insert/delete，原子持久化并 Ack。重复相同已提交消息可返回已有认证 Ack，不再修改集合；旧/缺序/损坏更新拒绝或受认证同步。`state.commit_ack` 表达 KGC 的 pending→committed 边界，目前未实现。

`CurrentStateCoordinator.authorization_transaction()` 必须把 fresh current-head、状态同步与 Auth 发布纳入同一线性化许可。许可期间不能先确认冲突 revoke 生效；在签发前版本变化则重启/拒绝。普通 lock/monotonic integer 只防局部竞争，不能证明 host 没冻结旧状态。多副本共享序列、credential versions、请求状态是尚未实现的工程义务。

已撤销身份覆盖其全部 credential 版本；renew 必须更新 digest/version，使旧 blob 失效；activate 是显式管理操作，不承诺旧属性版本自动恢复。撤销不更新 CT/RK/AF/context tokens；撤销前已经得到足够 Auth 的用户仍可协议外解密，不能声称材料销毁。

### 7.2 必须披露的隐私/失陷边界

- 同 context equality、A/形状/命中列表、J/I/t_I、DataID/时间/流量和公开版本等仍泄露。
- 对同用户同 CT，`W=T0q/TA=gT^(zαs)` 与 δq 无关，稳定可链接。fresh 临时组件不等于完整请求 unlinkability。
- 可信 enclave 可见属性明文；主算法是 TEE-protected PRF，不是对 enclave 盲的 OPRF。
- 若基态 μ/K0 泄露且结合同用户 RK，可得 `(K0/(g2^a)^μ)^RK=g2^α`，破坏系统机密性；不能因正常 TEE 无 RK 就宣称抗联合失陷。
- 单纯 component-mixing 拒绝不是抗串谋 reduction；跨 context token inequality 不是 unlinkability proof。

## 8. Pairing/AuthEnc status and local capability probes

以下是在当前 Python 环境的**基础能力探测**，无计时，无方案算法执行，无 benchmark 数据：

| 项目 | 2026-09-22 本机事实 | MYABE-08 状态 |
| --- | --- | --- |
| Python | 3.8.10 | scaffold 兼容此解释器 |
| py_ecc | 安装 8.0.0；BLS12-381 generator pairing 返回非单位 GT；hash_to_G1 callable | 库真实可用，但 08 adapter、正规 H0 suite/DST、strict imports、序列化与端到端 correctness 均未完成 |
| Charm | 本地 0.63 egg 路径；MNT224 创建与一次 G1×G2 pairing 可执行 | 仅历史 backend 事实；08 FABEO_COMPAT_PROFILE 未实例化/验证 |
| cryptography | 42.0.8；AESGCMSIV 导入及一个本地 encrypt/decrypt roundtrip 成功 | AES-GCM-SIV primitive 可用；08 row/DEM/KDF/AD/nonce/wire profile 未实现 |
| TEE | 未进行硬件部署或 SGX probe | 仅 EMULATED_TEE_PROFILE 接口；无 attestation/可信时间/封装/持久协调实现 |
| FABEO fair comparison | 历史 FABEO 使用 Charm/MNT224 | 未有与 MYABE-08 共同验证的 backend/profile，benchmark blocked |

BLS profile 规范大小：compressed G1=48、G2=96、scalar=32、GT=12×48=576 bytes。这些是**目标序列化描述**，不是本阶段已实现的 wire 结果。MNT224 的 08 大小字段为 None，不把旧计量直接移植。

本阶段不新增依赖、不安装库，不编写库可用即启用的 fallback。两个 pairing 描述符均为 NOT_IMPLEMENTED；未知名称或把 pairing 名传入 TEE axis 都拒绝；已知名称只允许检查 scaffold，setup 抛 `BackendNotImplementedError`。

## 9. Open implementation gaps and planned correctness gates

| Gate | 待完成工作 | 通过所能支持的结论 |
| --- | --- | --- |
| G0 规范/字节冻结 | 恢复缺失 TLV/FusePos/RAW_SCHEMA；确定 attribute normalization、H0 suite/DST、seed mixing、row KDF/nonce 域、完整 limits；独立向量 | 能实现同一规范，不是安全证明 |
| G1 Backend | BLS12-381 正规 hash-to-curve、group order、canonical scalar/G1/G2/GT、subgroup/identity/跨 PP/profile 检查；无假群或已知离散对数 H0 | primitive/representation correctness |
| G2 Crypto/wire | typed length framing，同值同编码、类型隔离、拼接歧义/截断/尾随数据拒绝；GCM-SIV vectors、KDF/PRF 独立域、Ed25519 签名绑定 | 指定向量的实现正确性 |
| G3 AF | 固定 payload、h/bot/排序/范围、finite retry、metadata/array tamper、无 retained map；nonmember/auth failure | 组件功能验证，非完整匿名性或 AF 安全归约 |
| G4 Algebra | OR/AND/阈值、重复标签后续 occurrence、多 slot、多余 J、超 c_max、fresh s/r_j；逐步核验 TA/T0/W/E | algebraic correctness，不是 selective-CPA |
| G5 Credentials/TEE | expired/forged/old credential/blob、无 PoP、namespace/发布/请求绑定、完整 S_id、零 μq/单位 K0q 重采样；无秘密出域 | 仅软件协议测试，不是 SGX security |
| G6 Current-state | revoke/activate、Ack 提交、重复/缺序/回滚/冻结/不可达、并发 revoke vs authorize、原子 replay、可信时间失败 | 单逻辑服务中被测试的 access-time 语义；多副本另验 |
| G7 Transform/FinalDec | cap/core/AF/DEM 全绑定、跨请求/用户/context 混用拒绝、错误 RK、nonce/expiry/消费、完整 Auth 传输计账 | 指定负例，不是 collusion/CCA/verifiable outsourcing 证明 |
| G8 Metrics/leakage | 实际 hook：TEE=1、CSP=1+t_I、system=2+t_I、FinalDec=0；失败请求分开；W 稳定；host transcript/log 扫描 | 操作数/披露边界，非 wall-clock speedup/unlinkability |
| G9 Fair benchmark | 相同 curve/backend/runtime/machine/serialization/workload/warmup/repetitions；计入协调/网络/签名 | 满足共同条件后才能启动正式性能比较 |

以上 gate 全部是**计划**，不被本阶段 40 个 scaffold 测试替代。Phase 1 不用 toy exponent model、mock pairing 或 fake Auth 演示 correctness。

`OperationCounts`、TEEMetrics、AFMetrics、TransformMetrics 的字段均以 None 起始；状态为 NOT_EXECUTED，不填 expected pairing count 冒充实际值。软件模拟的 enclave_transitions 保持 N/A。未来 instrument 必须独立记录 setup/keygen/provisioning、policy/user tokenization、verify/unseal、lookup/sync/协调等待、rerandomization/T0、cap、AF/LSSS/TA、FinalDec、Rev/RevStateUpt、网络字节以及 RevSet/注册/请求状态空间。

## 10. Planned Exp1–Exp7 mapping (not executed)

| Experiment | Modules/gates | 工作负载与将来指标 | 当前阻塞/解释边界 |
| --- | --- | --- | --- |
| Exp1 Occurrence optimization | scheme/lsss/tee/metrics；G1–G4/G8 | ell、c_max、k、t_I；实际幂/配对；重复 rank、跨 CT fresh r/s、抵消 | 算法未实现；不能用旧 3+t_I 样本 |
| Exp2 FABEO comparison | backend + 独立 baseline adapter；G9 | 相同策略形状/规模的 Setup/KeyGen/Encrypt core/Transform/Decrypt | 共同 backend 未具备；BLS 与 MNT224 时间不能直接比较 |
| Exp3 Storage | types/encoding/af；G2/G3 | `(ell+1)|G1|+c_max|G2|`、AF/header/DEM/签名；blob/credential/RevSet/注册/replay 另计 | 未有 canonical wire；CT 撤销组件/public KU/tree TK 理论为零，不是整个系统零开销 |
| Exp4 Contextual tokenization + AF | crypto/tee/af；G2/G3/G5 | u/ell/N/c_max/Lhit；policy/user batch、PRF、AF Build/Query/retry、认证拒绝 | 历史 OPRF 仅命名 baseline；跨 context 碰撞观测非匿名性证明；emulated 不计真实 transition |
| Exp5 Transform scaling | lsss/scheme/tee/state；G4–G8 | J/k/t_I/N；Query、重构、TA、T0、签名、coordination RTT/等待、全 request | 分别报告成功、失败、未授权；不能仅报 pairing 减少作速度结论 |
| Exp6 Privacy-preserving revocation | state/tee/credential；G5/G6 | RL、n_reg、request rate、lookup/memory/update/persistence；old-pending/future/并发 | 无 tree KU；旧可解密 Auth 缓存边界保留；RevSet O(RL) 不等于 TEE 总内存 |
| Exp7 Revocation transcript audit | types/credential/tee + 日志审计；G7/G8 | host 字段无 UID/handle/K0/μ/blob digest；fresh component 分布；同 CT W 稳定 | 不声称全请求 unlinkability；网络/输出/访问模式继续披露 |

不新增 benchmark runner，不输出 CSV、PNG、PDF、JSONL，不引用历史曲线作 MYABE-08 性能。未来每个 experiment 必须关联规范 hash、实现 commit、profile/backend、真实环境和独立 run manifest。

## 11. Phase 1 validation and change boundary

测试边界：package import（不加载历史或密码 backend）、两类 profile 分离、DTO canonical shape、unsupported/unimplemented fail-closed、所有八主算法/内部算法占位不返回成功、无历史树 API 依赖、CSP schema 与私有状态分离、未执行指标不伪造数值。

Canonical encoding 尚未实现，因此没有把 encoding correctness 测试写成已通过；相应测试只确认 encode/decode 明确 unavailable。测试构造中的 `b"test"` 群 wrapper 是故意无效的结构占位，不用于任何数学运算。

本阶段校验记录：

- 新 scaffold 定向测试：`40 passed in 0.24s`，0 failed，0 skipped。
- 全库测试命令：`PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider`。
- 全库实际结果：**178 passed in 15.39s；0 failed；0 skipped；退出码 0**（原有 138 项 + 新增 40 项）。没有 MYABE-08 密码正确性测试被伪装为通过。
- 对全部起始 1,669 个 Git 跟踪文件保存 SHA-256，并在完成后逐文件比对，防止历史结果被测试或脚本重写。
- 所有新代码、测试及此映射均位于 `src/core/myabe08/`。不改旧模块、根 requirements/pytest 配置，不删测试，不 commit。

最终 Git 检查执行了 `git status --short`、`git diff --stat`、`git diff -- src/core/myabe08`。状态仅 `?? src/core/myabe08/`；18 个新文件尚未暂存，因此普通 diff 不显示它们，不表示没有代码。另用逐文件 `git diff --no-index /dev/null <new-file>` 检查新增内容，`--check` 无空白错误。全库测试后原 1,669 个文件 SHA-256 全部未变；myabe08 外修改为 0。

## 12. Phase 2 recommendation (not started)

先完成 G0：恢复或澄清规范指向的精确 byte-level 规则及既有实现/SGX 证据的所属版本，固定独立向量。随后按 G1/G2 建立 BLS12-381 strict backend 与 GCM-SIV/编码实现，再分别实现 AF/LSSS、credential/软件 enclave、exact RevSet/current-head 协调，最后接通八算法并验证 2+t_I 与 TA/T0/W/E。

保持 EMULATED_TEE_PROFILE 标识、所有未通过 gate 的失败关闭，以及 FABEO benchmark blocked。直到共同 backend 和正确性 gate 完成才另行规划性能阶段。本次不继续实施这些工作。

## 13. Phase 3B implementation status (2026-09-23)

此节更新前述 Phase 1 计划表的当前状态，不能把旧的“计划/未实现”文字当作最新实现声明。`signing.py`、`credential.py`、`publication.py`、`sealing.py`、`attestation.py`、`channel.py`、`capability.py`、`state.py` 和 `tee.py` 现提供 Ed25519 凭据/发布/能力绑定、软件加密通道与封装、原子进程内 nonce 状态，以及要求外部 current-state coordinator 的部分软件授权路径。数学部分复用 `algebra.py`，AF/LSSS 仍复用 Phase 2B 组件。确切 wire/profile closure 见 [IMPLEMENTATION_PROFILE_V1.md](IMPLEMENTATION_PROFILE_V1.md) §15。

默认 `UnavailableCurrentStateCoordinator` 拒绝请求；唯一 ACTIVE coordinator 位于 `tests/protocol_fixtures.py`，仅用于 EMULATED 协议集成测试。`MyABE08` 八个公开方法仍显式未完成。真实 RevSet、Rev/RevStateUpt、current-head 同步、可信硬件时钟、远程证明、硬件 sealing、持久重启/回滚恢复和多副本一致性均未实现。软件结构检查与测试不证明 TEE 保密或匿名性。旧 G5 部分协议绑定已经有 correctness 覆盖；G6 的真实撤销/current-state gate 仍未通过。FABEO fair benchmark 继续 blocked，未运行计时实验。

## 14. Phase 3C implementation status (2026-09-23)

本节更新上面的 Phase 3B 时点记录。新增 [revocation.py](revocation.py)：独立 `K_rev` 的 RID HMAC、精确 handle set、规范状态 digest、单 pending 的 KGC Rev、认证加密 Delta、TEE RevStateUpt、认证 Ack 与 KGC commit、KGC/TEE/head 三个独立认证持久文件，以及单进程线性化 coordinator。`tee.py` 在真实 Phase 3C coordinator 路径上重载本地状态，先核对 fresh head/version/digest、再精确检查 RID；拒绝发生在 token/T0/cap 之前。Phase 3B 的 TEST coordinator 仅保留为旧测试回归 fixture；Phase 3C 新集成测试使用真实软件协调器。

这些是明确的 **EMULATED** 内部协议原语。八个 `MyABE08` 公开方法仍保持未实现，以免把软件正确性、管理 KGC provisioning、完整 Setup/KeyGen/Encrypt/Transform/FinalDec 和真实硬件信任边界混成已完成公共协议。单进程锁与三个认证文件不能抗宿主同时回滚，也不提供多副本共识、硬件可信时间、强零化或形式化撤销证明。exact state mismatch 采取拒绝，不提供 gap-sync。FABEO comparison 及正式 benchmark 仍 blocked。
