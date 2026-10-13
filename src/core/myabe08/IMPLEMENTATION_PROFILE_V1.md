# MYABE-08 Implementation Profile V1 — through Phase 3C emulated revocation core

**Status: PHASE_3C_EMULATED_REVOCATION_CORE_ONLY; full eight-algorithm public scheme/real TEE NOT_IMPLEMENTED; BENCHMARK_READY=NO.**

本文件固定本仓库的密码基础和唯一字节表示，不修改论文算法。算法唯一来源仍为 [ABE-Scheme-08.md](../../../../../Doc/ABE-Scheme-08.md)，读取快照 SHA-256 为 `d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`。Profile closure 来自本次 Phase 2A 授权；不继承 ABE-Scheme-07 或历史 05.3 的 wire。

## A. Normative from ABE-Scheme-08.md

以下由规范 §3、§5、§8 固定，本文件不更改：

| Item | Normative requirement |
|---|---|
| H_ctx / Digest | SHA-256 |
| Context | SHA256(Encode("PRIV", SysID, PolicyContextID, PolicyVersion)) |
| Contextual token | HMAC-SHA256(K_tok, Encode("MYABE-TOK", SysID, ctx_priv, x))；独立 256-bit K_tok |
| Row KDF | domain-separated BLAKE2b-256，输入 ctx_AF、τ |
| AF AuthEnc | AES-256-GCM-SIV，128-bit tag；96-bit nonce 从 ctx_AF、τ 派生 |
| Fixed rows | uint32 h + c_max 个 uint32 行号，0 为 bottom；严格递增、1-based、范围限定 |
| AF widths/retries | M 为 `4(c_max+1)` bytes，V 为 `4(c_max+1)+16` bytes，最多 32 次 seed retry |
| DEM | HKDF-SHA256(salt=ctx_CT, IKM=canonical E, info=b"MYABE-DEM", L=32)；AES-256-GCM-SIV；fresh nonce |
| H0 | 真正 hash-to-G1，不允许已知离散对数映射 |
| Pairing | Type-III 数学方向 G1 × G2 → GT；BLS12-381 / py_ecc 8.0.0 |
| Serialization widths | scalar 32、compressed G1 48、compressed G2 96、GT 576 bytes |
| Import checks | canonical encoding、curve/subgroup、SysID/ProfileMeta；identity 按调用上下文处理 |

本表记录 08 规范基础约束；后续 §11–§15 记录已实现的 AF、LSSS、代数及 Phase 3B 软件协议原语。八个公开主算法仍未实现。

## B. Repository implementation-profile closure

下列 exact byte decisions 使实现可重复，不声称是论文原文逐字规定。

| Item | Repository V1 decision | Reason |
|---|---|---|
| EncodingProfileID | `MYABE08_ENCODING_V1` | 显式 wire 版本 |
| Frame | tag:uint8 + payload_length:uint32be + exact payload | 类型、长度隔离，无 delimiter 拼接 |
| Tags | 01 bytes、02 UTF8、03 uint32、04 uint64、05 scalar32、06 list、07 tuple、08 record | 不合并 list/tuple 或不同宽度整数 |
| Integer byte order | 所有长度/计数/整数/AF rows 为 big-endian | 唯一字节表示 |
| Composite | 显式 uint32 元素/字段数量，递归 canonical frame | 截断、冗余、count mismatch 可拒绝 |
| Structured record | ordered schema + ordered named fields，详见下节 | 不依赖 dict 顺序、不自动序列化任意对象 |
| Attribute | 精确 namespace/name/value 字符串的 `MYABE08.AttributeV1` record | 不隐式 str 转换或 Unicode 归一化 |
| PolicyVersion | explicit UInt64 | 不依赖 Python 任意精度整数表示 |
| H0 DST | exact bytes `b"MYABE08-H0-BLS12381-V1"` | 独立 project domain |
| H0 suite | py_ecc 的 `BLS12381G1_XMD:SHA-256_SSWU_RO_` style path | XMD/SHA256、SSWU、isogeny、cofactor clearing |
| Row-KDF label | string `"MYABE-ROW-KDF"` | 独立域；不是历史 FX53 KDF |
| AF-nonce label | string `"MYABE-AF-NONCE"` | 与 row key 材料分离 |
| G2 ordering | compress_G2 的 z1||z2，各 48-byte big-endian；z1 是 x.imag+flags | 与指定 py_ecc API 精确对应 |
| GT ordering | FQ12 coeffs[0]…coeffs[11]，各 48-byte big-endian | 固定多项式基表示，非任意 repr |
| Resource bounds | framed value ≤16 MiB、nested depth≤64；fixed row allocation≤16 MiB | 在解析前拒绝过大/过深输入，非算法理论规模界 |

**Phase 2B closure:** FusePos、metadata、AF AD 和确定性 LSSS 规则见 §11；Phase 2A 已冻结字段不变。

## 1. Canonical Encoding V1

### 1.1 Frame and types

```text
Frame = tag[1] || payload_length[4, big-endian] || payload[payload_length]
```

解码必须消耗恰好一个完整 frame；任何 trailing bytes 都拒绝。

| Tag | Python API | Payload |
|---|---|---|
| 0x01 | exact bytes | 原始 bytes，可为空 |
| 0x02 | exact str | strict UTF-8，无 BOM 注入，无自动规范化，可为空 |
| 0x03 | UInt32(n) | 恰 4-byte uint32be |
| 0x04 | UInt64(n) | 恰 8-byte uint64be |
| 0x05 | FixedScalarBytes(raw) | 恰 32 bytes；field range 另由 backend 检查 |
| 0x06 | exact list | count:uint32be，随后 count 个子 frame |
| 0x07 | exact tuple | count:uint32be，随后 count 个子 frame |
| 0x08 | StructuredRecord(schema, fields) | field_count:uint32be，schema:string frame，随后每字段 name:string frame + value frame |

Record schema 与字段名非空；字段名不可重复；字段必须由有序 tuple 显式给定。字段顺序属于 schema 的含义，decoder 不排序。对于专用 `AttributeV1`，字段顺序固定为 namespace、name、value，三者必须为 string。

不接受 bool、裸 int、float、None、dict、set、bytearray、任意 dataclass 或自定义对象；不调用 repr/pickle，不隐式类型转换。字符串按精确 Unicode code point 序列编码，不把 NFC/NFD、大小写或不同 namespace 当作同一属性。应用层认证/登记不得假设本编码器替它完成语义归一化。

`encode()` 只支持这张显式类型表，`decode()` 返回相应 typed value。整数固定宽度，不允许短表示、符号字节或冗余前导字节；fixed scalar 宽度与数学 scalar canonical range 是两层检查。严格 decoder 拒绝 invalid tag、invalid UTF-8、错误 fixed length、截断、额外字段、数量不符、重复字段名和尾随内容。16 MiB/64 层限制同时适用于 encoder/decoder。

### 1.2 Dedicated context encoders

所有 `Encode(a,b,...)` 在 V1 中明确选择**ordered tuple frame**，不是把多个 frame 无根地串接。domain label 是 string frame，不是无类型 raw prefix。

- `encode_priv_context(sys_id, policy_context_id, version)`：tuple("PRIV", bytes(SysID), bytes(PolicyContextID), UInt64(version))。SysID 非空、PolicyContextID 至少 32 bytes。此 primitive 接受 uint64 的完整范围；高层 `PolicyContext` 的正版本约束仍由协议类型/入口处理。
- `encode_attribute(namespace,name,value)`：`StructuredRecord("MYABE08.AttributeV1", (("namespace",namespace),("name",name),("value",value)))`。
- `encode_token_input(sys_id,ctx_priv,canonical_attribute)`：tuple("MYABE-TOK", bytes(SysID), bytes(ctx_priv), bytes(canonical_attribute))。x 在此接口中明确是**完整 AttributeV1 canonical encoding 的 bytes 值**，即外层以 bytes frame 封装；输入前严格解析并核对 schema/字段，不接受任意未规范化属性字符串。
- `encode_row_kdf_input(ctx_af,tau)`：tuple("MYABE-ROW-KDF", bytes(ctx_af), bytes(tau))。
- `encode_af_nonce_input(ctx_af,tau)`：tuple("MYABE-AF-NONCE", bytes(ctx_af), bytes(tau))。
- `encode_dem_ad(ctx_ct)`：tuple("DEM", bytes(ctx_ct))。

ctx_priv、ctx_AF、ctx_CT 和 τ 均要求 exact 32-byte bytes，不接受可隐式转换对象。`sha256_digest(data)`/`context_hash(data)` 只散列精确 bytes；调用方先调用专用 encoder，避免隐式序列化规则。

## 2. Fixed AF row payload

接口：`encode_fixed_rows(rows,c_max,ell)` / `decode_fixed_rows(data,c_max,ell)`；仍兼容已有 keyword 参数调用。

```text
M = uint32be(h) || uint32be(row_1) || ... || uint32be(row_h)
    || uint32be(0) repeated (c_max-h) times
```

这里不是 TLV frame：它就是规范要求的固定宽度 plaintext。h 必须 1..c_max，ell 为 1..2^32−1，c_max 为正 uint32；rows 严格递增、1..ell。0 仅在尾部 padding 中出现。bool 不当作 int。错误宽度、h、顺序、重复、范围或非零 bottom 全部抛 `ContractError`。

示例 rows=(1,3,7)、c_max=5、ell=7：

```text
00000003 00000001 00000003 00000007 00000000 00000000
```

明文 24 bytes；若经主 AuthEnc 保护，完整槽载荷为 40 bytes。AF Build/Query 和 metadata AD 已在 Phase 2B 接通，见 §11。

## 3. Hash / contextual PRF / row KDF / AF nonce

```text
ctx_priv = SHA256(encode_priv_context(SysID, PolicyContextID, PolicyVersion))
tau = HMAC-SHA256(K_tok, encode_token_input(SysID, ctx_priv, canonical_attribute))
K_row = BLAKE2b(input=encode_row_kdf_input(ctx_AF,tau), digest_size=32)
nonce_material = BLAKE2b(input=encode_af_nonce_input(ctx_AF,tau), digest_size=32)
AF_nonce = nonce_material[:12]
```

BLAKE2b 是 32-byte digest 参数化实例，**不是 BLAKE2b-512 截断**，也不使用额外 keyed/person/salt 参数。两个 label 和 framing 构成 domain separation。Ktok 必须恰为 32 bytes；其与 Krev/其他秘密的独立生成/保管属于后续 Setup/TEE，当前函数不伪装成已完成 provisioning。

policy/user 调用同一 `contextual_token`，无 role/session/request nonce 参数。有限测试中的跨 context 不同输出只表示样本没有碰撞，不证明 unlinkability、collision resistance 或完整访问 transcript 隐私。

## 4. AES-256-GCM-SIV and DEM

`AES256GCMSIV` 延迟导入真实 `cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV`，key 必须 32 bytes，nonce 必须 12 bytes，AD/plaintext/ciphertext 必须 exact bytes。输出为 library ciphertext||16-byte tag；不自行实现 GCM-SIV，也不 fallback。

错误 key/nonce/AD/ciphertext/tag 导致 `AuthenticationError`；非法输入类型/参数宽度导致 `ContractError`。不释放未认证明文。使用 RFC 8452 Appendix C.2 非空 AES-256 已知答案向量作独立 primitive 校验。

**本机实际 API 限制：cryptography 42.0.8 的 AESGCMSIV.encrypt 拒绝零长度 plaintext（ValueError: data must not be zero length）。V1 adapter 显式拒绝空明文，并拒绝长度≤16 的 ciphertext/tag。** 这不是论文规定消息必须非空，也不是自行扩展 AEAD；是当前实现能力边界。后续需要处理空消息时须先解决库能力/版本 gate，不能 silent padding、切换 AES-GCM 或手写算法。

DEM：

```text
K = HKDF-SHA256(salt=ctx_CT, IKM=canonical_E, info=b"MYABE-DEM", L=32)
nonce = secrets.token_bytes(12)
AD = encode_dem_ad(ctx_CT)
DEMCiphertext = (nonce, AES256GCMSIV.encrypt(K,nonce,M,AD))
```

HKDF 由 cryptography 实现，KDF API 检查 IKM 恰为 576 bytes；**它不重做群验证**，调用方必须先经 BLS backend 的 strict GT import/serialization 得到 canonical_E。固定 fixture 使用真实 generator pairing 的 canonical GT。KDF 输入宽度正确不等于其数学来源合法。

`dem_encrypt` 不提供外部指定 nonce 参数；`derive_af_nonce` 是独立确定性 API，DEM 不调用它。重复 DEM 加密测试观察随机 nonce 不重复，不声称数学上永不碰撞。错误 context 同时改变 key/AD，解密拒绝。完整 Ciphertext/publication/ctx_CT 组装尚未实现。

## 5. BLS12-381 backend

### 5.1 Actual API and version gate

真实依赖：Python 3.8.10、`py_ecc 8.0.0`、`cryptography 42.0.8`。具体模块：

- `py_ecc.optimized_bls12_381`：G1/G2、add、multiply、pairing、is_on_curve、is_inf、FQ12、curve_order/field_modulus。
- `py_ecc.bls.point_compression`：compress_G1/decompress_G1、compress_G2/decompress_G2。
- `py_ecc.bls.hash_to_curve.hash_to_G1`：标准风格 XMD SHA-256/SSWU/映射与 cofactor clearing。

`BLS12381Backend` 要求库版本精确为 8.0.0；其他版本 fail closed，未经核验不自动接受。没有 Charm/MNT224 fallback。包导入仍不加载密码库，只有实际 primitive/backend 使用才导入。

### 5.2 Profile and SysID binding

```text
ProfileMeta = (
  SecurityProfileID = SECURITY_PROFILE_BLS12_381,
  CurveID = BLS12-381,
  BackendID = py_ecc-8.0.0,
  EncodingProfileID = MYABE08_ENCODING_V1
)
GroupBinding = (SysID, ProfileMeta)
```

backend 绑定唯一 SysID/ProfileMeta；所有 Scalar/G1Element/G2Element/GTElement 含完整 binding。每个数学/序列化操作重新验证输入 DTO 的类型、binding 和 canonical bytes，不把构造 dataclass 当作已验证点。所有 raw import 要显式传入 `binding=`，不同 SysID/curve/backend/security/encoding profile 拒绝混算。

固定宽度 raw group bytes 本身没有空间携带 SysID/ProfileMeta。**这些标识必须由未来经过认证的 PP/transport envelope 提供，raw bytes 单独不能证明来源；恶意重新标注来源不由数学点编码解决。** 当前未实现完整 PP/发布认证协议。不同 PP 实例须使用不同 SysID；不能为不同实例复用 SysID 后声称已得到额外 PP fingerprint 保护。

Pairing profile 的 `backend_status=FOUNDATION_V1_IMPLEMENTED` 与 scheme 的 `implementation_status=NOT_IMPLEMENTED` 分开。保留的 `require_pairing_backend()` 是旧 scaffold 的 scheme 集成 gate，仍拒绝 Setup；构建 foundation adapter 使用 `BLS12381Backend`。TEEProfile 继续独立为 EMULATED_TEE_PROFILE、INTERFACE_ONLY。

### 5.3 Math API

- Scalar：CSPRNG nonzero sample、add/mul/inv、explicit scalar_from_int。
- G1/G2：generator、scalar multiplication、point addition。
- Pairing：始终 `pair(G1Element,G2Element)`。仅 adapter 内调用 py_ecc `pairing(G2,G1,final_exponentiate=True)`；不得泄露反序 API 给后续算法。
- GT：pow/mul，供真实 bilinearity self-test 使用。
- 每种群/标量的严格 serialization/import；按需 allow_identity / allow_zero。

这里只是 backend 运算，不执行 Setup/Encrypt/TEEAuthorize 等。纯 Python/py_ecc 不提供 constant-time、内存清零、SGX 隔离或生产安全保证。

## 6. Canonical scalar/G1/G2/GT representation

| Type | Exact representation | Validation |
|---|---|---|
| Scalar | 32-byte big-endian integer n，0≤n<r | 拒绝超范围/错误长度；inv(0) 拒绝；allow_zero=False 时拒绝0 |
| G1 | py_ecc/IETF-style compressed，48-byte big-endian | flags、x<p、曲线、r-subgroup、recompress 等于原输入 |
| G2 | z1[48]||z2[48]；z1 为 x 的虚部及 flags，z2 为实部 | 相同检查，加 FQ2 分量/flag 合法性 |
| GT | c0[48]||...||c11[48]，各 big-endian | 每个 c<p，FQ12 非零，value^r=1；可选禁止单位元 |

GT 对应 py_ecc 8.0.0 的多项式基 `F_p[w]/(w^12 - 2*w^6 + 2)`，`value=sum(c_i*w^i)`。它不是 tower-basis 系数随意展平、压缩 GT、Miller-loop 未最终幂结果或 Python repr。576-byte 长度是该具体 profile 的选择。

G1/G2 检查 `is_on_curve` 以及 `[r]P=∞`，不能只检查压缩格式；测试使用真实 on-curve 但尚未 cofactor-cleared 的 G1/G2 作为非子群负例。GT 也进行 r 阶乘法子群检查，不允许任意 12 个合法 Fp 系数。

不全局禁止 identity：乘0、相消与 GT 的合法中间结果允许；只有调用明确 `allow_identity=False` 才拒绝。H0 对输出执行非单位元与 subgroup 检查；未来协议 C/K1q 等的非单位元要求仍由调用者显式指定。

## 7. H0

精确 DST bytes：`b"MYABE08-H0-BLS12381-V1"`（ASCII，22 bytes）。传给 py_ecc `hash_to_G1(token,H0_DST,hashlib.sha256)`；该 API 允许应用 DST，不要求把 suite 名称拼到 DST 中。这里的实际构造遵循库说明的 `BLS12381G1_XMD:SHA-256_SSWU_RO_` 路径。

输入要求 32-byte token；不先把 hash 值变成已知标量再乘生成元。测试验证相同输入相同点、两个样本不同、非单位元、曲线上、正确 subgroup 和 serialization roundtrip。有限样本不构成碰撞阻力证明。

## 8. Deterministic TEST vectors and independent checks

只读 fixture：[tests/vectors/profile_v1.json](tests/vectors/profile_v1.json)。所有 key/input 是公开 TEST 值，没有生产 secret。覆盖 bytes/string/uint32/uint64/scalar/list/tuple/record、attribute、ctx/token input、ctx_priv、token、row key、AF nonce material/nonce、fixed rows、DEM AD/HKDF key 和 H0 G1。

首次生成采用**不导入 myabe08** 的独立 struct/hashlib/hmac reference：按本文件 framing 构造预期字节；HKDF 使用 RFC5869 extract+expand 的 HMAC 公式；H0 调用直接 py_ecc 参考 API。H0 reference 和 backend 共享同一底层库，因此是 adapter 回归向量，不冒充第二个独立 hash-to-curve 库的互操作验证。另有 RFC8452 发布向量和 SHA256("abc") 外部已知答案。

pytest 只读取此文件并逐项比较，不写回、不自动 regenerate。变更 tag/域/字段顺序/DST/序列化应导致失败；任何 vector 更新均需显式审查与 profile 版本决定。

## 9. Validation boundary and remaining work

本阶段验证 encoding、AEAD、PRF/KDF、真实群运算与 pairing bilinearity。**Backend correctness 不等于 ABE correctness，更不等于 selective-CPA、collusion resistance 或 TEE security。** 未生成 wall-clock benchmark、speedup、论文图表或 MYABE-08 端到端性能结论。

保持未实现：完整 PolicyEncode、所有八个 scheme algorithms、credential/sealing/capability/TEE state machine。FusePos、AF Build/Query 和 AuthorizedSubset 仅是 Phase 2B correctness subsystem。FABEO_COMPAT_PROFILE 仍不可执行；FABEO 共同 backend benchmark blocked。

Phase 2B 已冻结 FusePos/AF metadata/AD 并完成 correctness gate。当前空消息 GCM-SIV 能力限制需在接通通用消息 Encrypt 前解决。

## 10. Phase 2A execution record (2026-09-22)

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest src/core/myabe08/tests -q -p no:cacheprovider
129 passed in 3.44s

PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
267 passed in 18.49s
```

两次均退出码 0、failed=0、skipped=0。原历史 138 项未修改；原 Phase 1 的 encoding-placeholder 检查已被实际 encoding 测试取代，其他 scaffold 边界检查继续通过。

环境实测：cryptography=42.0.8，py_ecc=8.0.0，AESGCMSIV import SUCCESS。向量文件 SHA-256：`e72ac04694aae9ec1b9ab34cf7a0c3a10c99a2397b0a60c46dd5aa397e1ee6aa`，测试前后未变化。

相对 Phase 1 新增 9 个文件、修改 8 个文件，均位于 myabe08。原 1,669 个 Git 跟踪文件和外部规范 SHA-256 未变。执行了要求的 git status/diff 检查；myabe08 从 Phase 1 起仍为未跟踪目录，所以普通 git diff 不含这些文件。额外按 Phase 2A 开始快照核对逐文件 diff，未暂存、未 commit；无历史 CSV/PNG/PDF/JSONL 再生成。

## 11. Phase 2B AF and LSSS profile closure

### 11.1 Normative from ABE-Scheme-08.md

- 对 distinct token 的 `L_tau` 使用完整策略行号，严格递增且 `h<=c_max`；固定宽度 `M_tau`，受保护 `V_tau`，槽宽 `4(c_max+1)+16`。
- `ctx_AF=SHA256(Encode("AF",Hdr_AF))`；`TokCtx(tau)=SHA256(Encode("AF-TOKEN",tau))`；`AD_tau=Encode("AF-row",ctx_AF,TokCtx(tau),meta_AF)`。`meta_AF` 包含 seed，但不含槽数组 digest。
- 三个不相交 segment；`segmentLength=max(4,floor((3u+5)/2))`，`m_AF=3*segmentLength`；单个 seeded mixing output 派生三个偏移。peeling、逆序 XOR assignment、最多 32 次 fresh seed 尝试。最终公开对象仅含 metadata 和槽数组。
- Query 所有认证/解析/非成员失败均给统一 miss。`phi(i_j)=(tau,j)` 中 j 来自完整 `L_tau`。`AuthorizedSubset` 固定行序 Gaussian，取确定性可行解、去掉零系数后验证，不求最小 `k` 或 `t_I`。

### 11.2 Historical audit and deviation

历史 `fxabe_05_3_exp/fx.py` 的 profile 字符串为 `FXABE05.3-SEGMENTED-XOR-V1`，每次取 16-byte seed。每个 lane **分别**计算 `SHA256(old_encode([PROFILE,seed,token,lane,counter]))[:8]`；以 `limit=2^64-(2^64 mod L)` 拒绝采样，再 `% L`，位置是 `lane*L+offset`。其 `L=max(2 if u>1 else 1,ceil(1.30u/3))`，最多 32 次 seed，队列 peeling，初始槽全为随机同宽 bytes，逆序 assignment。最终对象额外保存 PStore，槽中只有 4-byte locator + 16-byte check，不是完整受保护行列表。

因此历史 seed 确实影响定位，拒绝采样避免直接 `% L` 的模偏差；但三个 lane **不是同一个 mixer 输出**，容量公式、payload、发布对象也与 08 不同，不能原样移植。`fxabe_rev/retrievals/xor_core.py` 和 `fxabe_rev/filters/fxabf.py` 同属旧检索/PStore 或 adaptive layout 体系，仅供图剥离与测试形态参考，没有运行时依赖。

### 11.3 Repository FusePos V1 exact bytes

这是实现 profile closure，不宣称为论文原文逐字规则。`seed_AF` 恰为 16 bytes，token 恰为 32 bytes，`L>=4` 为 uint64。对于 counter=0..255：

```text
block = SHA256(Encode(("MYABE08-FUSEPOS-V1", seed_AF, token,
                       UInt64(L), UInt32(counter))))
lanes = (uint64be(block[0:8]), uint64be(block[8:16]),
         uint64be(block[16:24]))
limit = 2^64 - (2^64 mod L)
```

一次 block 是三个偏移的共同 seeded mixing output。若任一 lane `>=limit`，丢弃**整个** block，counter 加一；全部合格时返回 `(lanes[0]%L, L+lanes[1]%L, 2L+lanes[2]%L)`。256 个 block 均不合格则 fail closed。SHA-256 按随机输出建模时，拒绝采样没有直接模缩减偏差；这不是哈希输出独立性证明。三个位置天然落在三个连续、不相交 segment。不用 Python `hash()`、`repr()` 或 dict 顺序。

### 11.4 Header, metadata, AD and payload

`Hdr_AF` 的 V1 record schema 是 `MYABE08.AFHeaderV1`，字段顺序：`sys_id:bytes, ctx_priv:bytes32, matrix_digest:bytes32, ell:uint32, u:uint32, parameters:MYABE08.AFParametersV1`。参数子记录顺序：`profile_id:str, c_max:uint32, max_seed_attempts:uint32, row_width_bytes:uint32, authenc_id:str, tag_bytes:uint32`。`Encode("AF",Hdr_AF)` 是 Phase 2A 的 ordered tuple frame，第二元素为上述 record frame。

`meta_AF` 的 `MYABE08.AFMetadataV1` record 字段顺序：`profile_id:str, encoding_profile_id:str, sys_id:bytes, ell:uint32, u:uint32, c_max:uint32, segment_length:uint64, m_af:uint64, seed_af:bytes16, slot_payload_bytes:uint64`。它严格验证 `u>0,ell>0,u<=ell,1<=c_max<=2^32-1,ell<=2^32-1,L=max(4,(3u+5)//2),m=3L,bV=4(c_max+1)+16`。无槽数组摘要、token map 或 TokCtx 表。

`TokCtx` 的输入是 tuple frame `("AF-TOKEN",tau)`；AD 是 tuple frame `("AF-row",ctx_AF,TokCtx(tau),metadata_record)`，其中 metadata 是上述 record **本身**，不是裸字段拼接。每个 seed attempt 先构图剥离；失败时丢弃尝试态。成功后才按最终 seed metadata 加密全部 `V_tau`，因此不会把旧 seed 的 AD/ciphertext 用于新 seed。AES-256-GCM-SIV key/nonce 沿用 Phase 2A 的 row KDF/AF nonce；明文恰 `4(c_max+1)` bytes，输出恰 `bV` bytes。

Build 输入 entries 是完整策略行的一个分区：每行必须恰属一个 token；token 按 bytes 字典序固定顺序，消除输入容器顺序影响。生产 seed 与初始所有槽各由 `secrets.token_bytes` 生成；测试可显式注入 `seed_source(length)` 和 `slot_source(length)` 取得可复现 snapshot。所有槽先以正确宽度随机填充，再逆序覆盖 pivot；未被写的槽保留随机值，**不是全零槽**。每个成员等式构建后重新检查；超过 32 次剥离失败抛 `AFBuildError`，没有部分发布对象。测试注入不是生产随机配置。

Query 每次核对 header/context、metadata、槽数和槽宽，计算三槽 XOR，按 token 导出 key/nonce/AD 并认证解密，再严格调用 `decode_fixed_rows`。成员、非成员、篡改、错误 context、错误 seed、解析失败对正式 API 均只有 `AFQueryResult(False,())` miss；内部计数可区分 auth/parse，不写入公开 AF。`AFMetrics` 只记录操作/结构数量，旧 `_ns` 字段仍不填充。

### 11.5 Deterministic LSSS closure

`LSSSMatrix` 绑定矩阵 A、`ell`、`d`、BLS scalar field order 和外部 `1-based` 行号，要求矩形整数矩阵。`prepare_policy_rows` 是纯结构子过程：完整行序 token 上计算 `c(i)`，按 token 分组生成有序 `L_tau`；不执行 DO 授权或 TEE tokenization。`merge_af_hits` 返回升序 J 及完整 posting rank 的 witness；不同 token 声称同一行即失败。

`AuthorizedSubset` 将 J 升序规范化，重复 J **拒绝**。按升序变量列、方程自然行序，寻找第一个非零 pivot，Gauss-Jordan 消元；非 pivot 自由变量固定为零。字段是 Phase 2A backend 的 scalar order，使用其 canonical scalar serialization 比较零，绝不依赖 Python scalar truthiness。删除零系数行，再直接线性组合验证 `sum omega_i A_i=e1`；无解抛 `Unauthorized`。结果只保证确定性可行，不保证最小 `k` 或最小 `t_I`。纯集成检查由 `phi` 得到 `C_I`/`t_I`，不生成 `T_A` 或调用 pairing。

### 11.6 Scope and claims

AF 正确性与受保护载荷的拒绝行为**不是匿名性证明**；知道查询 token 的 CSP 可导出该 token 的行密钥。对象无显式 token map **不代表无 metadata 泄漏**。GCM-SIV 拒绝篡改不等于恶意 CSP 可验证计算。确定性 Gaussian 不等于全局最优重构；有限测试与向量不是形式化安全证明。没有 benchmark、FABEO 速度比较、TEE 安全结论。

Phase 2B 测试向量只在既有 JSON 增加 `phase2b` 对象；Phase 2A 原字段保持字节值语义不变，测试以 canonical JSON 投影 SHA-256 `958f1f7c302030af8eca1bbb0bceaa4f90fe1d00664fd1b9b740dea95e5d8651` 冻结。测试只读，不自动重写向量。

## 12. Phase 2B execution record (2026-09-23)

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest src/core/myabe08/tests -q -p no:cacheprovider
162 passed in 4.06s

PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
300 passed in 21.60s
```

两次均退出码 0、failed=0、skipped=0。B1–B10 指定的 functional gates 由定向测试和全库回归覆盖；它们只验证所列样本和实现边界，不是 AF 匿名性或 ABE 安全证明。测试未调用 benchmark，集成测试显式把 backend `pair` 替换为失败哨兵，确认结构链不执行 pairing。公开 AF dataclass 的直接字段审计为 `slots, metadata`，metadata 无 token mapping；AST 审计未发现运行时导入历史 `fxabe_05_3_exp` / `fxabe_rev`。

Git 当前将整个 `src/core/myabe08/` 显示为未跟踪目录，普通 `git diff --stat` 与路径 diff 因此为空。以 Phase 2B 开始前 SHA-256 清单比对：仅 myabe08 内 10 个原文件变化、4 个测试文件新增；原 1,669 个跟踪文件、外部 `ABE-Scheme-08.md` 及历史实验结果均未变。Phase 2A 向量字段语义保持原值，新增 `phase2b` 对象；pytest 从不重写 fixture。未 commit。

## 13. Phase 3A algebra-only correctness profile

### 13.1 Normative from ABE-Scheme-08.md

本阶段只按 08 版 §5.1–5.4、§5.6 步骤 6–7、§5.7–5.8 核验代数。Setup 独立取非零 `alpha,a`，发布 `g1^a,g2^a,gT^alpha`。KeyGen 独立取非零 `z,mu`，令 `RK=z^-1`、`K0=g2^(z alpha+a mu)`。Encrypt 取非零 `s,r_1..r_cmax`，以及允许零的 `y_2..y_d`；完整行序定义 `c(i)`，`Ci=(g1^a)^lambda_i H0(tau_i)^(-r_c(i))`、`Dj=g2^r_j`、`C=g1^s`、`E=(gT^alpha)^s`。即使未用 slot 也生成全部 `c_max` 个 `D_j`。

synthetic ephemeral helper 只实现 §5.6 的数学步骤：`mu_q=mu+delta_q`，零值重采样；`K1q=g2^mu_q`、`Ktauq=H0(tau)^mu_q`、`K0q=K0(g2^a)^delta_q`，单位 `K0q` 重采样；`T0q=e(C,K0q)`。Transform 取 AF 的完整 `phi` rank，先在 G1 按 slot 聚合 `Y_j`，再计算 `e(X,K1q)*product_j e(Y_j,D_j)`。Final algebra 计算 `(T0q/T_A)^RK`。真实 BLS12-381 群测试验证 `T_A=gT^(a mu_q s)`、`T0q/T_A=gT^(z alpha s)` 和恢复 `E`，但不验证 credential、TEE、capability、撤销或完整协议。

### 13.2 Repository core API and trust-domain closure

新增 [algebra.py](algebra.py) 的 `setup_algebra_core`、`keygen_algebra_core`、`encrypt_algebra_core`、`derive_ephemeral_algebra`、`transform_algebra_core` 和 `finaldec_algebra_core`。这是 internal/core API；八个 `MyABE08` public scheme methods 仍保持 `NotImplementedError`。Policy token 测试由固定 TEST key 的 Phase 2A contextual PRF **直接合成**，不称为已认证 PolicyEncode 或 certified TEE tokenization。

`AlgebraPublicParameters` 只含公开群元素、binding、`c_max`；`AlgebraMasterSecret` 单独含 `alpha,a`。KeyGen 返回两个分开的对象：`UserAlgebraBaseState(mu,k0)` 代表 enclave-side 数学状态，`UserRecoveryScalar(rk)` 代表 DU 本地恢复量；没有持久的三者合并对象。`EncryptCoreResult` 不含策略 token、`s,y,r_j`；`EphemeralAlgebraBundle` 只含 token、`K1q`、`Ktauq`、`T0q`，不含 `mu,mu_q,delta_q,K0,K0q`。TEST-only scalar 序列保存在测试 fixture/vector，不进入生产式返回类型。类型分离是架构检查，不是运行环境保密证明。

所有输入要匹配 BLS12-381 backend `GroupBinding`、field order 和 canonical 群表示。零/单位拒绝按调用 context 执行，不全局禁止中间单位元。KeyGen 遇到 `z alpha+a mu=0` 时重新取 `z,mu`；ephemeral 遇到 `mu_q=0` 或单位 `K0q` 时重新取 `delta_q`。**重试最多 32 次属于本仓库 fail-closed 资源界 closure**，不是 08 文档的逐字采样次数。生产默认调用 backend 的 `secrets.randbelow` 路径；测试才注入按非零/可零标记的固定 scalar source。不缓存 `s,y,r_j,delta_q`。

### 13.3 Operation accounting and test boundary

`AlgebraOperationCounts` 在 algebra core 每次实际 backend 调用成功后增加对应计数：G1/G2/GT exponentiation、G1/G2 群乘（backend 的 `add`）、GT 乘/除，以及 **pairing terms**。`pairing_summary` 只合并一个 synthetic T0 计数器与一个 CSP attribute Transform 计数器；Setup 的 `e(g1,g2)` 单独计数，不混入请求计数。测试还用 wrapper 直接观察 backend `pair()` 调用次数：成功请求为 T0 `1`、CSP `1+t_I`、合计 `2+t_I`。这些数字是核心代码实际请求的 pairing term 数，不含 backend 内部域运算，也不是 wall-clock 优势。

按 08 的确定性 Gaussian 解，`I` 非全局最小；`t_I=|{phi(i).rank:i in I}|`，可小于 `k`。Transform 在无解的 `J` 上于 attribute pairing 前返回 `Unauthorized`；若 synthetic T0 早已产生，失败请求可已有 1 次 T0 pairing，不得混入成功请求计数。测试中的逐 slot scalar ledger 只用于审计，真实 Transform 不读取 `r_j,s,alpha,a,z,mu_q`。

### 13.4 TEST vectors and scientific limits

既有 `tests/vectors/profile_v1.json` 只新增 `phase3a`；以前所有字段逐值不变，其 canonical JSON 投影 SHA-256 为 `665852875cf5693ef716b07179c828d105d2c904f2b79661fb9e1967861370bf`。固定 TEST scalar 为 `alpha=7,a=11,z=13,mu=17,s=19,y=(5),r=(23,29),delta_q=37`，并冻结 G1/G2/GT 的 canonical bytes、pair term 数和恢复结果。**NOT PRODUCTION SECRET**；pytest 只读，不自动重生。固定向量用于回归，另有真实 CSPRNG 的 12 次小型随机正确性试验；本环境完整试验约需数十秒，因此低于建议的 50–100 次，且未当作性能 benchmark。

跨请求、跨用户、跨 context、错误 RK 的有限负例只显示选定混合输入不能恢复目标 `E`；不构成 collusion resistance、unlinkability、selective-CPA 或恶意 CSP 安全证明。12 次随机等式闭合也不替代形式化证明。Phase 3A 不实现签名、credential、sealed state、RevSet、current-head 同步或 SGX。空 DEM 明文的 AESGCMSIV 库限制仍保留；FABEO 共同 backend 比较仍不可执行。

## 14. Phase 3A execution record (2026-09-23)

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest src/core/myabe08/tests -q -p no:cacheprovider
185 passed in 129.07s

PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
323 passed in 144.52s
```

两次最终测试均退出码 0、failed=0、skipped=0。完整测试中包含 12 次真实随机小型代数 roundtrip、固定群字节向量、多种 LSSS workload、逐 slot 真实群相消、backend `pair()` wrapper 调用轨迹及退化/混合负例。Setup 的 1 次 generator pairing 不计入请求级 `2+t_I`。这些运行时间仅说明测试成本，未运行 benchmark 或 FABEO 比较。

静态审计在 `algebra.py` 未发现历史 `fxabe_05_3_exp`、`fxabe_rev`、`fxdacp` 运行时导入，也无 tree-revocation、KU、OPRF 或 current-head 代码。对 Phase 3A 前的 SHA-256 快照比较：`myabe08` 内 7 个新文件、7 个原文件变化；目录外 0。`ABE-Scheme-08.md` 的 SHA-256 仍是 `d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`。Phase 2A/2B 向量字段逐值未变。整个 `myabe08` 目录尚未被 Git 跟踪，所以普通 `git diff`/`--stat` 为空；未 commit。

## 15. Phase 3B protocol binding — EMULATED_TEE_PROFILE only

### 15.1 Normative from ABE-Scheme-08.md

08 §5.1–5.6, §5.7 and §8.3 require an Ed25519 KGC credential over `MYABE-CRED` and canonical `SysID, UID, S_id, validity, credential_version, pk_auth`; DU proof of the independent authentication key; KGC-certified DO namespace; Ed25519 DO signature over `MYABE-PUBLISH, Digest(Hdr_CT), Digest(n_DEM,C_sym)`; a sealed user base state bound to credential digest/version; attestation binding measurement, profile, security version, fresh challenge and channel key; authenticated encrypted channel; fresh request nonce and expiry; and a capability over `MYABE-AUTH, SysID, Digest(Hdr_CT), ctx_priv, rev_version, request_nonce, expiry, Digest(B_q)`. `B_q` contains ordered tokens with ephemeral group components and `T0_q`, never UID or the sealed base state. Complete ciphertext digests cover indexed core components and all AF slots. TEE issues a request at most once, CSP consumes a cap at most once. The online current-state/RevSet check is normative and **has not been implemented** here. Phase 3B's default runtime coordinator therefore rejects authorization.

### 15.2 Repository implementation decisions (wire/profile closure)

| Item | Exact V1 decision | Boundary |
|---|---|---|
| DO certificate schema | `Encode("MYABE-DO-CERT", SysID:bytes, namespace:str, pk_DO:bytes32, (not_before:uint64,not_after:uint64), cert_version:uint64)`; Ed25519 KGC signature | 08 requires namespace certification but does not give this exact certificate schema |
| Canonical credential attributes | Nonempty sorted duplicate-free tuple of `AttributeV1` encodings; namespace/name/value are NFC and nonempty; validity is `[not_before,not_after)` UTC integer seconds | Normalization and field framing close a repository wire choice |
| Complete publication | `CiphertextHeaderV1` record in `publication.py`; `C_i`, `D_j` and AF slots use 1-based indexed tuple framing before SHA-256; `ctx_CT=SHA256(Encode("CT",Hdr_CT))` | Signature and verification bind actual array order and full filter digest; not an ABE well-formedness proof |
| Software sealing | Independent 32-byte `K_seal`; AES-256-GCM-SIV; fresh 12-byte CSPRNG nonce prepended to ciphertext; AD `Encode("MYABE-SEAL",SysID,"EMULATED_TEE_PROFILE","MYABE08-SEALED-USER-V1")` | 08 does not choose a sealing cipher. Opaque blob has no clear UID/version. No hardware sealing or durable anti-rollback |
| Software evidence | Separate Ed25519 emulated root signs `MYABE-EMULATED-ATTEST` with SysID, profile, measurement, security_version:uint64, challenge:bytes32, server X25519 public key:bytes32, session_id:bytes32 | Signature-bound **software evidence**, not a hardware quote or real remote attestation |
| Software channel | Ephemeral X25519; SHA-256 digest of ordered transcript containing SysID, profile, evidence digest, both public keys, challenge and session ID; HKDF-SHA-256 salt=transcript digest, info=`MYABE-EMULATED-CHANNEL-V1|DU->TEE` or `|TEE->DU`; AES-256-GCM-SIV with fresh nonce | Independent direction keys; record AD binds direction, session, sequence:uint64 and transcript digest. Sequence is monotonically checked under a lock |
| Time | `EmulatedClock.now()` returns software Unix seconds; TEST clock is under `tests/` | Missing clock rejects. Neither clock is hardware trusted time |
| Issue/consume state | In-memory, lock-protected `(SysID,nonce)` reserved→issued TEE store and one-time CSP consumption set; challenges consumed once | Volatile process state only; no restart persistence, expiry reclamation, rollback/freeze or distributed consistency claim |
| DU request state | DU-local immutable `header_digest, ctx_priv, nonce, expiry, session_id, challenge` snapshot; checks the response capability against the stored target/nonce/expiry and the original channel-bound request | Local protocol consistency check, not a signed channel transcript proof or durable request database |
| Current state | Runtime default `UnavailableCurrentStateCoordinator` raises; `CurrentHeadPermit.active=False` by default; only `tests/protocol_fixtures.py` provides active TEST transaction | No runtime always-allow coordinator; no RevSet, Rev or RevStateUpt implementation |
| Capability bytes | Ordered, unique token records in `B_q`; SHA-256 of canonical `bundle_bytes`; Ed25519 signs exact 08 field order with uint64 rev_version/expiry; `authorization_bytes` is an ordered envelope | A valid signature is transcript integrity and does not prove malicious-CSP transform correctness |

The implementation verifies credential, possession, authenticated blob, DO certificate, complete publication and current-state permit **before** calling the Phase 3A `derive_ephemeral_algebra` helper for T0. It does not duplicate the rerandomization formulas in `tee.py`. Certified DU tokenization enumerates only the verified credential's full `S_id`, deduplicates and sorts token bytes. DO policy tokenization requires a valid certificate plus channel-bound DO signature; this remains emulated, not full production `PolicyEncode`.

`EmulatedHostRequest`, published `Auth_q` and CSP-facing authorization bytes contain no UID, `rh_id`, credential/blob digest, `mu`, `K0`, `mu_q`, `delta_q` or `K0_q`; the private credential/blob/proof ingress is channel ciphertext. This Python field audit does not prove anonymity. Python memory zeroization, hardware isolation, side-channel resistance, trustworthy time, durable state and rollback protection are **not established**. A copied `B_q` remains mathematically usable after one-time protocol consumption; one-time checks only constrain compliant protocol state. Phase 2A's empty DEM plaintext blocker remains; tests encrypt a nonempty message. No formal proof, FABEO comparison or benchmark is implied by these correctness tests.

The read-only `phase3b` vector section contains **NOT PRODUCTION SECRET** fixed TEST Ed25519/X25519 seeds, seal key/nonce and transcript bytes. The prior-stage JSON projection is frozen by SHA-256 `dc4704e75ed5abc60586f1b5c4fd34466cbebd47b383b5d6368f194820d042df`; Phase 2A–3A fields are unchanged. Tests recompute the independent signatures, seal ciphertext, evidence, directional channel keys and capability digest from these bytes; no test rewrites the file.

## 16. Phase 3C exact RevSet and single-logical-head emulation

### 16.1 Normative from ABE-Scheme-08.md

08 §5.1–5.2, §5.6 step 4 and §6.1–6.5 require `rh_id=PRF_Krev(Encode("RID",SysID,UID))` with independent `K_rev`; exact TEE-local `RevSet`; strictly increasing `rev_version`; fixed-schema authenticated/confidential `Delta_v=(SysID,v,op,rh_id,prev_state_digest)`; atomic exact insertion/deletion and authenticated Ack; KGC pending→committed only after Ack; and a fresh online current-head authorization transaction serialized with revocation commit. Revocation affects **new authorization at access time**, including old CT lacking a completed Auth and future CT. A completed pre-revocation Auth/plaintext cannot be clawed back. Normal revoke does not change CT, AF, policy token, RK, blob or credential. A stale local snapshot must fail closed against the independent current head. These requirements are distinct from credential renew/versioning.

### 16.2 Repository implementation-profile closures

| Item | Exact V1 decision | Boundary |
|---|---|---|
| RID PRF | HMAC-SHA-256 with independent 32-byte `K_rev` over Phase 2A ordered tuple `Encode("RID",SysID,UID)`; 32-byte result | UID↔handle registry is KGC-private; TEE RevSet stores handles only |
| Exact set | Private Python `frozenset` of exact 32-byte handles; no host enumeration API | Membership is exact equality, not probabilistic; Python object secrecy is not established |
| State digest | `SHA256(Encode("MYABE-REV-STATE",SysID,UInt64(v),tuple(sorted(raw_handle_bytes))))`; tuple encoding includes count | No set iteration order, repr or pickle |
| Delta plaintext | Ordered tuple `("MYABE-REV-DELTA",SysID,UInt64(v),UInt32(op_code),rh_id:bytes32,prev_digest:bytes32)`; revoke=1, activate=2 | For fixed SysID both operations have identical width; unknown op rejected |
| Delta protection | Independent emulated X25519 channel purpose `REV`, transcript label `MYABE-REV-UPDATE-TRANSCRIPT-V1`, HKDF info `MYABE-REV-UPDATE-V1|KGC->TEE` / `|TEE->KGC`, GCM-SIV record; inner Ed25519 KGC signature domain `MYABE-REV-DELTA` | Neither `K_tok` nor `K_rev` is the AEAD transport key; this is a software authenticated channel |
| Management | Independent Ed25519 admin key signs `MYABE-REV-MGMT` over SysID, UID, op code and expected committed version | Single pending update only; redundant new revoke/activate rejected before version allocation |
| KGC lifecycle | Explicit `committed` / `pending` / `conflict` status; private registry, exact committed set, pending Delta, status and uint64 snapshot generation are in an independently keyed AES-256-GCM-SIV authenticated KGC file `MYABE08-KGC-REV-V1` | Generation compare-and-swap rejects two in-process managers attempting conflicting updates at the same committed version. UID↔RID registry may exist **only** in this KGC-private file, never TEE snapshot or host transcript |
| TEE snapshot | `Encode("MYABE08-REV-SNAPSHOT-V1",SysID,UInt64(v),sorted_handles,state_digest,replay_ack_records)` sealed by independent AES-256-GCM-SIV key with random nonce and schema/SysID AD | Temporary file, fsync, atomic replace and directory fsync; no plaintext UID registry; exact replay Ack cache persists |
| Ack | Separate Ed25519 TEE key signs `MYABE-REV-ACK` over SysID, UInt64(v), SHA-256(delta plaintext), new state digest | No UID/rh in host-facing Ack; exact protected-record replay returns the cached authenticated Ack |
| Current head | Separate authenticated encrypted head file `MYABE08-CURRENT-HEAD-V1` stores SysID/version/digest plus last predecessor digest and update digest; independent key and atomic replacement | Last transition permits exact Ack idempotency after a crash between head commit and KGC snapshot commit; does not make the OS/filesystem rollback resistant |
| Coordinator | `EMULATED_SINGLE_LOGICAL_COORDINATOR_V1`: one-process `RLock` held from permit through authorization commit/abort; independent CSPRNG transaction challenge and HMAC-authenticated permit; revoke commit waits for the same lock and persists head before acknowledgment | Single logical process only; no consensus, partition tolerance or multi-replica claim |
| Stale-state response | TEE reloads authenticated local snapshot and compares **both version and digest** with fresh head. Lower, higher or same-version fork all reject; no best-effort/async-only fallback | No authenticated gap-sync algorithm in V1; mismatch fails closed. Lower local state cannot reveal whether cause was rollback or freeze |
| `v_hint` | Host request carries an optional uint64 hint; every request still opens a fresh coordinator transaction, regardless of hint being below/equal/above local version | Hint is never a trusted current-head source and is not a rollback command |

The KGC plaintext snapshot field order is `Encode(KGC_SCHEMA, SysID, UInt64(committed_version), committed_digest, tuple(sorted((UID,rh_id))), tuple(sorted(committed_handles)), pending_record_or_empty_tuple, status, UInt64(snapshot_generation))`. The pending record order is `UInt64(v), UInt32(op), rh_id, prev_digest, protected_record, update_digest, expected_digest`. The independent head plaintext field order is `Encode(HEAD_SCHEMA, SysID, UInt64(v), digest, last_predecessor_digest, last_update_digest)`; at v0 the last two fields are 32 zero bytes. All three files authenticate their own schema/SysID in AEAD AD and use independently supplied 32-byte keys and fresh 12-byte nonces. The KGC UID registry is inside its private ciphertext only; the TEE snapshot contains sorted handles without UID. File-level atomic replace/fsync does not replace hardware monotonic storage.

`Rev()` persists a single pending protected Delta before returning it. `RevStateUpt()` persists set/version/digest/Ack atomically in the TEE snapshot; before KGC Ack commit, local TEE ahead of coordinator rejects authorization. The KGC verifies Ack signature, pending version/update digest/expected state digest, then advances the independent coordinator head and persists its committed KGC state. If a process stops after head persistence but before KGC persistence, the same signed Ack and recorded last head transition complete the pending KGC state idempotently after restart. **The coordinator head commit is `t_r`**, not the Rev API call, send, or TEE receive time. Authorization holds the head lock through exact RID lookup, Phase 3A ephemeral algebra, capability signing and `commit_authorization`; Auth is returned only after commit. The Phase 3B TEST coordinator remains only in regression fixtures; Phase 3C integration uses the real emulated coordinator and exact RevSet.

The three single-process authenticated files and locks validate tested ordering, not hardware freshness. An OS adversary able to roll back **all** sealed files across a full process restart may defeat this software model; trusted monotonic storage and distributed consensus remain open. Python cannot guarantee zeroization or isolation. No tree Cover/KU, public revocation TK or CT revocation component is introduced. Test-only fixed keys/nonces in `phase3c` vectors are **NOT PRODUCTION SECRET**; production defaults use CSPRNG. Prior Phase 1–3B vector fields remain unchanged (canonical JSON projection SHA-256 `545e5d1b5e8d4714d52cb9822ad2543815fdda3e44640f7e219a66be09ce54f2`). Neither operation counts nor pytest duration are performance benchmarks or formal security evidence.
