# 信任锚的来源核对流程

> 回答一个问题：**「锁定这个版本」这件事，凭什么可信？**
> 配套实现：`tools/fpenv.py` 的 `check-source` / `verify-artifact` / `lock --artifacts` / `provenance-template`
> 实测脚本：[examples/pytorch_lock_demo.py](../examples/pytorch_lock_demo.py)（真实 torch wheel 全流程）

---

## 0. 一句话结论

**单源不可信，单人不可信，事后补签不可信。**

所以核对由三件事共同成立：**多个来源对上哈希** + **多个角色分别签核** + **签核发生在锁定之前**。
这三条都不是纸面制度 —— 每一条都有对应的机器判定码，不满足就 `exit=3`，训练起不来。

---

## 1. 为什么必须多源：单源失效的四种方式

| 失效方式 | 说明 | 多源能否发现 |
|---|---|---|
| 镜像滞后 | 国内镜像同步延迟，拿到的是旧版或残缺索引 | 能（版本/哈希与官方不符） |
| 镜像被替换 | 镜像站被入侵，包体被换 | 能（哈希与官方不符） |
| 上游被投毒 | PyPI 上某个版本本身被恶意上传 | **不能** —— 所有源都会一致，这靠的是版本登记与人工审查 |
| 下载链路被污染 | 下载到的字节与索引声明不一致 | 能（`verify-artifact` 比对锁定值） |

**关键认知：多源核对解决的是「来源之间不一致」和「下载链路问题」，解决不了「上游本身被投毒」。**
后者只能靠版本白名单 + 人工审查 + 延迟窗口（不追最新版）。这个边界必须写清楚，否则会给人虚假安全感。

---

## 2. 来源分级：official 与 mirror 不能等价

| 级别 | 含义 | 能否单独作为依据 |
|---|---|---|
| **official** | 上游作者/发行方自己发布的端点 | **必须至少有一个**，否则判 `no-official` |
| **mirror** | 第三方镜像 | **不能**，只能交叉验证 |

已注册来源清单（`tools/fpenv.py` 的 `SOURCE_REGISTRY`）：

| id | 级别 | 端点类型 | 用途 |
|---|---|---|---|
| `pypi` | official | PyPI JSON API `/pypi/{name}/{version}/json` | 权威哈希（含 `digests.sha256`） |
| `pypi-simple` | official | PEP 503 `/simple/{name}/` | 官方索引交叉 |
| `pytorch` | official | `download.pytorch.org/whl/{name}/` | PyTorch 官方 wheel（含 CUDA 变体） |
| `tuna` | mirror | 清华 TUNA `/simple/` | 国内主用 |
| `aliyun` | mirror | 阿里云 `/simple/` | 交叉 |
| `ustc` | mirror | 中科大 `/simple/` | 交叉 |
| `tencent` | mirror | 腾讯云 `/simple/` | 交叉 |

> **实测结论（2026-10-23）**：镜像站**没有** PyPI JSON API（返回 404），只有 PEP 503 simple index。
> 所以正确做法是：**官方 JSON 拿权威哈希 + 各镜像 simple index 拿交叉证据**。
> 代码里按 `kind` 字段区分两类端点，用错了会失败而不是静默取到空值。

---

## 3. 人数与角色：几人核对、几人确认

### 3.1 默认配额

| 场景 | 核对人（check） | 确认人（approve） | 依据 |
|---|---|---|---|
| 关键组件（框架库、CUDA、推理引擎） | **≥3** | ≥1 | 三人核对，避免两人同时被同一错误说服 |
| 普通依赖 | ≥2 | ≥1 | 双人复核 |
| 紧急安全补丁 | ≥2 | ≥1 + 事后复核 | 缩到 2 人在 24h 内，补一次完整核对 |

**硬约束：同一人不得同时担任核对人与确认人**（`F-PROVENANCE-QUORUM` 会拦）。
理由很直接 —— 自己核自己确认，等于没有第二个人看过。

### 3.2 为什么是 3 而不是 2

本案的核心教训之一是「攻击者能实时了解排查进展并调整」。类比到核对环节：
两个人如果都在同一个信息环境里（同一份聊天记录、同一个上游公告），很可能同时被同一个伪造信息说服。
三个人的价值不在「多一双眼睛」，而在**降低同源信息同时失效的概率** —— 所以理想情况下第三个人应当独立取数（自己跑 `check-source`），而不是看前两人的结论。

### 3.3 角色填写方式（这就是机器判定的输入）

```json
"reviewers": [
  { "name": "alice", "role": "check",   "at": "2026-10-20T09:12:00Z" },
  { "name": "bob",   "role": "check",   "at": "2026-10-20T10:03:00Z" },
  { "name": "carol", "role": "check",   "at": "2026-10-20T14:40:00Z" },
  { "name": "dave",  "role": "approve", "at": "2026-10-21T08:00:00Z" }
]
```

- `at` 必须是各自实际取数的时间，**不能批量填同一个时间**（那是走过场的信号）。
- 所有 `at` 必须 **早于版本锁定时间** `lock.locked_at`，否则判 `F-PROVENANCE-STALE`
  —— 补签不算核对，这条专门防「出事后补流程」。

---

## 4. 操作流程（照做即可）

### 4.1 第一步：核对人独立取数

每个核对人**各自**执行（不要共享输出文件）：

```bash
fpenv check-source --name torch --version 2.4.0 \
    --file-contains cp311 --file-contains manylinux1_x86_64 \
    --source pypi --source tuna --source aliyun --source ustc \
    --json > alice-torch-2.4.0.json
```

输出里的 `verdict` 含义：

| verdict | exit | 处置 |
|---|---|---|
| `agree` | 0 | 通过，可进入下一步 |
| `conflict` | 3 | **立即停机上报**，不要继续，不要「先装了再说」 |
| `single` | 2 | 只有一个源成功，网络问题或端点异常，重试；仍单源则不得通过 |
| `no-official` | 2 | 只有镜像，缺第一事实源，必须补 official |
| `version-not-found` | 2 | 版本号错 / 该源无此版本，先确认版本是否真实存在 |

### 4.2 第二步：比对三个人的结果

三个人的 `agree` 字典必须**完全一致**。不一致说明：
- 有人在不同的时间点取数，而期间镜像变了（**这本身就是高危信号**，要查）；
- 或者有人取错了包/版本。

这一步目前需要人做（脚本无法判断「三个人是否独立」）。**但结论会被第三步的机器校验兜住**：
只要最终记录的 `sources` 里 official 与 mirror 的哈希不一致，`F-PROVENANCE-CONFLICT` 直接拦住。

### 4.3 第三步：填 provenance 记录

```bash
fpenv provenance-template --lock release.lock.json --policy policy.json --critical-only
```

生成的模板里每个组件已有 `sources` 骨架，核对人填入实际 `sha256`、`url`、`fetched_at`、`verdict`。
填完提交到代码仓库（**进评审，进版本历史**）。

### 4.4 第四步：锁定（含产物哈希）

```bash
fpenv lock --policy policy.json --release-id 2024-07-build-0812 \
    --ticket CHG-2024-0812 --approved-by infra-lead \
    --artifacts alice-torch-2.4.0.json \
    --provenance release.provenance.json \
    --out release.lock.json
```

两条硬拒绝：

- `--artifacts` 里 `verdict` 不是 `agree` → **拒绝锁定**（不允许锁定未通过核对的产物）。
- `--provenance` 的 `release_id` 与本次不一致 → 拒绝。

### 4.5 第五步：下载后校验（防错误下载）

```bash
fpenv verify-artifact --file torch-2.4.0-cp311-cp311-manylinux1_x86_64.whl \
    --lock release.lock.json
```

**双判据，缺一不可**：

| 判据 | 防的场景 | 实测反例 |
|---|---|---|
| 内容 sha256 == 锁定值 | 镜像给错文件、缓存污染、中间人替换 | 改 1 字节 → exit=3 |
| 文件名声称版本 == 锁定条目版本 | **改名冒名**：拿 2.4.0 的字节当 2.4.1 用 | 改名成 2.4.1 → exit=3 |

> **这一条是实测踩出来的**：最初只判内容哈希，演示第 4c 步「内容正确但改名为 2.4.1」直接被放行（exit=0）。
> 补上版本声明解析后才拦住。只判哈希的机制在「装错版本」这个目标上是**不完整的**。

### 4.6 第六步：安装生成物锁定

```bash
# pip install 之后（或解包后）
fpenv attest --policy policy.json --lock release.lock.json   # 对 site-packages 拍拓
fpenv audit  --policy policy.json                            # 之后任何改动都会被检出
```

实测数据（真实 torch 2.4.0 arm64 wheel 解包）：**10941 个文件，content 模式拍拓 0.5 秒**。
这个量级说明 `content` 模式在万文件规模下完全可用 —— 之前列的「未测」项现已填上。

---

## 5. 判定码总表（可信度相关的全部）

| 码 | 含义 | 严重度 | exit |
|---|---|---|---|
| `F-PROVENANCE-MISSING` | policy 要求核对但基线无 provenance 记录 | critical | 3 |
| `F-PROVENANCE-STALE` | prov 版本不符 / 签核时间晚于锁定时间 | critical | 3 |
| `F-PROVENANCE-THIN` | 关键组件来源不足 2 个 / 缺 official / 无核对记录 | critical | 3 |
| `F-PROVENANCE-CONFLICT` | 多来源哈希不一致 / verdict 非 agree | critical | 3 |
| `F-PROVENANCE-QUORUM` | 核对人/确认人人数不足，或角色兼任 | critical | 3 |
| `F-RELEASE-MISSING` | 基线未绑定版本 | critical | 3 |
| `F-RELEASE-MISMATCH` | 绑定版本 ≠ 合规版本 / release 块不自洽 | critical | 3 |
| `F-LOCK-DRIFT` | 实采包版本偏离 lock | critical | 3 |

全部归入「信任链断裂」，与普通文件差异（`exit=2`）分开处理。**区别很重要**：
exit=3 意味着「你连基线都不该信」，此时继续排查文件是浪费时间，应当先恢复信任链。

---

## 6. 反面清单（这些做法等于没做核对）

- ❌ 三个人看同一份输出文件 → 只有一个人真做了，另外两个是背书
- ❌ 只对镜像取数（`no-official`）→ 镜像滞后或被替换时无人可知
- ❌ 用 `latest` / 不写死版本 → 无法核对，也无法复现
- ❌ 核对完成后改 policy 或 lock 里的版本号 → `F-RELEASE-MISMATCH` 会露
- ❌ 出事之后补一份 provenance 记录 → `at` 晚于 `locked_at`，`F-PROVENANCE-STALE`
- ❌ 把 `verdict` 手填成 `agree` 但不填 `sha256` → 来源数为 0，`F-PROVENANCE-THIN`
- ❌ 只校验下载文件大小 → 大小相同内容不同的情况很常见
- ❌ 只校验内容哈希不校验版本声明 → 改名冒名可通过（本演示实测过）

---

## 7. 已知边界

1. **上游投毒不可防**：多源全一致时无从发现。缓解靠版本白名单与延迟窗口（不追最新版本）。
2. **镜像同步时差**：不同时刻取数可能得到不同结果；核对必须在同一时间窗口内完成，且记录 `fetched_at`。
3. **人数无法机器验证独立性**：机器只能验「填了几个不同的人」，不能验「是不是真的各自独立取数」。这是流程责任，不是技术能解决的。
4. **conda / 系统包管理器未覆盖**：当前 `check-source` 只实现了 PyPI 生态（official JSON + simple index）。conda channel、apt 源需要各自加解析器。
5. **镜像的 simple index 可能不全**：实测清华镜像对 torch 2.4.0 只列出 8 个文件，而 PyPI 官方 JSON 有 20 个。交叉时以交集为准，缺失不判失败（判 `agree` 只要求同名文件哈希一致）。
