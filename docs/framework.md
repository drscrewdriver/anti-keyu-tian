# 文件指纹检查框架：怎么设

> 目标：让「有人改了重要基础设置」在**造成经济损失之前**变成一个必定被拦住的事实，而不是事故后复盘才发现。
> 配套实现：[tools/fpenv.py](../tools/fpenv.py) · 示例配置：[examples/policy.example.json](../examples/policy.example.json)

---

## 0. 一句话结论

**本机自证必败。** 有 root 的人能改文件、能改 mtime、能改你自己的日志、也能改校验脚本本身。
框架成立的前提是三个锚点都在**被测机器之外**：

| 锚点 | 放在哪 | 为什么必须在外 |
|---|---|---|
| 基线（指纹文件） | 控制面 / WORM 存储 / 代码仓库 | 放本机 = 攻击者顺手改掉，比对永远干净 |
| 密钥 | KMS 或离线，**不进训练节点** | 密钥在节点上 = 能重签，签名形同虚设 |
| 检查器 | 只读镜像 / 控制面推送 | 检查器在可写盘上 = 先改检查器，再改环境 |

一条纪律补上第四点：**永远跟「参考基线」比，不跟「上一次」比。**
跟上次比，会让多次小改动逐步漂移而不触发（漂移链攻击）；跟参考比，任何累积偏移都会暴露。

还有第五点，也是最容易漏的：**指纹一致 ≠ 合规。**

```
脏环境 → 拍下脏基线 → 之后所有比对全部 CLEAN → 问题永远发现不了
```

所以整套流程必须是三段：**① 选合规固定版本 → ② 对该版本生成指纹 → ③ 全域文件指纹检查**。
第 ① 段给指纹加外部版本锚，让「基线本身是脏的」这件事也能被发现。详见 §2。

---

## 1. 威胁模型：root 能做什么、不能做什么

本案攻击者持有 sudo。设定框架前必须先把这条边界钉死，否则会误以为「加个校验脚本就安全了」。

| 能力 | 攻击者能否做到 | 对框架的含义 |
|---|---|---|
| 改文件内容 | 能 | 内容哈希可查，但 attacker 可同时改基线 |
| 改 mtime / atime | 能（`utime`） | 时间戳不能单独作证据 |
| 改属主 / 权限位 | 能（`chown`/`chmod`） | 同上 |
| **改 ctime** | **不能**，Linux 无 `setctime` 接口 | 核心判据之一，但会被「改系统时间」绕过 |
| 改系统时钟 | 能（`CAP_SYS_TIME`） | 所以 ctime 只是辅助证据，不是唯一真相 |
| 读本机文件 | 能 | **本机密钥 = 泄露密钥** |
| 改本机日志 | 能 | 审计日志必须异地 |
| 改校验脚本 | 能 | 检查器必须只读/外部执行 |
| 改控制面的基线 | 不能（无凭证） | **真正的信任锚** |

**结论：本地检查的价值是「快速发现」，不是「最终裁决」。裁决必须来自机器外。**

---

## 2. 三段式主流程

整条流程只有三段，缺任何一段都不成立：

```
① 选合规固定版本        ② 合规生成该版本的指纹        ③ 全域文件指纹检查
   lock                   attest                        audit
   ↓                      ↓                             ↓
 release.lock.json      基线 *.fp.json（带签名）        节点/构建机执行
 人审+工单留痕           绑定 release + lock_digest     exit=0 才放行
```

### 2.1 为什么必须有第 ① 段：指纹一致 ≠ 合规

这是整套框架里最容易漏掉、也最致命的一环。

`verify` 只回答一个问题：**「现在的文件，和基线那时一样吗？」**
它没有能力回答：**「基线那时，环境本来就是对的吗？」**

如果基线是在一个**已经被污染**的环境里拍的，那么：

```
脏环境 → 拍下脏指纹 → 之后所有 verify 全部 CLEAN → 问题永远发现不了
```

本案的攻击路径正好踩在这里：改动发生在 3 月，发现已是 7 月底。若当时就建了基线，
那份基线很可能是在 3 月之后拍的 —— 一套「只比对文件」的机制会全程绿灯。

所以第 ① 段的作用是给指纹加一个**外部锚**：证明「这份指纹对应的版本，
是某个人在某个时间点、凭某个工单、正式认定过合规的」。
检查时同时验两件事，缺一不可：

| 条件 | 回答的问题 | 失败表现 |
|---|---|---|
| 文件哈希 / ctime / inode | 文件被改过吗？ | `F-CONTENT` / `F-CTIME-DRIFT` / `F-INODE-SWAP` |
| release 绑定 + lock_digest | 这份基线是合规版本的吗？ | `F-RELEASE-MISSING` / `F-RELEASE-MISMATCH` |
| 实采包版本 vs lock 记录 | 现在的环境还是那个版本吗？ | `F-LOCK-DRIFT` |

实测（`examples/pipeline_demo.py` 第 4 步）：攻击者在脏环境里重拍基线 → 文件层面完全一致、
`verify` 本会 CLEAN，但因为新基线**没有绑定合规版本**，被判 `F-RELEASE-MISSING`、`exit=3`。
这就是第 ① 段买到的东西。

### 2.2 第 ① 段：选合规固定版本（`lock`）

```bash
fpenv lock --policy policy.json \
    --release-id goku-2024-07-build-0812 \
    --ticket CHG-2024-0812 --approved-by infra-lead \
    --out release.lock.json
```

**版本从哪来、凭什么信它**是这个框架最容易被糊过去的一环，单独成篇：
[来源核对流程](provenance.md) —— 几个来源、几个人核对、几个人确认、哪些官方/镜像端点、
以及每一步对应的机器判定码。一句话概括：单源不可信、单人不可信、事后补签不可信。

锁定产物哈希（防止装错版本）：

```bash
fpenv check-source --name torch --version 2.4.0 --source pypi --source tuna --json > check.json
fpenv lock --policy policy.json --release-id torch-2.4.0-verified \
    --ticket CHG-2024-0812 --artifacts check.json --out release.lock.json
fpenv verify-artifact --file torch-2.4.0-...whl --lock release.lock.json   # 下载后必验
```

`verify-artifact` 是**双判据**：内容 sha256 对锁定值 + 文件名声称版本对锁定版本。
只判前者会漏掉「改名冒名」（实测踩到，见 [provenance.md §4.5](provenance.md)）。

产出 `release.lock.json`，内容是一份**可验证的版本声明**：

```json
{
  "schema": "fpenv-release/v1",
  "release_id": "goku-2024-07-build-0812",
  "locked_at": "2026-10-23T07:40:00Z",
  "components": {
    "python": "3.11.9",
    "kernel": "5.15.0-105-generic",
    "os": "Ubuntu 22.04.4 LTS",
    "packages": { "numpy": "1.26.4", "torch": "2.4.0", "...": "..." }
  },
  "lock_digest": "9f2a...",
  "approval": { "ticket": "CHG-2024-0812", "approved_by": "infra-lead" }
}
```

要点：

- **`lock_digest`** 是组件集合的摘要，作为「是不是同一个版本」的跨文件口径。
- **审批字段不是装饰**：真实流程里这一步应受代码评审保护，工单号进变更系统。
- **在哪个环境拍**：在**你认定它是干净的**那个时刻拍。通常 = 新镜像构建完成后、
  或一次正式变更审批通过后。这不是技术问题，是流程纪律问题。

### 2.3 第 ② 段：生成被固定版本的指纹（`attest`）

```bash
fpenv attest --policy policy.json --lock release.lock.json
```

与 `collect` 的唯一区别：**强制要求 lock，并把 release 块写进每份指纹**。
release 块参与 `root_digest` 计算，因此被签名覆盖 —— 改了就 `F-SEAL-BROKEN`。

双向防呆：

- `attest` 时若 policy 钉死的版本与本次 lock 不符 → **直接拒绝生成**（防止拿错版本去拍拓）。
- `audit` 时若基线绑定的版本与 policy 钉死值不符 → `F-RELEASE-MISMATCH`。
- 即使攻击者改了 release 块并同步重算封印与签名，`components` 与 `lock_digest`
  的自洽性校验仍会暴露（已验证，见 tests 第 [16] 场景 D）。

### 2.4 第 ③ 段：全域文件指纹检查（`audit`）

「全域」指**安全边界全集**，不是扫全盘。七类作用域固化在 `init-policy` 里：

```bash
fpenv init-policy --name ml-prod --release-id goku-2024-07-build-0812 --out policy.json
```

| 作用域 | 模式 | 为什么在这一类里 |
|---|---|---|
| `framework-libs` | content | 被 sudo 替换的就是这里（本案主战场） |
| `launcher-and-hooks` | content | 启动脚本 / init 钩子 / cron |
| `access-control` | content | SSH / sudoers / PAM / passwd —— 加一行就是永久后门 |
| `kernel-and-boot` | meta | 决定 ctime 语义与隔离能力 |
| `scheduler-env` | meta | `LD_PRELOAD` 注入入口 |
| `container-runtime` | meta | 容器配置被改 = 隔离形同虚设 |
| `audit-integrity` | content | 先关日志再动手，是最常见的第一步 |

模式分配原则：**改了必然导致训练出错或权限失守的 → `content`；改了不起眼但该知道的 → `meta`**。
后者逐字节哈希太贵，没必要。

三个执行点（缺一不可）：

| 执行点 | 时机 | 失败动作 |
|---|---|---|
| A. 启动前门禁 | 训练任务拉起前 | 拒绝启动 |
| B. 训练期巡检 | 每 N 分钟 | 告警 + 可选停训 |
| C. 控制面外扫 | 每日 + 随机 | 隔离节点（对抗本机检查被 root 关掉） |

### 2.5 三段之间的信任传递

```
 人（审批+工单）
   │ 认定
   ▼
 release.lock.json ──lock_digest──► 指纹 *.fp.json（签名覆盖 release 块）
                                        │
                                        │ 部署到控制面（WORM/Git）
                                        ▼
                                    节点 audit
                                        │
                         ┌──────────────┴──────────────┐
                    文件没变                       版本是合规的
                （哈希/ctime/inode）        （release + lock_digest + 实采包版本）
                         └──────────────┬──────────────┘
                                    两者都成立才 exit=0
```

**这条链上任一环断裂，都算信任失效（exit=3），而不是「有差异待排查」。**
区别很重要：信任失效意味着「你连基线都不可信了」，此时继续排查文件是浪费时间，应该先恢复信任链。

---

## 3. 框架五件套

### 3.1 作用域矩阵（决定盯什么）

不是所有文件都值得逐字节哈希。按「被改的后果」排序，只对后果重的用 `content` 模式：

| 作用域 | 被篡改的后果 | 模式 | 频率 |
|---|---|---|---|
| 框架库 `site-packages` | 训练结果错误、算力空转（**本案主战场**） | content | 启动前 + 每 30 分钟 |
| 启动脚本 / hook / `init.py` | 任意代码执行、定向杀进程 | content | 启动前 + 每次变更 |
| 内核 / 启动参数 / sysctl | 关掉隔离、关掉审计 | meta | 每日 |
| SSH / sudoers / PAM | 留后门、提权 | content | 每小时（有堡垒机可降为每日） |
| 环境变量 / `ld.so.conf` | `LD_PRELOAD` 注入 | meta | 每小时 |
| 数据与权重 | 投毒（另一条线，见 [docs/outline.md](outline.md) 4.8） | hash 对拍 | 每次加载 |

完整示例见 [examples/policy.example.json](../examples/policy.example.json)。

### 3.2 基线管理

- **谁生成**：镜像构建流水线（不是运行中的节点）。
- **何时生成**：镜像构建后、每次经审批的变更后。绝不「发现差异就重拍」——那是把告警变成橡皮图章。
- **存哪**：控制面对象存储（开版本控制 + 对象锁/WORM），或直接进 Git。不进训练节点本地盘。
- **签名**：见 §4。
- **命名**：`<镜像 digest>/<scope>.fp.json`，与镜像一一对应，避免「不知道这份基线对应哪个版本」。
- **保留**：至少保留最近 N 个版本，事故复盘要做 `diff`。

### 3.3 检查执行点（三个，缺一不可）

| 执行点 | 时机 | 失败动作 | 对抗什么 |
|---|---|---|---|
| **A. 启动前门禁** | 训练任务拉起前 | 直接拒绝启动 | 环境已被改还继续烧卡 |
| **B. 训练期巡检** | 每 N 分钟（sidecar / systemd timer） | 告警 + 可选停训 | 运行中被改（本案手法） |
| **C. 控制面外扫** | 每日 + 随机 | 直接隔离节点 | 本机检查被绕过（root 级） |

C 是关键：节点上的检查可能被 root 关掉或伪造结果，控制面对比**该节点上报的指纹**与**基线**，才是不可绕过的。

> **堡垒机能否替代 C？不能。** 堡垒机管「谁登进来」，不管「训练进程改了什么」。
> 详见 [audit-chain.md §8](audit-chain.md) 的取舍表。

### 3.4 信任锚（最容易做错的一环）

三种方案，按强度排列：

| 方案 | 密钥在哪 | 能对抗什么 | 成本 |
|---|---|---|---|
| **控制面签名 + 节点只验** | 公私钥；节点只有公钥 | 内鬼改环境后无法重签基线 | 中（需非对称签名） |
| 节点持有对称密钥（**当前实现**） | 节点 | 基线被单独篡改；**不能**对抗拿到 root 的人重签 | 低 |
| 无签名 | — | 基本只能防手滑 | 无 |

> **诚实说明**：当前 `fpenv.py` 用的是 HMAC-SHA256，密钥通过 `--key-env` 注入。这能防「有人偷改基线文件」，**防不住**「有 root 的人读出密钥后重签」。
> 要真正对抗本案这种有 sudo 的内部人，必须换成 Ed25519：私钥留控制面，节点只放公钥验签。这是 P1 的升级项，已列进待验证清单。

### 3.5 响应与取证

- **结构化落盘**：`--json` 输出，字段稳定，可直接进日志管道。
- **异地投递**：检查结果推到控制面/日志中心。**本地日志可被删**，不算证据。
- **分级**：
  - `F-SEAL-BROKEN` / `F-SIG-INVALID` / `F-UNSIGNED` / `F-BASELINE-MISSING` / `F-CHECKER-MISMATCH` → **信任锚失效，立即停训 + 隔离节点**，不要继续排查。
  - `F-CONTENT` / `F-UNEXPECTED` / `F-MISSING` / `F-BACKDATED` → 高危，停该任务，保留现场（内存/进程/挂载），不重启。
  - `F-CTIME-DRIFT` / `F-INODE-SWAP` / `F-MODE` / `F-OWNER` → 高危待判，拉变更记录对账。
- **保留现场优先于恢复服务**：重启会清掉容器 upper 层和进程树，本案最关键的证据就没了。

---

## 4. 落地路径（按成本/收益排序）

### P0（一周内，几乎零成本）

1. 对 `site-packages` + 启动脚本跑 `collect`，基线进 Git/对象存储。
2. 训练启动脚本前加一行 `fpenv audit --policy ... || exit 1`。
3. 容器去 `sudo`、`site-packages` 只读挂载 —— 让「就地替换」这条路物理上不存在。

验收：手动改一个 `.py` 再还原 mtime，训练必须拒绝启动并报出 `F-CONTENT` + `F-BACKDATED`。
（已验证，见 [tests/test_fpenv.py](../tests/test_fpenv.py)）

### P1（一个月）

4. sidecar 每 30 分钟巡检，结果推日志中心。
5. 换 Ed25519 签名，节点只放公钥。
6. 控制面每日外扫，比对节点上报的 `root_digest` 与基线。
7. 变更审批 → 自动重拍拓 → 基线版本化。

验收：模拟「root 删掉 sidecar 并伪造 clean 输出」，控制面必须报出节点静默。

### P2（季度）

8. 与镜像签名（cosign）打通，基线绑定镜像 digest。
9. 告警接入值班，按「影响 GPU 小时」分级。
10. 定期红队演练：只给出「改环境不被发现」的目标，验证框架有效性。

---

## 5. 误报治理（决定这套东西能不能活下去）

框架最常见的死法不是被打穿，是**告警太多被无视**。

- **变更窗口**：任何 `apt`/`pip`/配置变更后，走审批 → 重拍拓，而不是「忽略告警」。
- **区分「该报」和「不该报」**：
  - `__pycache__`、`*.pyc`、日志、临时文件 → 基线阶段 exclude。
  - pip 解包保留 wheel 内 mtime 是**正常现象**，所以判据是「相对基线的倒挂」，不是绝对 `mtime < ctime`（这一点在实现时踩过，见 tests 第 [2] 项注释）。
- **容忍窗口**：`F-CTIME-DRIFT` 允许与已登记的变更记录对齐（谁、何时、工单号）。
- **性能**：`content` 模式在上万文件规模下的耗时未实测（见待验证清单）。大目录先用 `meta` 做高频巡检，`content` 只在启动前跑。

---

## 6. 与经济损失的对应关系

| 场景 | 不装框架的损失 | 装上之后的拦截点 |
|---|---|---|
| 框架库被改，loss 异常，团队排查 2 个月 | 数十人月 + 数千卡时 | 启动前门禁直接拦住 |
| 运行中被改，训练悄悄变差，产出模型不可用 | 重训成本 + 交付延期 | 30 分钟巡检发现 ctime 漂移 |
| 权重/checkpoint 被动过 | 静默错误模型上线 | 加载前 hash 对拍（另一条线） |
| 后门长期驻留，后续任意时刻再破坏 | 不可估量 | 每日外扫 + `authorized_keys` 基线 |

停训一次的成本是**可数的**（几十分钟卡时）；带毒训练一次的成本是**不可数的**（可能几周后才发现，且无法判断哪些实验受影响）。分级阈值应该按这个不对称来定，而不是按告警数量。

---

## 7. 已知边界（必须写清楚，否则不可信）

1. **HMAC 对称密钥**：节点上有密钥时，root 可重签。需升级 Ed25519（P1）。
2. **改系统时钟**：root 可回拨时钟，使 `ctime` 落在合理范围，规避 `F-CTIME-DRIFT`。缓解：控制面用自己时钟记录首次发现时间；节点时间源强制 NTP + 监控时钟偏移。
3. **内核级 rootkit**：可拦截 `stat`/`getdents` 返回伪造数据。本框架无法对抗，需 IMA/dm-verity 或硬件度量。
4. **overlayfs 白障**：容器层差异在重启后可能消失，必须落盘留存。
5. **性能未实测**：`content` 模式在上万文件下的耗时、对训练 I/O 的影响，尚无数据。**这一条未验证前不要在生产大集群上默认开 content 高频巡检。**
6. **Windows**：`ctime` 是创建时间，语义不同，`auto` 模式会关闭相关判据，只保留内容/大小/元数据比对。

---

## 8. 快速开始

```bash
# 0) 生成全域 policy（七类安全边界）
python3 tools/fpenv.py init-policy --name ml-prod \
    --baseline-dir /var/lib/fpenv/baselines \
    --release-id 2024-07-build-0812 --out policy.json

# ① 选定合规版本（人工审批 + 工单），产出 release lock
python3 tools/fpenv.py lock --policy policy.json --release-id 2024-07-build-0812 \
    --ticket CHG-2024-0812 --approved-by infra-lead --out release.lock.json

# 把 release_id / lock_digest 钉进 policy.json 的 release 段（受代码评审保护）

# ② 合规生成被固定版本的指纹（密钥从 KMS 注入，不落盘）
export FPENV_KEY="$(kms get fpenv/hmac)"
python3 tools/fpenv.py attest --policy policy.json --lock release.lock.json

# 基线部署到控制面（WORM / Git），节点本地不留可写副本

# ③ 全域检查
python3 tools/fpenv.py audit --policy /etc/fpenv/policy.json || { echo "环境不可信，拒绝启动"; exit 1; }
python3 tools/fpenv.py audit --policy /etc/fpenv/policy.json --json >> /var/log/fpenv.jsonl

# 事故复盘：与历史基线比对
python3 tools/fpenv.py diff --a baselines/old.fp.json --b baselines/new.fp.json
```

一条命令看全流程：`python3 examples/pipeline_demo.py`

退出码：`0` 两条件都成立（放行）· `2` 文件层面达到 `fail_on` 阈值 · `3` 信任链断裂
（基线缺失/签名无效/未签名/检查器被改/**版本未绑定或与合规版本不符**/包版本漂移）。

---

## 附：待验证清单

| 项 | 状态 |
|---|---|
| 篡改 + `utime` 还原 + `chmod` 还原 → 三判据命中 | ✅ 已验证 |
| policy 多作用域聚合、退出码、缺基线、检查器自校验 | ✅ 已验证 |
| `lock` → `attest` → `audit` 三段式：版本绑定、错版本拒绝、脏基线拦截 | ✅ 已验证 |
| release 块被改 + 同步重算封印/签名 → 自洽性校验暴露 | ✅ 已验证 |
| 包版本漂移（多装/版本变）→ `F-LOCK-DRIFT` | ✅ 已验证 |
| 全域 policy 模板（7 类作用域）可直接加载 | ✅ 已验证 |
| 合计自测 | ✅ 86/86 通过（WSL Ubuntu / Python 3.12.3） |
| 多源核对真实网络（torch 2.4.0：PyPI + 清华/阿里/中科大）→ agree | ✅ 已验证（8 文件哈希一致） |
| 真实 torch wheel 下载 + 锁定指纹校验 | ✅ 已验证（59.2MB / 2.8s / sha256 命中） |
| 篡改文件 / 改名冒名 → `verify-artifact` exit=3 | ✅ 已验证 |
| **`content` 模式万文件耗时** | ✅ 已测：真实 torch 解包 **10941 文件 / 0.5 秒** |
| overlayfs 跨层白障在真实容器里的表现 | ❌ 未测 |
| 改系统时钟对 `F-CTIME-DRIFT` 的实际规避效果 | ❌ 未测 |
| Ed25519 替换 HMAC（对抗持 root 的内部人重签） | ❌ 未实现 |
| conda / apt 源的来源核对解析器 | ❌ 未实现（当前只有 PyPI 生态） |
| 多人核对的「独立性」机器验证 | ❌ 无法验证（只能验填了几个人，验不了是否真的各自取数） |
