# anti-keyu-tian

面向 **ML 平台 / 训练环境** 的防御机制。核心是一个**基于指纹文件（manifest）的环境防篡改机制**：
把「有人动过环境」从一件靠感觉的事，变成一个**有退出码、能进门禁、能留证据**的判定。

背景事件：2024 年字节跳动训练破坏事件（田柯宇 / Keyu Tian）中，攻击者持续就地改写训练集群里的
PyTorch 源码、换数据采样种子、把 `sudo mv` 覆盖已安装库后用 `os.utime` 还原时间戳——故障被伪装成
随机硬件问题，团队排查数月。真正让事情露头的只是一次偶然的源码对读。

## 为什么值得做（写给要拍板的人）

技术细节在后面。先说三件不需要技术也能判断的事。

**一、给出 root 密码时，你同时给出了「出事后能不能查清」这个能力。**
同一个口令被三个人知道，那台机器上发生的一切就再也无法归因。半年后某次训练结果异常，
你能确认的只有「有人用 root 干过」，不能确认是谁。这时候所谓的「信任」，其实已经变成了「放弃追查」。

**二、信任是有成本的，只是记账在以后。**
- **本金**：一次违约的实际损失——算力、返工、事故处置。这是唯一被认真算过的部分。
- **利息**：违约后每一次需要证明清白的成本。一个人的违约，让所有人多背一套流程。
- **复利**：机制没建立时，人事一变动，这笔债重新欠一遍。同一类事故在不同团队反复发生，
  不是因为大家蠢，是每个组织都在用自己的学费买同一个教训。

**三、审计是给诚实的人准备的，不是防着人。**
有记录，好人才能被证明清白——没记录，出事时所有人都在嫌疑名单上，包括你。
更重要的是：**制度存在的意义之一，是把「得罪人」这件事从个人身上拿走。**
一个 SRE 最难的不是技术判断，是在「同事开口要权限」时说不了「不」；这个「不」写在制度里，
他就不必用自己的关系去付这笔成本。

本案被摧毁的不只是算力。受害者陈述里有一句：*「反复的失败……逐渐让人开始怀疑自己的技术判断，
甚至怀疑这些排查工作究竟还有没有意义。」* 这种损伤不会写进事故报告，恢复期却远超故障本身。

> 完整论述见 [docs/why.md](docs/why.md)。

## 为什么是 ML 平台（而不只是「任何系统」）

上一节说的是通用道理。ML 平台有它独有的结构性暴露，这决定了本仓库机制的具体形状：

| 性质 | 后果 |
|---|---|
| **错误是沉默的** | 训练「跑完了」和「跑对了」在日志上长得一样，没有 500 会告诉你 |
| **攻击者藏在噪声里** | 分布式训练本来就偶发异常，改种子/跳通信/kill 进程都能伪装成已知故障 |
| **没有 reference output** | 随机 + 重训代价高 + 无金标准，无法像其他系统那样「重跑一遍对比」 |
| **杠杆比极高** | `maximize = True` 一个字符串，换来五个月排查与数千卡时 |
| **资产密度高** | 损失单位是 GPU 小时，可直接换算成钱——这让 ROI 反而容易算 |
| **信任边界天然模糊** | 共享存储、多团队、实习生流动，是协作的必要条件而非疏忽 |
| **供应链是活的** | 被改的是运行时的 `site-packages`，`requirements.txt` 和 code review 全都看不见 |
| **验收依赖相信报告者** | 无法 review 一次训练，只能信周报与 demo |
| **时间放大** | 三周训练第二天被注入，后十九天全废；污染还会随 checkpoint 继承 |

**最深的一条是「藏在噪声里」**：它意味着在 ML 平台上，「异常检测」这条路先天不成立——
你无法从现象区分故障与攻击。所以唯一可行的方向是反过来：
不去抓异常，而是**证明「不该变的东西没变」**。本仓库整套机制都是这个判断的产物。

> 完整论述（含「什么样的 ML 平台不需要这些」的边界）见 [docs/why-ml.md](docs/why-ml.md)。

## 一句话结论

攻击者能还原 `mtime`、属主、权限位，**但还原不了 inode `ctime`**，也伪造不了签名后的指纹文件。
防御杠杆点在这两处，不在 `ls -l`。

而比「查得出被改过」更根本的一件事：**指纹能证明「现在对不对」，证明不了「曾经发生过什么」。**
所以除了指纹，还需要三条独立证据链——不可撤销日志、实时修改事件、源码与产物签名。
详见 [第四条线](#第四条线不可撤销证据)。

## 交付物

| 路径 | 内容 |
|---|---|
| [tools/fpenv.py](tools/fpenv.py) | 指纹与证据链本体，19 个子命令，仅标准库（Ed25519 需 cryptography） |
| [tests/test_fpenv.py](tests/test_fpenv.py) | 116 项自测：篡改反取证、policy 聚合、版本锚、来源核对、日志链、git、checkpoint |
| [docs/why.md](docs/why.md) | **为什么值得建**：root 密码的隐性条款、信任成本债、审计是给诚实的人准备的 |
| [docs/why-ml.md](docs/why-ml.md) | **为什么是 ML 平台**：错误沉默、藏在噪声里、无 reference output、杠杆比、资产密度 |
| [docs/framework.md](docs/framework.md) | **怎么设这套框架**：三段式主流程、威胁模型、五件套、落地路径、误报治理、已知边界 |
| [docs/provenance.md](docs/provenance.md) | **信任锚的来源核对流程**：几个来源 / 几人核对 / 几人确认 / 哪些官方与镜像端点 / 判定码 |
| [docs/audit-chain.md](docs/audit-chain.md) | **不可撤销证据**：哈希链日志、inotify 修改记录、git 源码链、签名 checkpoint |
| [docs/outline.md](docs/outline.md) | 防御大纲：攻击谱系 × 指纹特征 × 分层对策 |
| [examples/policy.example.json](examples/policy.example.json) | 多作用域 policy 示例（框架库/启动脚本/内核/准入控制/调度环境） |
| [examples/demo.py](examples/demo.py) | 演示一：拍拓 → 篡改并反取证 → audit 拦截 |
| [examples/pipeline_demo.py](examples/pipeline_demo.py) | 演示二：合规版本固定 → 指纹绑定 → 全域检查（含脏基线拦截） |
| [examples/pytorch_lock_demo.py](examples/pytorch_lock_demo.py) | 演示三：**真实 PyTorch** 多源核验 → 锁定 → 下载校验 → 安装产物拍拓 → 篡改检出 |
| [examples/provenance_chain_demo.py](examples/provenance_chain_demo.py) | 演示四：不可撤销日志 / inotify 事件 / git 源码链 / 签名 checkpoint |

## 三段式主流程

```
① 选合规固定版本        ② 合规生成该版本的指纹        ③ 全域文件指纹检查
   fpenv lock             fpenv attest                  fpenv audit
   多源核对 + 多人签核      绑定 release + lock_digest     exit=0 才放行
   ↓                      ↓                             ↓
 release.lock.json      基线 *.fp.json（签名覆盖）      节点 / 构建机
 含产物 sha256           含 release 块                  含版本锚校验
```

**为什么必须有第 ① 段**：`verify` 只能回答「文件变了没」，回答不了「基线本身是不是脏的」。
在已被污染的环境里拍的基线，之后所有比对都会 CLEAN —— 那才是最危险的情形。详见
[docs/framework.md §2](docs/framework.md)。

**版本凭什么可信**：单源不可信、单人不可信、事后补签不可信。多源交叉（official + mirror）+
多角色签核（关键组件 3 人核对 / 1 人确认，且不得兼任）全部落成机器判定码，不满足即 exit=3。
详见 [docs/provenance.md](docs/provenance.md)。

## 第四条线：不可撤销证据

指纹只回答「现在对不对」。另一半问题是**「什么时候被改的、能不能事后抹掉」** ——
攻击者能还原文件内容、mtime、权限，让指纹完全干净，但抹不掉已发生的事件。

```
① journal     哈希链 + Ed25519 逐条签名   改/删/重排/重算/清空 全部可检出（需外部锚定）
② watch-fs    inotify 实时事件            「改完再还原」也能证明它被写过
③ git-audit   借 git 的提交链             工作区漂移 / amend 重写 / 未跟踪后门
④ checkpoint  分片流式签名                改内容 / 回滚冒充 / 张冠李戴 / 改签名
```

详见 [docs/audit-chain.md](docs/audit-chain.md)。

**加堡垒机之后能砍什么**：堡垒机换掉的是「身份」，不是「完整性」——只有 `journal` 的 `actor`
归因和「节点登录审计」可以砍/降级；指纹、事件链、git、checkpoint 全部保留（它们管的是程序行为，
不经过交互登录）。且必须同时落实三个前提：网络层强制节点只接受堡垒机来源、会话录制实时异地、
堡垒机账号到节点账号一对一映射。取舍表见 [audit-chain.md §8](docs/audit-chain.md)。

**一条实测踩到的防线**：`verify_journal` 最初写 `if not sig: continue`，于是「改内容 + 重算整条链 +
抹掉签名」得到一条自洽且一路绿灯的链。现在缺失签名默认判 critical —— **「校验存在与否」本身也是一个
必须校验的维度**。

## 机制怎么工作

```
构建机（密钥来自 KMS）── fpenv collect ──► 基线（控制面 / WORM / Git）
                                                    │
训练节点启动前 ── fpenv audit ──────────────────────┤  差异 → exit≠0 → 拒绝启动
训练期 sidecar ── fpenv audit（每 N 分钟）───────────┤  差异 → 告警 + 落盘
控制面外扫     ── 比对节点上报的 root_digest ────────┘  节点静默 = 高危
```

**三个锚点都在机器外**：基线不在节点、密钥不进节点、检查器只读。这是框架成立的前提，
详见 [docs/framework.md](docs/framework.md) §0–§2.4。

判定项（每条都有独立证据，不靠单一信号）：

| 代码 | 含义 | 严重度 |
|---|---|---|
| `F-CONTENT` | 文件内容哈希 / 大小变了 | critical |
| `F-CTIME-DRIFT` | inode ctime 变了（用户态改不掉） | high |
| `F-BACKDATED` | 内容已变但 mtime 仍是基线值 = 时间被回填 | critical |
| `F-INODE-SWAP` | inode 变了 = 整体替换原文件 | high/critical |
| `F-UNEXPECTED` | 基线里没有的新文件（后门 / 启动钩子） | critical |
| `F-MISSING` | 基线里有、现在没了 | critical |
| `F-MODE` / `F-OWNER` | 权限位 / 属主变化 | high |
| `F-SEAL-BROKEN` | 指纹文件自身被改动（封印摘要不符） | critical |
| `F-SIG-INVALID` | 签名不匹配 = 指纹不是可信方生成的 | critical |
| `F-UNSIGNED` | policy 要求签名但基线未签名 | critical |
| `F-BASELINE-MISSING` | 该作用域的基线文件不存在 | critical |
| `F-CHECKER-MISMATCH` | 检查器自身摘要与 policy 钉死值不符 | critical |
| `F-RELEASE-MISSING` | policy 要求强制版本但基线未绑定 release | critical |
| `F-RELEASE-MISMATCH` | 基线绑定版本 ≠ 合规固定版本 / release 块不自洽 | critical |
| `F-RELEASE-UNPINNED` | policy 声明强制版本却没钉死 `release.expected` | critical |
| `F-LOCK-DRIFT` | 实采包版本偏离 lock 记录（版本变了 / 多装了包） | critical/high |
| `F-PROVENANCE-MISSING` | policy 要求来源核对但基线无 provenance 记录 | critical |
| `F-PROVENANCE-THIN` | 关键组件来源不足 2 个 / 缺 official / 无核对记录 | critical |
| `F-PROVENANCE-CONFLICT` | 多来源哈希不一致 / verdict 非 agree | critical |
| `F-PROVENANCE-QUORUM` | 核对人 / 确认人人数不足，或同一人兼任两角 | critical |
| `F-PROVENANCE-STALE` | prov 版本不符 / 签核时间晚于版本锁定（补签） | critical |
| `J-HASH-MISMATCH` / `J-CHAIN-BROKEN` / `J-SEQ-GAP` | 日志被改 / 链断 / 条目被删或重排 | critical |
| `J-UNSIGNED` / `J-SIG-INVALID` | 签名被抹掉 / 伪造（重算链后必然暴露） | critical |
| `J-TRUNCATED` / `J-ANCHOR-MISMATCH` | 日志被清空或截断 / 与外部锚定值不符 | critical |
| `G-DIRTY` / `G-UNTRACKED` / `G-HISTORY-REWRITTEN` | 源码漂移 / 后门文件 / 历史被 amend 重写 | critical |
| `C-CONTENT` / `C-ROLLBACK` / `C-SIG-TAMPERED` | checkpoint 被改 / 回滚冒充 / 签名文件被改 | critical |

退出码：`0` 干净 / `2` 有达阈差异 / `3` 信任链断裂（基线缺失、签名无效、未签名、检查器被改、版本未绑定或错版本、来源核对不过关）。
**可直接作为 CI 与训练启动的门禁。**

## 用法

```bash
# 全流程演示（临时目录，不碰真实环境）
python3 examples/provenance_chain_demo.py # 不可撤销日志 / inotify / git / 签名 checkpoint
python3 examples/pytorch_lock_demo.py  # 真实 PyTorch：多源核验→锁定→下载校验→产物拍拓→篡改检出
python3 examples/pipeline_demo.py      # 三段式：lock → attest → audit（含脏基线拦截）
python3 examples/demo.py               # 单点：拍拓 → 篡改并反取证 → 拦截

# 密钥（Ed25519）：私钥留控制面，公钥下发节点
python3 tools/fpenv.py keygen --priv ed25519.key --pub ed25519.pub

# 不可撤销日志：记事件 → 定期锚定到机器外 → 校验
python3 tools/fpenv.py journal append --journal audit.jsonl --kind fs.modify \
    --path src/train.py --priv ed25519.key --pub ed25519.pub
python3 tools/fpenv.py journal anchor --journal audit.jsonl --out audit.anchor.json --priv ed25519.key
python3 tools/fpenv.py journal verify --journal audit.jsonl --anchor audit.anchor.json --pub ed25519.pub

# 文件修改记录（inotify，无需 root）
python3 tools/fpenv.py watch-fs --root /opt/train --journal audit.jsonl --duration 3600

# 源码审计（expected-head 必须来自本机之外）
python3 tools/fpenv.py git-audit --repo . --expected-head <上次审计HEAD> --allow-branch main

# 生成物 / checkpoint 签名与验证
python3 tools/fpenv.py sign-checkpoint --path goku-step12000.pt --priv ed25519.key \
    --meta step=12000 --meta trial=goku-7b
python3 tools/fpenv.py verify-checkpoint --path goku-step12000.pt \
    --sig goku-step12000.pt.sig.json --pub ed25519.pub --min-step 10000

# 0) 生成全域 policy（七类安全边界）
python3 tools/fpenv.py init-policy --name ml-prod \
    --baseline-dir /var/lib/fpenv/baselines --release-id 2024-07-build-0812 --out policy.json

# ①-前置 多源核对下载指纹（official + mirror，缺 official 即不过）
python3 tools/fpenv.py check-source --name torch --version 2.4.0 \
    --source pypi --source tuna --source aliyun --json > check.json

# ① 固定合规版本（人审 + 工单 + 产物指纹），产出 release lock
python3 tools/fpenv.py lock --policy policy.json --release-id 2024-07-build-0812 \
    --ticket CHG-2024-0812 --approved-by infra-lead \
    --artifacts check.json --provenance release.provenance.json --out release.lock.json

# ①-后置 下载后校验（内容 + 版本声明双判据）
python3 tools/fpenv.py verify-artifact --file torch-2.4.0-....whl --lock release.lock.json

# ② 对固定版本生成全部指纹（密钥从 KMS 注入）
python3 tools/fpenv.py attest --policy policy.json --lock release.lock.json --key-env FPENV_KEY

# ③ 全域检查（门禁）
python3 tools/fpenv.py audit --policy policy.json --key-env FPENV_KEY --fail-on high

# 单作用域拍拓 / 校验
python3 tools/fpenv.py baseline --root /usr/lib/python3.11/site-packages \
    --label goku-sp --out /secure/env.fp.json --key-env FPENV_KEY
python3 tools/fpenv.py verify --baseline /secure/env.fp.json --key-env FPENV_KEY --fail-on high

# 训练期常驻巡检，首次发现即让任务失败
python3 tools/fpenv.py watch --baseline /secure/env.fp.json --key-env FPENV_KEY \
    --interval 300 --exit-on-find

# 两次拍拓比对（事故复盘）
python3 tools/fpenv.py diff --a before.fp.json --b after.fp.json
```

两种哈希模式：`content`（逐文件 sha256，准，用于门禁）/ `meta`（只读元数据，快，用于高频巡检）。

## 安全边界（重要）

- 对被拍拓目录**只读**：只用 `open(O_RDONLY)` / `lstat` / `readlink`，从不写入。
- 唯一写入目标是显式指定的 `--out`（及 `watch --log`）。
- 三道护栏：拒绝拍拓 `/proc` `/sys` `/dev`；拒绝把指纹文件写进被拍拓目录（防自污染）；
  拍拓 `/` `/usr` `/etc` 等大范围目录需显式 `--allow-broad`。
- 自测全部在 `tempfile.mkdtemp()` 建的一次性临时目录里跑，`finally` 中删除，结束校验残留为 0；
  不触碰真实 `site-packages`，不触碰 Windows 盘。

## 已验证 / 未验证

**已验证**（WSL Ubuntu，Python 3.12.3，116/116 通过）：
改内容 + `os.utime` 还原 mtime + `chmod` 还原权限 → 仍被 `F-CONTENT` / `F-CTIME-DRIFT` / `F-BACKDATED` 命中；
`mv` 整体替换（内容一致）→ `F-INODE-SWAP`；新增后门 / 删除文件 → `F-UNEXPECTED` / `F-MISSING`；
改指纹文件 → `F-SEAL-BROKEN` exit=3；policy 多作用域聚合、只报脏的那个 scope、未签名 → `F-UNSIGNED`、
缺基线 → `F-BASELINE-MISSING`、检查器摘要不符 → `F-CHECKER-MISMATCH`；纯读访问零假阳。
三段式流程：`lock` → `attest` → `audit` 全程走通；错版本被拒、未绑定版本的脏基线被 `F-RELEASE-MISSING` 拦下、
release 块被改并同步重算封印/签名仍被自洽性校验暴露、包版本漂移报 `F-LOCK-DRIFT`。

**真实网络 / 真实产物验证**（`examples/pytorch_lock_demo.py`，torch 2.4.0）：
PyPI 官方 + 清华/阿里/中科大镜像 → `agree`（8 个文件哈希一致）；真实 wheel 59.2MB 下载 2.8s，
锁定指纹命中；篡改 1 字节、改名冒名（内容对、文件名声称 2.4.1）均被 `verify-artifact` exit=3 拒绝；
解包 **10941 个文件**后 content 拍拓 **0.5 秒**，篡改后 mtime/权限还原仍被三判据命中，塞假包被 `F-UNEXPECTED` 拦。

**不可撤销证据链验证**（`examples/provenance_chain_demo.py`）：
journal 改内容 / 改 h / 删中间条 / 清空 / **重算整条链并抹掉签名** → 全部 exit=3；
锚定后清空日志 → `J-TRUNCATED`；inotify 捕获「改完内容 + 还原 mtime + 还原权限」全过程（6 条事件，
最终文件看起来完全干净）；git `--amend` 重写被 `merge-base --is-ancestor` 判非后代，
正常提交只报 info 不误报；checkpoint 改字节 / 回滚冒充（签名合法仅 step 不符）/ 张冠李戴 /
改签名元数据 → 全部 exit=3；200MB checkpoint 签名 0.3s（4 片，701 MB/s）。

**未验证**（诚实清单）：
fanotify 取触发进程 PID/UID（需 root，本环境不可用，当前 `actor` 是记录者填的而非内核给的）、
auditd、eBPF 内核级绕过、**多进程并发写同一 journal**（当前无文件锁，已知限制）、
overlayfs 跨层白障、改系统时钟对 ctime 判据的规避、conda/apt 源的核对解析器、
多人核对「独立性」的机器验证（只能验人数）。

**签名机制**：环境基线用 HMAC-SHA256（`--key-env`，侧重便捷）；
journal 与 checkpoint 用 **Ed25519 非对称签名**（`keygen` 生成，私钥留控制面、节点只放公钥）。
后者才真正对抗「持 root 的内部人重签」——HMAC 的密钥在节点上，读出来就能重签。

**注意**：Ed25519 只解决「谁签的」，不解决「私钥在哪」。私钥与产物同机时签名失去意义，
`sign-checkpoint` 会检测同机并打印警告，但那只是提醒，不是防护。

## 素材来源

事件陈述与证据整理：<https://keyu-tian-sabotage.github.io>

## 署名

本项目由 **drscrewdriver** 与 **DeepSeek V4.1 Flash**（昵称「大肥鱼」）协作完成。

| 角色 | 承担 |
|---|---|
| **drscrewdriver** | 问题定义与方向判断、验证环境提供、全部实测的执行与结果确认、对每条结论的取舍与拍板 |
| **DeepSeek V4.1 Flash** | 设计讨论与推演、代码起草、实跑调试、文档撰写 |

分工要说清是因为**责任要说清**：代码可以被 AI 起草，但「这条结论成立」由人确认；
未验证项一律标 ❌ 而不是含糊带过，也是为了这个。反过来，AI 的参与也没必要隐去——
一个讲归因的仓库，如果连自己是谁写的都说不清楚，就没资格要求别人交代清楚。

> 协作方式本身也在演进。这个项目里 AI 承担的部分，比一年前同类工作里能承担的多得多；
> 但「哪些是实跑验证过的」这条线，仍然只能由人守。

验证环境：WSL Ubuntu 24.04 / Python 3.12.3 / Windows 11 宿主。
所有标 ✅ 的结论均在上述环境实跑；标 ❌ 的未验证项一律保留未勾，不写成结论。

— 2026-10-24
