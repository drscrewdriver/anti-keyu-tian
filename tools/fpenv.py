#!/usr/bin/env python3
"""fpenv —— 训练环境指纹文件（manifest）机制。

设计目标：让「有人动过环境」变成一个可判定的问题，而不是靠感觉。
三层不可伪造性，按强度排序：
  1. 内容哈希   —— 可被「改内容 + 还原 mtime」绕过，但改不了内容本身
  2. inode ctime —— Linux 无 setctime 接口，utime 只能回填 atime/mtime
  3. 封印摘要+签名 —— 指纹文件自身一旦被改，verify 立刻报 seal broken

只依赖标准库。POSIX 语义完整，Windows 上 ctime 即创建时间，相关判据自动降级。

用法：
  fpenv baseline --root /usr/lib/python3.11/site-packages --label goku-sp --out sp.fp.json
  fpenv verify   --baseline sp.fp.json
  fpenv watch    --baseline sp.fp.json --interval 60
  fpenv diff     --a before.fp.json --b after.fp.json
  fpenv show     --baseline sp.fp.json
"""

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone

SCHEMA = "fpenv/v1"
RELEASE_SCHEMA = "fpenv-release/v1"
CTIME_TOL_NS = 1_000_000  # 1ms，容忍文件系统时间戳精度差异

DEFAULT_EXCLUDES = ["__pycache__", "*.pyc", "*.pyo", ".git", ".git/*", "*.log", "*.tmp"]

SEVERITY_ORDER = {"info": 0, "medium": 1, "high": 2, "critical": 3}

# 全域（whole-machine）默认作用域表：覆盖「能影响训练正确性与访问控制」的所有位置。
# 不追求扫全盘——只覆盖安全边界。hash_mode 按后果定：
#   content = 改了就必然出错，值得逐字节；meta = 改了也应知道，但逐字节太贵
WHOLE_MACHINE_SCOPES = [
    {"label": "framework-libs", "hash_mode": "content",
     "roots": ["/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages",
               "/usr/lib/python3.11/site-packages", "/usr/local/lib/python3.11/dist-packages",
               "/opt/conda/lib/python3.11/site-packages"],
     "excludes": ["__pycache__", "*.pyc", "*.pyo", "*.log"],
     "why": "被 sudo 替换的就是这里；本案主战场"},
    {"label": "launcher-and-hooks", "hash_mode": "content",
     "roots": ["/opt/train/bin", "/opt/train/hooks", "/etc/systemd/system",
               "/etc/cron.d", "/etc/cron.daily", "/var/spool/cron"],
     "excludes": ["*.log"],
     "why": "启动脚本 / init 钩子 / 定时任务：kill.py 写入 init.py 的位置"},
    {"label": "access-control", "hash_mode": "content",
     "roots": ["/etc/ssh", "/etc/sudoers.d", "/etc/pam.d", "/root/.ssh", "/etc/passwd",
               "/etc/group", "/etc/shadow"],
     "excludes": [],
     "why": "谁能登录、谁能 sudo；加一行 authorized_keys 就是永久后门"},
    {"label": "kernel-and-boot", "hash_mode": "meta",
     "roots": ["/boot", "/lib/modules", "/etc/modprobe.d", "/etc/sysctl.d", "/etc/default/grub"],
     "excludes": [],
     "why": "内核与启动参数：决定 ctime 语义与隔离能力"},
    {"label": "scheduler-env", "hash_mode": "meta",
     "roots": ["/etc/environment", "/etc/profile.d", "/etc/ld.so.conf.d", "/etc/ld.so.preload"],
     "excludes": [],
     "why": "环境变量与动态库搜索路径：LD_PRELOAD 注入入口"},
    {"label": "container-runtime", "hash_mode": "meta",
     "roots": ["/etc/docker", "/etc/containerd", "/etc/kubernetes"],
     "excludes": [],
     "why": "容器运行时配置被改 = 隔离形同虚设"},
    {"label": "audit-integrity", "hash_mode": "content",
     "roots": ["/etc/audit", "/etc/rsyslog.conf", "/etc/rsyslog.d"],
     "excludes": [],
     "why": "审计规则与日志配置；先关日志再动手，是最常见的第一步"},
]


# ---------------------------------------------------------------- helpers


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_key(args):
    """签名密钥：优先 --key-env 指向的环境变量，其次 --key-file。均无则返回 None（不签名）。"""
    if args.key_env:
        v = os.environ.get(args.key_env)
        if not v:
            sys.exit(f"fpenv: 环境变量 {args.key_env} 为空，拒绝以无签名模式继续（显式传 --unsigned 可跳过）")
        return v.encode()
    if args.key_file:
        with open(args.key_file, "rb") as f:
            return f.read().strip()
    return None


def excluded(rel, name, patterns):
    for p in patterns:
        if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p):
            return True
    return False


def scan(root, hash_mode="content", excludes=None, follow_symlinks=False):
    """遍历 root，产出指纹条目。条目键紧凑以减少大环境下的体积：
    p=相对路径 t=类型 f/s/l s=大小 h=哈希 m=mode u=uid g=gid i=inode
    mt=mtime_ns ct=ctime_ns nl=nlink
    """
    excludes = excludes if excludes is not None else DEFAULT_EXCLUDES
    entries = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and not excluded(
            os.path.relpath(os.path.join(dirpath, d), root), d, excludes))
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if excluded(rel, fn, excludes):
                continue
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                try:
                    target = os.readlink(full)
                except OSError:
                    target = "?"
                entries.append({"p": rel, "t": "l", "s": len(target), "h": _h(target.encode()), "m": mode,
                                "u": st.st_uid, "g": st.st_gid, "i": st.st_ino,
                                "mt": st.st_mtime_ns, "ct": st.st_ctime_ns, "nl": st.st_nlink})
                continue
            if not stat.S_ISREG(st.st_mode):
                entries.append({"p": rel, "t": "o", "s": st.st_size, "h": "", "m": mode,
                                "u": st.st_uid, "g": st.st_gid, "i": st.st_ino,
                                "mt": st.st_mtime_ns, "ct": st.st_ctime_ns, "nl": st.st_nlink})
                continue
            h = sha256_file(full) if hash_mode == "content" else ""
            entries.append({"p": rel, "t": "f", "s": st.st_size, "h": h, "m": mode,
                            "u": st.st_uid, "g": st.st_gid, "i": st.st_ino,
                            "mt": st.st_mtime_ns, "ct": st.st_ctime_ns, "nl": st.st_nlink})
    entries.sort(key=lambda e: e["p"])
    return entries


def _h(b):
    return hashlib.sha256(b).hexdigest()


def payload_of(manifest):
    d = {"schema": manifest["schema"], "label": manifest["label"], "scan": manifest["scan"],
         "extra": manifest.get("extra", {}), "entries": manifest["entries"]}
    if manifest.get("release"):
        d["release"] = manifest["release"]
    if manifest.get("provenance"):
        d["provenance"] = manifest["provenance"]
    return d


def root_digest(manifest):
    return _h(canonical(payload_of(manifest)))


def sign(digest_hex, key):
    return hmac.new(key, digest_hex.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- safety guards
#
# 本工具对 --root 指向的目录只做 open(O_RDONLY) / lstat / readlink，从不写入。
# 唯一写入目标是被显式指定的 --out（或 watch 的 --log）。以下护栏防止误用：
#   1. 拒绝把伪文件系统当根（/proc /sys /dev），scan 会卡死且无意义
#   2. 拒绝把指纹文件写进被拍拓目录（否则下次 verify 必然报 F-UNEXPECTED，自污染）
#   3. 直接拍拓 / 或盘符根需要 --allow-broad 显式确认

PSEUDO_FS = {"/proc", "/sys", "/dev", "/run", "/snap"}
BROAD_ROOTS = {"/", "/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var", "/home", "/root"}


def _norm(p):
    p = os.path.abspath(p)
    return p.rstrip("\\/") or "/"


def guard_roots(roots, allow_broad=False):
    for r in roots:
        n = _norm(r)
        if n in PSEUDO_FS or any(n.startswith(p + "/") for p in PSEUDO_FS):
            sys.exit(f"fpenv: 拒绝拍拓伪文件系统 {n}（内容动态且可能无限，scan 会卡死）")
        if not os.path.isdir(n):
            sys.exit(f"fpenv: 根目录不存在: {n}")
        if n in BROAD_ROOTS and not allow_broad:
            sys.exit(f"fpenv: {n} 覆盖范围过大，确认无误请加 --allow-broad")


def guard_out(out, roots):
    o = _norm(os.path.dirname(os.path.abspath(out)) or ".")
    for r in roots:
        rn = _norm(r)
        if o == rn or o.startswith(rn + os.sep) or o.startswith(rn + "/"):
            sys.exit(f"fpenv: 拒绝把指纹文件写进被拍拓目录 {rn}"
                     f"（否则指纹文件本身会被下次 scan 当成 F-UNEXPECTED 新文件）")


def cmd_baseline(args):
    key = load_key(args)
    roots = [os.path.abspath(r) for r in args.root]
    guard_roots(roots, args.allow_broad)
    out = args.out or (args.label or "env") + ".fp.json"
    guard_out(out, roots)

    all_entries = []
    for r in roots:
        all_entries.extend(scan(r, args.hash_mode, args.exclude))
    all_entries.sort(key=lambda e: e["p"])

    extra = {}
    for item in args.extra or []:
        k, _, v = item.partition("=")
        extra[k] = v

    manifest = {
        "schema": SCHEMA,
        "label": args.label or ",".join(os.path.basename(r.rstrip("/")) for r in roots),
        "created_at": now_iso(),
        "created_by": {"host": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version()},
        "scan": {"roots": roots, "hash_mode": args.hash_mode, "excludes": args.exclude, "follow_symlinks": False},
        "extra": extra,
        "entries": all_entries,
    }
    dg = root_digest(manifest)
    manifest["root_digest"] = dg
    manifest["sig"] = {"alg": "hmac-sha256", "value": sign(dg, key)} if key else None

    out = args.out or (args.label or "env") + ".fp.json"
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, out)

    print(f"baseline: {out}")
    print(f"  label      : {manifest['label']}")
    print(f"  roots      : {len(roots)}")
    print(f"  entries    : {len(all_entries)}")
    print(f"  hash_mode  : {args.hash_mode}")
    print(f"  root_digest: {dg}")
    print(f"  signed     : {'hmac-sha256' if key else 'no (未提供密钥)'}")
    return 0


# ---------------------------------------------------------------- verify


class Findings:
    def __init__(self):
        self.items = []

    def add(self, code, path, sev, detail):
        self.items.append({"code": code, "path": path, "severity": sev, "detail": detail})

    def max_sev(self):
        return max((SEVERITY_ORDER[i["severity"]] for i in self.items), default=-1)

    def count(self, sev=None):
        if sev is None:
            return len(self.items)
        return sum(1 for i in self.items if i["severity"] == sev)


def verify(manifest, key, hash_mode=None, ignore=None, posix=None, policy=None, scope_label=None):
    """返回 (findings, note)。posix=False 时跳过 ctime 判据并给出说明。
    policy 给定时额外校验版本锚（基线绑定的版本 == 合规固定版本）。"""
    f = Findings()
    if posix is None:
        posix = os.name == "posix"
    note = None
    ignore = ignore or []

    recalc = root_digest(manifest)
    if recalc != manifest.get("root_digest"):
        f.add("F-SEAL-BROKEN", "<manifest>", "critical",
              f"封印摘要不符：记录 {manifest.get('root_digest','')[:16]}… 实测 {recalc[:16]}…，指纹文件本身被改动")
        return f, "seal broken，后续比对无意义"

    if manifest.get("sig"):
        if key is None:
            note = "指纹文件已签名，但未提供密钥，跳过签名校验"
        elif not hmac.compare_digest(sign(manifest["root_digest"], key), manifest["sig"]["value"]):
            f.add("F-SIG-INVALID", "<manifest>", "critical", "HMAC 签名不匹配，指纹文件不是由可信方生成")
            return f, "signature invalid"

    # 版本锚：先确认「这份基线对应的就是合规版本」，再谈文件有没有变
    if policy is not None:
        check_release(manifest, policy, f, scope_label or manifest.get("label", "?"))
        # 实采 drift：当前机器实际装的包版本 vs lock 里记录的版本
        rel = manifest.get("release") or {}
        locked_pkgs = (rel.get("components") or {}).get("packages") or {}
        if locked_pkgs:
            roots = [r for r in manifest["scan"]["roots"] if os.path.isdir(r)]
            live = scan_package_versions(roots)
            drift = {k: (locked_pkgs[k], live[k]) for k in locked_pkgs
                     if k in live and live[k] != locked_pkgs[k]}
            added = sorted(set(live) - set(locked_pkgs))
            if drift:
                sample = ", ".join(f"{k} {a}→{b}" for k, (a, b) in list(drift.items())[:5])
                f.add("F-LOCK-DRIFT", scope_label or manifest.get("label", "?"), "critical",
                      f"{len(drift)} 个包的版本偏离 lock（合规版本）：{sample}")
            if added:
                sample = ", ".join(added[:5])
                f.add("F-LOCK-DRIFT", scope_label or manifest.get("label", "?"), "high",
                      f"出现 lock 未登记的 {len(added)} 个包：{sample}")

    hm = hash_mode or manifest["scan"].get("hash_mode", "content")
    roots = manifest["scan"]["roots"]
    current = {}
    for r in roots:
        if not os.path.isdir(r):
            f.add("F-ROOT-MISSING", r, "critical", "被拍拓的根目录不存在或不可访问")
            continue
        for e in scan(r, hm, manifest["scan"].get("excludes")):
            if any(fnmatch.fnmatch(e["p"], ig) for ig in ignore):
                continue
            current[e["p"]] = e

    base = {e["p"]: e for e in manifest["entries"]}

    for p in sorted(set(base) | set(current)):
        if any(fnmatch.fnmatch(p, ig) for ig in ignore):
            continue
        b, c = base.get(p), current.get(p)
        if b is None:
            f.add("F-UNEXPECTED", p, "critical",
                  f"基线中不存在的新文件（{c['t']}，{c['s']}B，mode={oct(c['m'])}）——疑似后门/启动钩子")
            continue
        if c is None:
            f.add("F-MISSING", p, "critical", "基线中存在、现在消失——疑似被删除或整体替换后未复原")
            continue

        # 内容
        if b.get("h") and c.get("h") and b["h"] != c["h"]:
            f.add("F-CONTENT", p, "critical", f"内容哈希变化 {b['h'][:12]}… → {c['h'][:12]}…")
        elif b["s"] != c["s"]:
            f.add("F-CONTENT", p, "critical", f"大小变化 {b['s']} → {c['s']}")

        # 元数据
        if b["m"] != c["m"]:
            f.add("F-MODE", p, "high", f"权限位变化 {oct(b['m'])} → {oct(c['m'])}")
        if b["u"] != c["u"] or b["g"] != c["g"]:
            f.add("F-OWNER", p, "high", f"属主变化 {b['u']}:{b['g']} → {c['u']}:{c['g']}")

        if b["i"] != c["i"]:
            sev = "high" if b.get("h") == c.get("h") else "critical"
            f.add("F-INODE-SWAP", p, sev,
                  f"inode 变化 {b['i']} → {c['i']}；内容{'一致（整体替换原文件）' if b.get('h')==c.get('h') else '也不一致'}")

        if posix:
            # 核心判据 1：ctime 自基线以来变动 = 任何写入/改属性都会留下、用户态改不掉的痕迹
            drift = abs(c["ct"] - b["ct"]) > CTIME_TOL_NS
            if drift:
                f.add("F-CTIME-DRIFT", p, "high",
                      f"ctime 变动 {ts(b['ct'])} → {ts(c['ct'])}（内容/mtime 可回填，ctime 不行）")
                # 核心判据 2：ctime 动了、但 mtime 与基线分毫不差，而内容/元数据确有变化
                #   = 写完之后用 utime 把时间回填成原值（事件中 a.py / re.py 的做法）
                #   注意：mtime 早于 ctime 本身不是证据（pip 解包会保留 wheel 里的 mtime），
                #   所以这里判的是「相对基线的倒挂」，而不是绝对倒挂。
                if c["mt"] == b["mt"] and (b.get("h") != c.get("h") or b["s"] != c["s"]):
                    f.add("F-BACKDATED", p, "critical",
                          f"内容已变但 mtime 仍为基线值 {ts(c['mt'])}，ctime 却是 {ts(c['ct'])} —— 时间被回填")
                elif c["mt"] < b["mt"] - CTIME_TOL_NS:
                    f.add("F-BACKDATED", p, "critical",
                          f"mtime 被改到基线之前 {ts(b['mt'])} → {ts(c['mt'])}，而 ctime 前移到 {ts(c['ct'])}")
    return f, note


def ts(ns):
    """纳秒精度显示——ctime 漂移常在毫秒级，秒级显示会看不出差异。"""
    dt = datetime.fromtimestamp(ns / 1e9, timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{ns % 1_000_000_000 // 1_000_000:03d}"


def report(f, note=None, as_json=False, limit=40):
    if as_json:
        print(json.dumps({"ok": f.count() == 0, "note": note, "findings": f.items},
                         ensure_ascii=False, indent=2))
        return
    if note:
        print(f"note: {note}")
    if not f.items:
        print("CLEAN — 无差异")
        return
    by_sev = {}
    for i in f.items:
        by_sev.setdefault(i["severity"], []).append(i)
    for sev in ("critical", "high", "medium", "info"):
        items = by_sev.get(sev)
        if not items:
            continue
        print(f"\n[{sev.upper()}] {len(items)} 项")
        for i in items[:limit]:
            print(f"  {i['code']:<16} {i['path']}")
            print(f"                   {i['detail']}")
        if len(items) > limit:
            print(f"  … 另有 {len(items)-limit} 项，用 --json 取全量")


def cmd_verify(args):
    try:
        with open(args.baseline, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except FileNotFoundError:
        f = Findings()
        f.add("F-BASELINE-MISSING", "<baseline>", "critical",
              f"基线文件缺失: {args.baseline}（无法证明环境可信）")
        report(f, None, args.json)
        return 3
    except json.JSONDecodeError as e:
        sys.exit(f"fpenv: 基线文件不是合法 JSON: {args.baseline}: {e}")
    key = load_key(args) if not args.unsigned else None
    f, note = verify(manifest, key, args.hash_mode, args.ignore, posix=_posix_mode(args))
    report(f, note, args.json)
    code = exit_for(f, args.fail_on)
    if not args.json:
        print(f"\nexit={code}  (fail-on={args.fail_on})")
    return code


def _posix_mode(args):
    m = getattr(args, "ctime_mode", "auto")
    if m == "on":
        return True
    if m == "off":
        return False
    return os.name == "posix"


def cmd_watch(args):
    with open(args.baseline, encoding="utf-8") as fh:
        manifest = json.load(fh)
    key = None if args.unsigned else load_key(args)
    runs = 0
    try:
        while True:
            runs += 1
            f, note = verify(manifest, key, args.hash_mode, args.ignore, posix=_posix_mode(args))
            stamp = now_iso()
            if f.items:
                print(f"[{stamp}] {f.count()} findings (max={max(f.items, key=lambda i: SEVERITY_ORDER[i['severity']])['severity']})")
                report(f, note, False, limit=10)
                if args.log:
                    with open(args.log, "a", encoding="utf-8") as lf:
                        lf.write(json.dumps({"at": stamp, "findings": f.items}, ensure_ascii=False) + "\n")
                if args.exit_on_find:
                    return 2
            else:
                print(f"[{stamp}] clean")
            if args.max_runs and runs >= args.max_runs:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


# ---------------------------------------------------------------- policy / audit
#
# 单点校验只解决「一台机器的一个目录」。真实框架要同时盯多个作用域、统一口径、
# 统一退出码。policy 文件是这套框架的单一事实源：
#   { "schema": "fpenv-policy/v1", "name": "...", "fail_on": "high",
#     "require_signed": true, "checker_sha256": "...",
#     "key_env": "FPENV_KEY",
#     "scopes": [ {"label":"site-packages", "roots":[...], "baseline":"...",
#                  "hash_mode":"content", "excludes":[...], "ignore":[...],
#                  "key_env":"..." } ] }

POLICY_SCHEMA = "fpenv-policy/v1"
TRUST_CODES = {"F-SEAL-BROKEN", "F-SIG-INVALID", "F-UNSIGNED", "F-CHECKER-MISMATCH",
               "F-BASELINE-MISSING", "F-RELEASE-MISSING", "F-RELEASE-MISMATCH",
               "F-RELEASE-UNPINNED", "F-LOCK-DRIFT"}


def exit_for(findings, fail_on):
    """统一退出码：0 干净 / 2 达到 fail_on / 3 信任锚点失效。"""
    if not findings.items:
        return 0
    if any(i["code"] in TRUST_CODES for i in findings.items):
        return 3
    return 2 if findings.max_sev() >= SEVERITY_ORDER[fail_on] else 0


def load_policy(path, require_scopes=True):
    try:
        with open(path, encoding="utf-8") as fh:
            p = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"fpenv: policy 不存在: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"fpenv: policy 不是合法 JSON: {e}")
    if p.get("schema") != POLICY_SCHEMA:
        sys.exit(f"fpenv: policy schema 应为 {POLICY_SCHEMA}，实际 {p.get('schema')!r}")
    scopes = p.get("scopes") or []
    if require_scopes and not scopes:
        sys.exit("fpenv: policy 未定义任何 scope")
    seen = set()
    for s in scopes:
        if not s.get("label"):
            sys.exit("fpenv: 每个 scope 必须有 label")
        if s["label"] in seen:
            sys.exit(f"fpenv: scope label 重复: {s['label']}")
        seen.add(s["label"])
    return p


def make_manifest(roots, label, hash_mode, excludes, extra, key, release=None, provenance=None):
    all_entries = []
    for r in roots:
        all_entries.extend(scan(r, hash_mode, excludes))
    all_entries.sort(key=lambda e: e["p"])
    manifest = {
        "schema": SCHEMA,
        "label": label,
        "created_at": now_iso(),
        "created_by": {"host": socket.gethostname(), "platform": platform.platform(),
                       "python": platform.python_version()},
        "scan": {"roots": roots, "hash_mode": hash_mode, "excludes": excludes,
                 "follow_symlinks": False},
        "extra": extra or {},
        "entries": all_entries,
    }
    # release 与 provenance 参与 payload → 被 root_digest 与签名覆盖，改不了
    if release:
        manifest["release"] = release
    if provenance:
        manifest["provenance"] = provenance
    dg = root_digest(manifest)
    manifest["root_digest"] = dg
    manifest["sig"] = {"alg": "hmac-sha256", "value": sign(dg, key)} if key else None
    return manifest


def write_manifest(manifest, out):
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, out)


# ---------------------------------------------------------------- release / lock
#
# 流程三段式：选合规版本 → 对该版本生成指纹 → 全域检查。
#
# 为什么需要中间这一段：
#   「和基线一致」≠「合规」。如果基线本身是在已被污染的环境里拍的，
#   verify 会永远 clean——这正是最危险的情形（脏基线）。
#   所以指纹必须**绑定一个外部认定过的版本**，检查时同时验两件事：
#     1. 文件没变（对基线）
#     2. 基线对应的是那个被正式固定下来的版本（对 lock）


def read_os_release():
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(p, encoding="utf-8") as f:
                kv = {}
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        kv[k] = v.strip().strip('"')
            return kv
        except OSError:
            continue
    return {}


def scan_package_versions(roots):
    """从 dist-info / egg-info 目录名解析已安装包版本。只读目录名，不解压 METADATA。"""
    pkgs = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for n in names:
            low = n.lower()
            if low.endswith(".dist-info") or low.endswith(".egg-info"):
                stem = n[: -len(".dist-info")] if low.endswith(".dist-info") else n[: -len(".egg-info")]
                name, sep, ver = stem.partition("-")
                if sep and ver:
                    pkgs[name.replace("_", "-").lower()] = ver
    return pkgs


_WHEEL_VER_RE = re.compile(r"^([A-Za-z0-9_.]+?)-(\d[^-]*)-")


def parse_wheel_version(fname):
    """从 wheel 文件名解析 (包名, 版本)。解析不出返回 (None, None)。

    wheel 命名规范 PEP 427：{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
    包名里的 '-' 已被规范化为 '_'，所以按 '-' 切分的前两段就是包名与版本。
    """
    if not fname.lower().endswith(".whl"):
        return None, None
    m = _WHEEL_VER_RE.match(fname)
    if not m:
        return None, None
    return m.group(1).replace("_", "-").lower(), m.group(2)


def cmd_verify_artifact(args):
    """下载后校验：文件 sha256 是否等于 lock 里锁定的值。

    「防止错误下载版本」需要同时判两件事：
      1. 内容哈希 == 锁定值（防篡改、防镜像给错文件）
      2. 文件名声称的版本 == 锁定条目的版本（防改名冒名 / 装错版本）
    只判第 1 件会漏掉「拿 A 的内容改名成 B」这种场景——本演示实测踩到过。
    """
    lock = load_lock(args.lock)
    arts = lock.get("artifacts") or {}
    if not arts:
        sys.exit("fpenv: lock 中没有 artifacts——请先用 lock --artifacts 锁定产物哈希")

    path = args.file
    if not os.path.isfile(path):
        sys.exit(f"fpenv: 文件不存在: {path}")
    actual = sha256_file(path)
    base = os.path.basename(path)

    expected = arts.get(base)
    matched_by = base
    renamed_from = None
    if expected is None:
        for fname, sha in arts.items():
            if sha == actual:
                expected, matched_by = sha, fname
                renamed_from = fname
                break

    content_ok = expected == actual
    problems = []
    if not content_ok:
        problems.append("内容哈希与锁定值不符" if expected
                        else "该文件不在 lock 的 artifacts 里（可能版本错误或未经核对）")
    elif renamed_from and renamed_from != base:
        problems.append(f"内容与锁定条目 {renamed_from} 相同，但文件名不同")

    # 版本声明校验：文件名声称的版本必须与锁定条目一致
    name_ver = parse_wheel_version(base)
    locked_name_ver = parse_wheel_version(matched_by or base)
    version_conflict = False
    if name_ver[1] and locked_name_ver[1] and name_ver[1] != locked_name_ver[1]:
        version_conflict = True
        problems.append(f"文件名声称版本 {name_ver[1]} ≠ 锁定条目版本 {locked_name_ver[1]}"
                        f"（改名冒名 / 装错版本）")

    ok = content_ok and not version_conflict and not renamed_from
    code = 0 if ok else 3

    if args.as_json:
        print(json.dumps({"file": path, "basename": base, "sha256": actual,
                          "expected": expected, "matched_entry": matched_by if content_ok else None,
                          "renamed_from": renamed_from,
                          "name_version": name_ver[1], "locked_version": locked_name_ver[1],
                          "content_ok": content_ok, "version_conflict": version_conflict,
                          "locked_entries": len(arts), "problems": problems,
                          "ok": ok, "exit": code},
                         ensure_ascii=False, indent=2))
        return code

    print(f"文件       : {path}")
    print(f"大小       : {os.path.getsize(path):,} B")
    print(f"实测 sha256: {actual}")
    print(f"锁定期望   : {expected or '（未在 lock 中登记）'}")
    if name_ver[1] or locked_name_ver[1]:
        print(f"文件名版本 : {name_ver[1] or '-'}   锁定版本: {locked_name_ver[1] or '-'}")
    if ok:
        print("\nPASS — 内容与版本声明都与锁定的产物一致")
    else:
        print("\nFAIL — 拒绝安装")
        for p in problems:
            print(f"  · {p}")
    print(f"exit={code}")
    return code


def collect_components(policy):
    """实采当前环境的组件版本集合——这就是「版本」的可验证表达。"""
    comps = {
        "python": platform.python_version(),
        "kernel": platform.release(),
        "machine": platform.machine(),
    }
    osr = read_os_release()
    if osr.get("PRETTY_NAME"):
        comps["os"] = osr["PRETTY_NAME"]
    elif osr.get("ID"):
        comps["os"] = f"{osr.get('ID')} {osr.get('VERSION_ID', '')}".strip()

    # 包版本：扫 policy 里所有 content 作用域，去重
    roots = []
    for s in policy["scopes"]:
        for r in s.get("roots") or []:
            if os.path.isdir(r):
                roots.append(r)
    pkgs = scan_package_versions(roots)
    if pkgs:
        comps["packages"] = dict(sorted(pkgs.items()))
    return comps


def lock_digest(components):
    """版本摘要：把组件集合压成一个短指纹，用来跨文件比对「是不是同一个版本」。"""
    return _h(canonical(components))


def load_lock(path):
    try:
        with open(path, encoding="utf-8") as fh:
            lk = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"fpenv: lock 文件不存在: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"fpenv: lock 不是合法 JSON: {path}: {e}")
    if lk.get("schema") != RELEASE_SCHEMA:
        sys.exit(f"fpenv: lock schema 应为 {RELEASE_SCHEMA}，实际 {lk.get('schema')!r}")
    if not lk.get("release_id"):
        sys.exit("fpenv: lock 缺少 release_id")
    if not lk.get("lock_digest"):
        sys.exit("fpenv: lock 缺少 lock_digest")
    return lk


def cmd_lock(args):
    """第一步：固定合规版本。产出 release lock（进审批与版本管理）。"""
    # lock 只负责「定版本 + 锁产物」，不扫文件，所以允许 policy 暂时没有 scopes
    policy = load_policy(args.policy, require_scopes=False)
    comps = collect_components(policy)
    ld = lock_digest(comps)

    prov = None
    if args.provenance:
        prov = load_provenance(args.provenance)
        # 版本锁定前就把来源核对结论挂上，避免「先锁后补核对」
        if prov.get("release_id") and prov["release_id"] != args.release_id:
            sys.exit(f"fpenv: provenance 的 release_id {prov['release_id']!r} "
                     f"≠ 本次 {args.release_id!r}")
        prov["release_id"] = args.release_id

    lock = {
        "schema": RELEASE_SCHEMA,
        "release_id": args.release_id,
        "locked_at": now_iso(),
        "locked_by": {"host": socket.gethostname(), "platform": platform.platform()},
        "components": comps,
        "lock_digest": ld,
        "policy": policy.get("name"),
        "approval": {
            "ticket": args.ticket or "",
            "approved_by": args.approved_by or "",
        },
    }
    if prov:
        lock["provenance_digest"] = _h(canonical(prov))
    if args.artifacts:
        # 锁定产物哈希：从 check-source 的 --json 输出或手写 JSON 里取 agree 的文件
        try:
            with open(args.artifacts, encoding="utf-8") as f:
                art_src = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            sys.exit(f"fpenv: --artifacts 文件无法读取: {e}")
        art = art_src.get("agree") if isinstance(art_src, dict) and "agree" in art_src else art_src
        if not isinstance(art, dict) or not art:
            sys.exit("fpenv: --artifacts 中没有可锁定的 {filename: sha256} 条目")
        if isinstance(art_src, dict) and art_src.get("verdict") not in (None, "agree"):
            sys.exit(f"fpenv: 来源核对结论是 {art_src.get('verdict')!r}，拒绝锁定未通过核对的产物")
        lock["artifacts"] = dict(sorted(art.items()))
        # 产物指纹单独一把摘要：lock_digest 的口径固定为 components，
        # 否则 check_release 里 components↔lock_digest 的自洽性校验会失效
        lock["artifacts_digest"] = _h(canonical(lock["artifacts"]))
    out = args.out or f"{args.release_id}.lock.json"
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(lock, f, ensure_ascii=False, indent=2)
    os.replace(tmp, out)

    print(f"lock: {out}")
    print(f"  release_id : {lock['release_id']}")
    print(f"  lock_digest: {ld}")
    print(f"  python     : {comps.get('python')}")
    print(f"  kernel     : {comps.get('kernel')}")
    print(f"  os         : {comps.get('os', '-')}")
    print(f"  packages   : {len(comps.get('packages') or {})}")
    if args.ticket:
        print(f"  ticket     : {args.ticket}")
    if prov:
        n_src = sum(len(c.get("sources") or []) for c in prov.get("checks") or [])
        print(f"  provenance : 已挂载（{len(prov.get('checks') or [])} 组件 / {n_src} 来源记录）")
    if args.artifacts:
        print(f"  artifacts  : 已锁定 {len(lock['artifacts'])} 个产物指纹")
        for fname, sha in list(lock["artifacts"].items())[:3]:
            print(f"      {fname}  {sha[:32]}…")
    print("\n下一步：fpenv attest --policy <policy> --lock " + out + "  （对固定版本生成全部指纹）")
    return 0


def release_block(lock):
    """写进 manifest 的版本绑定块。lock_digest 是跨文件口径。"""
    return {
        "id": lock["release_id"],
        "lock_digest": lock["lock_digest"],
        "locked_at": lock.get("locked_at"),
        "components": lock.get("components", {}),
        "approval": lock.get("approval", {}),
    }


def check_release(manifest, policy, findings, scope_label):
    """校验「基线对应的版本 == policy 钉死的合规版本」，并验 lock_digest 自洽。"""
    want = policy.get("release") or {}
    enforce = want.get("enforce", False)
    expected_id = want.get("expected")
    expected_ld = want.get("lock_digest")

    rel = manifest.get("release")
    if not rel:
        if enforce:
            findings.add("F-RELEASE-MISSING", scope_label, "critical",
                         "基线未绑定版本（未走 lock→attest 流程），无法证明对应的是合规版本")
        return
    if rel.get("lock_digest") != lock_digest(rel.get("components") or {}):
        findings.add("F-RELEASE-MISMATCH", scope_label, "critical",
                     "release 块内 components 与 lock_digest 不自洽——版本绑定被改过")
        return
    if enforce and not expected_id:
        findings.add("F-RELEASE-UNPINNED", scope_label, "critical",
                     "policy 要求强制版本但未钉死 release.expected")
        return
    if expected_id and rel.get("id") != expected_id:
        findings.add("F-RELEASE-MISMATCH", scope_label, "critical",
                     f"基线版本 {rel.get('id')!r} ≠ policy 钉死的合规版本 {expected_id!r}")
    if expected_ld and rel.get("lock_digest") != expected_ld:
        findings.add("F-RELEASE-MISMATCH", scope_label, "critical",
                     f"基线 lock_digest {rel.get('lock_digest','')[:16]}… ≠ policy 钉死值 {expected_ld[:16]}…")


def cmd_attest(args):
    """第二步：对已固定的版本生成全部作用域指纹（等价 collect，但强制带 lock）。"""
    lock = load_lock(args.lock)
    policy = load_policy(args.policy)

    # policy 若钉死版本，必须与本次 attest 的 lock 一致——防止拿错版本去拍拓
    want = policy.get("release") or {}
    if want.get("expected") and want["expected"] != lock["release_id"]:
        sys.exit(f"fpenv: policy 钉死的版本是 {want['expected']!r}，"
                 f"但本次 attest 用的是 {lock['release_id']!r}——拒绝生成错版指纹")
    if want.get("lock_digest") and want["lock_digest"] != lock["lock_digest"]:
        sys.exit("fpenv: lock_digest 与 policy 钉死值不符，拒绝生成错版指纹")

    rel = release_block(lock)
    return _collect(policy, args, release=rel)


def _collect(policy, args, release=None):
    base_key = load_key(argparse.Namespace(key_env=args.key_env or policy.get("key_env"),
                                           key_file=getattr(args, "key_file", None)))
    ok = 0
    for s in policy["scopes"]:
        roots = [os.path.abspath(r) for r in s.get("roots") or []]
        if not roots:
            print(f"  skip {s['label']}: policy 未定义 roots")
            continue
        existing = [r for r in roots if os.path.isdir(r)]
        if not existing:
            print(f"  skip {s['label']}: roots 在本机均不存在（构建机与训练机路径可能不同）")
            continue
        guard_roots(existing, args.allow_broad)
        out = s.get("baseline")
        if not out:
            print(f"  skip {s['label']}: policy 未定义 baseline 路径")
            continue
        guard_out(out, existing)
        key = base_key
        if s.get("key_env") and s["key_env"] != (args.key_env or policy.get("key_env")):
            key = load_key(argparse.Namespace(key_env=s["key_env"], key_file=None))
        hm = args.hash_mode or s.get("hash_mode", "content")
        m = make_manifest(existing, s["label"], hm, s.get("excludes", DEFAULT_EXCLUDES),
                          s.get("extra"), key, release=release)
        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
        write_manifest(m, out)
        ok += 1
        rel_tag = f" release={release['id']}" if release else ""
        print(f"  {s['label']:<24} entries={len(m['entries']):<7} "
              f"digest={m['root_digest'][:16]}…{rel_tag} -> {out}")
    print(f"collect: {ok} scope(s) 完成")
    return 0


def cmd_collect(args):
    """按 policy 把所有 scope 的基线一次性拍拓出来（构建镜像后 / 变更审批后执行）。"""
    policy = load_policy(args.policy)
    return _collect(policy, args)





def checker_matches(policy):
    """检查器自校验：policy 里钉死的 sha256 与当前 fpenv.py 是否一致。
    局限：能改 policy 的攻击者也能改这一行——所以 policy 必须来自本机之外（只读挂载/控制面拉取）。"""
    want = policy.get("checker_sha256")
    if not want:
        return None
    got = sha256_file(os.path.abspath(__file__))
    return (want, got, want == got)


def cmd_audit(args):
    policy = load_policy(args.policy)
    fail_on = args.fail_on or policy.get("fail_on", "high")
    require_signed = policy.get("require_signed", True) and not args.unsigned
    base_key = None
    if not args.unsigned:
        base_key = load_key(argparse.Namespace(key_env=args.key_env or policy.get("key_env"),
                                               key_file=args.key_file))

    results = []
    agg = Findings()

    # 检查器自校验
    if policy.get("checker_sha256"):
        r = checker_matches(policy)
        if r and not r[2]:
            agg.add("F-CHECKER-MISMATCH", "<checker>", "critical",
                    f"fpenv.py 摘要不符：policy 钉死 {r[0][:16]}… 实际 {r[1][:16]}…，检查器本身可能被动过")

    for s in policy["scopes"]:
        label = s["label"]
        path = s.get("baseline")
        if not path:
            results.append({"label": label, "baseline": None, "note": "policy 未定义 baseline",
                            "findings": [], "counts": {}})
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                manifest = json.load(fh)
        except FileNotFoundError:
            f = Findings()
            f.add("F-BASELINE-MISSING", label, "critical", f"基线文件缺失: {path}（无法证明环境可信）")
            results.append({"label": label, "baseline": path, "note": None,
                            "findings": f.items, "counts": {"critical": 1}})
            for i in f.items:
                agg.items.append({**i, "scope": label})
            continue

        key = base_key
        if s.get("key_env") and s["key_env"] != (args.key_env or policy.get("key_env")):
            key = load_key(argparse.Namespace(key_env=s["key_env"], key_file=None))

        f, note = verify(manifest, key, args.hash_mode or s.get("hash_mode"),
                         list(args.ignore or []) + list(s.get("ignore") or []),
                         posix=_posix_mode(args), policy=policy, scope_label=label)
        if require_signed and not manifest.get("sig"):
            f.add("F-UNSIGNED", "<manifest>", "critical",
                  "基线未签名——无法证明它出自可信方（--unsigned 可临时放行）")
        for i in f.items:
            agg.items.append({**i, "scope": label})
        results.append({"label": label, "baseline": path,
                        "entries": len(manifest["entries"]), "note": note,
                        "release": (manifest.get("release") or {}).get("id"),
                        "ok": not f.items, "findings": f.items,
                        "counts": {sv: f.count(sv) for sv in SEVERITY_ORDER if f.count(sv)}})

    code = exit_for(agg, fail_on)

    # 不属于任何 scope 的问题（检查器自校验失败等）单独成组，否则会在 JSON 里丢失
    policy_level = [i for i in agg.items if "scope" not in i]

    if args.json:
        print(json.dumps({
            "ok": not agg.items, "policy": policy.get("name"), "fail_on": fail_on,
            "scopes": results,
            "findings": policy_level,
            "summary": {"scopes": len(results),
                        "dirty": sum(1 for r in results if r.get("findings")),
                        "findings": len(agg.items),
                        "max_severity": (max(agg.items, key=lambda i: SEVERITY_ORDER[i["severity"]])["severity"]
                                         if agg.items else None)},
            "exit": code}, ensure_ascii=False, indent=2))
        return code

    print(f"policy : {policy.get('name')}  ({len(results)} scopes, fail_on={fail_on}, "
          f"require_signed={require_signed})")
    for r in results:
        cnt = r.get("counts") or {}
        status = "CLEAN" if not r.get("findings") else " / ".join(f"{k}:{v}" for k, v in cnt.items())
        print(f"\n[{r['label']}] {status}")
        if r.get("baseline"):
            print(f"  baseline: {r['baseline']}  entries={r.get('entries', '?')}")
        if r.get("note"):
            print(f"  note: {r['note']}")
        for i in r.get("findings") or []:
            print(f"    {i['severity'].upper():<9} {i['code']:<17} {i['path']}")
            print(f"              {i['detail']}")
    if policy_level:
        print("\n[policy] 框架自身的问题")
        for i in policy_level:
            print(f"    {i['severity'].upper():<9} {i['code']:<17} {i['path']}")
            print(f"              {i['detail']}")
    print(f"\nsummary: {len(results)} scopes, "
          f"{sum(1 for r in results if r.get('findings'))} dirty, {len(agg.items)} findings")
    print(f"exit={code}  (fail-on={fail_on})")
    return code


def cmd_init_policy(args):
    """生成全域 policy 模板。作用域表是全的，是否需要裁剪由人审时决定。"""
    import copy
    scopes = []
    for s in WHOLE_MACHINE_SCOPES:
        sc = copy.deepcopy(s)
        why = sc.pop("why")
        sc["baseline"] = f"{args.baseline_dir.rstrip('/')}/{sc['label']}.fp.json"
        sc["why"] = why
        scopes.append(sc)
    policy = {
        "schema": POLICY_SCHEMA,
        "name": args.name,
        "fail_on": "high",
        "require_signed": True,
        "key_env": args.key_env or "FPENV_KEY",
        "release": {
            "enforce": bool(args.release_id),
            "expected": args.release_id or "",
            "lock_digest": "",
        },
        "scopes": scopes,
    }
    out = args.out or "policy.whole.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(policy, f, ensure_ascii=False, indent=2)
    print(f"policy: {out}")
    print(f"  scopes: {len(scopes)}（全域）")
    for s in scopes:
        print(f"    {s['label']:<22} {s['hash_mode']:<8} {s['why']}")
    print("\n下一步：")
    print(f"  1) fpenv lock   --policy {out} --release-id <版本ID> --ticket <工单> --out rel.lock.json")
    print(f"  2) 把 lock_digest 填进 {out} 的 release.lock_digest")
    print(f"  3) fpenv attest --policy {out} --lock rel.lock.json")
    print("  4) 部署基线到控制面，节点执行 fpenv audit")
    return 0


# ---------------------------------------------------------------- provenance / sources
#
# 信任锚的版本不能「我觉得是这个版本」。必须多来源交叉核对 + 多人签核，
# 并且这件事要能被机器判定，否则就是纸面制度。
#
# 来源分级（这条分级决定了「几个来源才算够」）：
#   official —— 上游作者/发行方自己发布的端点。任何结论必须至少有 1 个 official 支撑
#   mirror   —— 第三方镜像。只用来**交叉验证** official，不能单独作为唯一依据
#              （镜像可能滞后、被替换、或本身是投毒入口）

PROVENANCE_SCHEMA = "fpenv-provenance/v1"

# 两类端点（实测得出的结论，2026-10-23）：
#   pypi-json    —— 官方 JSON API，带每版本分发文件的 digests.sha256。镜像站**没有**这个端点（404）
#   simple-index —— PEP 503 索引，URL 片段里带 #sha256=。官方与国内镜像**都**有，且含历史版本
# 所以「多方核对」的正确做法是：官方 JSON 拿权威哈希 + 各镜像 simple index 拿交叉证据。

SOURCE_REGISTRY = {
    # ---- official：上游自建，作为第一事实源
    "pypi": {
        "tier": "official", "kind": "pypi-json",
        "url": "https://pypi.org/pypi/{name}/{version}/json",
        "why": "PyPI 官方 JSON API，digests.sha256 由上传者提供",
    },
    "pypi-simple": {
        "tier": "official", "kind": "simple-index",
        "url": "https://pypi.org/simple/{name}/",
        "why": "PyPI 官方 PEP 503 索引，含全部历史版本",
    },
    "pytorch": {
        "tier": "official", "kind": "simple-index",
        "url": "https://download.pytorch.org/whl/{name}/",
        "why": "PyTorch 官方 wheel index（含 CUDA 变体）",
    },
    # ---- mirror：仅交叉验证，不能单独作为唯一依据
    "tuna": {
        "tier": "mirror", "kind": "simple-index",
        "url": "https://pypi.tuna.tsinghua.edu.cn/simple/{name}/",
        "why": "清华 TUNA，国内主用镜像",
    },
    "aliyun": {
        "tier": "mirror", "kind": "simple-index",
        "url": "https://mirrors.aliyun.com/pypi/simple/{name}/",
        "why": "阿里云 PyPI 镜像",
    },
    "ustc": {
        "tier": "mirror", "kind": "simple-index",
        "url": "https://mirrors.ustc.edu.cn/pypi/simple/{name}/",
        "why": "中科大镜像",
    },
    "tencent": {
        "tier": "mirror", "kind": "simple-index",
        "url": "https://mirrors.cloud.tencent.com/pypi/simple/{name}/",
        "why": "腾讯云镜像",
    },
}

DEFAULT_SOURCES = ["pypi", "tuna", "aliyun"]


# 默认核对策略：关键组件三人制，普通组件两人制
DEFAULT_QUORUM = {"checkers": 2, "approvers": 1}
CRITICAL_QUORUM = {"checkers": 3, "approvers": 1}


def source_url(sid, name, version):
    spec = SOURCE_REGISTRY.get(sid)
    if not spec:
        return None
    return spec["url"].format(name=name, version=version)


def fetch_url(url, timeout=25, retries=3):
    """只读 GET 文本，返回 (text, err)。

    带重试：跨境链路对 pypi.org 会间歇性 timeout / connection reset，
    单次失败就判「来源不可用」会把网络抖动误报成来源缺失。
    只对瞬时错误重试，HTTP 4xx 不重试（那是端点本身的问题，重试无意义）。
    """
    import urllib.error
    import urllib.request
    last = None
    for attempt in range(max(1, retries)):
        req = urllib.request.Request(url, headers={"User-Agent": "fpenv/1 provenance-check"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace"), None
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500:
                return None, f"HTTP {e.code}"
            last = f"HTTP {e.code}"
        except Exception as e:  # noqa: BLE001 - 网络异常种类多，统一归类
            last = f"{type(e).__name__}: {e}"
        if attempt < retries - 1:
            time.sleep(1.5 * (attempt + 1))
    return None, last


def fetch_json(url, timeout=25):
    txt, err = fetch_url(url, timeout)
    if err:
        return None, err
    try:
        return json.loads(txt), None
    except json.JSONDecodeError as e:
        return None, f"JSON 解析失败: {e}"


def extract_sha_from_pypi(data):
    """PyPI JSON：取所有分发文件的 sha256。同一 release 下多个文件是正常的，
    比对时按文件名对齐，而不是简单取第一个。"""
    out = {}
    for f in (data.get("urls") or []):
        name = f.get("filename") or ""
        dig = (f.get("digests") or {}).get("sha256")
        if name and dig:
            out[name] = dig
    if not out:
        # 兼容老式 releases 结构
        for files in (data.get("releases") or {}).values():
            for f in files or []:
                name = f.get("filename") or ""
                dig = (f.get("digests") or {}).get("sha256")
                if name and dig:
                    out[name] = dig
    return out


_ANCHOR_RE = re.compile(r'<a\s[^>]*href="([^"]+)"', re.I)


def extract_sha_from_simple(html, version, filename_contains=None):
    """PEP 503 simple index：从 <a href="...whl#sha256=..."> 里取指定版本的文件哈希。

    simple index 列出全部历史版本，所以必须按版本号过滤，否则会拿到别的版本
    ——这正好也是「装错版本」事故的成因，过滤逻辑本身要严。
    """
    out = {}
    ver_tag = "-" + str(version) + "-"
    for href in _ANCHOR_RE.findall(html):
        if "#sha256=" not in href:
            continue
        base, _, frag = href.partition("#sha256=")
        sha = frag.strip().lower()
        if len(sha) < 64:
            continue
        fname = base.rsplit("/", 1)[-1]
        if ver_tag not in "-" + fname:
            continue
        if filename_contains and not any(t in fname for t in filename_contains):
            continue
        out[fname] = sha[:64]
    return out


def fetch_source_files(sid, name, version, filename_contains=None):
    """按来源类型分别取哈希，返回 (files, url, err)。"""
    spec = SOURCE_REGISTRY.get(sid)
    if not spec:
        return {}, None, "未在来源清单中注册（禁止用清单之外的端点做核对）"
    url = spec["url"].format(name=name, version=version)
    if spec["kind"] == "pypi-json":
        data, err = fetch_json(url)
        if err:
            return {}, url, err
        return extract_sha_from_pypi(data), url, None
    txt, err = fetch_url(url)
    if err:
        return {}, url, err
    files = extract_sha_from_simple(txt, version, filename_contains)
    return files, url, None if files else f"索引中未找到 {version} 的文件"


def cmd_check_source(args):
    """多来源交叉核对：从 official + mirror 分别拉取，比对同一文件的哈希。

    判定：
      agree   —— ≥2 个来源成功，含 official，且同名文件 sha256 全一致
      conflict—— 存在同名文件但 sha256 不同（投毒 / 镜像被替换）
      single  —— 只有 1 个来源成功，不构成多源核对
      no-official —— 有多个来源但全是镜像，缺少第一事实源
      version-not-found —— 所有来源都找不到该版本（最常见：拼错版本号）
    """
    name, version = args.name, args.version
    sids = args.source or list(DEFAULT_SOURCES)
    results = []
    for sid in sids:
        if sid not in SOURCE_REGISTRY:
            print(f"  skip {sid}: 未在来源清单中注册（禁止用清单之外的端点做核对）")
            continue
        spec = SOURCE_REGISTRY[sid]
        files, url, err = fetch_source_files(sid, name, version, args.file_contains)
        results.append({"source": sid, "tier": spec["tier"], "kind": spec["kind"],
                        "url": url, "ok": bool(files), "error": err, "files": files})

    ok_src = [r for r in results if r["ok"]]
    agree, conflict = {}, {}
    for fname in sorted({f for r in ok_src for f in r["files"]}):
        vals = {r["source"]: r["files"][fname] for r in ok_src if fname in r["files"]}
        if len(set(vals.values())) > 1:
            conflict[fname] = vals
        elif len(vals) >= 2:
            agree[fname] = next(iter(vals.values()))

    has_official = any(r["tier"] == "official" and r["ok"] for r in ok_src)
    if not ok_src:
        verdict, code = "version-not-found", 2
    elif conflict:
        verdict, code = "conflict", 3
    elif len(ok_src) < 2:
        verdict, code = "single", 2
    elif not has_official:
        verdict, code = "no-official", 2
    elif agree:
        verdict, code = "agree", 0
    else:
        verdict, code = "insufficient", 2

    if args.json:
        print(json.dumps({"name": name, "version": version, "verdict": verdict,
                          "official_present": has_official,
                          "sources": results,
                          "agree": agree, "conflict": conflict, "exit": code},
                         ensure_ascii=False, indent=2))
        return code

    print(f"核对目标: {name}=={version}")
    n_off = sum(1 for s in results if s["tier"] == "official")
    print(f"来源清单: {len(results)} 个（official={n_off}, "
          f"mirror={sum(1 for s in results if s['tier'] == 'mirror')}）")
    for r in results:
        mark = "OK  " if r["ok"] else "FAIL"
        print(f"  [{mark}] {r['source']:<12} {r['tier']:<8} {r['kind']:<13} "
              f"{len(r['files']):>3} files  {r['error'] or ''}")
    print(f"\n判定: {verdict}（official 存在={has_official}）")
    if conflict:
        print("  冲突（同名文件哈希不一致，必须停机排查）：")
        for fname, vals in list(conflict.items())[:5]:
            print(f"    {fname}")
            for s, v in vals.items():
                print(f"      {s}: {v}")
    elif agree:
        print(f"  一致文件数: {len(agree)}")
        for fname, v in list(agree.items())[:3]:
            print(f"    {fname}  {v[:32]}…")
    print(f"\nexit={code}")
    return code


def load_provenance(path):
    with open(path, encoding="utf-8") as fh:
        pv = json.load(fh)
    if pv.get("schema") != PROVENANCE_SCHEMA:
        sys.exit(f"fpenv: provenance schema 应为 {PROVENANCE_SCHEMA}，实际 {pv.get('schema')!r}")
    return pv


def check_provenance(prov, release, policy, findings, scope_label):
    """把「几人核对、几人确认、几个来源」变成机器判定。
    prov 来自 manifest 或独立 provenance 文件；release 来自 manifest.release。"""
    need = policy.get("provenance") or {}
    if not need.get("enforce", False):
        return
    label = scope_label

    if not prov:
        findings.add("F-PROVENANCE-MISSING", label, "critical",
                     "policy 要求来源核对，但基线未附带 provenance 记录")
        return

    if prov.get("release_id") != (release or {}).get("id"):
        findings.add("F-PROVENANCE-STALE", label, "critical",
                     f"prov 对应版本 {prov.get('release_id')!r} ≠ 当前合规版本 {(release or {}).get('id')!r}")
        return

    crit_names = set(need.get("critical_components") or [])
    checks = {c.get("component", "").lower(): c for c in prov.get("checks") or []}

    # 1) 每个关键组件都要有核对记录
    missing = []
    packages = (release or {}).get("components", {}).get("packages") or {}
    for pkg in packages:
        if pkg in crit_names and pkg not in checks:
            missing.append(pkg)
    if missing:
        findings.add("F-PROVENANCE-THIN", label, "critical",
                     f"{len(missing)} 个关键组件缺少来源核对记录：{', '.join(missing[:5])}")

    # 2) 每个关键组件：来源数够、必须含 official、哈希必须一致
    for pkg in sorted(crit_names):
        c = checks.get(pkg)
        if not c:
            continue
        srcs = c.get("sources") or []
        tiers = [s.get("tier") for s in srcs]
        if len(srcs) < 2:
            findings.add("F-PROVENANCE-THIN", label, "critical",
                         f"{pkg}: 只有 {len(srcs)} 个来源，至少需要 2 个（1 official + 1 mirror）")
        if "official" not in tiers:
            findings.add("F-PROVENANCE-THIN", label, "critical",
                         f"{pkg}: 缺少 official 来源——镜像不能作为唯一依据")
        shas = {s.get("sha256") for s in srcs if s.get("sha256")}
        if len(shas) > 1:
            findings.add("F-PROVENANCE-CONFLICT", label, "critical",
                         f"{pkg}: 多来源哈希不一致（{len(shas)} 种），疑似投毒或被替换")
        if c.get("verdict") not in (None, "agree"):
            findings.add("F-PROVENANCE-CONFLICT", label, "critical",
                         f"{pkg}: 核对结论为 {c.get('verdict')!r}，非 agree")

    # 3) 人数与角色：核对人 ≥N、确认人 ≥1、且同一人不得兼任
    min_check = int(need.get("min_checkers", CRITICAL_QUORUM["checkers"] if crit_names
                             else DEFAULT_QUORUM["checkers"]))
    min_appr = int(need.get("min_approvers", DEFAULT_QUORUM["approvers"]))
    reviewers = prov.get("reviewers") or []
    checkers = {r["name"] for r in reviewers if r.get("role") == "check" and r.get("name")}
    approvers = {r["name"] for r in reviewers if r.get("role") == "approve" and r.get("name")}
    if len(checkers) < min_check:
        findings.add("F-PROVENANCE-QUORUM", label, "critical",
                     f"核对人 {len(checkers)} < 要求 {min_check}（双人核对防止单人伪造结论）")
    if len(approvers) < min_appr:
        findings.add("F-PROVENANCE-QUORUM", label, "critical",
                     f"确认人 {len(approvers)} < 要求 {min_appr}")
    overlap = checkers & approvers
    if overlap:
        findings.add("F-PROVENANCE-QUORUM", label, "critical",
                     f"角色冲突：{', '.join(sorted(overlap))} 同时是核对人与确认人（自核自确认无效）")

    # 4) 时间：核对必须发生在版本锁定之前或同时，不能事后补签
    locked_at = (release or {}).get("locked_at") or ""
    late = [r.get("name") for r in reviewers
            if r.get("at") and locked_at and r["at"] > locked_at]
    if late:
        findings.add("F-PROVENANCE-STALE", label, "critical",
                     f"以下人员签核时间晚于版本锁定时间：{', '.join(str(x) for x in late[:5])}（补签不算核对）")


def cmd_provenance_template(args):
    """生成 provenance 记录模板——人照着填，机器照着判。"""
    lock = load_lock(args.lock)
    policy = load_policy(args.policy) if args.policy else {}
    crit = set((policy.get("provenance") or {}).get("critical_components") or [])
    packages = (lock.get("components") or {}).get("packages") or {}
    checks = []
    for pkg, ver in sorted(packages.items()):
        if args.critical_only and pkg not in crit:
            continue
        checks.append({
            "component": pkg,
            "version": ver,
            "critical": pkg in crit,
            "sources": [
                {"id": "pypi", "tier": "official", "url": "", "sha256": "", "fetched_at": ""},
                {"id": "tuna", "tier": "mirror", "url": "", "sha256": "", "fetched_at": ""},
            ],
            "verdict": "",
            "note": "",
        })
    prov = {
        "schema": PROVENANCE_SCHEMA,
        "release_id": lock["release_id"],
        "created_at": "",
        "quorum": CRITICAL_QUORUM if crit else DEFAULT_QUORUM,
        "reviewers": [
            {"name": "", "role": "check", "at": ""},
            {"name": "", "role": "check", "at": ""},
            {"name": "", "role": "approve", "at": ""},
        ],
        "checks": checks,
    }
    out = args.out or f"{lock['release_id']}.provenance.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(prov, f, ensure_ascii=False, indent=2)
    print(f"provenance 模板: {out}")
    print(f"  待核对组件: {len(checks)}（其中关键 {sum(1 for c in checks if c['critical'])}）")
    print(f"  要求: 核对人 ≥{prov['quorum']['checkers']}，确认人 ≥{prov['quorum']['approvers']}")
    print("\n填写指引：")
    print("  1) 每个组件用 `fpenv check-source --name X --version Y --json` 取多源哈希")
    print("  2) official 与 mirror 的 sha256 必须一致，verdict 填 agree")
    print("  3) 核对人自己填 name 与 at（ISO 8601），确认人在核对完成后填")
    print("  4) 任何一处 conflict 立即停机上报，不要填 agree")
    return 0


class SourceUrlPlaceholder:
    """模板里 url 留空占位，避免误导人以为已经取过证。"""
    def __init__(self, idx):
        self.idx = idx

    def __str__(self):
        return ""


# ---------------------------------------------------------------- journal (append-only chain)
#
# 为什么需要「不可撤销日志」而不是再算一次指纹：
#   指纹只能回答「现在对不对」，回答不了「什么时候被改的、谁改的、改了几次」。
#   本案最要命的一点正是：攻击者一边参会一边改，团队看不到「改动发生」这件事本身。
#
# 结构：哈希链（每条的 prev 指向上一条的 h）+ Ed25519 逐条签名。
#   - 改任意一条内容 → 该条 h 变 → 后续所有 prev 断裂
#   - 删中间一条     → 链断
#   - 重排           → seq 与 prev 都对不上
#   - 整条重写并重算链 → 没有私钥就签不出来（这正是 HMAC 换 Ed25519 的意义）
#   - 截断尾部       → 本机无法发现，必须靠外部锚定（见 anchor）
#
# 诚实的边界：本机日志可被 root 删除/截断。所以 journal 必须定期把链头锚到外部，
# 否则它只是「比没有强」，不是「不可撤销」。

JOURNAL_SCHEMA = "fpenv-journal/v1"
JOURNAL_ENTRY_SCHEMA = "fpenv-entry/v1"
ANCHOR_SCHEMA = "fpenv-anchor/v1"

ENTRY_KINDS = {
    "fs.modify": "文件被写入/修改",
    "fs.create": "新文件出现",
    "fs.delete": "文件消失",
    "fs.attrib": "文件属性变化（chmod/chown/utime）",
    "git.head": "源码仓库 HEAD 变化",
    "git.dirty": "源码工作区出现未提交改动",
    "lock.release": "版本被锁定",
    "attest.baseline": "基线被拍拓",
    "checkpoint.sign": "产物被签名",
    "audit.result": "一次审计完成",
    "anchor.publish": "链头被锚定到外部",
}


def _ed25519_import():
    try:
        from cryptography.hazmat.primitives import serialization  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)  # noqa: F401
    except ImportError as e:
        sys.exit(f"fpenv: 需要 cryptography 才能用 Ed25519（{e}）。"
                 "安装：pip install cryptography —— 或继续用 HMAC（--key-env）")


def ed25519_keygen(priv_path, pub_path):
    _ed25519_import()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    priv_pem = k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    pub_pem = k.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    for p, data, mode in ((priv_path, priv_pem, 0o600), (pub_path, pub_pem, 0o644)):
        with open(p, "wb") as f:
            f.write(data)
        try:
            os.chmod(p, mode)
        except OSError:
            pass
    return priv_path, pub_path


def ed25519_sign(priv_path, data: bytes) -> str:
    _ed25519_import()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with open(priv_path, "rb") as f:
        k = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(k, Ed25519PrivateKey):
        sys.exit(f"fpenv: {priv_path} 不是 Ed25519 私钥")
    return k.sign(data).hex()


def ed25519_verify(pub_path, data: bytes, sig_hex: str) -> bool:
    _ed25519_import()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    with open(pub_path, "rb") as f:
        k = serialization.load_pem_public_key(f.read())
    if not isinstance(k, Ed25519PublicKey):
        sys.exit(f"fpenv: {pub_path} 不是 Ed25519 公钥")
    try:
        k.verify(bytes.fromhex(sig_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def entry_payload(e):
    """参与哈希的字段：不含 h 与 sig 本身。"""
    return {k: v for k, v in e.items() if k not in ("h", "sig")}


def entry_hash(e):
    return _h(canonical(entry_payload(e)))


def read_journal(path):
    """读 jsonl；坏行直接报错，不静默跳过（静默跳过等于允许插垃圾）。"""
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                sys.exit(f"fpenv: journal 第 {lineno} 行不是合法 JSON: {e}")
    return entries


def append_entry(path, kind, actor=None, path_=None, before=None, after=None,
                 meta=None, priv=None, pub=None, hmac_key=None):
    """追加一条。并发安全靠 O_APPEND + 单行原子写（<PIPE_BUF 的 jsonl 行）。
    真正多写者场景应加文件锁，这里显式说明限制而不是假装安全。"""
    if kind not in ENTRY_KINDS:
        sys.exit(f"fpenv: 未知事件类型 {kind!r}，允许: {', '.join(ENTRY_KINDS)}")
    entries = read_journal(path)
    prev = entries[-1]["h"] if entries else ""
    e = {
        "schema": JOURNAL_ENTRY_SCHEMA,
        "seq": (entries[-1]["seq"] + 1) if entries else 1,
        "at": now_iso(),
        "kind": kind,
        "actor": actor or os.environ.get("USER") or os.environ.get("USERNAME") or "?",
        "host": socket.gethostname(),
        "path": path_,
        "before": before,
        "after": after,
        "meta": meta or {},
        "prev": prev,
    }
    e["h"] = entry_hash(e)
    if priv:
        e["sig"] = {"alg": "ed25519", "key": os.path.basename(pub or ""),
                    "value": ed25519_sign(priv, bytes.fromhex(e["h"]))}
    elif hmac_key:
        e["sig"] = {"alg": "hmac-sha256", "key": "", "value": sign(e["h"], hmac_key)}
    else:
        e["sig"] = None
    line = json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(line.encode()) > 4096:
        sys.exit("fpenv: 单条事件过大（>4KB），jsonl 追加的原子性无法保证")
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())
    return e


def verify_journal(entries, pub=None, hmac_key=None, anchor=None, require_signed=True):
    """校验链完整性。返回 findings 列表。

    检查顺序刻意如此：先结构，再哈希，再签名，最后锚定。
    结构错了就没必要再算哈希。

    require_signed 默认 True 且很关键：**删掉 sig 字段本身必须是失败**。
    否则攻击者改完内容、重算整条链、再把签名抹掉，就能得到一条「自洽且无签名」的链，
    而「没签名所以跳过校验」会让它一路绿灯。实测踩过这个洞。
    """
    out = []

    def add(code, sev, seq, detail):
        out.append({"code": code, "severity": sev, "seq": seq, "detail": detail})

    if not entries:
        if anchor and anchor.get("seq"):
            add("J-TRUNCATED", "critical", 0,
                f"锚定记录显示链已到 seq={anchor['seq']}，但本地日志为空——日志被清空")
        return out

    # 1) seq 连续性
    for i, e in enumerate(entries):
        want = i + 1
        if e.get("seq") != want:
            add("J-SEQ-GAP", "critical", e.get("seq"),
                f"第 {i+1} 条记录的 seq={e.get('seq')}，应为 {want}——有记录被删除或重排")

    # 2) prev 链接 + 自身哈希
    prev_h = ""
    for i, e in enumerate(entries):
        if e.get("prev") != prev_h:
            add("J-CHAIN-BROKEN", "critical", e.get("seq"),
                f"seq={e.get('seq')} 的 prev={str(e.get('prev'))[:16]}… 与上一条 h={prev_h[:16]}… 不符")
        want_h = entry_hash(e)
        if e.get("h") != want_h:
            add("J-HASH-MISMATCH", "critical", e.get("seq"),
                f"seq={e.get('seq')} 内容哈希不符：记录 {str(e.get('h'))[:16]}… 实测 {want_h[:16]}…")
        prev_h = e.get("h") or ""

    # 3) 签名：缺失也算失败（这是防「重算链 + 抹掉签名」的关键）
    for e in entries:
        sig = e.get("sig")
        seq = e.get("seq")
        if not sig:
            if require_signed:
                add("J-UNSIGNED", "critical", seq,
                    f"seq={seq} 没有签名——改完内容重算整条链再把签名抹掉，正是这种特征")
            continue
        if sig.get("alg") == "ed25519":
            if not pub:
                if require_signed:
                    add("J-UNVERIFIED", "high", seq,
                        f"seq={seq} 是 Ed25519 签名，但未提供公钥，无法验证")
            elif not ed25519_verify(pub, bytes.fromhex(e["h"]), sig["value"]):
                add("J-SIG-INVALID", "critical", seq,
                    f"seq={seq} Ed25519 签名无效——记录不是可信方写的（链可能被重算过）")
        elif sig.get("alg") == "hmac-sha256" and hmac_key:
            if not hmac.compare_digest(sign(e["h"], hmac_key), sig["value"]):
                add("J-SIG-INVALID", "critical", seq, f"seq={seq} HMAC 不符")

    # 4) 截断：本地最后一条必须覆盖到锚定的 seq
    if anchor:
        a_seq = anchor.get("seq") or 0
        last_seq = entries[-1].get("seq") or 0
        last_h = entries[-1].get("h")
        if last_seq < a_seq:
            add("J-TRUNCATED", "critical", last_seq,
                f"锚定记录到 seq={a_seq}，本地只到 {last_seq}——尾部被截断")
        elif a_seq and anchor.get("h") and last_seq >= a_seq:
            at = next((x for x in entries if x.get("seq") == a_seq), None)
            if at and at.get("h") != anchor.get("h"):
                add("J-ANCHOR-MISMATCH", "critical", a_seq,
                    f"seq={a_seq} 的哈希与外部锚定值不符——历史被重写后重算")
    return out


def journal_report(findings, as_json=False, limit=20):
    if as_json:
        print(json.dumps({"ok": not findings, "count": len(findings),
                          "findings": findings}, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print("CLEAN — 日志链完整，签名有效")
            return
        for f in findings[:limit]:
            print(f"  {f['severity'].upper():<9} {f['code']:<18} seq={f['seq']}")
            print(f"            {f['detail']}")
        if len(findings) > limit:
            print(f"  … 另有 {len(findings)-limit} 项")


def cmd_journal(args):
    sub = args.journal_cmd

    if sub == "append":
        meta = {}
        for item in args.meta or []:
            k, _, v = item.partition("=")
            meta[k] = v
        e = append_entry(args.journal, args.kind, args.actor, args.path,
                         args.before, args.after, meta,
                         priv=args.priv, pub=args.pub,
                         hmac_key=(os.environ.get(args.key_env) if args.key_env else None))
        print(f"appended seq={e['seq']} kind={e['kind']} h={e['h'][:16]}… "
              f"signed={'ed25519' if args.priv else ('hmac' if args.key_env else 'no')}")
        return 0

    if sub == "verify":
        entries = read_journal(args.journal)
        anchor = None
        if args.anchor:
            with open(args.anchor, encoding="utf-8") as f:
                anchor = json.load(f)
        if args.anchor_sig and args.pub:
            # 锚定文件本身也要验签，否则改锚定文件就能掩盖截断
            with open(args.anchor, "rb") as f:
                raw = f.read()
            sig_path = args.anchor_sig
            with open(sig_path, encoding="utf-8") as f:
                sig = json.load(f)["sig"]
            if not ed25519_verify(args.pub, _h(raw).encode(), sig):
                print("锚定文件签名无效")
                return 3
        fs = verify_journal(entries, args.pub,
                            os.environ.get(args.key_env) if args.key_env else None,
                            anchor, require_signed=not args.allow_unsigned)
        journal_report(fs, args.json)
        if not args.json:
            print(f"\nentries={len(entries)}  findings={len(fs)}")
        return 3 if fs else 0

    if sub == "show":
        entries = read_journal(args.journal)
        for e in entries[-args.limit:]:
            print(f"  #{e['seq']:<4} {e['at']}  {e['kind']:<16} "
                  f"{e.get('actor',''):<10} {e.get('path') or e.get('meta',{}).get('release_id','') or ''}")
            if e.get("before") or e.get("after"):
                print(f"        {str(e.get('before'))[:16]}… → {str(e.get('after'))[:16]}…")
            if args.verbose and e.get("meta"):
                print(f"        meta={e['meta']}")
        print(f"\n共 {len(entries)} 条，链头 h={entries[-1]['h'][:16] if entries else '-'}…")
        return 0

    if sub == "anchor":
        entries = read_journal(args.journal)
        if not entries:
            sys.exit("fpenv: 日志为空，无法锚定")
        last = entries[-1]
        anchor = {
            "schema": ANCHOR_SCHEMA,
            "seq": last["seq"],
            "h": last["h"],
            "at": now_iso(),
            "entries": len(entries),
            "note": "此文件必须复制到本机之外（控制面/WORM/Git）。留在本机等于没锚定。",
        }
        out = args.out or (args.journal + ".anchor.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(anchor, f, ensure_ascii=False, indent=2)
        sig_out = None
        if args.priv:
            sig_out = out + ".sig"
            raw = open(out, "rb").read()
            with open(sig_out, "w", encoding="utf-8") as f:
                json.dump({"alg": "ed25519",
                           "sig": ed25519_sign(args.priv, _h(raw).encode())}, f)
        print(f"anchor: {out}")
        print(f"  seq={anchor['seq']} entries={anchor['entries']} h={anchor['h'][:32]}…")
        if sig_out:
            print(f"  signed: {sig_out}")
        print("\n⚠ 现在必须把它复制到本机之外。否则日志被整段删除/截断时无从发现。")
        return 0

    sys.exit(f"fpenv: 未知 journal 子命令 {sub}")


# ---------------------------------------------------------------- watch-fs (file change record)
#
# 「文件修改记录」与「文件指纹」是两条独立证据链：
#   指纹：现在是什么样
#   事件：什么时候、被谁、改成了什么样
# 攻击者能还原 mtime/权限/内容，但**无法取消已发生的事件**。
# 这正是本案缺的那一环——团队看不到「改动正在发生」。

IN_ACCESS, IN_MODIFY, IN_ATTRIB = 0x1, 0x2, 0x4
IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO = 0x8, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF = 0x100, 0x200, 0x400, 0x800
IN_ISDIR = 0x40000000

MASK_KIND = {
    IN_CREATE: "fs.create",
    IN_CLOSE_WRITE: "fs.modify",
    IN_MODIFY: "fs.modify",
    IN_DELETE: "fs.delete",
    IN_MOVED_FROM: "fs.delete",
    IN_MOVED_TO: "fs.create",
    IN_ATTRIB: "fs.attrib",
}


def cmd_watch_fs(args):
    """用 inotify 监听目录，把每次写入/属性变化记进 journal。

    只依赖 libc inotify，不需要 root（fanotify 才需要 CAP_SYS_ADMIN）。
    无法覆盖子目录时 inotify 会漏——所以默认递归加 watch。
    """
    import ctypes
    import select
    import struct

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.exit(f"fpenv: 目录不存在: {root}")
    if os.name != "posix":
        sys.exit("fpenv: watch-fs 需要 Linux inotify（Windows 上不可用，这是已知边界）")

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK)
    if fd < 0:
        sys.exit(f"fpenv: inotify_init1 失败: {os.strerror(ctypes.get_errno())}")

    mask = (IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_ATTRIB
            | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)
    wd_path = {}

    def add_dir(d):
        wd = libc.inotify_add_watch(fd, d.encode(), mask)
        if wd >= 0:
            wd_path[wd] = d

    add_dir(root)
    for dirpath, dirnames, _ in os.walk(root):
        for d in dirnames:
            add_dir(os.path.join(dirpath, d))

    print(f"watching {root} (inotify, {len(wd_path)} dirs) → {args.journal}")
    if args.duration:
        print(f"  时长 {args.duration}s / 最多 {args.max_events} 条事件")

    key = os.environ.get(args.key_env) if args.key_env else None
    deadline = time.time() + args.duration if args.duration else None
    count = 0
    try:
        while True:
            if deadline and time.time() >= deadline:
                break
            if count >= args.max_events:
                break
            r, _, _ = select.select([fd], [], [], 0.5)
            if not r:
                continue
            buf = os.read(fd, 1 << 16)
            off = 0
            while off < len(buf):
                wd, m, _cookie, ln = struct.unpack_from("iIII", buf, off)
                name = buf[off + 16: off + 16 + ln].split(b"\x00")[0].decode("utf-8", "replace")
                off += 16 + ln
                base = wd_path.get(wd)
                if not base:
                    continue
                full = os.path.join(base, name) if name else base
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if m & IN_ISDIR:
                    if m & (IN_CREATE | IN_MOVED_TO):
                        add_dir(full)
                    kind = "fs.create" if m & (IN_CREATE | IN_MOVED_TO) else "fs.delete"
                else:
                    kind = None
                    for bit, k in MASK_KIND.items():
                        if m & bit:
                            kind = k
                            break
                    if kind is None:
                        continue
                # 当场记指纹：事件发生时的内容状态，事后无法回溯
                sha, size = None, None
                if kind != "fs.delete" and os.path.isfile(full):
                    try:
                        sha = sha256_file(full) if (not args.no_hash and
                                                    os.path.getsize(full) <= args.max_hash_bytes) else None
                        size = os.path.getsize(full)
                    except OSError:
                        pass
                e = append_entry(args.journal, kind, args.actor, rel,
                                 before=None, after=sha,
                                 meta={"mask": hex(m), "size": size,
                                       "note": "inotify observed"},
                                 hmac_key=key)
                count += 1
                print(f"  #{e['seq']:<4} {kind:<12} {rel}"
                      + (f"  sha={sha[:12]}…" if sha else ""))
    except KeyboardInterrupt:
        pass
    finally:
        os.close(fd)

    print(f"\nrecorded {count} events → {args.journal}")
    return 0


# ---------------------------------------------------------------- git-audit (source code)
#
# 项目源码天然已有不可撤销日志：git commit 对象哈希 = 父提交 + tree + 元数据。
# 改任何历史都会改变后续所有哈希，且这个链条由所有协作者的克隆共同见证。
# 所以源码维度的正确做法不是「自己再算一遍文件指纹」，而是：
#   1. 工作区必须干净（源码 == 已审 HEAD）
#   2. HEAD 必须是上次审计 HEAD 的**后代**（不是重写来的）
#   3. 没有未跟踪的可执行/脚本文件（后门常以新文件形式出现）
#   4. HEAD 必须落在允许的分支或 tag 上

GIT_TRUST_CODES = {"G-HISTORY-REWRITTEN"}


def git_run(repo, *args, timeout=30):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                       timeout=timeout)
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


def cmd_git_audit(args):
    repo = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo, ".git")):
        sys.exit(f"fpenv: 不是 git 仓库: {repo}")

    findings = []

    def add(code, sev, detail):
        findings.append({"code": code, "severity": sev, "detail": detail})

    rc, head, err = git_run(repo, "rev-parse", "HEAD")
    if rc != 0:
        sys.exit(f"fpenv: 无法读取 HEAD: {err}")
    rc, branch, _ = git_run(repo, "rev-parse", "--abbrev-ref", "HEAD")

    # 1) 工作区是否干净
    rc, status, _ = git_run(repo, "status", "--porcelain", "--untracked-files=all")
    if status:
        dirty = [ln for ln in status.splitlines() if not ln.startswith("??")]
        untracked = [ln[3:] for ln in status.splitlines() if ln.startswith("??")]
        if dirty:
            add("G-DIRTY", "critical",
                f"{len(dirty)} 个已跟踪文件有未提交改动——源码与已审版本不一致：{dirty[:3]}")
        if untracked:
            risky = [u for u in untracked if re.search(r"\.(sh|py|so|service|js|pl)$", u)]
            sev = "critical" if risky else "medium"
            add("G-UNTRACKED", sev,
                f"{len(untracked)} 个未跟踪文件"
                + (f"，其中疑似脚本/可执行 {risky[:3]}" if risky else f"：{untracked[:3]}"))

    # 2) 历史是否被重写：新 HEAD 必须是旧 HEAD 的后代
    if args.expected_head:
        exp = args.expected_head
        if head == exp:
            pass
        else:
            rc, _, _ = git_run(repo, "merge-base", "--is-ancestor", exp, head)
            if rc == 0:
                rc2, cnt, _ = git_run(repo, "rev-list", "--count", f"{exp}..{head}")
                add("G-ADVANCED", "info",
                    f"HEAD 从 {exp[:12]} 前进到 {head[:12]}（新增 {cnt or '?'} 个提交，属正常演进）")
            else:
                add("G-HISTORY-REWRITTEN", "critical",
                    f"当前 HEAD {head[:12]} 不是上次审计 HEAD {exp[:12]} 的后代——"
                    "历史被 rebase/amend/force-push 重写过")

    # 3) 分支白名单
    if args.allow_branch:
        if branch not in args.allow_branch:
            add("G-BRANCH", "critical",
                f"当前分支 {branch!r} 不在允许列表 {args.allow_branch} 中")

    # 4) tag 签名情况
    rc, tags, _ = git_run(repo, "tag", "--points-at", "HEAD")
    if args.require_tag and not tags:
        add("G-NO-TAG", "high", "HEAD 上没有 tag——无法定位「这是哪个已发布版本」")

    # 5) 关键文件的最近改动者（谁最近动过）
    recent = []
    if args.trace:
        for f in args.trace:
            rc, out, _ = git_run(repo, "log", "-3", "--format=%h|%an|%ad|%s",
                                 "--date=iso", "--", f)
            if out:
                recent.append((f, out.splitlines()))

    code = 3 if any(f["severity"] == "critical" for f in findings) else 0
    if args.json:
        print(json.dumps({"ok": not findings, "repo": repo, "head": head, "branch": branch,
                          "findings": findings,
                          "trace": [{"file": f, "commits": c} for f, c in recent],
                          "exit": code}, ensure_ascii=False, indent=2))
    else:
        print(f"repo   : {repo}")
        print(f"HEAD   : {head}")
        print(f"branch : {branch}")
        if findings:
            for f in findings:
                print(f"  {f['severity'].upper():<9} {f['code']:<20} {f['detail']}")
        else:
            print("  CLEAN — 工作区干净，无历史重写迹象")
        if recent:
            print("\n最近改动者（按文件）：")
            for f, lines in recent:
                print(f"  {f}")
                for ln in lines:
                    print(f"    {ln}")
        print(f"\nexit={code}")
    if args.journal:
        append_entry(args.journal, "git.head", args.actor, repo,
                     before=args.expected_head, after=head,
                     meta={"branch": branch, "dirty": bool(status), "findings": len(findings)},
                     hmac_key=os.environ.get(args.key_env) if args.key_env else None)
    return code


# ---------------------------------------------------------------- checkpoint sign / verify
#
# 「已签名的 checkpoint」要防的不止是「文件被改」，还有四件更隐蔽的事：
#   1. 换文件     —— 签名里必须绑内容哈希
#   2. 张冠李戴   —— 把 A 的签名套到 B 上（同上，靠哈希）
#   3. 回滚冒充   —— 用旧 checkpoint 冒充新进度（绑 step / 单调性）
#   4. 事后重签   —— 私钥必须在训练节点之外（流程约束，代码只能记录这一事实）
# 大文件不能整读进内存再去签：分片哈希，签名覆盖「总哈希 + 分片清单 + 元数据」。

CKPT_SCHEMA = "fpenv-checkpoint/v1"
CHUNK = 64 << 20  # 64MB 分片，10GB checkpoint 也只有 160 片


def chunked_digest(path, chunk=CHUNK, max_chunks=100000):
    """流式算总体 sha256 + 每片 sha256。返回 (total_hex, size, [chunk_hex...])。"""
    total = hashlib.sha256()
    chunks = []
    size = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            total.update(b)
            chunks.append(hashlib.sha256(b).hexdigest())
            size += len(b)
            if len(chunks) > max_chunks:
                sys.exit(f"fpenv: 分片数超过 {max_chunks}，检查 chunk 大小设置")
    return total.hexdigest(), size, chunks


def cmd_sign_checkpoint(args):
    if not os.path.isfile(args.path):
        sys.exit(f"fpenv: 文件不存在: {args.path}")
    if not args.priv:
        sys.exit("fpenv: 签名必须提供 Ed25519 私钥 --priv（HMAC 不能用于对外证明）")

    meta = {}
    for item in args.meta or []:
        k, _, v = item.partition("=")
        meta[k] = v
    if "step" in meta:
        try:
            meta["step"] = int(meta["step"])
        except ValueError:
            pass

    t0 = time.time()
    total, size, chunks = chunked_digest(args.path, args.chunk_size << 20)
    dt = time.time() - t0

    body = {
        "schema": CKPT_SCHEMA,
        "name": os.path.basename(args.path),
        "size": size,
        "sha256": total,
        "chunk_size": args.chunk_size << 20,
        "chunks": chunks,
        "chunks_digest": _h(canonical(chunks)),
        "meta": meta,
        "signed_at": now_iso(),
        "signed_by": args.signer or os.environ.get("USER", "?"),
        "signer_host": socket.gethostname(),
    }
    body["payload_digest"] = _h(canonical({k: v for k, v in body.items()
                                           if k != "payload_digest"}))
    sig = ed25519_sign(args.priv, bytes.fromhex(body["payload_digest"]))
    body["sig"] = {"alg": "ed25519", "value": sig}

    out = args.out or (args.path + ".sig.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False, indent=2)

    print(f"signed: {out}")
    print(f"  file        : {body['name']}")
    print(f"  size        : {size:,} B ({size/1073741824:.2f} GiB)")
    print(f"  sha256      : {total}")
    print(f"  chunks      : {len(chunks)} × {args.chunk_size}MB  ({dt:.1f}s, "
          f"{size/1048576/max(dt,0.001):.0f} MB/s)")
    print(f"  meta        : {meta}")
    print(f"  signer      : {body['signed_by']} @ {body['signer_host']}")
    if body["signer_host"] == socket.gethostname():
        print("\n⚠ 签名主机与产物同机。若攻击者能在此机执行，就能在篡改后重新签名。")
        print("  正确做法：私钥只在控制面/离线机器，训练节点只做验证。")
    return 0


def cmd_verify_checkpoint(args):
    if not os.path.isfile(args.path):
        sys.exit(f"fpenv: 文件不存在: {args.path}")
    with open(args.sig, encoding="utf-8") as f:
        sig = json.load(f)
    if sig.get("schema") != CKPT_SCHEMA:
        sys.exit(f"fpenv: 签名文件 schema 应为 {CKPT_SCHEMA}")

    problems = []

    def add(code, sev, detail):
        problems.append({"code": code, "severity": sev, "detail": detail})

    # 1) 签名本身
    recomputed = _h(canonical({k: v for k, v in sig.items()
                               if k not in ("payload_digest", "sig")}))
    if recomputed != sig.get("payload_digest"):
        add("C-SIG-TAMPERED", "critical",
            "签名文件的 payload_digest 不符——签名文件自身被改过")
    if not args.pub:
        add("C-NO-PUBKEY", "critical", "未提供公钥，无法验证签名真实性")
    elif not ed25519_verify(args.pub, bytes.fromhex(sig["payload_digest"]),
                            sig.get("sig", {}).get("value", "")):
        add("C-SIG-INVALID", "critical", "Ed25519 签名无效——不是可信方签的")

    # 2) 文件名与大小（快速失败，避免白读几个 GB）
    if sig.get("name") != os.path.basename(args.path):
        add("C-NAME-MISMATCH", "critical",
            f"文件名 {os.path.basename(args.path)!r} 与签名记录 {sig.get('name')!r} 不符")
    actual_size = os.path.getsize(args.path)
    actual_sha = None
    if sig.get("size") != actual_size:
        add("C-SIZE-MISMATCH", "critical",
            f"大小 {actual_size:,} 与签名记录 {sig.get('size'):,} 不符")
    else:
        # 3) 内容：分片流式校验
        total, size, chunks = chunked_digest(args.path, sig.get("chunk_size", CHUNK))
        actual_sha = total
        if total != sig.get("sha256"):
            add("C-CONTENT", "critical",
                f"总体 sha256 不符：签名 {sig.get('sha256','')[:16]}… 实测 {total[:16]}…")
        elif _h(canonical(chunks)) != sig.get("chunks_digest"):
            bad = [i for i, (a, b) in enumerate(zip(chunks, sig.get("chunks") or [])) if a != b]
            add("C-CHUNK", "critical",
                f"分片哈希不符（{len(bad)} 片），首个差异在第 {bad[0] if bad else '?'} 片"
                "——总哈希相同但分片不同理论上不可能，说明签名文件的 chunks 被改")
        elif len(chunks) != len(sig.get("chunks") or []):
            add("C-CHUNK", "critical",
                f"分片数 {len(chunks)} ≠ 签名记录 {len(sig.get('chunks') or [])}")

    # 4) 回滚检查：step 必须 >= 允许下限
    meta = sig.get("meta") or {}
    step = meta.get("step")
    if args.min_step is not None:
        if not isinstance(step, int):
            add("C-NO-STEP", "critical",
                "签名里没有整数 step，无法判断是否回滚到旧检查点")
        elif step < args.min_step:
            add("C-ROLLBACK", "critical",
                f"checkpoint step={step} 低于要求下限 {args.min_step}——疑似回滚冒充")

    code = 3 if any(p["severity"] == "critical" for p in problems) else 0
    if args.json:
        print(json.dumps({"ok": not problems, "file": args.path,
                          "sha256": sig.get("sha256"), "meta": meta,
                          "findings": problems, "exit": code},
                         ensure_ascii=False, indent=2))
    else:
        print(f"file   : {os.path.basename(args.path)}")
        print(f"size   : {actual_size:,} B")
        print(f"sha256 : 签名 {sig.get('sha256')}")
        if actual_sha and actual_sha != sig.get("sha256"):
            print(f"         实测 {actual_sha}   ← 不符")
        print(f"meta   : {meta}")
        print(f"signer : {sig.get('signed_by')} @ {sig.get('signer_host')}  at {sig.get('signed_at')}")
        if problems:
            print()
            for p in problems:
                print(f"  {p['severity'].upper():<9} {p['code']:<16} {p['detail']}")
        else:
            print("\nPASS — 签名有效，内容与签名记录一致，无回滚迹象")
        print(f"exit={code}")
    return code


# ---------------------------------------------------------------- diff / show


def cmd_diff(args):
    with open(args.a, encoding="utf-8") as fh:
        A = json.load(fh)
    with open(args.b, encoding="utf-8") as fh:
        B = json.load(fh)
    a = {e["p"]: e for e in A["entries"]}
    b = {e["p"]: e for e in B["entries"]}
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = [p for p in sorted(set(a) & set(b)) if a[p].get("h") != b[p].get("h") or a[p]["s"] != b[p]["s"]]
    print(f"a: {A['label']} @ {A['created_at']}  digest={A['root_digest'][:16]}…")
    print(f"b: {B['label']} @ {B['created_at']}  digest={B['root_digest'][:16]}…")
    print(f"added={len(added)} removed={len(removed)} changed={len(changed)}")
    for tag, lst in (("A+", added), ("B-", removed), ("~~", changed)):
        for p in lst[:30]:
            print(f"  {tag} {p}")
    return 0


def cmd_show(args):
    with open(args.baseline, encoding="utf-8") as fh:
        m = json.load(fh)
    print(f"label       : {m['label']}")
    print(f"created_at  : {m['created_at']}")
    print(f"created_by  : {m['created_by']}")
    print(f"roots       : {m['scan']['roots']}")
    print(f"hash_mode   : {m['scan']['hash_mode']}")
    print(f"extra       : {m.get('extra')}")
    print(f"entries     : {len(m['entries'])}")
    print(f"root_digest : {m['root_digest']}")
    print(f"signature   : {'hmac-sha256 ' + m['sig']['value'][:16] + '…' if m.get('sig') else 'none'}")
    if args.list:
        for e in m["entries"][: args.list]:
            print(f"  {e['t']} {oct(e['m']):>8} {e['s']:>10}  {e['p']}")
    return 0


# ---------------------------------------------------------------- cli


def build_parser():
    p = argparse.ArgumentParser(prog="fpenv", description="训练环境指纹文件机制（stdlib only）")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, need_key=True):
        sp.add_argument("--key-file", help="HMAC 密钥文件")
        sp.add_argument("--key-env", help="存放 HMAC 密钥的环境变量名（推荐）")
        if need_key:
            sp.add_argument("--unsigned", action="store_true", help="显式允许不校验签名")
        sp.add_argument("--hash-mode", choices=["content", "meta"], default=None,
                        help="content=逐文件 sha256（门禁用）；meta=仅元数据（高频巡检用）")
        sp.add_argument("--ignore", action="append", help="glob 忽略，可重复")
        sp.add_argument("--ctime-mode", choices=["auto", "on", "off"], default="auto",
                        help="ctime 判据开关（Windows 上 ctime 是创建时间，auto 会关闭）")
        sp.add_argument("--json", action="store_true")

    b = sub.add_parser("baseline", help="拍拓：生成指纹文件")
    b.add_argument("--root", action="append", required=True, help="被拍拓目录，可重复")
    b.add_argument("--label", help="标签，如 goku-site-packages")
    b.add_argument("--out", help="输出文件")
    b.add_argument("--exclude", action="append", default=None, help="glob 排除，可重复")
    b.add_argument("--extra", action="append", help="附加键值，如 image_digest=sha256:…")
    b.add_argument("--allow-broad", action="store_true",
                   help="允许拍拓 / /usr /etc 等大范围目录（默认拒绝）")
    common(b, need_key=False)

    v = sub.add_parser("verify", help="校验：与指纹文件比对")
    v.add_argument("--baseline", required=True)
    v.add_argument("--fail-on", choices=["critical", "high", "medium", "info"], default="high")
    common(v)

    w = sub.add_parser("watch", help="周期巡检（训练期常驻）")
    w.add_argument("--baseline", required=True)
    w.add_argument("--interval", type=int, default=60)
    w.add_argument("--max-runs", type=int, default=0)
    w.add_argument("--log", help="追加写入 jsonl")
    w.add_argument("--exit-on-find", action="store_true", help="首次发现即退出（训练任务侧门禁）")
    common(w)

    d = sub.add_parser("diff", help="两份指纹文件比对")
    d.add_argument("--a", required=True)
    d.add_argument("--b", required=True)

    s = sub.add_parser("show", help="查看指纹文件")
    s.add_argument("--baseline", required=True)
    s.add_argument("--list", type=int, default=0, help="列出前 N 条条目")

    a = sub.add_parser("audit", help="按 policy 校验全部作用域（框架入口）")
    a.add_argument("--policy", required=True)
    a.add_argument("--fail-on", choices=["critical", "high", "medium", "info"], default=None)
    common(a)

    c = sub.add_parser("collect", help="按 policy 一次性拍拓全部作用域")
    c.add_argument("--policy", required=True)
    c.add_argument("--allow-broad", action="store_true", help="允许拍拓大范围目录")
    common(c, need_key=False)

    ip = sub.add_parser("init-policy", help="生成全域 policy 模板（七类安全边界）")
    ip.add_argument("--name", default="ml-train-env")
    ip.add_argument("--baseline-dir", default="/var/lib/fpenv/baselines")
    ip.add_argument("--release-id", help="合规版本 ID（填了则 policy 强制版本校验）")
    ip.add_argument("--key-env", default="FPENV_KEY")
    ip.add_argument("--out", default="policy.whole.json")

    lk = sub.add_parser("lock", help="第一步：固定合规版本，产出 release lock")
    lk.add_argument("--policy", required=True)
    lk.add_argument("--release-id", required=True, help="合规版本标识，如 goku-2024-07-build-0812")
    lk.add_argument("--out", help="输出 lock 文件")
    lk.add_argument("--ticket", help="变更工单号（进审批链）")
    lk.add_argument("--approved-by", help="审批人")
    lk.add_argument("--artifacts", help="锁定产物哈希：check-source --json 的输出文件")
    lk.add_argument("--provenance", help="挂载来源核对记录（fpenv-provenance/v1）")

    cs = sub.add_parser("check-source", help="多来源交叉核对下载指纹（official + mirror）")
    cs.add_argument("--name", required=True, help="包名，如 torch")
    cs.add_argument("--version", required=True, help="版本，如 2.4.0")
    cs.add_argument("--source", action="append",
                    help=f"来源 id，可重复；默认 {'/'.join(DEFAULT_SOURCES)}")
    cs.add_argument("--file-contains", action="append",
                    help="只核对文件名含这些串的产物，如 cp311 --file-contains manylinux1_x86_64")
    cs.add_argument("--json", action="store_true")

    va = sub.add_parser("verify-artifact", help="下载后校验产物指纹是否等于 lock 锁定值")
    va.add_argument("--file", required=True, help="已下载的文件路径")
    va.add_argument("--lock", required=True, help="release lock 文件")
    va.add_argument("--json", action="store_true", dest="as_json")

    pt = sub.add_parser("provenance-template", help="生成来源核对记录模板（照填，机器判）")
    pt.add_argument("--lock", required=True)
    pt.add_argument("--policy")
    pt.add_argument("--critical-only", action="store_true")
    pt.add_argument("--out")

    at = sub.add_parser("attest", help="第二步：对已固定版本生成全部作用域指纹")
    at.add_argument("--policy", required=True)
    at.add_argument("--lock", required=True)
    at.add_argument("--allow-broad", action="store_true")
    common(at, need_key=False)

    # ---- 密钥
    kg = sub.add_parser("keygen", help="生成 Ed25519 密钥对（私钥留控制面，公钥下发节点）")
    kg.add_argument("--priv", required=True, help="私钥输出路径")
    kg.add_argument("--pub", required=True, help="公钥输出路径")

    # ---- 不可撤销日志
    j = sub.add_parser("journal", help="不可撤销日志：哈希链 + 签名（事件记录）")
    js = j.add_subparsers(dest="journal_cmd", required=True)

    ja = js.add_parser("append", help="追加一条事件")
    ja.add_argument("--journal", required=True)
    ja.add_argument("--kind", required=True, choices=sorted(ENTRY_KINDS))
    ja.add_argument("--actor")
    ja.add_argument("--path")
    ja.add_argument("--before", help="变更前指纹")
    ja.add_argument("--after", help="变更后指纹")
    ja.add_argument("--meta", action="append", help="k=v，可重复")
    ja.add_argument("--priv", help="Ed25519 私钥（推荐）")
    ja.add_argument("--pub")
    ja.add_argument("--key-env")

    jv = js.add_parser("verify", help="校验链完整性 / 签名 / 截断")
    jv.add_argument("--journal", required=True)
    jv.add_argument("--anchor", help="外部锚定文件")
    jv.add_argument("--anchor-sig", help="锚定文件的签名")
    jv.add_argument("--pub", help="Ed25519 公钥")
    jv.add_argument("--key-env")
    jv.add_argument("--allow-unsigned", action="store_true",
                    help="显式允许无签名条目（默认要求每条都有签名，缺失即失败）")
    jv.add_argument("--json", action="store_true")

    jsh = js.add_parser("show", help="查看最近事件")
    jsh.add_argument("--journal", required=True)
    jsh.add_argument("--limit", type=int, default=20)
    jsh.add_argument("--verbose", action="store_true")

    jan = js.add_parser("anchor", help="导出链头锚定记录（必须复制到机器外）")
    jan.add_argument("--journal", required=True)
    jan.add_argument("--out")
    jan.add_argument("--priv", help="Ed25519 私钥，用于签锚定文件")

    # ---- 文件修改记录
    wf = sub.add_parser("watch-fs", help="inotify 实时记录文件修改事件到 journal")
    wf.add_argument("--root", required=True)
    wf.add_argument("--journal", required=True)
    wf.add_argument("--duration", type=int, default=0, help="运行秒数，0=直到 Ctrl-C")
    wf.add_argument("--max-events", type=int, default=1000)
    wf.add_argument("--actor")
    wf.add_argument("--no-hash", action="store_true", help="只记事件不算哈希（更快）")
    wf.add_argument("--max-hash-bytes", type=int, default=64 << 20,
                    help="超过此大小不算内容哈希，只记大小")
    wf.add_argument("--key-env")

    # ---- 源码审计
    ga = sub.add_parser("git-audit", help="项目源码审计：工作区 / 历史重写 / 分支白名单")
    ga.add_argument("--repo", required=True)
    ga.add_argument("--expected-head", help="上次审计记录的 HEAD（防历史重写）")
    ga.add_argument("--allow-branch", action="append", help="允许的分支，可重复")
    ga.add_argument("--require-tag", action="store_true", help="HEAD 必须有 tag")
    ga.add_argument("--trace", action="append", help="列出该文件的最近改动者")
    ga.add_argument("--journal", help="把结果写入 journal")
    ga.add_argument("--actor")
    ga.add_argument("--key-env")
    ga.add_argument("--json", action="store_true")

    # ---- checkpoint 签名
    sc = sub.add_parser("sign-checkpoint", help="签名生成物 / checkpoint（分片流式）")
    sc.add_argument("--path", required=True)
    sc.add_argument("--priv", required=True)
    sc.add_argument("--out", help="签名输出路径")
    sc.add_argument("--meta", action="append", help="k=v，如 step=12000 trial=goku-7b")
    sc.add_argument("--signer", help="签名人")
    sc.add_argument("--chunk-size", type=int, default=64, help="分片大小 MB，默认 64")

    vc = sub.add_parser("verify-checkpoint", help="验证生成物签名 / 内容 / 回滚")
    vc.add_argument("--path", required=True)
    vc.add_argument("--sig", required=True)
    vc.add_argument("--pub", help="Ed25519 公钥")
    vc.add_argument("--min-step", type=int, help="允许的最小 step（防回滚冒充）")
    vc.add_argument("--json", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "keygen":
        priv, pub = ed25519_keygen(args.priv, args.pub)
        print(f"private: {priv}  （留控制面/离线，绝不进训练节点）")
        print(f"public : {pub}   （下发到所有节点做验证）")
        return 0
    return {"baseline": cmd_baseline, "verify": cmd_verify, "watch": cmd_watch,
            "diff": cmd_diff, "show": cmd_show, "collect": cmd_collect,
            "audit": cmd_audit, "init-policy": cmd_init_policy,
            "lock": cmd_lock, "attest": cmd_attest,
            "check-source": cmd_check_source, "verify-artifact": cmd_verify_artifact,
            "provenance-template": cmd_provenance_template,
            "journal": cmd_journal, "watch-fs": cmd_watch_fs,
            "git-audit": cmd_git_audit,
            "sign-checkpoint": cmd_sign_checkpoint,
            "verify-checkpoint": cmd_verify_checkpoint}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
