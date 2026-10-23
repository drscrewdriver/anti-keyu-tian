#!/usr/bin/env python3
"""fpenv 自测：在真实 POSIX 文件系统上复现「篡改 + 反取证」并验证检出。

复现的攻击动作（对应事件里 a.py/e.py/re.py 的手法）：
  A1 就地改写已安装库文件内容
  A2 用 os.utime 把 mtime/atime 还原成原值  ← 反取证
  A3 把权限位、属主改回原样                  ← 反取证
  A4 整体替换（写临时文件后 mv 覆盖）→ inode 变
并验证：以上四项全做，F-CTIME-DRIFT / F-BACKDATED / F-INODE-SWAP 仍能命中。

用法（在 WSL/Linux 下）：
  python3 tests/test_fpenv.py
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FPENV = os.path.join(os.path.dirname(HERE), "tools", "fpenv.py")

# 直接复用被测模块的摘要/签名函数，用于构造「攻击者会做的同步修正」场景
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("fpenv_mod", FPENV)
_fpenv = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_fpenv)

KEY = "test-key-0123456789"


def fpenv_root_digest(manifest):
    return _fpenv.root_digest(manifest)


def fpenv_sign(digest_hex):
    import hmac as _h
    import hashlib as _hh
    return _h.new(KEY.encode(), digest_hex.encode(), _hh.sha256).hexdigest()

PASS, FAIL = [], []


def run(*args, env=None, expect=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    r = subprocess.run([sys.executable, FPENV, *args], capture_output=True, text=True, env=e)
    out = (r.stdout or "") + (r.stderr or "")
    if expect is not None and r.returncode != expect:
        raise AssertionError(f"期望 exit={expect} 实际 {r.returncode}\n$ fpenv {' '.join(args)}\n{out}")
    return r.returncode, out


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not cond else ""))


def codes(out):
    """从 --json 输出里取 code 集合；兼容 verify（顶层 findings）与 audit（顶层 + scopes[].findings）。"""
    start = out.find("{")
    data = json.loads(out[start:])
    items = list(data.get("findings") or [])
    items += [i for s in data.get("scopes", []) for i in s.get("findings") or []]
    return {i["code"] for i in items}, items


def make_env(root):
    """造一个仿 site-packages 的目录树。"""
    os.makedirs(os.path.join(root, "torch", "nn"), exist_ok=True)
    files = {
        "torch/__init__.py": "__version__ = '2.4.0'\n",
        "torch/nn/functional.py": "def clip_grad_norm_(p, m):\n    return _clip(p, m)\n",
        "torch/utils/data/sampler.py": "class DistributedSampler:\n    def __iter__(self):\n"
                                       "        g.manual_seed(self.seed + self.epoch)\n",
        "torch/optim/adamw.py": "class AdamW:\n    maximize = False\n",
        "torch/_C.so": "ELF-fake-binary" * 100,
        "torch/version.txt": "2.4.0\n",
    }
    for rel, body in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body)
    # 固定一个旧 mtime，模拟「已安装很久的库」
    old = 1700000000
    for dirpath, _, names in os.walk(root):
        for n in names:
            os.utime(os.path.join(dirpath, n), (old, old))
    return files


def main():
    if os.name != "posix":
        print("skip: 本测试需要 POSIX 文件系统（ctime 语义）")
        return 0

    tmp = tempfile.mkdtemp(prefix="fpenv-test-")
    root = os.path.join(tmp, "site-packages")
    try:
        make_env(root)
        base = os.path.join(tmp, "sp.fp.json")
        keyenv = "FPENV_TEST_KEY"
        os.environ[keyenv] = "test-key-0123456789"

        print("\n[1] 拍拓 + 洁净校验")
        _, out = run("baseline", "--root", root, "--label", "sp", "--out", base,
                     "--key-env", keyenv)
        check("baseline 生成", os.path.exists(base))
        check("baseline 已签名", "hmac-sha256" in out, out)
        code, out = run("verify", "--baseline", base, "--key-env", keyenv, expect=0)
        check("洁净环境 verify exit=0", code == 0)
        check("洁净环境 CLEAN", "CLEAN" in out, out)

        print("\n[2] 攻击 A1+A2+A3：改内容 + 还原 mtime + 还原权限位")
        victim = os.path.join(root, "torch/nn/functional.py")
        st0 = os.stat(victim)
        with open(victim, "w") as f:
            f.write("def clip_grad_norm_(p, m):\n    return _clip(p, m) * 2  # tampered\n")
        os.utime(victim, ns=(st0.st_atime_ns, st0.st_mtime_ns))       # A2 还原时间
        os.chmod(victim, stat.S_IMODE(st0.st_mode))                    # A3 还原权限
        st1 = os.stat(victim)
        check("mtime 已还原", st1.st_mtime_ns == st0.st_mtime_ns)
        check("mode 已还原", stat.S_IMODE(st1.st_mode) == stat.S_IMODE(st0.st_mode))
        check("ctime 确实变了（改不掉）", st1.st_ctime_ns != st0.st_ctime_ns)

        code, out = run("verify", "--baseline", base, "--key-env", keyenv, "--json",
                        "--fail-on", "high", expect=2)
        cs, items = codes(out)
        check("verify exit=2（门禁拦截）", code == 2)
        check("命中 F-CONTENT", "F-CONTENT" in cs, sorted(cs))
        check("命中 F-CTIME-DRIFT", "F-CTIME-DRIFT" in cs, sorted(cs))
        check("命中 F-BACKDATED（mtime<ctime）", "F-BACKDATED" in cs, sorted(cs))

        print("\n[3] 攻击 A4：整体替换（内容相同、inode 变）")
        p2 = os.path.join(root, "torch/optim/adamw.py")
        st2 = os.stat(p2)
        tmpf = p2 + ".new"
        with open(tmpf, "w") as f:
            f.write("class AdamW:\n    maximize = False\n")
        os.utime(tmpf, ns=(st2.st_atime_ns, st2.st_mtime_ns))
        os.chmod(tmpf, stat.S_IMODE(st2.st_mode))
        os.replace(tmpf, p2)
        st3 = os.stat(p2)
        check("inode 已变化", st3.st_ino != st2.st_ino)
        check("mtime 仍与原值一致", st3.st_mtime_ns == st2.st_mtime_ns)
        code, out = run("verify", "--baseline", base, "--key-env", keyenv, "--json", expect=2)
        cs, items = codes(out)
        check("命中 F-INODE-SWAP", "F-INODE-SWAP" in cs, sorted(cs))

        print("\n[4] 新增后门文件 / 删除文件")
        with open(os.path.join(root, "torch/init.py"), "w") as f:
            f.write("import os; os.system('pkill torchrun')\n")
        b = os.path.join(root, "torch/version.txt")
        os.remove(b)
        code, out = run("verify", "--baseline", base, "--key-env", keyenv, "--json", expect=2)
        cs, _ = codes(out)
        check("命中 F-UNEXPECTED（新增后门）", "F-UNEXPECTED" in cs, sorted(cs))
        check("命中 F-MISSING（文件消失）", "F-MISSING" in cs, sorted(cs))

        print("\n[5] 指纹文件本身被改 → F-SEAL-BROKEN")
        tampered = os.path.join(tmp, "tampered.fp.json")
        with open(base, encoding="utf-8") as f:
            m = json.load(f)
        m["entries"][0]["h"] = "0" * 64
        with open(tampered, "w", encoding="utf-8") as f:
            json.dump(m, f, separators=(",", ":"))
        code, out = run("verify", "--baseline", tampered, "--key-env", keyenv, "--json", expect=3)
        cs, _ = codes(out)
        check("命中 F-SEAL-BROKEN 且 exit=3", "F-SEAL-BROKEN" in cs and code == 3, sorted(cs))

        print("\n[6] 错误密钥 → F-SIG-INVALID")
        m2 = dict(m)
        with open(base, encoding="utf-8") as f:
            m2 = json.load(f)
        code, out = run("verify", "--baseline", base, "--key-env", keyenv, "--json", expect=2)
        os.environ["FPENV_WRONG_KEY"] = "wrong-key"
        code, out = run("verify", "--baseline", base, "--key-env", "FPENV_WRONG_KEY", "--json", expect=3)
        cs, _ = codes(out)
        check("错误密钥 exit=3", code == 3, sorted(cs))
        check("命中 F-SIG-INVALID", "F-SIG-INVALID" in cs, sorted(cs))

        print("\n[7] watch 门禁模式（首次发现即退出）")
        code, out = run("watch", "--baseline", base, "--key-env", keyenv,
                        "--interval", "1", "--max-runs", "1", "--exit-on-find", "--json", expect=2)
        check("watch --exit-on-find exit=2", code == 2, out[:300])

        print("\n[8] diff：两次拍拓可比")
        b2 = os.path.join(tmp, "sp2.fp.json")
        run("baseline", "--root", root, "--label", "sp2", "--out", b2)
        code, out = run("diff", "--a", base, "--b", b2, expect=0)
        check("diff 输出 added/removed/changed", "added=" in out and "changed=" in out, out)

        print("\n[9] 误报控制：纯读访问不应告警")
        for dirpath, _, names in os.walk(root):
            for n in names:
                open(os.path.join(dirpath, n), "rb").read()
        os.environ[keyenv] = "test-key-0123456789"
        # 上一步已污染，改为重新拍拓后校验
        b3 = os.path.join(tmp, "sp3.fp.json")
        run("baseline", "--root", root, "--label", "sp3", "--out", b3, "--key-env", keyenv)
        code, out = run("verify", "--baseline", b3, "--key-env", keyenv, expect=0)
        check("重新拍拓后干净", "CLEAN" in out, out)
        before = {e["p"]: e["ct"] for e in json.load(open(b3))["entries"]}
        for dirpath, _, names in os.walk(root):
            for n in names:
                open(os.path.join(dirpath, n), "rb").read()
        code, out = run("verify", "--baseline", b3, "--key-env", keyenv, expect=0)
        check("纯读不改变 ctime（无假阳）", "CLEAN" in out, out)

        print("\n[10] policy 框架：collect → audit 全作用域")
        mdir = os.path.join(tmp, "manifests")
        os.makedirs(mdir, exist_ok=True)
        # 第二个作用域故意与被篡改目录互不重叠，用于验证「只报该脏的那个 scope」
        ldir = os.path.join(tmp, "launcher")
        os.makedirs(ldir, exist_ok=True)
        with open(os.path.join(ldir, "run_train.sh"), "w") as f:
            f.write("#!/bin/sh\nexec torchrun --nproc_per_node=8 train.py\n")
        policy = {
            "schema": "fpenv-policy/v1",
            "name": "ml-train-env",
            "fail_on": "high",
            "require_signed": True,
            "key_env": keyenv,
            "scopes": [
                {"label": "site-packages", "roots": [root],
                 "baseline": os.path.join(mdir, "sp.fp.json"),
                 "hash_mode": "content", "excludes": ["__pycache__", "*.pyc"]},
                {"label": "launcher", "roots": [ldir],
                 "baseline": os.path.join(mdir, "launcher.fp.json"),
                 "hash_mode": "meta"},
            ],
        }
        ppath = os.path.join(tmp, "policy.json")
        with open(ppath, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)

        code, out = run("collect", "--policy", ppath, "--key-env", keyenv, expect=0)
        check("collect 两个 scope 均产出", out.count("->") == 2, out)
        check("collect 生成基线文件", all(os.path.exists(s["baseline"]) for s in policy["scopes"]))

        code, out = run("audit", "--policy", ppath, "--key-env", keyenv, "--json", expect=0)
        data = json.loads(out[out.find("{"):])
        check("洁净环境 audit exit=0", code == 0)
        check("audit 覆盖 2 个 scope", data["summary"]["scopes"] == 2, data["summary"])
        check("audit 全部 CLEAN", data["summary"]["dirty"] == 0, data["summary"])

        # 只改一个 scope 覆盖的文件 → 应只报一个 scope dirty，且带 scope 标签
        victim2 = os.path.join(root, "torch/_C.so")
        st = os.stat(victim2)
        with open(victim2, "a") as f:
            f.write("x")
        os.utime(victim2, ns=(st.st_atime_ns, st.st_mtime_ns))
        code, out = run("audit", "--policy", ppath, "--key-env", keyenv, "--json", expect=2)
        data = json.loads(out[out.find("{"):])
        check("篡改后 audit exit=2", code == 2)
        lines = [ln for ln in out.splitlines()]
        dirty = [s for s in data["scopes"] if s.get("findings")]
        check("仅 1 个 scope 报脏", len(dirty) == 1, [s["label"] for s in data["scopes"]])
        check("报脏 scope 正确", dirty and dirty[0]["label"] == "site-packages",
              dirty[0]["label"] if dirty else None)

        # 未签名基线 + require_signed → F-UNSIGNED（信任锚点失效 exit=3）
        unsigned_scope = {"label": "unsigned", "roots": [root],
                          "baseline": os.path.join(mdir, "unsigned.fp.json"),
                          "hash_mode": "meta"}
        run("baseline", "--root", root, "--label", "unsigned",
            "--out", unsigned_scope["baseline"])
        p2 = json.loads(json.dumps(policy))
        p2["scopes"] = [unsigned_scope]
        p2path = os.path.join(tmp, "policy-unsigned.json")
        with open(p2path, "w", encoding="utf-8") as f:
            json.dump(p2, f)
        code, out = run("audit", "--policy", p2path, "--key-env", keyenv, "--json", expect=3)
        cs, items = codes(out)
        check("未签名基线 → F-UNSIGNED 且 exit=3", "F-UNSIGNED" in cs and code == 3, sorted(cs))
        code, out = run("audit", "--policy", p2path, "--unsigned", "--json")
        check("--unsigned 放行未签名", "F-UNSIGNED" not in codes(out)[0])

        # 基线文件缺失 → F-BASELINE-MISSING
        p3 = json.loads(json.dumps(policy))
        p3["scopes"] = [{"label": "ghost", "roots": [root],
                         "baseline": os.path.join(mdir, "nope.fp.json")}]
        p3path = os.path.join(tmp, "policy-ghost.json")
        with open(p3path, "w", encoding="utf-8") as f:
            json.dump(p3, f)
        code, out = run("audit", "--policy", p3path, "--key-env", keyenv, "--json", expect=3)
        check("基线缺失 → F-BASELINE-MISSING", "F-BASELINE-MISSING" in codes(out)[0])

        # checker 自校验
        p4 = json.loads(json.dumps(policy))
        p4["checker_sha256"] = "0" * 64
        p4path = os.path.join(tmp, "policy-checker.json")
        with open(p4path, "w", encoding="utf-8") as f:
            json.dump(p4, f)
        code, out = run("audit", "--policy", p4path, "--key-env", keyenv, "--json", expect=3)
        check("检查器摘要不符 → F-CHECKER-MISMATCH", "F-CHECKER-MISMATCH" in codes(out)[0])

        # 坏 policy 必须明确报错，不静默
        bad = os.path.join(tmp, "bad-policy.json")
        with open(bad, "w") as f:
            f.write('{"schema":"wrong","scopes":[]}')
        code, out = run("audit", "--policy", bad)
        check("坏 policy 明确报错", code != 0 and "schema" in out, out[:200])

        print("\n[12] 安全护栏：不碰伪文件系统 / 不自污染 / 不拍拓盘符根")
        code, out = run("baseline", "--root", "/proc", "--out", os.path.join(tmp, "x.json"))
        check("拒绝 /proc", code != 0 and "伪文件系统" in out, out[:200])
        code, out = run("baseline", "--root", "/", "--out", os.path.join(tmp, "x.json"))
        check("拒绝 / 除非 --allow-broad", code != 0 and "allow-broad" in out, out[:200])
        code, out = run("baseline", "--root", root, "--out", os.path.join(root, "sp.fp.json"))
        check("拒绝把指纹文件写进被拍拓目录", code != 0 and "自污染" not in out and "拒绝把指纹文件" in out, out[:300])
        check("被拍拓目录未残留指纹文件", not os.path.exists(os.path.join(root, "sp.fp.json")))

        print("\n[13] 写入边界：只写 --out，其余零写入")
        snapshot = {}
        for dirpath, _, names in os.walk(root):
            for n in names:
                p = os.path.join(dirpath, n)
                snapshot[p] = (os.stat(p).st_ino, os.stat(p).st_ctime_ns)
        run("verify", "--baseline", b3, "--key-env", keyenv, "--json")
        after = {}
        for dirpath, _, names in os.walk(root):
            for n in names:
                p = os.path.join(dirpath, n)
                after[p] = (os.stat(p).st_ino, os.stat(p).st_ctime_ns)
        check("verify 完全不改动被扫目录", snapshot == after,
              f"{len(snapshot)} vs {len(after)}")

        print("\n[14] 无密钥时 verify 必须报出「跳过签名校验」，不静默放行")
        code, out = run("verify", "--baseline", b3)
        check("签名基线 + 无密钥 → 明确 note 提示", "跳过签名校验" in out, out[:200])

        print("\n[15] 三段式流程：合规版本固定 → 指纹绑定 → 全域检查")
        # 造一个带 dist-info 的假环境，让 lock 能采到包版本
        rel_root = os.path.join(tmp, "rel-env")
        os.makedirs(os.path.join(rel_root, "torch-2.4.0.dist-info"))
        os.makedirs(os.path.join(rel_root, "numpy-1.26.4.dist-info"))
        with open(os.path.join(rel_root, "torch", "__init__.py") if os.path.isdir(
                os.path.join(rel_root, "torch")) else os.path.join(rel_root, "lib.py"), "w") as f:
            f.write("VERSION = '2.4.0'\n")
        # 上面那个写法别扭，直接建目录
        os.makedirs(os.path.join(rel_root, "torch"), exist_ok=True)
        with open(os.path.join(rel_root, "torch", "__init__.py"), "w") as f:
            f.write("__version__ = '2.4.0'\n")

        relmdir = os.path.join(tmp, "rel-manifests")
        relpolicy = {
            "schema": "fpenv-policy/v1",
            "name": "rel-demo",
            "fail_on": "high",
            "require_signed": True,
            "key_env": keyenv,
            "release": {"enforce": True, "expected": "", "lock_digest": ""},
            "scopes": [{"label": "framework-libs", "roots": [rel_root],
                        "baseline": os.path.join(relmdir, "libs.fp.json"),
                        "hash_mode": "content"}],
        }
        rp = os.path.join(tmp, "rel-policy.json")
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(relpolicy, f, indent=2)

        lockf = os.path.join(tmp, "rel.lock.json")
        code, out = run("lock", "--policy", rp, "--release-id", "goku-2024-07-build-0812",
                        "--out", lockf, "--ticket", "CHG-2024-0812", expect=0)
        check("lock 生成成功", os.path.exists(lockf), out[:300])
        lk = json.load(open(lockf))
        check("lock 采到 python 版本", bool(lk["components"].get("python")), lk["components"])
        check("lock 采到包版本", "torch" in (lk["components"].get("packages") or {}),
              lk["components"].get("packages"))
        check("lock_digest 存在", bool(lk.get("lock_digest")))
        check("工单进 lock", lk["approval"]["ticket"] == "CHG-2024-0812")

        # attest 需 policy 与 lock 一致
        code, out = run("attest", "--policy", rp, "--lock", lockf, "--key-env", keyenv)
        check("policy 未钉死版本时 attest 通过", code == 0, out[:300])
        m = json.load(open(relpolicy["scopes"][0]["baseline"]))
        check("指纹已绑定 release", (m.get("release") or {}).get("id") == "goku-2024-07-build-0812",
              m.get("release"))
        check("指纹带 lock_digest", (m.get("release") or {}).get("lock_digest") == lk["lock_digest"])

        # 钉死正确版本 → clean
        relpolicy["release"]["expected"] = "goku-2024-07-build-0812"
        relpolicy["release"]["lock_digest"] = lk["lock_digest"]
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(relpolicy, f, indent=2)
        code, out = run("audit", "--policy", rp, "--key-env", keyenv, "--json", expect=0)
        data = json.loads(out[out.find("{"):])
        check("版本钉死且一致 → audit clean", code == 0 and data["summary"]["dirty"] == 0, data["summary"])
        check("结果里带 release 标识", data["scopes"][0].get("release") == "goku-2024-07-build-0812")

        print("\n[16] 版本锚：脏基线/错版本必须被拒")
        # 场景 A：policy 钉死另一个版本 → F-RELEASE-MISMATCH
        rp2 = os.path.join(tmp, "rel-policy-wrong.json")
        wrong = json.loads(json.dumps(relpolicy))
        wrong["release"]["expected"] = "goku-2024-08-build-9999"
        with open(rp2, "w", encoding="utf-8") as f:
            json.dump(wrong, f)
        code, out = run("audit", "--policy", rp2, "--key-env", keyenv, "--json", expect=3)
        check("错版本 → F-RELEASE-MISMATCH + exit=3",
              "F-RELEASE-MISMATCH" in codes(out)[0] and code == 3, codes(out)[0])

        # 场景 B：基线未绑定版本但 policy 强制 → F-RELEASE-MISSING
        nobind = os.path.join(relmdir, "nobind.fp.json")
        run("baseline", "--root", rel_root, "--label", "nobind", "--out", nobind, "--key-env", keyenv)
        rp3 = os.path.join(tmp, "rel-policy-nobind.json")
        nb = json.loads(json.dumps(relpolicy))
        nb["scopes"][0]["baseline"] = nobind
        with open(rp3, "w", encoding="utf-8") as f:
            json.dump(nb, f)
        code, out = run("audit", "--policy", rp3, "--key-env", keyenv, "--json", expect=3)
        check("未绑定版本 → F-RELEASE-MISSING", "F-RELEASE-MISSING" in codes(out)[0])

        # 场景 C：attest 时 policy 钉死版本与 lock 不符 → 直接拒绝
        code, out = run("attest", "--policy", rp2, "--lock", lockf, "--key-env", keyenv)
        check("错版本 attest 被拒", code != 0 and "拒绝生成错版指纹" in out, out[:300])

        # 场景 D：release 块被改（components 与 lock_digest 不自洽）
        tam = json.load(open(relpolicy["scopes"][0]["baseline"]))
        tam["release"]["components"]["python"] = "9.9.9"
        # 重算封印摘要，模拟「攻击者会做的同步修正」
        tam["root_digest"] = fpenv_root_digest(tam)
        tam["sig"] = {"alg": "hmac-sha256", "value": fpenv_sign(tam["root_digest"])}
        tamp = os.path.join(relmdir, "tampered.fp.json")
        with open(tamp, "w", encoding="utf-8") as f:
            json.dump(tam, f)
        rp4 = os.path.join(tmp, "rel-policy-tam.json")
        t4 = json.loads(json.dumps(relpolicy))
        t4["scopes"][0]["baseline"] = tamp
        with open(rp4, "w", encoding="utf-8") as f:
            json.dump(t4, f)
        code, out = run("audit", "--policy", rp4, "--key-env", keyenv, "--json", expect=3)
        check("release 块被改 → F-RELEASE-MISMATCH（自洽性校验）",
              "F-RELEASE-MISMATCH" in codes(out)[0], codes(out)[0])

        print("\n[17] 版本漂移：包里多装了/版本变了必须报 F-LOCK-DRIFT")
        os.makedirs(os.path.join(rel_root, "evil-0.1.dist-info"))
        code, out = run("audit", "--policy", rp, "--key-env", keyenv, "--json", expect=3)
        check("未知包 → F-LOCK-DRIFT", "F-LOCK-DRIFT" in codes(out)[0], codes(out)[0])

        print("\n[18] 全域 policy 模板")
        whole = os.path.join(tmp, "whole.json")
        code, out = run("init-policy", "--name", "ml-prod", "--baseline-dir",
                        os.path.join(tmp, "whole-baselines"), "--release-id",
                        "goku-2024-07-build-0812", "--out", whole, expect=0)
        wp = json.load(open(whole))
        check("全域模板 7 类作用域", len(wp["scopes"]) == 7, len(wp["scopes"]))
        check("全域模板带版本强制", wp["release"]["enforce"] is True)
        check("每个作用域都有 why", all(s.get("why") for s in wp["scopes"]))
        labels = {s["label"] for s in wp["scopes"]}
        for must in ("framework-libs", "access-control", "launcher-and-hooks", "audit-integrity"):
            check(f"包含 {must}", must in labels, labels)
        check("模板可直接被 audit 加载", run("audit", "--policy", whole, "--key-env", keyenv)[0] in (0, 2, 3))

        print("\n[19] 来源核对与产物锁定（离线，用本地校验函数验证判定逻辑）")
        # wheel 文件名解析
        cases = [
            ("torch-2.4.0-cp312-none-macosx_11_0_arm64.whl", "torch", "2.4.0"),
            ("torch-2.4.0-cp311-cp311-manylinux1_x86_64.whl", "torch", "2.4.0"),
            ("numpy-1.26.4-cp312-cp312-win_amd64.whl", "numpy", "1.26.4"),
            ("torch_geometric-2.5.0-py3-none-any.whl", "torch-geometric", "2.5.0"),
            ("not-a-wheel.tar.gz", None, None),
        ]
        for fname, want_name, want_ver in cases:
            got = _fpenv.parse_wheel_version(fname)
            check(f"解析 {fname[:32]}", got == (want_name, want_ver), got)

        # simple index 解析：必须按版本过滤，不能串版本
        html = (
            '<a href="../../packages/x/torch-2.4.0-cp312-none-macosx_11_0_arm64.whl'
            '#sha256=' + "a" * 64 + '">torch-2.4.0</a>'
            '<a href="../../packages/y/torch-2.4.1-cp312-none-macosx_11_0_arm64.whl'
            '#sha256=' + "b" * 64 + '">torch-2.4.1</a>'
            '<a href="../../packages/z/torch-2.4.0-cp311-cp311-manylinux1_x86_64.whl'
            '#sha256=' + "c" * 64 + '">torch-2.4.0-linux</a>'
        )
        got = _fpenv.extract_sha_from_simple(html, "2.4.0")
        check("simple 索引按版本过滤（不含 2.4.1）",
              got == {"torch-2.4.0-cp312-none-macosx_11_0_arm64.whl": "a" * 64,
                      "torch-2.4.0-cp311-cp311-manylinux1_x86_64.whl": "c" * 64}, got)
        got = _fpenv.extract_sha_from_simple(html, "2.4.0", ["macosx_11_0_arm64"])
        check("simple 索引按平台过滤", list(got) == ["torch-2.4.0-cp312-none-macosx_11_0_arm64.whl"], got)
        got = _fpenv.extract_sha_from_simple(html, "2.4.9")
        check("simple 索引找不到版本时返回空", got == {}, got)

        # PyPI JSON 解析
        fake_json = {"urls": [
            {"filename": "torch-2.4.0-x.whl", "digests": {"sha256": "d" * 64}},
            {"filename": "torch-2.4.0-y.whl", "digests": {"sha256": "e" * 64}},
            {"filename": "nohash.whl", "digests": {}},
        ]}
        got = _fpenv.extract_sha_from_pypi(fake_json)
        check("PyPI JSON 解析", got == {"torch-2.4.0-x.whl": "d" * 64, "torch-2.4.0-y.whl": "e" * 64}, got)

        # 来源清单必须区分 official / mirror
        offs = [k for k, v in _fpenv.SOURCE_REGISTRY.items() if v["tier"] == "official"]
        mirs = [k for k, v in _fpenv.SOURCE_REGISTRY.items() if v["tier"] == "mirror"]
        check("来源清单含 official", len(offs) >= 2, offs)
        check("来源清单含 mirror", len(mirs) >= 2, mirs)
        check("默认核对源含 official", any(_fpenv.SOURCE_REGISTRY[s]["tier"] == "official"
                                            for s in _fpenv.DEFAULT_SOURCES))

        print("\n[20] verify-artifact：内容 + 版本声明双判据")
        lockf2 = os.path.join(tmp, "art.lock.json")
        goods = os.path.join(tmp, "torch-2.4.0-cp312-none-macosx_11_0_arm64.whl")
        with open(goods, "wb") as f:
            f.write(os.urandom(4096))
        real_sha = _fpenv.sha256_file(goods)
        lock2 = {
            "schema": "fpenv-release/v1", "release_id": "torch-2.4.0-verified",
            "locked_at": "2026-10-23T00:00:00Z",
            "components": {"python": "3.12.3"},
            "lock_digest": _fpenv.lock_digest({"python": "3.12.3"}),
            "artifacts": {os.path.basename(goods): real_sha},
            "artifacts_digest": "x",
        }
        with open(lockf2, "w", encoding="utf-8") as f:
            json.dump(lock2, f)

        code, out = run("verify-artifact", "--file", goods, "--lock", lockf2, expect=0)
        check("正确产物放行", code == 0 and "PASS" in out, out[-300:])

        # 内容篡改
        bad = os.path.join(tmp, "torch-2.4.0-cp312-none-macosx_11_0_arm64.whl.bak")
        shutil.copyfile(goods, bad)
        with open(bad, "r+b") as f:
            f.seek(100)
            f.write(b"\xff\xff")
        code, out = run("verify-artifact", "--file", bad, "--lock", lockf2, "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("内容篡改 → exit=3", code == 3 and d["content_ok"] is False, d["problems"])
        check("内容篡改给出原因", any("不在 lock" in p or "哈希" in p for p in d["problems"]), d["problems"])

        # 改名冒名：内容正确但文件名声称另一个版本
        renamed = os.path.join(tmp, "torch-2.4.1-cp312-none-macosx_11_0_arm64.whl")
        shutil.copyfile(goods, renamed)
        code, out = run("verify-artifact", "--file", renamed, "--lock", lockf2, "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("改名冒名 → exit=3", code == 3, d)
        check("识别版本声明冲突", d["version_conflict"] is True, d)
        check("识别重命名", d["renamed_from"] is not None, d)

        print("\n[21] lock 锁定产物：非 agree 结论必须拒绝")
        good_check = os.path.join(tmp, "ok-check.json")
        with open(good_check, "w", encoding="utf-8") as f:
            json.dump({"verdict": "agree", "agree": {"a.whl": "f" * 64}}, f)
        lk3 = os.path.join(tmp, "art2.lock.json")
        code, out = run("lock", "--policy", rp, "--release-id", "torch-x",
                        "--artifacts", good_check, "--out", lk3, expect=0)
        l3 = json.load(open(lk3))
        check("agree 结论可锁定", l3["artifacts"] == {"a.whl": "f" * 64}, l3.get("artifacts"))
        check("产物有独立摘要", bool(l3.get("artifacts_digest")))

        bad_check = os.path.join(tmp, "bad-check.json")
        with open(bad_check, "w", encoding="utf-8") as f:
            json.dump({"verdict": "conflict", "agree": {"a.whl": "f" * 64}}, f)
        code, out = run("lock", "--policy", rp, "--release-id", "torch-y",
                        "--artifacts", bad_check, "--out", os.path.join(tmp, "art3.lock.json"))
        check("conflict 结论拒绝锁定", code != 0 and "拒绝锁定" in out, out[-200:])

        print("\n[22] 不可撤销日志：哈希链 + Ed25519 签名")
        priv = os.path.join(tmp, "k.key")
        pub = os.path.join(tmp, "k.pub")
        code, _ = run("keygen", "--priv", priv, "--pub", pub, expect=0)
        check("keygen 生成密钥对", os.path.exists(priv) and os.path.exists(pub))
        check("私钥权限 600", stat.S_IMODE(os.stat(priv).st_mode) == 0o600,
              oct(stat.S_IMODE(os.stat(priv).st_mode)))

        jr = os.path.join(tmp, "j.jsonl")
        for kind, p in [("fs.modify", "a.py"), ("fs.create", "b.py"), ("lock.release", "c")]:
            run("journal", "append", "--journal", jr, "--kind", kind,
                "--path", p, "--priv", priv, "--pub", pub, expect=0)
        check("日志 3 条", len(open(jr).read().strip().split("\n")) == 3)

        code, out = run("journal", "verify", "--journal", jr, "--pub", pub, expect=0)
        check("干净链 verify exit=0", code == 0 and "CLEAN" in out, out)

        # 改内容不重算 → 哈希不符 + 链断
        ents = [json.loads(l) for l in open(jr) if l.strip()]
        ents[1]["actor"] = "mallory"
        f1 = os.path.join(tmp, "j-t1.jsonl")
        with open(f1, "w") as f:
            for e in ents:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
        code, out = run("journal", "verify", "--journal", f1, "--pub", pub, "--json", expect=3)
        cs, _ = codes(out)
        check("改内容 → J-HASH-MISMATCH", "J-HASH-MISMATCH" in cs, cs)
        # 注意：只改 actor 不改 h，prev 仍然连贯，所以这里不应出现 CHAIN-BROKEN。
        # 真正会断链的是「改了 h 但没同步后续 prev」，下面单独测。

        # 改 h 但不修正后续 prev → 链断
        ents_chain = [json.loads(l) for l in open(jr) if l.strip()]
        ents_chain[0]["h"] = "0" * 64
        f1b = os.path.join(tmp, "j-t1b.jsonl")
        with open(f1b, "w") as f:
            for e in ents_chain:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
        code, out = run("journal", "verify", "--journal", f1b, "--pub", pub, "--json", expect=3)
        cs, _ = codes(out)
        check("改 h 不改 prev → J-CHAIN-BROKEN", "J-CHAIN-BROKEN" in cs, cs)

        # 重算整条链 + 抹掉签名 → 必须靠 J-UNSIGNED 拦住（这是实测抓到的洞）
        prev = ""
        ents2 = [json.loads(l) for l in open(jr) if l.strip()]
        ents2[1]["actor"] = "mallory"
        for e in ents2:
            e["prev"] = prev
            e["sig"] = None
            e["h"] = _fpenv.entry_hash(e)
            prev = e["h"]
        f2 = os.path.join(tmp, "j-t2.jsonl")
        with open(f2, "w") as f:
            for e in ents2:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
        code, out = run("journal", "verify", "--journal", f2, "--pub", pub, "--json", expect=3)
        cs, _ = codes(out)
        check("重算链 + 抹签名 → J-UNSIGNED", "J-UNSIGNED" in cs, cs)
        check("重算链不留哈希错误（证明攻击者确实重算成功）",
              "J-HASH-MISMATCH" not in cs, cs)
        code, out = run("journal", "verify", "--journal", f2, "--pub", pub,
                        "--allow-unsigned", "--json", expect=0)
        check("--allow-unsigned 显式放行", code == 0, code)

        # 删中间一条 → seq gap + 链断
        f3 = os.path.join(tmp, "j-t3.jsonl")
        with open(f3, "w") as f:
            for e in ents[:1] + ents[2:]:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
        code, out = run("journal", "verify", "--journal", f3, "--pub", pub, "--json", expect=3)
        cs, _ = codes(out)
        check("删中间条 → J-SEQ-GAP", "J-SEQ-GAP" in cs, cs)

        # 锚定 + 清空 → 截断
        anchor = os.path.join(tmp, "j.anchor.json")
        run("journal", "anchor", "--journal", jr, "--out", anchor, "--priv", priv, expect=0)
        a = json.load(open(anchor))
        check("锚定记录 seq", a["seq"] == 3, a)
        empty = os.path.join(tmp, "j-empty.jsonl")
        open(empty, "w").close()
        code, out = run("journal", "verify", "--journal", empty, "--pub", pub,
                        "--anchor", anchor, "--json", expect=3)
        check("清空 → J-TRUNCATED", "J-TRUNCATED" in codes(out)[0], codes(out)[0])

        print("\n[23] 密钥错误 / 无公钥")
        wrong_priv = os.path.join(tmp, "w.key")
        wrong_pub = os.path.join(tmp, "w.pub")
        run("keygen", "--priv", wrong_priv, "--pub", wrong_pub, expect=0)
        code, out = run("journal", "verify", "--journal", jr, "--pub", wrong_pub, "--json",
                        expect=3)
        check("错误公钥 → J-SIG-INVALID", "J-SIG-INVALID" in codes(out)[0], codes(out)[0])

        print("\n[24] 源码审计：git-audit")
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        gp = ["git", "-C", repo, "-c", "user.email=a@b.c", "-c", "user.name=t"]
        subprocess.run(gp[:3] + ["init", "-q", "-b", "main"], check=True)
        with open(os.path.join(repo, "main.py"), "w") as f:
            f.write("print(1)\n")
        subprocess.run(gp + ["add", "-A"], check=True)
        subprocess.run(gp + ["commit", "-q", "-m", "init"], check=True)
        h1 = subprocess.run(gp + ["rev-parse", "HEAD"], capture_output=True,
                            text=True).stdout.strip()

        code, out = run("git-audit", "--repo", repo, expect=0)
        check("干净仓库 exit=0", code == 0, out)

        with open(os.path.join(repo, "main.py"), "a") as f:
            f.write("# injected\n")
        code, out = run("git-audit", "--repo", repo, "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("工作区漂移 → G-DIRTY", any(f["code"] == "G-DIRTY" for f in d["findings"]), d["findings"])

        subprocess.run(gp + ["checkout", "--", "main.py"], check=True)
        with open(os.path.join(repo, "main.py"), "a") as f:
            f.write("# stealth\n")
        subprocess.run(gp + ["add", "-A"], check=True)
        subprocess.run(gp + ["commit", "-q", "--amend", "-m", "init"], check=True)
        h2 = subprocess.run(gp + ["rev-parse", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
        check("amend 后 HEAD 变化", h1 != h2)
        code, out = run("git-audit", "--repo", repo, "--expected-head", h1, "--json",
                        expect=3)
        d = json.loads(out[out.find("{"):])
        check("历史重写 → G-HISTORY-REWRITTEN",
              any(f["code"] == "G-HISTORY-REWRITTEN" for f in d["findings"]), d["findings"])

        subprocess.run(gp + ["commit", "-q", "--allow-empty", "-m", "next"], check=True)
        h3 = subprocess.run(gp + ["rev-parse", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
        code, out = run("git-audit", "--repo", repo, "--expected-head", h2, "--json", expect=0)
        d = json.loads(out[out.find("{"):])
        check("正常前进 → G-ADVANCED(info) 不拦", code == 0 and any(
            f["code"] == "G-ADVANCED" for f in d["findings"]), d["findings"])

        os.makedirs(os.path.join(repo, "scripts"))
        with open(os.path.join(repo, "scripts", "hook.sh"), "w") as f:
            f.write("#!/bin/sh\necho evil\n")
        code, out = run("git-audit", "--repo", repo, "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("未跟踪脚本 → G-UNTRACKED critical", any(
            f["code"] == "G-UNTRACKED" and f["severity"] == "critical"
            for f in d["findings"]), d["findings"])

        code, out = run("git-audit", "--repo", repo, "--allow-branch", "release", "--json",
                        expect=3)
        d = json.loads(out[out.find("{"):])
        check("分支不在白名单 → G-BRANCH", any(f["code"] == "G-BRANCH" for f in d["findings"]),
              d["findings"])

        print("\n[25] 已签名 checkpoint：全链路")
        ck = os.path.join(tmp, "model-step500.pt")
        with open(ck, "wb") as f:
            for _ in range(5):
                f.write(os.urandom(1 << 20))
        sig = ck + ".sig.json"
        code, out = run("sign-checkpoint", "--path", ck, "--priv", priv, "--out", sig,
                        "--signer", "ci", "--meta", "step=500", expect=0)
        check("签名生成", os.path.exists(sig))
        s = json.load(open(sig))
        check("分片数正确（5MB / 64MB = 1 片）", len(s["chunks"]) == 1, len(s["chunks"]))
        check("有 payload_digest 与 sig", s.get("payload_digest") and s["sig"]["value"])

        code, out = run("verify-checkpoint", "--path", ck, "--sig", sig, "--pub", pub,
                        "--min-step", "100", expect=0)
        check("正常验证通过", code == 0 and "PASS" in out, out)

        print("\n[26] checkpoint 四种攻击")
        # a) 改字节（同名不同目录）
        d2 = os.path.join(tmp, "bad")
        os.makedirs(d2)
        bad = os.path.join(d2, os.path.basename(ck))
        shutil.copyfile(ck, bad)
        with open(bad, "r+b") as f:
            f.seek(100)
            f.write(b"\x00\xff\x00")
        code, out = run("verify-checkpoint", "--path", bad, "--sig", sig, "--pub", pub,
                        "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("改字节 → C-CONTENT", any(f["code"] == "C-CONTENT" for f in d["findings"]),
              d["findings"])

        # b) 回滚：合法签名的旧版本
        old = os.path.join(tmp, "model-step100.pt")
        with open(old, "wb") as f:
            f.write(os.urandom(1024))
        old_sig = old + ".sig.json"
        run("sign-checkpoint", "--path", old, "--priv", priv, "--out", old_sig,
            "--meta", "step=100", expect=0)
        code, out = run("verify-checkpoint", "--path", old, "--sig", old_sig, "--pub", pub,
                        "--json", expect=0)
        check("不设下限时旧版本通过（证明签名有效）", code == 0, code)
        code, out = run("verify-checkpoint", "--path", old, "--sig", old_sig, "--pub", pub,
                        "--min-step", "500", "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("设下限 → C-ROLLBACK", any(f["code"] == "C-ROLLBACK" for f in d["findings"]),
              d["findings"])

        # c) 张冠李戴
        other = os.path.join(tmp, "other.pt")
        with open(other, "wb") as f:
            f.write(os.urandom(2048))
        code, out = run("verify-checkpoint", "--path", other, "--sig", sig, "--pub", pub,
                        "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        cs = {f["code"] for f in d["findings"]}
        check("张冠李戴 → 名称/大小不符",
              "C-NAME-MISMATCH" in cs and "C-SIZE-MISMATCH" in cs, cs)

        # d) 篡改签名文件本身
        tam_sig = os.path.join(tmp, "tam.sig.json")
        s2 = json.load(open(sig))
        s2["meta"]["step"] = 999999          # 改元数据骗过回滚检查
        json.dump(s2, open(tam_sig, "w"))
        code, out = run("verify-checkpoint", "--path", ck, "--sig", tam_sig, "--pub", pub,
                        "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("改签名元数据 → C-SIG-TAMPERED",
              any(f["code"] == "C-SIG-TAMPERED" for f in d["findings"]), d["findings"])

        # e) 无公钥 → 无法验证真实性
        code, out = run("verify-checkpoint", "--path", ck, "--sig", sig, "--json", expect=3)
        d = json.loads(out[out.find("{"):])
        check("无公钥 → C-NO-PUBKEY",
              any(f["code"] == "C-NO-PUBKEY" for f in d["findings"]), d["findings"])

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'='*60}\nPASS {len(PASS)}  FAIL {len(FAIL)}")
    if FAIL:
        for n in FAIL:
            print(f"  failed: {n}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
