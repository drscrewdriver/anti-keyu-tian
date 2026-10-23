#!/usr/bin/env python3
"""可复现演示：拍拓 → 篡改并反取证 → audit 抓住。

在没有真实训练机的机器上验证框架行为，全程只在 tempfile 目录里操作。

用法：
  python3 examples/demo.py              # 默认演示
  python3 examples/demo.py --keep       # 保留临时目录以便人工查看
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FPENV = os.path.join(ROOT, "tools", "fpenv.py")
KEY_ENV = "FPENV_DEMO_KEY"


def sh(*args, check=True):
    e = dict(os.environ)
    e[KEY_ENV] = "demo-key"
    r = subprocess.run([sys.executable, FPENV, *args], capture_output=True, text=True, env=e)
    if check and r.returncode not in (0, 2, 3):
        print(r.stdout, r.stderr)
        raise SystemExit(f"命令失败: fpenv {' '.join(args)} (exit={r.returncode})")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    keep = "--keep" in sys.argv
    tmp = tempfile.mkdtemp(prefix="fpenv-demo-")
    try:
        sp = os.path.join(tmp, "site-packages")
        os.makedirs(os.path.join(sp, "torch", "nn"))
        os.makedirs(os.path.join(sp, "torch", "utils"))
        files = {
            "torch/__init__.py": "__version__ = '2.4.0'\n",
            "torch/nn/functional.py": "def clip_grad_norm_(p, m):\n    return _clip(p, m)\n",
            "torch/utils/sampler.py": "class DistributedSampler:\n    pass\n",
        }
        for rel, body in files.items():
            with open(os.path.join(sp, rel), "w") as f:
                f.write(body)
        old = 1700000000
        for d, _, ns in os.walk(sp):
            for n in ns:
                os.utime(os.path.join(d, n), (old, old))

        policy = {
            "schema": "fpenv-policy/v1",
            "name": "demo",
            "fail_on": "high",
            "require_signed": True,
            "key_env": KEY_ENV,
            "scopes": [{"label": "site-packages", "roots": [sp],
                        "baseline": os.path.join(tmp, "sp.fp.json"),
                        "hash_mode": "content"}],
        }
        ppath = os.path.join(tmp, "policy.json")
        with open(ppath, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)

        print("=" * 68)
        print("步骤 1｜拍拓基线")
        print("=" * 68)
        _, out = sh("collect", "--policy", ppath, "--key-env", KEY_ENV)
        print(out.strip())

        print("\n" + "=" * 68)
        print("步骤 2｜攻击者：改内容 + 还原 mtime + 还原权限位")
        print("=" * 68)
        victim = os.path.join(sp, "torch/nn/functional.py")
        st = os.stat(victim)
        with open(victim, "w") as f:
            f.write("def clip_grad_norm_(p, m):\n    return _clip(p, m) * 2  # tampered\n")
        os.utime(victim, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.chmod(victim, st.st_mode)
        st2 = os.stat(victim)
        print(f"  mtime 还原成功 : {st2.st_mtime_ns == st.st_mtime_ns}")
        print(f"  mode  还原成功 : {st2.st_mode == st.st_mode}")
        print(f"  ctime 却变了   : {st2.st_ctime_ns != st.st_ctime_ns}  ← 这个改不掉")

        print("\n" + "=" * 68)
        print("步骤 3｜audit 拦截")
        print("=" * 68)
        code, out = sh("audit", "--policy", ppath, "--key-env", KEY_ENV, check=False)
        print(out.strip())
        print(f"\n>>> exit={code}（训练启动脚本里 `|| exit 1` 即可拒绝启动）")
        assert code == 2, "应被拦截"

        if keep:
            print(f"\n临时目录保留在: {tmp}")
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
