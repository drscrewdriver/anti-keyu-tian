#!/usr/bin/env python3
"""三段式全流程演示：选合规版本 → 生成绑定指纹 → 全域检查。

与 demo.py 的区别：demo.py 只演示「指纹能抓篡改」；
本脚本演示完整的合规链条，包含最关键的那一步——
**脏基线（在已被污染的环境里拍的指纹）必须被拒**。

全程只在临时目录操作，不碰真实系统。

用法：
  python3 examples/pipeline_demo.py
  python3 examples/pipeline_demo.py --keep
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
KEY_ENV = "FPENV_PIPELINE_KEY"


def sh(*args, check=True, allow=(0,)):
    e = dict(os.environ)
    e[KEY_ENV] = "pipeline-key"
    r = subprocess.run([sys.executable, FPENV, *args], capture_output=True, text=True, env=e)
    out = (r.stdout or "") + (r.stderr or "")
    if check and r.returncode not in allow:
        print(out)
        raise SystemExit(f"失败: fpenv {' '.join(args)} exit={r.returncode}")
    return r.returncode, out


def banner(n, title):
    print("\n" + "=" * 70)
    print(f"第 {n} 步｜{title}")
    print("=" * 70)


def main():
    keep = "--keep" in sys.argv
    tmp = tempfile.mkdtemp(prefix="fpenv-pipeline-")
    try:
        sp = os.path.join(tmp, "site-packages")
        os.makedirs(os.path.join(sp, "torch", "nn"))
        # 造出带 dist-info 的「安装」痕迹，lock 才能采到版本
        os.makedirs(os.path.join(sp, "torch-2.4.0.dist-info"))
        os.makedirs(os.path.join(sp, "numpy-1.26.4.dist-info"))
        for rel, body in {
            "torch/__init__.py": "__version__ = '2.4.0'\n",
            "torch/nn/functional.py": "def clip_grad_norm_(p, m):\n    return _clip(p, m)\n",
        }.items():
            with open(os.path.join(sp, rel), "w") as f:
                f.write(body)
        old = 1700000000
        for d, _, ns in os.walk(sp):
            for n in ns:
                os.utime(os.path.join(d, n), (old, old))

        mdir = os.path.join(tmp, "baselines")
        policy = {
            "schema": "fpenv-policy/v1",
            "name": "goku-train-env",
            "fail_on": "high",
            "require_signed": True,
            "key_env": KEY_ENV,
            "release": {"enforce": True, "expected": "", "lock_digest": ""},
            "scopes": [{
                "label": "framework-libs",
                "roots": [sp],
                "baseline": os.path.join(mdir, "framework-libs.fp.json"),
                "hash_mode": "content",
                "why": "被 sudo 替换的就是这里",
            }],
        }
        ppath = os.path.join(tmp, "policy.json")
        with open(ppath, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)

        banner(1, "选定合规固定版本（人工审批 + 工单留痕）")
        lockf = os.path.join(tmp, "release.lock.json")
        _, out = sh("lock", "--policy", ppath, "--release-id", "goku-2024-07-build-0812",
                    "--out", lockf, "--ticket", "CHG-2024-0812", "--approved-by", "infra-lead")
        print(out.strip())
        lk = json.load(open(lockf))
        print(f"\n  包版本快照: {lk['components'].get('packages')}")

        banner(2, "合规生成被固定版本的指纹（绑定 release）")
        # 把版本钉进 policy（真实流程中这一步是审批后写入，受代码评审保护）
        policy["release"]["expected"] = lk["release_id"]
        policy["release"]["lock_digest"] = lk["lock_digest"]
        with open(ppath, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)
        _, out = sh("attest", "--policy", ppath, "--lock", lockf, "--key-env", KEY_ENV)
        print(out.strip())

        banner(3, "全域检查：合规版本 + 文件未变，双条件同时成立")
        code, out = sh("audit", "--policy", ppath, "--key-env", KEY_ENV, allow=(0, 2, 3))
        print(out.strip())
        print(f"\n>>> exit={code}（0=放行训练）")
        assert code == 0, "干净环境应放行"

        banner(4, "关键场景：有人拿「脏基线」来冒充合规")
        print("  攻击方式：在已被污染的环境里重新拍一份指纹，替换控制面基线。")
        print("  只比较文件的话 —— 永远 clean。看版本锚是否拦得住。\n")
        dirty = os.path.join(sp, "torch/nn/functional.py")
        with open(dirty, "w") as f:
            f.write("def clip_grad_norm_(p, m):\n    return _clip(p, m) * 2  # 已被注入\n")
        # 攻击者在脏环境里重新拍拓（相当于「重拍基线」），并同步修正封印与签名
        code, out = sh("collect", "--policy", ppath, "--key-env", KEY_ENV)
        print("  （已用 collect 重拍基线，模拟篡改基线）")
        code, out = sh("audit", "--policy", ppath, "--key-env", KEY_ENV, allow=(0, 2, 3))
        print(out.strip())
        print(f"\n>>> exit={code}")
        if code == 3:
            print("  ✓ 版本锚生效：基线虽被重拍，但未绑定合规版本 → 直接判信任失效")
        else:
            print("  ✗ 未拦住，需检查版本锚逻辑")

        banner(5, "版本漂移：环境里多装了东西（未走审批）")
        # 恢复干净，重新走正规流程
        with open(dirty, "w") as f:
            f.write("def clip_grad_norm_(p, m):\n    return _clip(p, m)\n")
        sh("attest", "--policy", ppath, "--lock", lockf, "--key-env", KEY_ENV)
        os.makedirs(os.path.join(sp, "backdoor-0.1.dist-info"))
        code, out = sh("audit", "--policy", ppath, "--key-env", KEY_ENV, allow=(0, 2, 3))
        print(out.strip())
        print(f"\n>>> exit={code}")
        assert code == 3, "未知包应被判 drift"

        if keep:
            print(f"\n临时目录: {tmp}")
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
