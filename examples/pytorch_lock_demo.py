#!/usr/bin/env python3
"""PyTorch 全流程演示：多方核验下载指纹 → 指纹锁定 → 安装产物锁定。

真实网络、真实 torch wheel，全流程零模拟：
  ① 多源核对    PyPI 官方 JSON + 清华/阿里/中科大镜像的 PEP503 索引，比对同名文件 sha256
  ② 反例        装错版本 / 下载被篡改，两种都必须拦住
  ③ 指纹锁定    lock 把核验通过的产物哈希固定下来
  ④ 下载校验    真下载 torch wheel，比对锁定值
  ⑤ 产物锁定    解包（= pip 落盘结果）→ 对安装树拍拓 → 篡改 → 检出

为什么用 arm64 wheel 解包而不是 pip install：
  linux x86_64 的 torch CUDA wheel 是 760MB，arm64 版 59MB 但无法在 linux 上 import。
  wheel 就是 zip，pip 安装本质是解包+重定位，所以解包结果与「安装生成物」在文件层面等价。
  本演示只关心文件指纹，不关心能否运行。

用法：
  python3 examples/pytorch_lock_demo.py            # 完整流程
  python3 examples/pytorch_lock_demo.py --keep     # 保留临时目录
  python3 examples/pytorch_lock_demo.py --offline  # 跳过下载步骤（仅多源核对与锁定）
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FPENV = os.path.join(ROOT, "tools", "fpenv.py")

PKG = "torch"
VER = "2.4.0"
WHEEL = f"torch-2.4.0-cp312-none-macosx_11_0_arm64.whl"
MIRROR_BASE = "https://pypi.tuna.tsinghua.edu.cn"
KEY_ENV = "FPENV_PT_KEY"


def sh(*args, check=True, allow=(0,), quiet=False):
    e = dict(os.environ)
    e[KEY_ENV] = "pytorch-demo-key"
    r = subprocess.run([sys.executable, FPENV, *args], capture_output=True, text=True, env=e)
    out = (r.stdout or "") + (r.stderr or "")
    if not quiet:
        print(out.rstrip())
    if check and r.returncode not in allow:
        raise SystemExit(f"命令失败: fpenv {' '.join(args)} exit={r.returncode}")
    return r.returncode, out


def banner(n, title, sub=""):
    print("\n" + "=" * 72)
    print(f"第 {n} 步｜{title}")
    if sub:
        print(f"        {sub}")
    print("=" * 72)


def resolve_wheel_url(fname):
    """从镜像的 simple index 解析真实下载地址（相对路径要拼回主机）。"""
    url = f"{MIRROR_BASE}/simple/{PKG}/"
    req = urllib.request.Request(url, headers={"User-Agent": "fpenv-demo"})
    with urllib.request.urlopen(req, timeout=40) as r:
        html = r.read().decode("utf-8", "replace")
    m = re.search(r'href="([^"#]*' + re.escape(fname) + r')#sha256=([0-9a-f]{64})', html)
    if not m:
        return None, None
    href, sha = m.group(1), m.group(2)
    if href.startswith("/"):
        href = MIRROR_BASE + href
    elif not href.startswith("http"):
        href = f"{MIRROR_BASE}/simple/{PKG}/" + href
    # 归一化 ../ 路径
    href = re.sub(r"/simple/[^/]+/\*\*/", "/", href)
    parts = []
    for seg in href.split("/"):
        if seg == "..":
            if parts:
                parts.pop()
        elif seg not in ("", "."):
            parts.append(seg)
    scheme = parts[0]
    return scheme + "//" + "/".join(parts[1:]), sha


def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "fpenv-demo"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        last = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if time.time() - last > 3:
                pct = f"{done*100/total:.0f}%" if total else "?"
                print(f"    … {done/1048576:.1f}/{total/1048576:.0f} MB ({pct})", flush=True)
                last = time.time()
    return time.time() - t0


def main():
    keep = "--keep" in sys.argv
    offline = "--offline" in sys.argv
    tmp = tempfile.mkdtemp(prefix="fpenv-pytorch-")
    try:
        wheel_path = os.path.join(tmp, WHEEL)
        check_json = os.path.join(tmp, "check.json")
        lockf = os.path.join(tmp, "release.lock.json")
        pdir = os.path.join(tmp, "policy.json")

        # ---------------------------------------------------------------- ①
        banner(1, "多源核对下载指纹", "PyPI 官方 JSON + 三个国内镜像的 PEP503 索引")
        code, out = sh("check-source", "--name", PKG, "--version", VER,
                       "--file-contains", "cp312-none-macosx_11_0_arm64",
                       "--source", "pypi", "--source", "tuna",
                       "--source", "aliyun", "--source", "ustc",
                       "--json", allow=(0, 2, 3), quiet=True)
        data = json.loads(out[out.find("{"):])
        with open(check_json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        for s in data["sources"]:
            mark = "OK  " if s["ok"] else "FAIL"
            print(f"  [{mark}] {s['source']:<9} {s['tier']:<8} {len(s['files'])} files  {s['error'] or ''}")
        print(f"\n  判定: {data['verdict']}   official 存在: {data['official_present']}")
        for fn, sha in list(data["agree"].items()):
            print(f"    {fn}\n      sha256 = {sha}")
        assert data["verdict"] == "agree", "多源核对未通过"
        locked_sha = data["agree"].get(WHEEL)
        assert locked_sha, "目标 wheel 未出现在核对结果里"

        # ---------------------------------------------------------------- ②
        banner(2, "反例：装错版本 / 下载被篡改，都必须拦住")
        # 2a：核对一个不存在的版本
        code, out = sh("check-source", "--name", PKG, "--version", "2.4.99",
                       "--source", "pypi", "--source", "tuna",
                       allow=(0, 2, 3))
        print(f"  → 不存在的版本 2.4.99: exit={code}")
        assert code != 0

        # 2b：同一文件名在不同版本下哈希不同 —— 证明哈希能区分版本
        code, out = sh("check-source", "--name", PKG, "--version", "2.4.1",
                       "--file-contains", "cp312-none-macosx_11_0_arm64",
                       "--source", "pypi", "--source", "tuna", "--json",
                       allow=(0, 2, 3), quiet=True)
        d2 = json.loads(out[out.find("{"):])
        other = (d2.get("agree") or {}).get(WHEEL.replace("2.4.0", "2.4.1"))
        print(f"  2.4.0 的 {WHEEL[:40]}…")
        print(f"    sha256 = {locked_sha[:48]}…")
        if other:
            print(f"  2.4.1 的同名产物")
            print(f"    sha256 = {other[:48]}…")
            print(f"  → 两个版本哈希不同: {other != locked_sha}（所以哈希能识别装错版本）")
        else:
            print("  （2.4.1 的同名 wheel 未在索引中找到，跳过对比）")

        # ---------------------------------------------------------------- ③
        banner(3, "指纹锁定：把核验通过的产物哈希固定进 release lock")
        policy = {
            "schema": "fpenv-policy/v1",
            "name": "pytorch-demo",
            "fail_on": "high",
            "require_signed": True,
            "key_env": KEY_ENV,
            "release": {"enforce": True, "expected": "", "lock_digest": ""},
            "scopes": [],
        }
        with open(pdir, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)
        sh("lock", "--policy", pdir, "--release-id", f"{PKG}-{VER}-verified",
           "--ticket", "CHG-2024-0812", "--approved-by", "infra-lead",
           "--artifacts", check_json, "--out", lockf)
        lk = json.load(open(lockf))
        print(f"\n  artifacts_digest = {lk['artifacts_digest']}")
        print(f"  锁定产物条目     = {len(lk['artifacts'])}")

        # ---------------------------------------------------------------- ④
        banner(4, "下载真实 torch wheel 并校验指纹",
               f"{WHEEL} ≈ 59MB，走清华镜像")
        if offline:
            print("  --offline：跳过下载")
        else:
            url, sha_from_index = resolve_wheel_url(WHEEL)
            print(f"  下载地址: {url[:88]}…")
            print(f"  索引声明: {sha_from_index}")
            dt = download(url, wheel_path)
            size = os.path.getsize(wheel_path)
            print(f"  完成: {size/1048576:.1f} MB / {dt:.1f}s ({size/1048576/max(dt,0.1):.2f} MB/s)")
            code, out = sh("verify-artifact", "--file", wheel_path, "--lock", lockf,
                           allow=(0, 3))
            assert code == 0, "真实下载的 wheel 校验失败"

            # 4b：错误下载 —— 内容被改一个字节
            banner("4b", "反例：下载到被篡改的文件")
            bad = os.path.join(tmp, "corrupted.whl")
            shutil.copyfile(wheel_path, bad)
            with open(bad, "r+b") as f:
                f.seek(1024)
                b = f.read(1)
                f.seek(1024)
                f.write(bytes([b[0] ^ 0xFF]))
            code, out = sh("verify-artifact", "--file", bad, "--lock", lockf, allow=(0, 3))
            print(f"  → exit={code}（非 0 = 拒绝安装）")
            assert code == 3, "篡改文件未被拦截"

            # 4c：改名冒名 —— 内容是真的，但文件名声称另一个版本
            banner("4c", "反例：改名冒名（内容正确、文件名声称 2.4.1）")
            print("  这是只判内容哈希会漏掉的场景：拿 2.4.0 的字节冒充 2.4.1。\n")
            wrong = os.path.join(tmp, "torch-2.4.1-cp312-none-macosx_11_0_arm64.whl")
            shutil.copyfile(wheel_path, wrong)
            code, out = sh("verify-artifact", "--file", wrong, "--lock", lockf, allow=(0, 3))
            print(f"  → exit={code}（版本声明与锁定不符，必须拒绝）")
            assert code == 3, "改名冒名未被拦截"

        # ---------------------------------------------------------------- ⑤
        banner(5, "安装产物锁定：解包 → 拍拓 → 篡改 → 检出",
               "wheel 解包结果 = pip 落盘结果（文件层面等价）")
        if offline:
            print("  --offline：跳过（需要真实 wheel）")
            return 0

        site = os.path.join(tmp, "site-packages")
        t0 = time.time()
        with zipfile.ZipFile(wheel_path) as z:
            z.extractall(site)
        nfiles = sum(len(fs) for _, _, fs in os.walk(site))
        print(f"  解包 {nfiles} 个文件 → {os.path.relpath(site, tmp)}（{time.time()-t0:.1f}s）")
        print("  目录结构:")
        for top in sorted(os.listdir(site))[:6]:
            p = os.path.join(site, top)
            kind = "dir " if os.path.isdir(p) else "file"
            print(f"    {kind} {top}")
        if len(os.listdir(site)) > 6:
            print(f"    … 另有 {len(os.listdir(site))-6} 项")

        policy["scopes"] = [{
            "label": "site-packages",
            "roots": [site],
            "baseline": os.path.join(tmp, "baselines", "site-packages.fp.json"),
            "hash_mode": "content",
            "excludes": ["__pycache__", "*.pyc"],
        }]
        with open(lockf, encoding="utf-8") as f:
            lk = json.load(f)
        policy["release"]["expected"] = lk["release_id"]
        policy["release"]["lock_digest"] = lk["lock_digest"]
        with open(pdir, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)

        t0 = time.time()
        code, out = sh("attest", "--policy", pdir, "--lock", lockf, quiet=True)
        print(out.rstrip())
        print(f"  拍拓耗时 {time.time()-t0:.1f}s")

        # 干净基线自检
        code, out = sh("audit", "--policy", pdir, allow=(0, 2, 3), quiet=True)
        print(f"  干净环境 audit: exit={code}")
        assert code == 0

        # 5b：篡改安装产物
        banner("5b", "篡改安装产物：改一个文件并还原 mtime / 权限位")
        target = None
        for d, _, fs in os.walk(os.path.join(site, "torch")):
            for f in fs:
                if f.endswith(".py") and "version" in f:
                    target = os.path.join(d, f)
                    break
            if target:
                break
        if not target:
            for d, _, fs in os.walk(os.path.join(site, "torch")):
                for f in fs:
                    if f.endswith(".py"):
                        target = os.path.join(d, f)
                        break
                if target:
                    break
        rel = os.path.relpath(target, site)
        st0 = os.stat(target)
        with open(target, "a") as f:
            f.write("\n# __injected__ = True\n")
        os.utime(target, ns=(st0.st_atime_ns, st0.st_mtime_ns))
        os.chmod(target, stat.S_IMODE(st0.st_mode))
        st1 = os.stat(target)
        print(f"  目标: {rel}")
        print(f"  mtime 还原: {st1.st_mtime_ns == st0.st_mtime_ns}   "
              f"mode 还原: {stat.S_IMODE(st1.st_mode) == stat.S_IMODE(st0.st_mode)}   "
              f"ctime 变了: {st1.st_ctime_ns != st0.st_ctime_ns}")
        code, out = sh("audit", "--policy", pdir, allow=(0, 2, 3))
        print(f"  → exit={code}")
        assert code == 2, "篡改未检出"

        # 5c：塞入一个假包
        banner("5c", "塞入未登记的包（模拟依赖投毒 / 后门包）")
        os.makedirs(os.path.join(site, "torchvision-0.19.0.dist-info"))
        with open(os.path.join(site, "torchvision-0.19.0.dist-info", "METADATA"), "w") as f:
            f.write("Name: torchvision\nVersion: 0.19.0\n")
        code, out = sh("audit", "--policy", pdir, allow=(0, 2, 3))
        print(f"  → exit={code}")
        assert code == 2

        print("\n" + "=" * 72)
        print("全流程通过：多源核验 → 锁定 → 下载校验 → 产物拍拓 → 篡改检出")
        print("=" * 72)
        if keep:
            print(f"\n临时目录: {tmp}")
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
