#!/usr/bin/env python3
"""源码 / 生成物 / checkpoint 的三条证据链演示。

前两个演示（demo.py / pipeline_demo.py / pytorch_lock_demo.py）都在回答「现在对不对」。
这个演示回答另一个问题：**「什么时候被改的、谁改的、能不能事后抹掉」**。

三条相互独立的证据链：
  ① 不可撤销日志（journal）  哈希链 + Ed25519 逐条签名。改/删/重排/重算都能发现
  ② 文件修改记录（watch-fs） inotify 实时事件。攻击者能还原文件，但抹不掉已发生的事件
  ③ 源码与生成物（git / checkpoint）  利用 git 的 commit 链 + 对产物做分片签名

全程临时目录，结束即删。

用法：
  python3 examples/provenance_chain_demo.py
  python3 examples/provenance_chain_demo.py --keep
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FPENV = os.path.join(ROOT, "tools", "fpenv.py")


def sh(*args, check=True, allow=(0,), quiet=False):
    e = dict(os.environ)
    r = subprocess.run([sys.executable, FPENV, *args], capture_output=True, text=True, env=e)
    out = (r.stdout or "") + (r.stderr or "")
    if not quiet:
        print(out.rstrip())
    if check and r.returncode not in allow:
        raise SystemExit(f"命令失败: fpenv {' '.join(args)} exit={r.returncode}\n{out}")
    return r.returncode, out


def git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", repo, "-c", "user.email=a@b.c", "-c", "user.name=tester",
                        *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} 失败: {r.stderr}")
    return r.stdout.strip()


def banner(n, title, sub=""):
    print("\n" + "=" * 74)
    print(f"第 {n} 步｜{title}")
    if sub:
        print(f"        {sub}")
    print("=" * 74)


def main():
    keep = "--keep" in sys.argv
    tmp = tempfile.mkdtemp(prefix="fpenv-chain-")
    try:
        priv = os.path.join(tmp, "ed25519.key")
        pub = os.path.join(tmp, "ed25519.pub")
        journal = os.path.join(tmp, "audit.jsonl")
        anchor = os.path.join(tmp, "audit.anchor.json")

        banner(0, "生成 Ed25519 密钥对", "私钥留控制面 / 离线，节点只放公钥")
        sh("keygen", "--priv", priv, "--pub", pub)
        print(f"  私钥权限: {oct(os.stat(priv).st_mode)[-3:]}（应为 600）")

        # ------------------------------------------------------------ ①
        banner(1, "不可撤销日志：哈希链 + 逐条签名")
        for kind, p, meta in [
            ("fs.modify", "src/train.py", ["by=alice", "tool=vim"]),
            ("fs.modify", "src/model.py", ["by=alice"]),
            ("lock.release", "release.lock.json", ["release_id=r-2024-07"]),
        ]:
            args = ["journal", "append", "--journal", journal, "--kind", kind,
                    "--path", p, "--priv", priv, "--pub", pub]
            for m in meta:
                args += ["--meta", m]
            sh(*args, quiet=True)
        sh("journal", "show", "--journal", journal)
        code, _ = sh("journal", "verify", "--journal", journal, "--pub", pub, quiet=True)
        print(f"  → verify exit={code}（0 = 链完整、签名有效）")
        assert code == 0

        banner("1b", "锚定：把链头复制到机器外", "本机日志可被 root 删除，锚定才有意义")
        sh("journal", "anchor", "--journal", journal, "--out", anchor, "--priv", priv)
        a = json.load(open(anchor))
        print(f"  锚定 seq={a['seq']} h={a['h'][:32]}…")

        banner("1c", "攻击：改一条历史事件，再把哈希链全部重算")
        entries = [json.loads(l) for l in open(journal) if l.strip()]
        entries[1]["actor"] = "mallory"          # 篡改第 2 条的 actor
        # 攻击者重算后续所有链（模拟「改完顺手修好一致性」）
        prev = ""
        for e in entries:
            e["prev"] = prev
            payload = {k: v for k, v in e.items() if k not in ("h", "sig")}
            import hashlib
            h = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            e["h"] = h
            e["sig"] = None                      # 没有私钥 → 签不出来
            prev = h
        tampered = os.path.join(tmp, "tampered.jsonl")
        with open(tampered, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")) + "\n")
        code, out = sh("journal", "verify", "--journal", tampered, "--pub", pub,
                       "--anchor", anchor, allow=(0, 2, 3), quiet=True)
        print(out.rstrip())
        print(f"\n  → exit={code}")
        assert code == 3, "重算后的链未被发现"
        print("  ✓ 链被重算得自洽、seq 也对，但签名抹掉 + 与锚定不符 → 仍然暴露")

        banner("1d", "攻击：直接删除一条中间事件")
        cut = [json.loads(l) for l in open(journal) if l.strip()]
        del cut[1]
        cutf = os.path.join(tmp, "cut.jsonl")
        with open(cutf, "w", encoding="utf-8") as f:
            for e in cut:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")) + "\n")
        code, out = sh("journal", "verify", "--journal", cutf, "--pub", pub,
                       allow=(0, 2, 3), quiet=True)
        codes = [ln.strip() for ln in out.splitlines() if "J-" in ln]
        print("  检出：")
        for c in codes[:4]:
            print(f"    {c}")
        print(f"  → exit={code}")
        assert code == 3

        banner("1e", "攻击：把整个日志清空（截断）")
        empty = os.path.join(tmp, "empty.jsonl")
        open(empty, "w").close()
        code, out = sh("journal", "verify", "--journal", empty, "--pub", pub,
                       "--anchor", anchor, allow=(0, 2, 3), quiet=True)
        print(out.rstrip())
        print(f"  → exit={code}")
        assert code == 3
        print("  ✓ 这就是锚定的价值：本地清空，但外部锚定记录到过 seq=3")

        # ------------------------------------------------------------ ②
        banner(2, "文件修改记录：inotify 实时事件", "攻击者能还原文件，但抹不掉已发生的事件")
        wdir = os.path.join(tmp, "workspace")
        os.makedirs(os.path.join(wdir, "src"))
        src = os.path.join(wdir, "src", "model.py")
        with open(src, "w") as f:
            f.write("class Model:\n    pass\n")
        st0 = os.stat(src)

        jr = os.path.join(tmp, "fs-events.jsonl")
        proc = subprocess.Popen(
            [sys.executable, FPENV, "watch-fs", "--root", wdir, "--journal", jr,
             "--duration", "6", "--max-events", "50"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(1.2)
        print("  （监听已启动，现在模拟一次「改完再还原」的攻击）")
        with open(src, "a") as f:
            f.write("# backdoor\n")
        os.utime(src, ns=(st0.st_atime_ns, st0.st_mtime_ns))   # 还原 mtime
        os.chmod(src, st0.st_mode)                              # 还原权限
        with open(src, "r+") as f:                              # 再把内容改回去
            f.seek(0)
            f.truncate()
            f.write("class Model:\n    pass\n")
        os.utime(src, ns=(st0.st_atime_ns, st0.st_mtime_ns))
        out, _ = proc.communicate(timeout=20)
        print(out.rstrip()[-700:])

        st2 = os.stat(src)
        print(f"\n  最终状态: mtime 还原={st2.st_mtime_ns == st0.st_mtime_ns}  "
              f"内容与原始一致")
        evs = [json.loads(l) for l in open(jr) if l.strip()]
        print(f"  但事件流记录了 {len(evs)} 次写入：")
        for e in evs:
            print(f"    #{e['seq']} {e['kind']:<12} {e['path']}  actor={e['actor']}")
        assert len(evs) >= 2, "事件未记录"
        print("\n  ✓ 文件现在看起来与原始完全一样，但「被写过」这件事无法撤销")

        # ------------------------------------------------------------ ③
        banner(3, "项目源码：利用 git 天然不可撤销的提交链")
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        git(repo, "init", "-q", "-b", "main")
        with open(os.path.join(repo, "train.py"), "w") as f:
            f.write("print('train v1')\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "init")
        head1 = git(repo, "rev-parse", "HEAD")
        print(f"  初始 HEAD: {head1[:12]}")

        code, out = sh("git-audit", "--repo", repo, allow=(0, 3), quiet=True)
        print(out.rstrip())
        assert code == 0

        banner("3b", "攻击：悄悄改源码但不提交")
        with open(os.path.join(repo, "train.py"), "a") as f:
            f.write("# injected: send gradients to evil.example\n")
        code, out = sh("git-audit", "--repo", repo, "--trace", "train.py",
                       allow=(0, 3))
        assert code == 3, "工作区漂移未检出"

        banner("3c", "攻击：改历史（amend），让改动「看起来从没发生过」")
        git(repo, "checkout", "--", "train.py")
        with open(os.path.join(repo, "train.py"), "a") as f:
            f.write("# stealth\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "--amend", "-m", "init")
        head2 = git(repo, "rev-parse", "HEAD")
        print(f"  amend 后 HEAD: {head2[:12]}（原 {head1[:12]}）")
        code, out = sh("git-audit", "--repo", repo, "--expected-head", head1,
                       allow=(0, 3))
        assert code == 3, "历史重写未检出"
        print("  ✓ merge-base --is-ancestor 判定新 HEAD 不是旧 HEAD 的后代 → 历史被重写")

        banner("3d", "正常演进不应告警（正向对照）")
        git(repo, "commit", "-q", "--allow-empty", "-m", "feat: next step")
        head3 = git(repo, "rev-parse", "HEAD")
        code, out = sh("git-audit", "--repo", repo, "--expected-head", head2,
                       allow=(0, 3), quiet=True)
        print(out.rstrip())
        assert code == 0, "正常提交被误报"
        print("  ✓ 新 HEAD 是旧 HEAD 的后代 → 判为正常演进（info），不拦")

        # ------------------------------------------------------------ ④
        banner(4, "已签名 checkpoint：分片流式签名 + 防回滚")
        ckpt_dir = os.path.join(tmp, "ckpts")
        os.makedirs(ckpt_dir)
        ckpt = os.path.join(ckpt_dir, "goku-step12000.pt")
        # 造一个 200MB 的假 checkpoint（分片 64MB → 4 片）
        with open(ckpt, "wb") as f:
            for i in range(200):
                f.write(os.urandom(1 << 20))
        sig = ckpt + ".sig.json"
        sh("sign-checkpoint", "--path", ckpt, "--priv", priv, "--out", sig,
           "--signer", "trainer-ci", "--meta", "step=12000", "--meta", "trial=goku-7b")

        banner("4a", "正常验证")
        code, out = sh("verify-checkpoint", "--path", ckpt, "--sig", sig,
                       "--pub", pub, "--min-step", "10000")
        assert code == 0

        banner("4b", "攻击：改 1 个字节（权重被动手脚，签名文件不动）")
        bad_dir = os.path.join(ckpt_dir, "bad")
        os.makedirs(bad_dir)
        bad = os.path.join(bad_dir, os.path.basename(ckpt))   # 同名不同目录：签名文件仍有效
        shutil.copyfile(ckpt, bad)
        with open(bad, "r+b") as f:
            f.seek(50 << 20)                                  # 落在第 2 片
            b = f.read(1)
            f.seek(50 << 20)
            f.write(bytes([b[0] ^ 0xFF]))
        code, out = sh("verify-checkpoint", "--path", bad, "--sig", sig,
                       "--pub", pub, allow=(0, 3))
        assert code == 3, "篡改未检出"
        print("  ✓ 签名无法伪造，但仍能定位到具体哪一片被改")

        banner("4c", "攻击：回滚到旧 checkpoint 冒充新进度",
               "这份旧 checkpoint 的签名是合法的 —— 只有 step 元数据能揭穿")
        old = os.path.join(ckpt_dir, "goku-step8000.pt")
        with open(old, "wb") as f:
            for i in range(60):
                f.write(os.urandom(1 << 20))
        old_sig = old + ".sig.json"
        sh("sign-checkpoint", "--path", old, "--priv", priv, "--out", old_sig,
           "--signer", "trainer-ci", "--meta", "step=8000", "--meta", "trial=goku-7b",
           quiet=True)
        code, out = sh("verify-checkpoint", "--path", old, "--sig", old_sig,
                       "--pub", pub, "--min-step", "10000", allow=(0, 3))
        assert code == 3, "回滚未检出"
        print("  ✓ 内容与签名全部有效，仅因 step=8000 < 要求下限 10000 被拦")

        banner("4d", "攻击：把 A 的签名套到 B 上（张冠李戴）")
        other = os.path.join(ckpt_dir, "other.pt")
        with open(other, "wb") as f:
            f.write(os.urandom(1024))
        code, out = sh("verify-checkpoint", "--path", other, "--sig", sig,
                       "--pub", pub, allow=(0, 3), quiet=True)
        print(out.rstrip()[:600])
        assert code == 3
        print("  ✓ 文件名 / 大小 / 哈希三重不符")

        print("\n" + "=" * 74)
        print("三条证据链全部验证通过：日志不可撤销 / 事件不可抹除 / 源码与产物可证")
        print("=" * 74)
        if keep:
            print(f"\n临时目录: {tmp}")
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
