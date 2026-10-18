#!/usr/bin/env python3
"""QEMU hardware bench: datawipe against real kernel drivers and emulated drives.

A throwaway VM boots this machine's kernel with an initramfs holding busybox, the NVMe/AHCI
modules and the datawipe binary. It sees four emulated drives, all backed by files in the
work directory:

  /dev/sda      SATA "HDD" (AHCI, 7200 rpm), 1 GiB of known plaintext   -> wiped
  /dev/sdb      SATA disk with an ext4 filesystem, mounted read-only     -> must be refused
  /dev/sdc      SATA disk used as swap                                   -> must be refused
  /dev/nvme0n1  NVMe namespace, 256 MiB of known plaintext               -> Format NVM, fingerprint-verified
  /dev/mmcblk0  eMMC 4.41 (SDHCI), 64 MiB user area + 2 x 1 MiB boot      -> wiped; boot areas must survive,
                partitions, all of it known plaintext                       exactly as the plan warns

Nothing here can reach a host disk: the VM has no access to them, and every drive it sees is a
file this script created. datawipe runs on the VM's serial console, so its confirmation prompt
reads a real terminal; this script plays the operator, typing (sometimes wrong) answers and
pressing Ctrl-C. Afterwards the host checks the disk images and the signed certificates.

usage: scripts/qemu_bench.py [--datawipe build/datawipe] [--work DIR] [--keep]
exit: 0 all checks passed, 1 a check failed, 2 setup problem, 77 prerequisites missing
"""

import argparse
import base64
import hashlib
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Drivers the VM needs; their dependencies are resolved from modinfo when the cache is built.
ROOT_MODULES = ["nvme", "ahci", "sdhci-pci", "mmc_block"]
PASSPHRASE = "bench passphrase, not a secret"
FLAG = "--i-understand-this-is-destructive"
PLAINTEXT = b"DATAWIPE-TEST"
EMMC_BOOT = 1 << 20  # each of the two eMMC boot partitions
STEP_TIMEOUT = 180  # seconds; the slowest step (1 GiB verified wipe) takes a few


class Setup(Exception):
    pass


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def modules_order_file(cache: Path, roots) -> Path:
    return cache / ("modules-" + hashlib.sha256(" ".join(sorted(roots)).encode()).hexdigest()[:12] + ".order")


def kernel_cache(kver: str, roots=None) -> Path:
    """vmlinuz + the modules `roots` need (in load order, see modules_order_file), extracted once
    from this kernel's packages. Shared by the bench and the ISO builder."""
    roots = list(roots or ROOT_MODULES)
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "datawipe-bench" / kver
    order_file = modules_order_file(cache, roots)
    if (cache / "vmlinuz").exists() and order_file.exists():
        order = order_file.read_text().split()
        if all((cache / f"{m}.ko").exists() for m in order):
            return cache
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        print(f"  fetching kernel {kver} packages (once; cached in {cache})", flush=True)
        try:
            run(["apt-get", "download", f"linux-image-{kver}", f"linux-modules-{kver}"], cwd=tmp,
                stdout=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise Setup(f"cannot download the kernel packages for {kver}: {e}")
        root = Path(tmp) / "root"
        for deb in Path(tmp).glob("*.deb"):
            run(["dpkg-deb", "-x", str(deb), str(root)])
        vmlinuz = next(root.glob(f"boot/vmlinuz-{kver}"), None)
        if not vmlinuz:
            raise Setup("kernel image not found in the package")
        shutil.copy(vmlinuz, cache / "vmlinuz")
        index = {}  # module name (either spelling) -> file
        for f in root.glob(f"usr/lib/modules/{kver}/kernel/**/*.ko*"):
            name = f.name.split(".ko")[0]
            index[name] = index[name.replace("-", "_")] = f

        order = []

        def add(name):  # dependencies first
            key = name if name in index else name.replace("-", "_")
            if key not in index:
                raise Setup(f"module {name} not found")
            src = index[key]
            mod = src.name.split(".ko")[0]
            if mod in order:
                return
            deps = subprocess.run(["modinfo", "-F", "depends", str(src)], capture_output=True, text=True).stdout.strip()
            for d in filter(None, deps.split(",")):
                add(d)
            dst = cache / f"{mod}.ko"
            if src.suffix == ".zst":
                run(["zstd", "-qdf", str(src), "-o", str(dst)])
            elif src.suffix == ".xz":
                run(["xz", "-dkc", str(src)], stdout=open(dst, "wb"))
            else:
                shutil.copy(src, dst)
            order.append(mod)

        for m in roots:
            add(m)
        order_file.write_text(" ".join(order) + "\n")
    return cache


def make_plaintext_image(path: Path, mib: int):
    run([str(REPO / "scripts" / "mk_test_image.sh"), str(path), str(mib)], stdout=subprocess.DEVNULL)


def md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def plaintext_count(path: Path) -> int:
    n = 0
    with open(path, "rb") as f:
        tail = b""
        for block in iter(lambda: f.read(1 << 20), b""):
            data = tail + block
            n += data.count(PLAINTEXT)
            tail = data[-(len(PLAINTEXT) - 1):]
    return n


class Step:
    def __init__(self, name, cmd, rc, answers=(), interrupt=None, expect=(), forbid=()):
        self.name, self.cmd, self.rc = name, cmd, rc
        self.answers = list(answers)  # (prompt regex, reply), in order
        self.interrupt = interrupt    # (regex, delay seconds): press Ctrl-C after it appears
        self.expect, self.forbid = list(expect), list(forbid)
        self.out, self.got = "", None
        self.unexpected_prompts = 0  # confirmation prompts beyond the scripted answers
        self.timed_out = False


SERIAL_PROMPT = r"Type the device SERIAL NUMBER"
PATH_PROMPT = r"Type the full device path"


def steps():
    ok_sata = [(SERIAL_PROMPT, "DWSATA0001"), (PATH_PROMPT, "/dev/sda")]
    ok_nvme = [(SERIAL_PROMPT, "DWNVME0001"), (PATH_PROMPT, "/dev/nvme0n1")]
    sata_run = f"datawipe run /dev/sda {FLAG} --cert /work/sata.json --buffer-size 1M --sync-every 8M"
    return [
        Step("probe SATA", "datawipe probe /dev/sda", 0, expect=[r"Identity source\s+ata-identify", r"Classification\s+HDD"]),
        Step("probe NVMe", "datawipe probe /dev/nvme0n1", 0, expect=[r"Identity source\s+nvme-identify"]),
        Step("ata-unlock on a drive without a password: nothing to do", "datawipe ata-unlock /dev/sda", 0,
             expect=[r"No ATA password is set"], forbid=[SERIAL_PROMPT]),
        Step("refused: no destructive flag", "datawipe run /dev/sda", 2,
             expect=[r"requires --i-understand-this-is-destructive"], forbid=[SERIAL_PROMPT]),
        Step("refused: answers piped, not typed", f"echo DWSATA0001 | datawipe run /dev/sda {FLAG}", 2,
             expect=[r"requires an interactive terminal"], forbid=[SERIAL_PROMPT]),
        Step("refused: wrong serial typed", f"datawipe run /dev/sda {FLAG}", 2,
             answers=[(SERIAL_PROMPT, "NOT-THE-SERIAL")], expect=[r"serial number confirmation did not match"]),
        Step("refused: wrong path typed", f"datawipe run /dev/sda {FLAG}", 2,
             answers=[(SERIAL_PROMPT, "DWSATA0001"), (PATH_PROMPT, "/dev/sdb")],
             expect=[r"device path confirmation did not match"]),
        Step("refused: mounted disk (before any prompt)", f"datawipe run /dev/sdb {FLAG}", 2,
             expect=[r"in use \(device is mounted"], forbid=[SERIAL_PROMPT]),
        Step("refused: swap disk (before any prompt)", f"datawipe run /dev/sdc {FLAG}", 2,
             expect=[r"in use \(device is active swap"], forbid=[SERIAL_PROMPT]),
        Step("SATA wipe, Ctrl-C mid-pass", sata_run, 7, answers=ok_sata, interrupt=(r"== Step 1/1", 0.4),
             expect=[r"Result\s+INTERRUPTED", r"datawipe-DW-BENCH-SATA-DWSATA0001\.dwjournal"]),
        Step("refused: plain rerun over the journal", sata_run, 2, answers=ok_sata,
             expect=[r"Continue it with --resume"]),
        Step("SATA wipe resumed", sata_run + " --resume", 0, answers=ok_sata,
             expect=[r"\[REAL\] Host overwrite", r"Result\s+SUCCESS, achieved Clear", r"Verification\s+PASSED",
                     r"SCI\s+100\.00", r"signed with Ed25519"]),
        Step("SATA re-verified later from its certificate", "datawipe verify /dev/sda --cert /work/sata.json", 0,
             expect=[r"Verification\s+PASSED"]),
        Step("probe eMMC (EXT_CSD)", "datawipe probe /dev/mmcblk0", 0,
             expect=[r"Identity source\s+emmc-ext-csd", r"Classification\s+eMMC"]),
        Step("refused: an eMMC boot partition as target", f"datawipe run /dev/mmcblk0boot0 {FLAG}", 2,
             expect=[r"eMMC hardware partition"], forbid=[SERIAL_PROMPT]),
        Step("eMMC wipe", f"datawipe run /dev/mmcblk0 {FLAG} --cert /work/emmc.json", 0,
             answers=[(SERIAL_PROMPT, "0xdeadbeef"), (PATH_PROMPT, "/dev/mmcblk0")],
             expect=[r"hardware partitions outside the user area are NOT covered", r"REAL DEVICE: running this plan destroys",
                     r"boot 2048 KiB", r"Result\s+SUCCESS", r"Verification\s+PASSED"]),
        Step("NVMe Format NVM, fingerprint-verified", f"datawipe run /dev/nvme0n1 {FLAG} --cert /work/nvme.json", 0,
             answers=ok_nvme,
             expect=[r"\[REAL\] .*FORMAT NVM|FORMAT NVM \(User Data Erase\)", r"Pre-wipe fingerprints",
                     r"Result\s+SUCCESS", r"Verification\s+PASSED", r"signed with Ed25519"]),
        Step("the pre-wipe fingerprint file is removed once the certificate exists", "ls /work/*.dwfp", 1),
    ]


def scenario_script(all_steps):
    lines = [
        "trap '' INT",  # Ctrl-C is for datawipe (it installs its own handler), not this shell
        "export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu",
        "export DATAWIPE_STATE_DIR=/work DATAWIPE_SIGN_KEY=/work/org.key.pem",
        f"export DATAWIPE_KEY_PASSPHRASE='{PASSPHRASE}'",
        "cd /work",
    ]
    for i, s in enumerate(all_steps):
        lines += [f"echo '@@BEGIN {i}@@'", s.cmd, f"echo \"@@EXIT {i} $?@@\""]
    lines += [
        "for f in /work/*.json /work/*.jsonl /work/*.pdf; do [ -f \"$f\" ] || continue; "
        "echo \"@@FILE ${f##*/}@@\"; base64 \"$f\"; echo '@@ENDFILE@@'; done",
        "echo '@@ALLDONE@@'",
        "sync; poweroff -f",
    ]
    return "\n".join(lines) + "\n"


INIT = """#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
for m in {modules}; do insmod /mod/$m.ko; done
for i in $(seq 50); do [ -b /dev/nvme0n1 ] && [ -b /dev/sdc ] && [ -b /dev/mmcblk0boot1 ] && break; sleep 0.1; done
mkdir -p /mnt/busy && mount -o ro /dev/sdb /mnt/busy && swapon /dev/sdc
setsid -c sh /scenario.sh </dev/ttyS0 >/dev/ttyS0 2>&1
poweroff -f
"""


def build_initramfs(work: Path, cache: Path, datawipe: Path, all_steps) -> Path:
    root = work / "initramfs"
    for d in ["bin", "dev", "proc", "sys", "mod", "tmp", "work", "mnt", "usr/bin"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    busybox = shutil.which("busybox")
    if not busybox or "statically linked" not in subprocess.run(["file", busybox], capture_output=True, text=True).stdout:
        raise Setup("a statically linked busybox is required (busybox-static)")
    shutil.copy(busybox, root / "bin" / "busybox")
    modules = modules_order_file(cache, ROOT_MODULES).read_text().split()
    for m in modules:
        shutil.copy(cache / f"{m}.ko", root / "mod" / f"{m}.ko")
    shutil.copy(datawipe, root / "usr" / "bin" / "datawipe")
    for lib in re.findall(r"(/\S+\.so[\.\d]*)", subprocess.run(["ldd", str(datawipe)], capture_output=True, text=True).stdout):
        dst = root / lib.lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(os.path.realpath(lib), dst)
    shutil.copy(work / "org.key.pem", root / "work" / "org.key.pem")
    (root / "init").write_text(INIT.format(modules=" ".join(modules)))
    (root / "init").chmod(0o755)
    (root / "scenario.sh").write_text(scenario_script(all_steps))
    image = work / "initramfs.cpio.gz"
    files = subprocess.run(["find", "."], cwd=root, capture_output=True, text=True, check=True).stdout
    cpio = subprocess.run(["cpio", "-o", "-H", "newc"], cwd=root, input=files.encode(), capture_output=True, check=True)
    import gzip
    image.write_bytes(gzip.compress(cpio.stdout, 1))
    return image


def boot_and_drive(work: Path, cache: Path, initramfs: Path, all_steps, timeout=900):
    qemu = [
        "qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "1024", "-display", "none", "-monitor", "none",
        "-serial", "stdio", "-no-reboot",
        "-kernel", str(cache / "vmlinuz"), "-initrd", str(initramfs),
        "-append", "console=ttyS0 quiet loglevel=3 panic=-1",
        "-device", "ahci,id=ahci",
        "-drive", f"if=none,id=sata,file={work/'sata.img'},format=raw",
        "-device", "ide-hd,drive=sata,bus=ahci.0,serial=DWSATA0001,model=DW-BENCH-SATA,rotation_rate=7200",
        "-drive", f"if=none,id=busy,file={work/'busy.img'},format=raw",
        "-device", "ide-hd,drive=busy,bus=ahci.1,serial=DWBUSY0001,model=DW-BENCH-BUSY,rotation_rate=7200",
        "-drive", f"if=none,id=swap,file={work/'swap.img'},format=raw",
        "-device", "ide-hd,drive=swap,bus=ahci.2,serial=DWSWAP0001,model=DW-BENCH-SWAP,rotation_rate=7200",
        "-drive", f"if=none,id=nvme,file={work/'nvme.img'},format=raw",
        "-device", "nvme,drive=nvme,serial=DWNVME0001",
        "-device", "sdhci-pci",
        "-drive", f"if=none,id=emmc,file={work/'emmc.img'},format=raw",
        "-device", f"emmc,drive=emmc,boot-partition-size={EMMC_BOOT}",
    ]
    p = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    buf, files = "", {}
    cur, answered, ctrl_c_at = None, 0, None
    deadline = time.time() + timeout
    transcript = open(work / "console.log", "w")
    try:
        while True:
            if time.time() > deadline:
                raise Setup("the VM did not finish in time (see console.log)")
            if ctrl_c_at and time.time() >= ctrl_c_at:
                p.stdin.write(b"\x03")
                ctrl_c_at = None
            r, _, _ = select.select([p.stdout], [], [], 0.05)
            if r:
                chunk = os.read(p.stdout.fileno(), 65536)
                if not chunk:
                    break
                text = chunk.decode("utf-8", "replace").replace("\r", "")
                transcript.write(text)
                buf += text
                if cur is not None:
                    cur.out += text
            # step boundaries
            while True:
                m = re.search(r"@@BEGIN (\d+)@@\n", buf)
                e = re.search(r"@@EXIT (\d+) (\d+)@@\n", buf)
                if m and (not e or m.start() < e.start()):
                    cur, answered = all_steps[int(m.group(1))], 0
                    cur.started = time.time()
                    cur.out = buf[m.end():]
                    buf = buf[m.end():]
                    if cur.interrupt:
                        cur._int_pending = True
                    continue
                if e:
                    step = all_steps[int(e.group(1))]
                    step.got = int(e.group(2))
                    step.out = step.out[: step.out.find("@@EXIT")] if "@@EXIT" in step.out else step.out
                    buf = buf[e.end():]
                    cur = None
                    continue
                break
            if cur is not None:
                # Answer the k-th prompt once it has appeared, like an operator reading the screen.
                if answered < len(cur.answers) and re.search(cur.answers[answered][0], cur.out):
                    time.sleep(0.2)
                    p.stdin.write((cur.answers[answered][1] + "\n").encode())
                    answered += 1
                # A prompt the scenario did not expect means the gate let something through: refuse
                # it (empty answer) so the run cannot proceed, and fail the step.
                seen = len(re.findall(f"{SERIAL_PROMPT}|{PATH_PROMPT}", cur.out))
                if seen > len(cur.answers) + cur.unexpected_prompts:
                    time.sleep(0.2)
                    p.stdin.write(b"\n")
                    cur.unexpected_prompts += 1
                if not cur.timed_out and time.time() - cur.started > STEP_TIMEOUT:
                    cur.timed_out = True
                    p.stdin.write(b"\x03\n")
                if getattr(cur, "_int_pending", False) and re.search(cur.interrupt[0], cur.out):
                    cur._int_pending = False
                    ctrl_c_at = time.time() + cur.interrupt[1]
            # files
            while True:
                m = re.search(r"@@FILE (\S+)@@\n(.*?)@@ENDFILE@@\n", buf, re.S)
                if not m:
                    break
                files[m.group(1)] = base64.b64decode("".join(m.group(2).split()))
                buf = buf[: m.start()] + buf[m.end():]
            if "@@ALLDONE@@" in buf and p.poll() is not None:
                break
            if p.poll() is not None and not r:
                break
    finally:
        transcript.close()
        if p.poll() is None:
            p.kill()
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datawipe", default=str(REPO / "build" / "datawipe"))
    ap.add_argument("--work")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    for tool in ["qemu-system-x86_64", "busybox", "cpio", "mkfs.ext4", "mkswap", "apt-get", "dpkg-deb", "zstd"]:
        if not shutil.which(tool):
            print(f"skip: {tool} not found")
            return 77
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        print("skip: no access to /dev/kvm")
        return 77
    datawipe = Path(args.datawipe).resolve()
    if not datawipe.exists():
        print(f"no datawipe binary at {datawipe}")
        return 2

    work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix="dw_bench_", dir=os.getcwd()))
    work.mkdir(parents=True, exist_ok=True)
    print(f"QEMU bench, work directory {work}")
    passed = failed = 0

    def check(what, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  ok    {what}")
        else:
            failed += 1
            print(f"  FAIL  {what}")
            for line in detail.strip().splitlines()[-15:]:
                print(f"        | {line}")

    try:
        cache = kernel_cache(os.uname().release)
        print("== preparing drives")
        make_plaintext_image(work / "sata.img", 1024)
        make_plaintext_image(work / "nvme.img", 256)
        # QEMU's SD host is slow (~4 MiB/s), so a small card; the user area must be a power of 2.
        make_plaintext_image(work / "emmc.img", 64 + 2 * EMMC_BOOT // (1 << 20))
        run(["truncate", "-s", "64M", str(work / "busy.img")])
        run(["mkfs.ext4", "-q", "-F", str(work / "busy.img")])
        run(["truncate", "-s", "64M", str(work / "swap.img")])
        run(["mkswap", "-q", str(work / "swap.img")], stdout=subprocess.DEVNULL)
        before = {n: md5(work / n) for n in ["busy.img", "swap.img"]}
        env = dict(os.environ, DATAWIPE_KEY_PASSPHRASE=PASSPHRASE)
        run([str(datawipe), "keygen", str(work / "org")], env=env, stdout=subprocess.DEVNULL)

        all_steps = steps()
        initramfs = build_initramfs(work, cache, datawipe, all_steps)
        print("== booting the VM and driving datawipe on its serial console")
        files = boot_and_drive(work, cache, initramfs, all_steps)

        for s in all_steps:
            problems = []
            if s.unexpected_prompts:
                problems.append(f"{s.unexpected_prompts} confirmation prompt(s) the scenario did not expect")
            if s.timed_out:
                problems.append(f"no result within {STEP_TIMEOUT} s")
            if s.got != s.rc:
                problems.append(f"exit {s.got}, expected {s.rc}")
            problems += [f"missing /{x}/" for x in s.expect if not re.search(x, s.out)]
            problems += [f"unexpected /{x}/" for x in s.forbid if re.search(x, s.out)]
            check(f"{s.name} (exit {s.got})", not problems, "; ".join(problems) + "\n" + s.out)

        print("== host-side checks")
        check("SATA image: no plaintext left", plaintext_count(work / "sata.img") == 0)
        check("NVMe image: no plaintext left", plaintext_count(work / "nvme.img") == 0)
        # The eMMC image holds both boot partitions and the user area; only the boot partitions
        # may still contain plaintext: 2 x 1 MiB of 64-byte lines.
        left = plaintext_count(work / "emmc.img")
        check(f"eMMC image: user area clean, plaintext only in the 2 MiB of boot partitions ({left} lines)",
              left == 2 * EMMC_BOOT // 64)
        check("mounted disk untouched", md5(work / "busy.img") == before["busy.img"])
        check("swap disk untouched", md5(work / "swap.img") == before["swap.img"])
        for name in ["sata", "nvme", "emmc"]:
            cert, log = files.get(f"{name}.json"), files.get(f"{name}.dwlog.jsonl")
            check(f"{name} certificate, session log and PDF came out of the VM",
                  cert is not None and log is not None and f"{name}.pdf" in files)
            if cert is None or log is None:
                continue
            (work / f"{name}.json").write_bytes(cert)
            (work / f"{name}.dwlog.jsonl").write_bytes(log)
            v = subprocess.run([str(datawipe), "verify-cert", str(work / f"{name}.json"), "--pubkey",
                                str(work / "org.pub.pem")], capture_output=True, text=True)
            check(f"{name} certificate: signature trusted, whole session chained",
                  v.returncode == 0 and "VALID, by the trusted key" in v.stdout and "chained to the certificate" in v.stdout,
                  v.stdout + v.stderr)
            text = cert.decode()
            if name == "sata":
                check("sata certificate: 2 runs, REAL execution, sanitized",
                      '"runs": 2' in text and '"execution": "REAL"' in text and '"outcome": "sanitized"' in text)
                check("sata session log: detection -> plan -> interrupted -> resume -> execution -> verification -> "
                      "certificate", "detection -> plan -> interrupted -> resume -> execution -> verification -> certificate"
                      in v.stdout, v.stdout)
            elif name == "emmc":
                check("emmc certificate: eMMC identity, boot areas disclosed as not covered",
                      '"source": "emmc-ext-csd"' in text and "NOT covered" in text and '"outcome": "sanitized"' in text)
            else:
                check("nvme certificate: Format NVM, verified against pre-wipe fingerprints",
                      '"method_id": "ssd-nvme.format-erase"' in text and '"expected_content": "differs from its pre-wipe '
                      'fingerprint"' in text and '"outcome": "sanitized"' in text)
    except (Setup, subprocess.CalledProcessError) as e:
        print(f"setup failed: {e}")
        return 2
    finally:
        if args.keep:
            print(f"work directory kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
