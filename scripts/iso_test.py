#!/usr/bin/env python3
"""Boot tests for the DataWipe live image (scripts/build_iso.py), in QEMU.

  1. UEFI with Secure Boot ON (OVMF with Microsoft's keys enrolled), the image as a USB stick:
     the full operator path through the live menu, on the serial console: kernel lockdown
     active, choose the state stick (it holds the organisation's signing key), wipe a SATA disk
     (typing WIPE, the serial number, the path and the key passphrase), verify the certificate,
     power off. The host then checks the wiped disk and the certificate left on the stick.
  2. Legacy BIOS (SeaBIOS), the image as a CD: boots to the menu.
  3. UEFI without Secure Boot, the image as a CD: boots to the menu.

usage: scripts/iso_test.py [--iso build/datawipe-live.iso] [--datawipe build/datawipe] [--keep]
exit: 0 passed, 1 failed, 2 setup problem, 77 prerequisites missing
"""

import argparse
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
sys.path.insert(0, str(REPO / "scripts"))
import build_iso  # noqa: E402
import qemu_bench  # noqa: E402

OVMF = Path("/usr/share/OVMF")
PASSPHRASE = "iso test passphrase, not secret"


class Fail(Exception):
    pass


class Console:
    """The VM's serial console, driven like an operator at a terminal."""

    def __init__(self, cmd, log: Path):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self.buf = ""
        self.log = open(log, "w")

    def expect(self, pattern, timeout=60):
        """Wait for `pattern` in output not yet consumed; return the text up to and including it."""
        deadline = time.time() + timeout
        rx = re.compile(pattern)
        while True:
            m = rx.search(self.buf)
            if m:
                text, self.buf = self.buf[: m.end()], self.buf[m.end():]
                return text
            if time.time() > deadline:
                raise Fail(f"timed out waiting for /{pattern}/; last output:\n{self.buf[-1500:]}")
            r, _, _ = select.select([self.p.stdout], [], [], 0.2)
            if r:
                chunk = os.read(self.p.stdout.fileno(), 65536)
                if not chunk:
                    raise Fail(f"VM exited while waiting for /{pattern}/; last output:\n{self.buf[-1500:]}")
                text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", chunk.decode("utf-8", "replace")).replace("\r", "")
                self.log.write(text)
                self.buf += text

    def send(self, text, delay=0.3):
        time.sleep(delay)
        self.p.stdin.write(text.encode())

    def line(self, text):
        self.send(text + "\r")

    def finish(self, timeout=60):
        try:
            self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            raise Fail("the VM did not power off")
        finally:
            self.log.close()


def number_of(listing: str, needle: str) -> str:
    for ln in listing.splitlines():
        if needle in ln:
            m = re.match(r"\s*(\d+)\)?\s", ln)
            if m:
                return m.group(1)
    raise Fail(f"'{needle}' not in the list:\n{listing}")


def boot_to_menu(con: Console, timeout=180):
    con.expect(r"DataWipe on the serial console", timeout)  # the GRUB menu, on serial
    con.send("s")                                          # its hotkey
    return con.expect(r"Choice: ", timeout)


def qemu_base(memory=2048):
    return ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", str(memory), "-display", "none",
            "-monitor", "none", "-serial", "stdio", "-no-reboot"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iso", default=str(REPO / "build" / "datawipe-live.iso"))
    ap.add_argument("--datawipe", default=str(REPO / "build" / "datawipe"))
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    iso, datawipe = Path(a.iso).resolve(), Path(a.datawipe).resolve()
    if not os.access("/dev/kvm", os.R_OK | os.W_OK) or not shutil.which("qemu-system-x86_64"):
        print("skip: QEMU/KVM not available")
        return 77
    sb_code, sb_vars = OVMF / "OVMF_CODE_4M.ms.fd", OVMF / "OVMF_VARS_4M.ms.fd"
    plain_code, plain_vars = OVMF / "OVMF_CODE_4M.fd", OVMF / "OVMF_VARS_4M.fd"
    for f in [sb_code, sb_vars, plain_code, plain_vars]:
        if not f.exists():
            print(f"skip: {f} missing (package ovmf)")
            return 77
    if not iso.exists():
        print(f"no image at {iso}: run scripts/build_iso.py first")
        return 2

    work = Path(tempfile.mkdtemp(prefix="dw_isotest_", dir=os.getcwd()))
    print(f"live image boot tests, work directory {work}")
    passed = failed = 0

    def check(what, ok, detail=""):
        nonlocal passed, failed
        passed += ok
        failed += not ok
        print(f"  {'ok   ' if ok else 'FAIL '} {what}")
        if not ok and detail:
            for ln in detail.strip().splitlines()[-12:]:
                print(f"        | {ln}")

    try:
        t = build_iso.tools()
        # The target disk, full of known plaintext; the state stick (FAT) with the org key.
        qemu_bench.make_plaintext_image(work / "target.img", 128)
        env = dict(os.environ, DATAWIPE_KEY_PASSPHRASE=PASSPHRASE)
        subprocess.run([str(datawipe), "keygen", str(work / "org")], env=env, check=True, stdout=subprocess.DEVNULL)
        stick = work / "stick.img"
        subprocess.run(["mkfs.vfat", "-C", "-n", "DWSTATE", str(stick), str(64 * 1024)], check=True,
                       stdout=subprocess.DEVNULL)
        build_iso.mtool(t, "mmd", "-i", stick, "::/datawipe", "::/datawipe/keys")
        for f in ["org.key.pem", "org.pub.pem"]:
            build_iso.mtool(t, "mcopy", "-i", stick, work / f, f"::/datawipe/keys/{f}")

        # ---- 1. UEFI + Secure Boot, booted from USB, full operator path.
        print("== UEFI, Secure Boot ON, image on a USB stick: wipe through the menu")
        shutil.copy(sb_vars, work / "vars-sb.fd")
        con = Console(qemu_base() + [
            "-machine", "q35,smm=on", "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={sb_code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={work/'vars-sb.fd'}",
            "-device", "qemu-xhci,id=xhci",
            "-drive", f"if=none,id=bootusb,format=raw,readonly=on,file={iso}",
            "-device", "usb-storage,bus=xhci.0,drive=bootusb,bootindex=0",
            "-drive", f"if=none,id=state,format=raw,file={stick}",
            "-device", "usb-storage,bus=xhci.0,drive=state",
            "-drive", f"if=none,id=target,format=raw,file={work/'target.img'}",
            "-device", "ide-hd,drive=target,bus=ide.0,serial=DWISO0001,model=DW-ISO-TARGET,rotation_rate=7200",
        ], work / "console-uefi-sb.log")
        menu = boot_to_menu(con)
        check("boots under Secure Boot; kernel lockdown is active", "Secure Boot: on (kernel lockdown active)" in menu, menu)
        check("no state stick yet: warns that certificates would be lost", "lost at power-off" in menu, menu)

        con.line("2")
        stores = con.expect(r"Number \(Enter to cancel\): ")
        con.line(number_of(stores, 'LABEL="DWSTATE"'))
        out = con.expect(r"Press Enter to continue")
        check("state stick mounted, signing key found on it", "signing key found" in out, out)
        con.line("")

        # The guided mode (datawipe interactive), started by the live menu with the destructive flag.
        con.expect(r"Choice: ")
        con.line("1")
        guided = con.expect(r"Choice: ")
        check("guided mode: state on the stick, signing key picked up from it, physical disks listed",
              "guided mode" in guided and "/mnt/store/datawipe" in guided and "org.key.pem" in guided
              and "LISTED" in guided, guided)
        con.line("1")
        listing = con.expect(r"Press Enter to continue")
        check("drive list shows the target with its serial and marks the boot stick",
              "DW-ISO-TARGET" in listing and "DWISO0001" in listing and "[this DataWipe boot media]" in listing, listing)
        con.line("")

        con.expect(r"Choice: ")
        con.line("3")
        disks = con.expect(r"\(Enter cancels\): ")
        con.line(number_of(disks, "DW-ISO-TARGET"))
        plan = con.expect(r"Continue to that confirmation\? \[y/N\] ", 120)
        con.line("y")
        con.expect(r"Type the device SERIAL NUMBER to continue: ", 60)
        con.line("DWISO0001")
        prompt = con.expect(r"Type the full device path \(/dev/\S+\) to confirm: ")
        con.line(re.search(r"Type the full device path \((/dev/\S+)\)", prompt).group(1))
        con.expect(r"Passphrase for \S+: ")
        con.line(PASSPHRASE)
        run_out = con.expect(r"Press Enter to continue", 600)
        check("plan screen: host overwrite, level Clear, signed certificate announced",
              "1. Host overwrite" in plan and "Level reached" in plan and "Clear" in plan
              and "signed with /mnt/store/datawipe/keys/org.key.pem" in plan and "WILL BE DESTROYED" in plan, plan)
        check("wipe through the guided mode: REAL overwrite, SUCCESS, ARVS read-back PASSED, signed",
              "[REAL] Host overwrite" in run_out and "Result            SUCCESS" in run_out
              and "Verification      PASSED" in run_out and "signed with Ed25519" in run_out and "DONE" in run_out,
              run_out)
        con.line("")

        con.expect(r"Choice: ")
        con.line("4")
        certs = con.expect(r"\(Enter cancels\): ")
        con.line(number_of(certs, ".dwcert.json"))
        vc = con.expect(r"Press Enter to continue")
        check("certificate verified in the live system against the published key",
              "VALID, by the trusted key" in vc and "chained to the certificate" in vc
              and "CERTIFICATE CHECK PASSED" in vc, vc)
        con.line("")
        con.expect(r"Choice: ")
        con.line("q")
        con.expect(r"Choice: ")
        con.line("0")
        con.finish()

        print("== host-side checks")
        left = qemu_bench.plaintext_count(work / "target.img")
        check(f"target disk: no plaintext left ({left})", left == 0)
        out_dir = work / "stick-out"
        out_dir.mkdir()
        subprocess.run([str(build_iso.tools()["mcopy"]), "-s", "-i", str(stick), "::/datawipe", str(out_dir)],
                       check=True, env=dict(t["env"], MTOOLS_SKIP_CHECK="1"))
        certs = sorted((out_dir / "datawipe").glob("*.dwcert.json"))
        check("certificate, session log and PDF are on the state stick",
              len(certs) == 1 and len(list((out_dir / "datawipe").glob("*.dwlog.jsonl"))) == 1
              and len(list((out_dir / "datawipe").glob("*.dwcert.pdf"))) == 1,
              "\n".join(str(p) for p in (out_dir / "datawipe").iterdir()))
        if certs:
            v = subprocess.run([str(datawipe), "verify-cert", str(certs[0]), "--pubkey", str(work / "org.pub.pem")],
                               capture_output=True, text=True)
            check("host verifies the stick's certificate: trusted signature, whole session chained",
                  v.returncode == 0 and "VALID, by the trusted key" in v.stdout and "chained" in v.stdout,
                  v.stdout + v.stderr)
            text = certs[0].read_text()
            check("certificate: physical disk, serial DWISO0001, REAL execution, Clear, sanitized",
                  '"backend": "physical-block"' in text and '"serial": "DWISO0001"' in text
                  and '"execution": "REAL"' in text and '"outcome": "sanitized"' in text
                  and '"method_name": "HDD: pseudo-random overwrite (Clear only)"' in text)

        # ---- 2. Legacy BIOS from CD.
        print("== legacy BIOS, image as a CD")
        con = Console(qemu_base(1024) + ["-cdrom", str(iso), "-boot", "d"], work / "console-bios.log")
        menu = boot_to_menu(con)
        check("boots on legacy BIOS to the menu; Secure Boot reported off", "Secure Boot: off" in menu, menu)
        con.line("0")
        con.finish()

        # ---- 3. UEFI without Secure Boot, from CD.
        print("== UEFI, Secure Boot off, image as a CD")
        shutil.copy(plain_vars, work / "vars.fd")
        con = Console(qemu_base(1024) + [
            "-machine", "q35",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={plain_code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={work/'vars.fd'}",
            "-cdrom", str(iso)], work / "console-uefi.log")
        menu = boot_to_menu(con)
        check("boots on UEFI (no Secure Boot) from CD to the menu", "Choice:" in menu or "Secure Boot: off" in menu, menu)
        con.line("0")
        con.finish()
    except (Fail, build_iso.BuildError, subprocess.CalledProcessError) as e:
        check("live image scenario", False, str(e))
    finally:
        if a.keep:
            print(f"work directory kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
