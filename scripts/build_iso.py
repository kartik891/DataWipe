#!/usr/bin/env python3
"""Build the DataWipe live image: a hybrid ISO that boots from CD or USB stick.

Boots on UEFI with Secure Boot (Ubuntu's Microsoft-signed shim, Ubuntu's signed GRUB, Ubuntu's
signed kernel and modules: nothing in the boot chain is ours, so no key enrolment is needed),
on UEFI without Secure Boot, and on legacy BIOS. Userland is a small initramfs that runs from
RAM: busybox, bash, datawipe, the storage drivers, and the live menu (iso/datawipe-menu).

Needs no root. Tools that are not installed (xorriso, mtools, BIOS GRUB modules) and the kernel
are fetched once as Ubuntu packages into ~/.cache and used from there.

usage: scripts/build_iso.py [--datawipe build/datawipe] [--out build/datawipe-live.iso]
"""

import argparse
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import qemu_bench  # noqa: E402  (kernel cache)

# Drivers for the live system; dependencies are resolved from modinfo.
ISO_MODULES = [
    "nvme", "ahci", "sdhci-pci", "sdhci-acpi", "mmc_block",       # disks: NVMe, SATA, eMMC (PCI and laptop ACPI)
    "mpt3sas", "megaraid_sas", "hpsa",                            # server HBAs (LSI/Broadcom SAS, MegaRAID, HP Smart Array)
    "usb-storage", "uas", "usbhid", "hid-generic",                # USB sticks and keyboards
    "exfat", "nls_iso8859_1", "nls_utf8",                         # state stick filesystems (FAT, ext4, cp437 are built in)
]
TOOL_PACKAGES = ["xorriso", "libisoburn1t64", "libisofs6t64", "libburn4t64", "mtools", "grub-pc-bin"]
SHIM = Path("/usr/lib/shim/shimx64.efi.signed.latest")
MOKMANAGER = Path("/usr/lib/shim/mmx64.efi")
SIGNED_GRUB_CD = Path("/usr/lib/grub/x86_64-efi-signed/gcdx64.efi.signed")
BIOS_GRUB_MODULES = ["biosdisk", "iso9660", "part_msdos", "part_gpt", "normal", "linux", "search", "search_fs_file",
                     "configfile", "echo", "test", "serial", "terminal", "ls", "all_video"]


class BuildError(Exception):
    pass


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def cache_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "datawipe-build"


def tools() -> dict:
    """Paths of xorriso, mformat/mmd/mcopy and the BIOS GRUB module directory, plus the
    environment to run them in (LD_LIBRARY_PATH for fetched libraries)."""
    root = cache_dir() / "tools"
    if not (root / "usr" / "bin" / "xorriso").exists() or not (root / "usr" / "lib" / "grub" / "i386-pc").exists():
        root.mkdir(parents=True, exist_ok=True)
        print(f"  fetching build tools (once; cached in {root})", flush=True)
        with tempfile.TemporaryDirectory() as tmp:
            try:
                run(["apt-get", "download"] + TOOL_PACKAGES, cwd=tmp, stdout=subprocess.DEVNULL)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                raise BuildError(f"cannot download {TOOL_PACKAGES}: {e}")
            for deb in Path(tmp).glob("*.deb"):
                run(["dpkg-deb", "-x", deb, root])
    env = dict(os.environ, LD_LIBRARY_PATH=f"{root}/usr/lib/x86_64-linux-gnu:{os.environ.get('LD_LIBRARY_PATH', '')}")
    t = {"env": env, "xorriso": root / "usr/bin/xorriso", "grub_i386": root / "usr/lib/grub/i386-pc"}
    for m in ["mmd", "mcopy"]:
        t[m] = shutil.which(m) or root / "usr/bin" / m  # per-command links to the mtools binary
    missing = subprocess.run(["ldd", t["xorriso"]], capture_output=True, text=True, env=env).stdout
    if "not found" in missing:
        raise BuildError("xorriso is missing libraries: " + " ".join(re.findall(r"(\S+) => not found", missing)))
    return t


def mtool(t, name, *args):
    subprocess.run([str(t[name])] + [str(a) for a in args], check=True, env=dict(t["env"], MTOOLS_SKIP_CHECK="1"))


def copy_with_libs(binary: Path, root: Path, dest: str):
    out = root / dest.lstrip("/")
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(binary, out)
    ldd = subprocess.run(["ldd", str(binary)], capture_output=True, text=True).stdout
    for lib in re.findall(r"(/\S+\.so[\.\d]*)", ldd):
        d = root / lib.lstrip("/")
        d.parent.mkdir(parents=True, exist_ok=True)
        if not d.exists():
            shutil.copy(os.path.realpath(lib), d)


def build_initramfs(work: Path, kcache: Path, datawipe: Path) -> Path:
    root = work / "rootfs"
    for d in ["bin", "dev", "proc", "sys", "tmp", "mnt/store", "etc/datawipe", "lib/datawipe-modules", "usr/bin", "root"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    busybox = shutil.which("busybox")
    if not busybox or "statically linked" not in subprocess.run(["file", busybox], capture_output=True, text=True).stdout:
        raise BuildError("a statically linked busybox is required (package busybox-static)")
    shutil.copy(busybox, root / "bin/busybox")
    copy_with_libs(Path(shutil.which("bash")), root, "/bin/bash")
    blkid = shutil.which("blkid") or "/usr/sbin/blkid"  # util-linux: filesystem types and labels
    copy_with_libs(Path(blkid), root, "/usr/bin/blkid")
    copy_with_libs(datawipe, root, "/usr/bin/datawipe")
    for src, dst in [("iso/datawipe-menu", "usr/bin/datawipe-menu"), ("scripts/hardware_test.sh", "usr/bin/hardware_test.sh"),
                     ("iso/init", "init")]:
        shutil.copy(REPO / src, root / dst)
        (root / dst).chmod(0o755)
    # terminfo so bash's line editing and `clear` work on the console and serial terminals
    for ti in ["l/linux", "v/vt100", "v/vt220", "x/xterm", "x/xterm-256color"]:
        for base in ["/usr/share/terminfo", "/lib/terminfo"]:
            if Path(base, ti).exists():
                (root / "usr/share/terminfo" / ti).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(Path(base, ti), root / "usr/share/terminfo" / ti)
                break
    order = qemu_bench.modules_order_file(kcache, ISO_MODULES).read_text().split()
    for m in order:
        shutil.copy(kcache / f"{m}.ko", root / "lib/datawipe-modules" / f"{m}.ko")
    (root / "etc/datawipe/modules").write_text(" ".join(order) + "\n")
    (root / "etc/profile").write_text("export TERM=${TERM:-linux} HOME=/root PS1='datawipe# '\n")

    files = subprocess.run(["find", "."], cwd=root, capture_output=True, text=True, check=True).stdout
    cpio = subprocess.run(["cpio", "-o", "-H", "newc", "--quiet"], cwd=root, input=files.encode(), capture_output=True,
                          check=True).stdout
    out = work / "initrd.gz"
    out.write_bytes(gzip.compress(cpio, 6))
    return out


def build_iso(datawipe: Path, out: Path):
    for f in [SHIM, MOKMANAGER, SIGNED_GRUB_CD]:
        if not f.exists():
            raise BuildError(f"{f} not found (packages shim-signed, grub-efi-amd64-signed)")
    if not shutil.which("grub-mkimage") or not shutil.which("mkfs.vfat"):
        raise BuildError("grub-mkimage (grub-common) and mkfs.vfat (dosfstools) are required")
    t = tools()
    kver = os.uname().release
    kcache = qemu_bench.kernel_cache(kver, ISO_MODULES)
    version = subprocess.run([str(datawipe), "--version"], capture_output=True, text=True).stdout.split()[-1]

    with tempfile.TemporaryDirectory(prefix="dw_iso_", dir=out.parent) as tmp:
        work = Path(tmp)
        tree = work / "tree"
        (tree / "boot/grub/i386-pc").mkdir(parents=True)
        (tree / ".disk").mkdir()
        (tree / "EFI/boot").mkdir(parents=True)
        shutil.copy(kcache / "vmlinuz", tree / "boot/vmlinuz")
        shutil.copy(build_initramfs(work, kcache, datawipe), tree / "boot/initrd.gz")
        shutil.copy(REPO / "iso/grub.cfg", tree / "boot/grub/grub.cfg")
        # Ubuntu's signed CD GRUB finds its filesystem by /.disk/info, then reads /boot/grub/grub.cfg.
        (tree / ".disk/info").write_text(f"DataWipe {version} live amd64\n")

        # UEFI: removable-media path EFI/boot/bootx64.efi = shim -> grubx64.efi = signed GRUB.
        efi_files = {"bootx64.efi": SHIM, "grubx64.efi": SIGNED_GRUB_CD, "mmx64.efi": MOKMANAGER}
        for name, src in efi_files.items():
            shutil.copy(src, tree / "EFI/boot" / name)
        efi_img = work / "efi.img"
        run(["mkfs.vfat", "-C", "-n", "DWEFI", efi_img, 8192], stdout=subprocess.DEVNULL)
        mtool(t, "mmd", "-i", efi_img, "::/EFI", "::/EFI/boot")
        for name, src in efi_files.items():
            mtool(t, "mcopy", "-i", efi_img, src, f"::/EFI/boot/{name}")

        # BIOS: GRUB El Torito core with the modules grub.cfg needs, plus the hybrid MBR.
        for f in Path(t["grub_i386"]).iterdir():
            if f.suffix in (".mod", ".lst"):
                shutil.copy(f, tree / "boot/grub/i386-pc" / f.name)
        eltorito = tree / "boot/grub/i386-pc/eltorito.img"
        run(["grub-mkimage", "-d", t["grub_i386"], "-O", "i386-pc-eltorito", "-p", "/boot/grub", "-o", eltorito]
            + BIOS_GRUB_MODULES)

        tmp_iso = work / "out.iso"
        run([t["xorriso"], "-as", "mkisofs", "-r", "-V", "DATAWIPE", "-J", "-joliet-long", "-l", "-iso-level", "3",
             "--grub2-mbr", Path(t["grub_i386"]) / "boot_hybrid.img", "-partition_offset", "16", "--mbr-force-bootable",
             "-append_partition", "2", "0xef", efi_img, "-appended_part_as_gpt",
             "-c", "boot.catalog",
             "-b", "boot/grub/i386-pc/eltorito.img", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
             "--grub2-boot-info",
             "-eltorito-alt-boot", "-e", "--interval:appended_partition_2:all::", "-no-emul-boot",
             "-o", tmp_iso, tree], env=t["env"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.move(tmp_iso, out)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    (out.parent / (out.name + ".sha256")).write_text(f"{digest}  {out.name}\n")
    return digest


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datawipe", default=str(REPO / "build" / "datawipe"))
    ap.add_argument("--out", default=str(REPO / "build" / "datawipe-live.iso"))
    a = ap.parse_args()
    datawipe, out = Path(a.datawipe).resolve(), Path(a.out).resolve()
    if not datawipe.exists():
        print(f"no datawipe binary at {datawipe} (build first)")
        return 2
    try:
        digest = build_iso(datawipe, out)
    except (BuildError, qemu_bench.Setup, subprocess.CalledProcessError) as e:
        print(f"build failed: {e}")
        return 2
    print(f"{out}  ({out.stat().st_size // (1 << 20)} MiB)\nsha256 {digest}")
    print("Write it to a USB stick with: sudo dd if=" + str(out) + " of=/dev/sdX bs=4M conv=fsync status=progress")
    return 0


if __name__ == "__main__":
    sys.exit(main())
