# datawipe

The wipe-engine core of **DataWipe: Secure Disk Sanitization System with Controlled Execution
and Certification**, in C++20 on Linux. Device access uses raw syscalls and ioctls; the only library dependency
is OpenSSL libcrypto, for the Ed25519 certificate signatures.

It does the following:

1. **Detects** a target's geometry and drive identity (paper §III-D).
2. **Chooses** a NIST SP 800-88 method from the media type (§III-E).
3. **Wipes:** HDD overwrites are real, device commands are logged.
4. **Verifies** with ARVS: it reads back 5–10% of the disk and re-wipes failures, then scores the result with the Sanitization Confidence Index (SCI).
   - **How much it reads** depends on the drive's wear and the erase method's risk (W, F, E).
   - **Where it reads** is concentrated on hidden areas and boundaries (H, B).
5. **Certifies** with TECC: the session is a SHA-256 hash chain, and the certificate (JSON and PDF) seals its terminal hash with an Ed25519 signature by the organisation's key.

## Scope

- **Supported storage:** HDDs, SATA and NVMe SSDs, and eMMC (laptops, Chromebooks, thin clients, single-board and embedded devices), wiped from a Linux host, or from the bootable ISO once it exists.
- **Mobile phones (Android) are out of scope.** Without root, nothing on a phone can reach the flash directly, so the only option is the OS's own factory reset, a cryptographic erase that can't be independently read back. That would contradict DataWipe's central claim of verification that doesn't trust firmware or OS self-reports.

## Safety model

- Targets are **disk image files**, **loop devices backed by an image you own**, and **physical disks**.
- A physical disk is wiped only after all of these, in this order:
  1. it identified itself with its own commands (ATA IDENTIFY / NVMe Identify, as root);
  2. nothing uses it: no mounted filesystem, no active swap, no LVM/RAID/dm-crypt holder, on the disk or any partition (checked **before** anyone is asked anything);
  3. `--i-understand-this-is-destructive` was given;
  4. at an interactive terminal (piped answers are refused), the operator retyped the drive's serial number, then its device path;
  5. the drive is identified again from scratch and must still report the confirmed serial;
  6. it is opened exclusively (`O_EXCL`), which the kernel refuses while anything else holds it.
- The safety guard (`src/device/safety_guard.*`) runs again on every open. It resolves symlinks and re-checks the opened inode, so a path swapped between the check and the open is detected.
- The guard refuses:
  - character devices;
  - images that aren't owned by the invoking user (`SUDO_UID` under sudo);
  - images attached to a loop device;
  - loop devices backed by files that aren't yours.
- Firmware commands not yet validated on real hardware are only sent with `--experimental` (see "What is real" below). Without it, plans fall back to proven methods and list what they left out.

## Install

`scripts/package.sh` makes a release in `dist/`: a `.deb`, a tarball of the same files, the live ISO and `SHA256SUMS`.

```sh
sha256sum -c SHA256SUMS
sudo apt install ./datawipe_0.1.0_amd64.deb      # Ubuntu 25.10 / 26.04 or newer
man datawipe
datawipe                                         # guided mode
```

- **Other distributions:** unpack `datawipe-0.1.0-linux-x86_64.tar.gz` and copy its `usr/` tree to `/usr/local`. The binary needs glibc 2.38+, libstdc++ from GCC 15+ and OpenSSL 3; on anything older, build from source or use the ISO.
- **Windows, or wiping a machine's own system disk:** write `datawipe-0.1.0-live.iso` to a USB stick (Rufus or balenaEtcher in DD mode, or `dd`) and boot from it.
- **Installed files:** `/usr/bin/datawipe`, drive profiles and `hardware_test.sh` in `/usr/share/datawipe/`, this README in `/usr/share/doc/datawipe/`.
- **Licence:** MIT (`LICENSE`). The binaries use OpenSSL libcrypto (Apache-2.0), linked statically into `datawipe.exe`.

## Windows (preview)

`datawipe.exe` is cross-compiled on Linux with MinGW-w64. It runs the whole pipeline (plan, wipe, ARVS read-back with SCI, signed certificates, the guided mode) on disk image files and on whole physical disks. Certificates verify across platforms.

- **Targets:** image files, and disks named `\\.\PhysicalDriveN` (`Get-Disk` lists the numbers). Volumes (`\\.\C:`, `\\?\Volume{...}`) are always refused.
- **The same gate as on Linux:** `--i-understand-this-is-destructive`, an interactive terminal on which the serial number and path are retyped, and an Administrator terminal (reading or writing a disk needs it; read-only `probe` without it shows the storage descriptor only).
- **A disk with any volume on it is refused:** a drive letter, an EFI or recovery partition, or the running Windows installation. Take the disk offline first (`Set-Disk -Number N -IsOffline $true`; afterwards `-IsOffline $false`), or delete its partitions. Storage Spaces virtual disks are refused.
- **SATA drives get the full plan.** As Administrator, ATA drives (direct, or behind a USB bridge that implements SAT) are identified with ATA IDENTIFY, native max, DCO IDENTIFY and TCG discovery, sent as the same ATA PASS-THROUGH(16) command blocks as on Linux, through `IOCTL_SCSI_PASS_THROUGH_DIRECT`. The read-only whitelist applies unchanged. A disk opened for reading is opened with write access, because Windows requires it for pass-through; nothing writes through that handle.
- **Every firmware command is `--experimental` on Windows**, including the enhanced Secure Erase that is proven on Linux, because this transport has not yet run on hardware. Without the flag, plans fall back to host overwrite (Clear) and list what they left out. Windows or its storage driver may also refuse ATA security commands; the step then fails before the drive changes, and `ata-unlock` is the recovery if a password was set.
- **NVMe, eMMC, and drives whose IDENTIFY fails** are identified from the Windows storage descriptor (model, serial, bus, size, seek penalty, TRIM). Windows' inbox drivers do not pass Format NVM, Sanitize or eMMC commands through, so these get a host overwrite (Clear), flag or not, and sectors hidden by an HPA or DCO are not reached there. For Purge on these, use the live ISO.
- **HPA/DCO removal** (experimental) asks Windows to re-read the disk size (`IOCTL_DISK_UPDATE_PROPERTIES`); if it still reports the old size, reboot before the second run.
- **Build:** `scripts/win_toolchain.sh` once (fetches MinGW-w64, builds OpenSSL for Windows, unpacks Wine; all under `~/.cache/datawipe-win`, no root), then `scripts/win_build.sh --test`.
- **Tested under Wine only, and only on image files.** The 10 unit suites pass, including the Windows command policy, and the image end-to-end script passes 91 of 92 checks; the one failure is a path-spelling comparison that only Wine produces. **Nothing has touched a physical disk through the Windows build**: Wine does not emulate the storage IOCTLs or SCSI pass-through. A spare disk, or a virtual disk (VHD) created in Disk Management, is the safe first target; a VHD has no ATA layer, so Secure Erase needs a real SATA disk.
- **Pool and dynamic disks:** a member of a Storage Spaces pool or a dynamic (LDM) disk is refused, read from its partition table (as Administrator).
- **Not detected yet:** USB bridge speed (the duration estimate assumes the drive's native speed).

## Build and test

CI (`.github/workflows/ci.yml`, GitHub Actions; not yet run, as the project has no remote): Linux build with the unit suites, the image and loop-device end-to-end runs, the QEMU bench and the live image; the Windows cross-build tested under Wine; and a native Windows build on a Windows runner, which runs the unit suites and an image wipe on the real Windows API, probes a throwaway VHD and the runner's system disk read-only, and checks that the destructive gate refuses without a terminal.

```sh
cmake -S . -B build && cmake --build build -j
cd build && ctest            # 9 unit suites + e2e_image + qemu_bench (~1 min)
sudo ../scripts/e2e.sh --loop   # the same end-to-end run through a loop device (needs root)
sudo ../scripts/hardware_test.sh /dev/sdX [report-dir] [key.pem]   # SPARE drive only: validates the experimental commands
```

`scripts/e2e.sh` is the Phase 5 acceptance test. It does the following:

1. Creates a 100 MiB image full of a known plaintext.
2. With `--loop`, attaches the image as a loop device.
3. Runs probe → plan → run.
4. Checks that no plaintext line survives, the image no longer compresses, and the certificate verifies.
5. Re-reads the medium from its certificate.
6. Checks that zeroing 10 MiB of the image makes `verify` fail, and that editing one character of the certificate makes `verify-cert` fail.
7. Presses Ctrl-C mid-wipe, then checks that a plain rerun and a resume with the wrong drive profile are both refused, and that `--resume` finishes the wipe.
8. Checks that an SSD plan leaves the image byte-identical.
9. Checks that unsafe targets are refused.
10. Checks TECC, using a key made with `datawipe keygen`:
    - the auditor's check passes with the published key;
    - it fails with another organisation's key, a forged signature, or an edited session log;
    - the PDF verifies on its own;
    - a log edited while a wipe is paused blocks `--resume`;
    - a wrong key passphrase stops a run before anything is written.

## Live image (bootable USB / CD)

Needed to wipe the disk a machine boots from, and the easiest way to run DataWipe on any PC.

```sh
cd build && make iso       # -> build/datawipe-live.iso (~55 MiB) + .sha256; no root needed
sudo dd if=datawipe-live.iso of=/dev/sdX bs=4M conv=fsync status=progress   # sdX = a USB stick
```

- **Boots on:** UEFI with Secure Boot on (Ubuntu's Microsoft-signed shim, GRUB, kernel and modules, so no key enrolment), UEFI without Secure Boot, and legacy BIOS. Both CD and USB.
- **Runs from RAM:** no disk is mounted except the state stick you choose.
- **Use a second USB stick (FAT32, exFAT or ext4) as the state stick.** Journals, pre-wipe fingerprints, certificates, PDFs, session logs and hardware-test reports go to its `datawipe/` folder, so they survive power-off and reboots (an interrupted wipe resumes from it). Put the organisation's signing key in `datawipe/keys/<name>.key.pem`, or create one from the menu.
- **Menu:** the first entry opens datawipe's guided mode (list and inspect drives, wipe with the serial-and-path confirmation, verify a certificate, create a signing key), the same one an installed system has. The rest is what only a live system needs: choose the state stick, run the spare-drive hardware test, unfreeze drives by suspending, shell, power off.
- **Headless servers:** choose the "serial console" boot entry (ttyS0, 115200).
- **Drivers included:** SATA/AHCI, NVMe, eMMC (PCI and laptop ACPI), USB storage and keyboards, and the common server HBAs (LSI/Broadcom mpt3sas, MegaRAID, HP Smart Array).
- **Tested** in QEMU by `scripts/iso_test.py`. It boots the image under real Secure Boot firmware (Microsoft keys), checks kernel lockdown is active, wipes a SATA disk through the guided mode with the state on an emulated USB stick, and checks the certificate from the host. It also boots it on legacy BIOS and on UEFI without Secure Boot.

## Guided mode

`datawipe` with no command on a terminal (or `datawipe interactive`) opens a menu: list drives, inspect one, wipe, verify a certificate, create a signing key, settings. The wipe path shows the drive, a plain-language plan (steps, level reached, rough duration, whether the certificate will be signed), offers to resume an interrupted wipe, asks for confirmation, then shows progress and a result screen.

```sh
datawipe                                                        # image files and your own loop devices only
sudo datawipe interactive --i-understand-this-is-destructive --state-dir ~/datawipe-state   # also lists physical disks
```

- It is a front end to the commands below, with the same checks. A physical disk still needs its serial number and device path retyped, and a disk in use is refused.
- Physical disks are listed only when the program was started with the destructive flag. Without it the list holds loop devices backed by an image you own; image files are given by path.
- The signing key is `--sign-key`, else `$DATAWIPE_SIGN_KEY`, else the first `*.key.pem` in `<state dir>/keys/` (where the menu's key creation puts it).
- The duration on the plan screen is an assumption from the drive type and USB speed, not a measurement; the progress bar shows the real rate.
- Colour is used on a terminal and dropped when output is piped or `NO_COLOR` is set. The command trace is hidden unless `-v` is given.

## Walkthrough

```sh
scripts/mk_test_image.sh disk.img 100            # 100 MiB of "DATAWIPE-TEST..." lines
L=$(scripts/loop_attach.sh disk.img)             # optional: go through /dev/loopN

build/datawipe keygen acme                       # once per organisation: acme.key.pem (encrypted), acme.pub.pem
build/datawipe probe $L --identity profiles/hdd_with_hpa.json
build/datawipe plan  $L --identity profiles/hdd_with_hpa.json
sudo build/datawipe run $L --identity profiles/hdd_with_hpa.json --sign-key acme.key.pem
#   -> overwrite passes with progress bar, ARVS read-back, then next to the image:
#      disk.img.<UTC time>.dwcert.json   signed certificate
#      disk.img.<UTC time>.dwcert.pdf    printable copy, signed JSON attached
#      disk.img.<UTC time>.dwlog.jsonl   the session's hash chain

scripts/loop_detach.sh $L
build/datawipe verify-cert disk.img.*.dwcert.json --pubkey acme.pub.pem   # the auditor's check
build/datawipe verify disk.img --cert disk.img.*.dwcert.json               # re-read the medium, fresh sample
grep -c DATAWIPE-TEST disk.img                              # 0
```

Without a loop device, pass `disk.img` itself as the target; no sudo is needed.

## Commands

| command | does |
|---|---|
| `probe <target> --identity <profile.json>` | size, sector sizes, ATA-IDENTIFY-shaped identity, classification |
| `plan <target> --identity <profile.json>` | the method, its steps and standards; touches nothing |
| `run <target> --identity <profile.json>` | executes the plan, verifies, writes the certificate |
| `verify <target> --cert <cert.json>` | re-reads the medium against a certificate |
| `verify-cert <cert.json\|.pdf> [--pubkey K] [--log L]` | TECC check: seal, signature, trusted key, full session history |
| `keygen <prefix> [--no-passphrase]` | a new organisation signing key pair |
| `ata-unlock /dev/sdX --i-understand-this-is-destructive --experimental [--password P]` | removes the ATA password an interrupted Secure Erase left (default `DataWipeTmp`); goes through the same confirmation gate |
| `probe /dev/sdX` | read-only detection of a real disk (identify commands only) |

The `run` command takes these options:

| option | default | meaning |
|---|---|---|
| `--buffer-size` | `4M` | size of each write |
| `--sync-every` | `256M` | how often `fdatasync` runs and progress is checkpointed |
| `--direct` | off | use O_DIRECT writes |
| `--resume`, `--restart` | | continue or discard an interrupted wipe (see `<image>.dwjournal`) |
| `--sampler arvs\|uniform` | `arvs` | risk-weighted clusters, or uniform single sectors (the paper's baseline) |
| `--verify-budget P%` | `5%` | ARVS base budget: share of the range's sectors, scaled up to 2× by drive/method risk |
| `--fixed-budget` | | ARVS reads exactly the base budget (for comparisons with uniform sampling) |
| `--verify-samples N` | `4603` | uniform sampler: how many sectors to read |
| `--sci-lambda L` | `3` | SCI: weight of a high-risk failure relative to a baseline one |
| `--rewipe-attempts N` | `3` | re-wipes of a failing cluster before its sectors are NOT VERIFIED |
| `--no-verify` | | skip the read-back |
| `--cert <path>` | | where to write the certificate (`X.json`; the log and PDF go to `X.dwlog.jsonl`, `X.pdf`) |
| `--sign-key <org.key.pem>` | `$DATAWIPE_SIGN_KEY` | Ed25519 key that signs the certificate; passphrase from `$DATAWIPE_KEY_PASSPHRASE` or the terminal |
| `--keep-hidden` | | leave the HPA/DCO area alone (caps the result at Clear) |
| `--no-defense-in-depth` | | for self-encrypting SSDs, crypto erase only, without the extra block erase |
| `--json` | | machine-readable output |

**Exit codes:**

| code | meaning |
|---|---|
| 0 | done |
| 1 | usage error |
| 2 | refused |
| 3 | detection failed |
| 4 | not supported |
| 5 | error |
| 6 | plan failed (journal kept) |
| 7 | interrupted (resumable) |
| 8 | verification or certificate integrity failed |

## What is real and what is simulated

**Simulated drives** (an image or loop device with an `--identity` profile): host overwrites are real; firmware commands are built, state-checked against the drive's rules and logged. On an HDD profile, the Secure Erase is **EMULATED** (a second real pass produces its effect, so read-back still applies). SSD/eMMC firmware steps are **SIMULATED**: the image is untouched, and the certificate outcome is `simulated`.

**Real drives**: every step is **REAL**: firmware commands go to the drive through SG_IO / NVMe admin / MMC ioctls, and no host pass stands in for them. What may be sent (`src/engine/command_support.cpp`):

| command | status | why |
|---|---|---|
| host overwrite (any disk) | proven | QEMU bench: real SATA and NVMe drivers, read-back verified |
| NVMe Format NVM, user-data erase | proven | QEMU bench: sent to the confirmed namespace, fingerprint-verified |
| ATA SECURITY ERASE UNIT, enhanced, on an HDD | proven | real drive: WD5000AAKX (500 GB) through a USB 2.0 dock, 79 min against the drive's own estimate of 82, fingerprint-verified over 57.9 M sectors |
| ATA SECURITY ERASE UNIT, normal (any drive) or enhanced on an SSD | `--experimental` | not yet run on real hardware; QEMU does not emulate the ATA Security feature set |
| ATA SANITIZE, NVMe Sanitize | `--experimental` | not emulated by QEMU |
| HPA/DCO removal (SET MAX ADDRESS, DCO RESTORE) | `--experimental` | not emulated by QEMU |
| NVMe Format crypto erase, eMMC SANITIZE, eMMC secure erase (BLKSECDISCARD), discard | `--experimental` | not emulated by QEMU (its eMMC is a 4.41 card without them) |
| TCG Opal key regeneration | not implemented | needs an authenticated Opal session; use the vendor's PSID revert |

**eMMC** is identified from its EXT_CSD register (read with CMD8), giving the revision, capacity, SANITIZE and secure-erase support, boot/RPMB/general-purpose partition sizes and the wear estimate (ARVS factor W). The method follows the paper's §III-B: SANITIZE if supported, otherwise secure erase via BLKSECDISCARD, otherwise two host passes (Clear). eMMC boot, RPMB and general-purpose partitions are separate hardware areas that a user-area wipe does not reach, so the plan and certificate say so; they can't be targeted directly.

**Firmware erases on real drives, and what can go wrong:**
- **ATA Secure Erase** sets a temporary user password first; the erase clears it. The password is fixed and documented (`DataWipeTmp`), so if the erase is interrupted (power loss, crash) and the drive locks at the next power-up, `datawipe ata-unlock` recovers it even without the journal. `run` points to it when it finds a locked drive.
- **Its timeout is twice the drive's own estimate** (IDENTIFY words 89/90) plus 30 minutes, at least 2 hours, or 72 hours when the drive gives none. A timeout that's too short would make the kernel reset the drive mid-erase.
- **HPA/DCO removal is a separate first run on real drives.** It removes the hidden area (non-volatile), asks the kernel to re-read the capacity, and exits with code 10. Nothing is overwritten against a stale size. The next run wipes the full native capacity; if the kernel still showed the old size, reboot or re-plug the drive first.

After a firmware erase the disk content is vendor-defined, so verification uses **pre-wipe fingerprints**: the sampled sectors are hashed before the first destructive command (`<state dir>/datawipe-<model>-<serial>.dwfp`, recorded in the session chain and reused on resume), and each must differ afterwards.

A physical disk's journal, fingerprints and certificate go to `$DATAWIPE_STATE_DIR` (default: the current directory), named `datawipe-<model>-<serial>.*`, so an interrupted wipe is found again even if `/dev/sdb` became `/dev/sdc`.

## Interruptions

- **During an overwrite pass:** Ctrl-C, a dropped USB connection or a power cut all leave a journal. `--resume` continues from the last confirmed position. It first steps back two flush intervals and rewrites them, because some USB bridges hide the drive's write cache from the kernel.
- **During verification or pre-wipe fingerprinting:** Ctrl-C stops between clusters. The journal, which holds the pattern key, is kept until the certificate is written, so `--resume` repeats only the verification and never the wipe.
- **During a firmware erase:** the drive finishes on its own. If it's left locked, see `ata-unlock`.
- Progress is shown for every long phase. When output is piped, there's a line per 10% and at least one a minute.

## Where things are

| path | what |
|---|---|
| `src/device/` | backends (image, loop, physical read-only), safety guard, identity providers (simulated JSON, ATA/NVMe pass-through, sysfs), classifier |
| `src/engine/method_selector.*` | DeviceProfile → WipePlan: the §III-E matrix |
| `src/engine/overwrite_engine.*` | chunked, double-buffered writes; fdatasync / O_DIRECT trade-offs are in the header |
| `src/engine/pattern.*`, `src/core/chacha20.*` | position-addressable ChaCha20 pattern; why ChaCha20 is in the header |
| `src/engine/run_journal.*` | crash-safe resume journal |
| `src/verify/risk_model.*` | ARVS equation (1): factors H, W, F, B, E; AHP weights; per-method priors |
| `src/verify/arvs_sampler.*` | ARVS: budget from W, F, E; placement by H, B |
| `src/verify/sci.*` | SCI, equations (3) and (4) |
| `src/verify/readback_verifier.*` | read-back against a pattern or pre-wipe fingerprints; Stage 6 re-wipe |
| `src/verify/fingerprint.*` | pre-wipe sector hashes for device-internal erases (SSD) |
| `src/tecc/session_chain.*` | the TECC hash chain and its log file |
| `src/tecc/ed25519.*` | signing keys (OpenSSL) |
| `src/cert/certificate.*` | certificate body, TECC seal, checks, re-verification data |
| `src/cert/pdf.*` | the PDF certificate |
| `src/platform/win_*` | Windows build: POSIX gaps filled on Win32, and the (not yet implemented) device layer |
| `src/cli/main.cpp` | the CLI commands |
| `src/cli/interactive.cpp` | the guided mode (the only code that lists drives) |
| `profiles/` | simulated drive identities (format in `profiles/README.md`) |
| `src/engine/passthrough_executor.cpp` | sends plan commands to real drives |
| `src/engine/command_support.*` | proven / experimental / unsupported commands; capability masking |
| `scripts/` | test image, loop attach/detach, end-to-end test, `qemu_bench.py`, `hardware_test.sh` |

## Limits, stated plainly

- **Only some ARVS parameters are measured.** Every certificate records, for the method used, whether F is `measured` or `assumed`, with its counts and 95% interval:
  - **Measured:** the failure rates F for SSD Secure Erase (1 of 5 drives that reported success kept data), enhanced Secure Erase (0 of 4), and one- vs two-pass overwrite on flash (7 of 8 vs 1 of 8 drives kept data). These come from Wei et al., FAST 2011, Tables 1–2, estimated as (x+½)/(n+1) because the samples are 4–8 drives.
  - **Assumed:** everything else, including all HDD rates, SANITIZE, NVMe Format, Opal and eMMC. No published failure rates exist for these.
  - **Not calibrated:** the AHP judgments are the author's, and SCI's λ = 3 is illustrative. The weights do change results: with B ≈ 0, detection of planted failures drops from ~98% to ~77%, so calibrating them against real failure data (the planned spare-drive study) matters.
- **One deliberate deviation from the paper's Table II:** the risk term uses E = 1 − confidence. The table's E values are confidences (overwrite 0.9, Sanitize 0.2); added as-is, they would make the most verifiable method the riskiest.
- **A re-wiped cluster makes the outcome `sanitized-with-repairs`, not `sanitized`.** A failure in the sample means unsampled areas may have failed the same way, and the SCI (computed from the first read) shows how much.
- **TECC is only as good as key custody** (paper §VI). Anyone holding an organisation's private key can issue valid certificates. `keygen` encrypts the key (AES-256, file mode 0600); keeping it offline or in an HSM is the organisation's job. HSM (PKCS#11) signing is not built yet.
- **Trust comes from the published public key, never from the certificate.** The certificate names the key that signed it, but a forger can re-sign with their own key. Only `--pubkey` with the organisation's key, obtained through a trusted channel, proves origin.
- **The PDF has no PDF-level signature (PAdES).** It's a readable copy; the signed record is the JSON attached inside it, and `verify-cert` checks that.
- **Unsigned certificates are allowed** (no `--sign-key`). They prove integrity, not origin, and say so in the output and the PDF.
- **The pattern key is stored in the certificate** so the medium can be re-verified later. It is not a secret; it only determines the overwrite pattern.
- **Through a buffered loop device**, flushes and reads reach the backing file. To reach the disk underneath, attach with `losetup --direct-io=on`.
- **Real-drive execution has been tested on QEMU's emulated drives and on one physical drive.** The bench exercises the real kernel drivers (AHCI, NVMe) and ioctls, but a QEMU drive is not firmware. One 500 GB SATA HDD (WD5000AAKX, USB 2.0 dock) has been wiped end to end twice: host overwrite (Clear) and overwrite + enhanced Secure Erase (Purge), both verified at SCI 100. That is one drive model from one vendor; every other firmware command is still `--experimental`, and `scripts/hardware_test.sh` on spare drives is the only way one becomes proven.
- **Controller-wide NVMe operations are refused on multi-namespace controllers.** NVMe Sanitize always acts on every namespace, and so does Format when the controller says so (FNA bit 0). The operator confirmed one namespace, so these are refused while the controller has others.
- **eMMC boot, RPMB and general-purpose partitions are not wiped.** They normally hold firmware rather than user data, but every plan lists them as not covered, and the QEMU bench confirms their contents survive.
- **USB enclosures may not pass ATA commands through.** A drive behind a USB bridge often only accepts host overwrites; the plan then falls back to Clear.
- **Certificates of firmware erases can't be re-verified later.** `datawipe verify` needs a host-known pattern; after a firmware erase the content is vendor-defined, and the fingerprints are only meaningful against the medium as it was right after the wipe.
