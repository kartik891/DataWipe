DataWipe for Windows - PREVIEW
==============================

Runs the DataWipe pipeline on disk image files and on whole physical disks:
plan, wipe, read-back verification (ARVS + SCI) and signed certificates
(TECC).

- Every wipe can do a HOST OVERWRITE (NIST Clear).
- SATA drives can also get firmware erase (ATA Secure Erase, SANITIZE,
  HPA/DCO removal = Purge), but only with --experimental: these commands
  are validated on Linux, not yet through Windows.
- NVMe and eMMC drives get host overwrite only: Windows does not pass
  their erase commands through. For Purge on them, boot the live ISO.

THIS PREVIEW HAS NOT YET BEEN RUN AGAINST A PHYSICAL DISK ON WINDOWS. Try it
on a spare disk, or on a virtual disk (Disk Management > Action > Create VHD,
then attach it), never on a disk holding data you need.

Image files (no Administrator rights needed):

    fsutil file createnew disk.img 67108864
    .\datawipe.exe run disk.img --identity profiles\hdd_basic.json
    .\datawipe.exe                       (guided menu)

A physical disk (Administrator terminal):

    Get-Disk                                     find the disk number N
    Set-Disk -Number N -IsOffline $true          a disk with volumes is refused
    .\datawipe.exe probe \\.\PhysicalDriveN       read-only
    .\datawipe.exe run \\.\PhysicalDriveN --i-understand-this-is-destructive --state-dir C:\datawipe
                                                 asks you to retype the serial number and path
    Set-Disk -Number N -IsOffline $false         afterwards
    or: .\datawipe.exe interactive --i-understand-this-is-destructive
    add --experimental to allow Secure Erase / SANITIZE on a SATA drive

If an interrupted Secure Erase left the drive with a password (it locks at the
next power-up), recover it with:
    .\datawipe.exe ata-unlock \\.\PhysicalDriveN --i-understand-this-is-destructive --experimental

Refused: volumes (\\.\C:), the disk holding Windows, any disk with a drive
letter, EFI or recovery partition still visible, Storage Spaces virtual disks.

Certificates made here verify on Linux and the other way round:

    .\datawipe.exe verify-cert <file>.dwcert.json --pubkey <issuer>.pub.pem

Notes
- datawipe.exe is one self-contained file; no installer, no extra DLLs.
- It is not code-signed, so SmartScreen or antivirus may warn about it.
- Keep a signing key (keygen) in a folder only you can read: Windows has no
  0600 file mode, so the key file inherits the folder's permissions. It is
  still encrypted with your passphrase.
- Ctrl-C pauses a wipe safely; run the same command with --resume.
- Full documentation: README.md. Licence: LICENSE.txt (MIT); copyright.txt lists
  third-party code (OpenSSL, Apache-2.0, linked into datawipe.exe).
