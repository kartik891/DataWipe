# Simulated identity profiles (`datawipe.identity.v1`)

A profile describes the drive an image file or loop device *pretends to be*. It produces the
same `AtaIdentity` struct a real `ATA IDENTIFY DEVICE` would, so everything downstream of
device detection is identical for simulated and real targets. Every profile-derived record is
tagged `identity.source = "simulated"`.

| key | type | IDENTIFY equivalent |
|---|---|---|
| `schema` | `"datawipe.identity.v1"` (required) | — |
| `description` | string, ignored | — |
| `transport` | `sata` \| `nvme` \| `emmc` (required) | which command set answered |
| `model`, `serial`, `firmware` | string (`model`, `serial` required) | words 27-46, 10-19, 23-26 |
| `rotation_rate` | 0..65535; `1` = non-rotating | word 217 |
| `capacity.total_sectors` | `"auto"` or integer | DCO max (the real medium size) |
| `capacity.dco_hidden_sectors` | integer, default 0 | DCO max − native max |
| `capacity.hpa_hidden_sectors` | integer, default 0 | native max − words 100-103 |
| `security.{supported,enabled,locked,frozen,enhanced_erase}` | bool | word 128 bits 0,1,2,3,5 |
| `sanitize.{supported,crypto_scramble,overwrite,block_erase}` | bool | word 59 bits 12,13,14,15 |
| `self_encrypting` | bool | TCG Level 0 Discovery |
| `wear_ratio` | 0..1, optional | not IDENTIFY: NVMe Percentage Used / 100, SATA SMART wear (ARVS factor W) |

Sector counts are in the device's logical sectors (512 B for image files). `"auto"` uses the
measured size, so one profile fits any image. Hidden regions sit at the **end** of the image,
exactly where an HPA/DCO sits on a real drive. Unknown keys are rejected.
