# CCS2026 Artifacts - From Fault to Oracle: Breaking Google Pixel TPU Hardware Memory Isolation via Trusted Deserialization Faults

[Artifact Evaluation appendix (PDF)](ccs2026-From-fault-to-oracle_final_version.pdf) · [LaTeX source](ccs2026-ae-template.tex)

This repository contains the artifacts of our ACM CCS 2026 paper. They support three stages: acquire two EdgeTPU memory regions from a prepared Pixel 9a, import the resulting dump logs into IDA and recover candidate functions, and scan the reconstructed firmware for candidate fault-oracle memory-access sites. The PDF is the formal artifact appendix; this README gives the commands and checks for each stage.

The artifact was awarded the ACM CCS 2026 **Artifacts Available**, **Artifacts Evaluated — Functional**, and **Artifacts Reproduced** badges.

You can run the complete workflow from Stage 1, or start from one of the supplied intermediate artifacts:

- To reproduce **dump import and firmware recovery**, start from **Stage 2** with the bundled pre-collected `.log` files.
- For the **shortest offline path**, go directly to **Stage 3** and open the supplied IDA Pro 9.2 database.

A complete Stage 1 acquisition is deliberately throttled and takes **more than 16 hours per memory region** (Section 1.6). The offline Stages 2 and 3 need neither this acquisition nor a Pixel device, but they do require **IDA Pro 9.2** and an **ARM Hex-Rays decompiler** license.

---

## Artifact Contents

| Path | Purpose |
| --- | --- |
| `POC/DumpAuto_stable/runner.c` / `runner` | Repeated memory acquisition, stability checks, logging, and resume support |
| `POC/DumpAuto_stable/cracktpu_dumpMem_automatic.c` / `cracktpu` | Device-side helper invoked by `runner` for each requested address |
| `POC/DumpAuto_stable/compile.sh` | Builds and deploys the Android helpers |
| `POC/DumpAuto_stable/edgetpu.h` | EdgeTPU device-interface definitions |
| `Public_artifacts/edgetpu-rio.fw` | Raw firmware image for a fresh IDA import |
| `Public_artifacts/0x0ff00000_0x0ff0E4FF_dump.log` | Bundled dump for the first recovered memory region |
| `Public_artifacts/0x10000000_0x1000ea80_dump.log` | Bundled dump for the second recovered memory region |
| `Public_artifacts/import_dump_log_to_ida.py` | Imports recovered address/value records into IDA |
| `Public_artifacts/recover_tpu_funcs.py` | Recovers candidate Thumb functions in a selected segment |
| `Public_artifacts/table3.py` | Prints Table 3 candidate-pattern counts as an aligned table in IDA's Output window |
| `Public_artifacts/table4.py` | Prints Table 4 structural metrics as an aligned table in IDA's Output window |
| `edgetpu-rio_eval_re.fw.i64` | Prepared IDA Pro 9.2 database containing reconstructed on-chip code and firmware analysis |
| `Public_artifacts/faultoracle_scanner_mc.py` | Scans configured handlers for candidate fault-oracle memory-access sites |
| `ccs2026-From-fault-to-oracle_final_version.pdf` / `ccs2026-ae-template.tex` | Artifact appendix and its LaTeX source |

---

# Workflow Overview

| Stage | Paper | What it covers | Required resources |
| --- | --- | --- | --- |
| **Stage 1** | §6.2 (RQ1) | On-device memory acquisition and resume behavior | Prepared rooted Pixel 9a |
| **Stage 2** | §6.2, Tables 3–4; §6.4 | Dump import, firmware recovery, and table checks | Bundled logs, firmware image, IDA Pro 9.2, ARM Hex-Rays for Table 4 |
| **Stage 3** | §6.3 (RQ2) | Fault-oracle scanner operation and candidate-site inspection | Prepared `.i64`, IDA Pro 9.2, ARM Hex-Rays |

We recommend starting with **Stage 3**, then using Stage 2 or Stage 1 to inspect earlier steps of the workflow.

---

# Stage 1 — Acquire the EdgeTPU Memory Dumps

> **Paper:** §6.2 (RQ1) — Tables 2, 3, 4, 6; Appendices C, D.

## 1.1 Access the Prepared Pixel 9a

During artifact evaluation, we provided a prepared **rooted Pixel 9a**, accessed remotely through **Tailscale + SSH** and shared among evaluators. This remote access was available only during artifact evaluation and is not part of this release. In the commands below, `<user>` and `<device-ip>` stand for the SSH user and address of the device.

The on-device acquisition workflow is validated on this prepared Pixel 9a and its installed EdgeTPU firmware build. The same addresses, handler locations, or acquisition behavior should not be assumed to apply unchanged to other Pixel models or firmware versions.

Log in to the device over SSH (the prepared device used port 8022):

```bash
ssh -p 8022 <user>@<device-ip>
```

Root access is already enabled on the prepared device. After logging in, run `su` to enter a root shell; no additional rooting steps are required. Follow Section 1.3 to prepare the device before running the acquisition commands.

---

## 1.2 Build and Deploy the Acquisition Tools

Prebuilt copies of `runner` and `cracktpu` are included in `POC/DumpAuto_stable/`; on the prepared review device they were **already deployed**. If the helpers are already on your device, skip this section and continue at Section 1.3.

To confirm the helpers are present, run this in your SSH session:

```bash
ls -l /data/local/tmp/runner /data/local/tmp/cracktpu
```

Rebuild only if they are missing, or if you want to verify that the deployed binaries correspond to the sources in this package.

### 1.2.1 Build

The NDK version used to produce the bundled binaries is **r26.1.10909125**. Set `NDK` to your own NDK root and run:

```bash
export NDK="/absolute/path/to/android-ndk"

cd POC/DumpAuto_stable
sh compile.sh
```

`compile.sh` hardcodes the macOS NDK host directory `darwin-x86_64` (four occurrences) and the toolchain `aarch64-linux-android34-clang`. On Linux, replace `darwin-x86_64` with `linux-x86_64`. The script performs no error checking: if `NDK` is unset, it fails with `/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android34-clang: No such file or directory`.

The script runs `adb push` after each of its two builds. **Without ADB, both pushes fail, but both binaries are still produced in the current directory**, which is all Section 1.2.2 needs. Check:

```bash
file runner cracktpu
# ELF 64-bit LSB pie executable, ARM aarch64 ...
```

### 1.2.2 Deploy

Choose the path that matches your access. Tailscale/SSH and ADB are separate access paths: joining the Tailscale network does **not** provide ADB access to the prepared device.

**Path A — remote device, over SSH (`scp`).** This is the path used with the prepared review device. `/data/local/tmp/` is not necessarily writable by the SSH user, so copy to the home directory first and move the files into place from the root shell:

```bash
# from POC/DumpAuto_stable/ on your own machine
scp -P 8022 runner cracktpu <user>@<device-ip>:~/
```

Then, in your SSH session:

```bash
su
cp ~<user>/runner ~<user>/cracktpu /data/local/tmp/
cd /data/local/tmp
chmod 755 runner cracktpu
```

If your SSH user can write `/data/local/tmp/` directly, `scp -P 8022 runner cracktpu <user>@<device-ip>:/data/local/tmp/` replaces the copy step; the `chmod` is still required.

**Path B — your own locally connected device, over ADB.** `compile.sh` already pushes both binaries, so only the permissions remain:

```bash
adb shell chmod 755 /data/local/tmp/runner
adb shell chmod 755 /data/local/tmp/cracktpu
```

Note that the acquisition workflow is validated only on the authors' prepared Pixel 9a and its firmware build; other devices are not assumed compatible.

### 1.2.3 Verify the deployed binaries

To check that the helpers on the device match the copies in this package:

```bash
# on the device, in your SSH session
md5sum /data/local/tmp/runner /data/local/tmp/cracktpu
```

```text
f86aedee0c073489f87f0de70af4e17e  runner
4cbd8712321ecbac5477502faaa4867e  cracktpu
```

These are the checksums of `POC/DumpAuto_stable/runner` and `POC/DumpAuto_stable/cracktpu` as shipped. A rebuild from source will not reproduce them byte for byte unless the same NDK version and host toolchain are used.

---

## 1.3 Prepare the Device Before Running `runner`

Stage 1 requires root privileges, and root access is already enabled on the prepared Pixel 9a. In your SSH session, run the following command to enter a root shell before preparing the device:

```bash
su
```

Then stop the EdgeTPU logging service:

```bash
stop edgetpu_logging
```

Prepare the working directory:

```bash
cd /data/local/tmp
chmod 755 runner cracktpu
mkdir -p review-dumps
```

The important point is that `runner` should be executed from the same root shell after `edgetpu_logging` has been stopped.

---

## 1.4 Acquire the Two Memory Regions

The artifact contains two reference dump files:

```text
0x0ff00000_0x0ff0E4FF_dump.log
0x10000000_0x1000ea80_dump.log
```

`runner` accepts arguments in the following order:

```text
./runner START END_EXCLUSIVE HELPER_PATH OUTPUT_LOG
```

It advances in four-byte steps.

**The ending address is exclusive.**

### Region 1

> **Paper:** §6.2, on-chip executable region — Table 4; Appendix D.

```bash
./runner 0x0ff00000 0x0ff0e500 ./cracktpu \
  review-dumps/0x0ff00000_0x0ff0E4FF_dump.log
```

This includes the final word beginning at `0x0ff0e4fc`, covering bytes through `0x0ff0e4ff`.

### Region 2

> **Paper:** §6.2, secure-DRAM firmware-image subrange — Tables 2, 3; Appendix C.

```bash
./runner 0x10000000 0x1000ea84 ./cracktpu \
  review-dumps/0x10000000_0x1000ea80_dump.log
```

This includes the final word beginning at `0x1000ea80`.

---

## 1.5 Device Reboot and Resume Behavior

The Pixel may reboot during acquisition.

Therefore, an SSH disconnection while `runner` is executing may indicate a **device reboot** rather than normal completion. After reconnecting, `su` and `stop edgetpu_logging` must be executed again before resuming the acquisition.

If this happens:

1. Wait for the Pixel to reappear on Tailscale.
2. Reconnect using the same SSH command:

```bash
ssh -p 8022 <user>@<device-ip>
```

3. Run `su` to re-enter a root shell, then stop the logging service again:

```bash
su
stop edgetpu_logging
cd /data/local/tmp
```

4. Re-run the **same `runner` command with the same output path**.

`runner` reads the last valid address already present in the output log and resumes from the next word. A partially completed acquisition therefore does not need to restart from the beginning.

For an independent run, use a new output filename or directory. If the device is shared, the same path may already hold another user's log: `runner` resumes and appends to it if it is partial, and reports `dump already complete` and exits if it is complete.

---

## 1.6 Stability Checks and Running Time

For each address, `runner` requests three consecutive matching reads, with a two-second interval.

If the value does not stabilize after 15 attempts, it attempts neighboring-address reconstruction (the paper's sliding-offset fallback). If that fallback also fails, the acquisition terminates with an error.

The two-second interval is a deliberate, conservative throttle. The prepared review device was shared among evaluators, and we observed that frequent acquisition requests, particularly under concurrent access, could occasionally destabilize it. Since each word needs at least three reads and therefore at least two intervals (4 s), a complete acquisition takes **more than 16 hours per region** even without retries or reboots.

Table 6 of the paper reports unthrottled costs and counts a single read for a normal word, so the wall-clock time of a `runner` acquisition is not comparable to it. To measure the per-read cost that Table 6 reports, run `cracktpu` directly in the root shell prepared in Section 1.3 (e.g., `./cracktpu 0x10000000`) and read its `[TIME]` line; `runner` discards this output.

To avoid this wait, we bundle the pre-collected dumps (Section 1.9), so you can reproduce all subsequent analysis, starting at Stage 2, without a complete acquisition.

---

## 1.7 Restore the Logging Service

After finishing the acquisition:

```bash
start edgetpu_logging
exit
```

---

## 1.8 Retrieve the Logs

For a locally connected device:

```bash
adb pull /data/local/tmp/review-dumps ./review-dumps
```

Over SSH, output files created from a root shell may need their permissions adjusted before transfer via `scp` or SFTP.

---

## 1.9 Expected Dump Format

Each record contains an address and a 32-bit word:

```text
0x10000000:0xea00003a
0x10000004:0xea000038
```

Some entries may include an instability annotation:

```text
0x1000000c:0xea000036:cache_unstable
```

Words recovered by the neighboring-address fallback (Section 1.6) are tagged `flag_insurance_operation_2_2`, `flag_insurance_operation_1_3`, or `flag_insurance_operation_3_1` instead:

```text
0x100005ec:0xffe8f000:flag_insurance_operation_2_2
```

The bundled reference files contain:

| Reference log | First word address | Last word address | Word records | Tagged records |
| --- | --- | --- | ---: | ---: |
| `0x0ff00000_0x0ff0E4FF_dump.log` | `0x0ff00000` | `0x0ff0e4fc` | 14,656 | 2,175 |
| `0x10000000_0x1000ea80_dump.log` | `0x10000000` | `0x1000ea80` | 15,009 | 2,150 |

The tagged records comprise 2,172 `cache_unstable` and 3 fallback records in the first file (2,170 and 3 within the 14,648-word window of Tables 4 and 6, which excludes the final 32 bytes), and 2,109 and 41 in the second; these match Table 6.

These counts describe the bundled reference files. A new acquisition is not expected to be byte-for-byte identical at every unstable location.

For a new acquisition, primarily check:

- address coverage,
- successful acquisition/resume behavior, and
- correct handling of tagged entries.

---

# Stage 2 — Import the Dumps into IDA and Recover Functions

> **Paper:** §6.2 — Tables 3–4; §6.4 — Figure 3.

This stage reproduces the offline firmware-reconstruction workflow using the supplied dump logs.

The two inputs are:

```text
Public_artifacts/0x0ff00000_0x0ff0E4FF_dump.log
Public_artifacts/0x10000000_0x1000ea80_dump.log
```

---

## 2.1 Load the Raw Firmware

Open:

```text
Public_artifacts/edgetpu-rio.fw
```

in **IDA Pro 9.2** as a **32-bit ARM, little-endian** firmware image. Set **Instruction set** to **32-bit** when loading the firmware.

### Important: firmware base address

For a fresh firmware import, load the firmware at:

```text
0x0ffff000
```

The two dump regions begin at different addresses and must **not** be used as the firmware base.

Allow IDA's initial auto-analysis to complete and save a working database.

We recommend working on a copy because the import and recovery scripts modify the database.

---

## 2.2 Import the First Dump

In IDA, choose:

```text
File → Script file…
```

and run:

```text
Public_artifacts/import_dump_log_to_ida.py
```

When prompted, select:

```text
Public_artifacts/0x0ff00000_0x0ff0E4FF_dump.log
```

Wait for the import and reanalysis to finish.

---

## 2.3 Import the Second Dump

Run the same script again and select:

```text
Public_artifacts/0x10000000_0x1000ea80_dump.log
```

The importer patches each 32-bit word at its recorded absolute address in little-endian order.

Check the IDA output window for messages similar to:

```text
[import_dump] patched words: ...
[import_dump] malformed lines skipped: ...
[import_dump] unmapped addresses skipped: ...
[import_dump] tagged entries: ...
[import_dump] patched range: ...
```

For the bundled reference files, the expected record counts are:

```text
First region:  14,656
Second region: 15,009
```

If fewer words are patched, inspect the segment mappings and any reported unmapped addresses.

---

## 2.4 Recover Candidate Firmware Functions

> **Paper:** §6.2 — Table 4; Appendix D.

After importing both dumps, run:

```text
File → Script file…
```

and select:

```text
Public_artifacts/recover_tpu_funcs.py
```

Before running the script, check:

```python
SEG_NAME = "ROM"
```

The script analyzes function gaps in the segment selected by `SEG_NAME`.

If the imported region resides in a different segment, for example:

```text
.dump_0ff
```

change `SEG_NAME` to the actual segment name and rerun the script.

In the supplied prepared database, the on-chip segment used by Table 4 is
named `DUMP_ROM`. Use that name when intentionally repeating on-chip recovery.

Repeat for other relevant segments if necessary.

The recovery pass uses:

- Thumb prologue patterns,
- recovered call targets, and
- orphan code regions

to create candidate functions.

It performs up to four iterations by default and stops early if no additional functions are created.

The final output should contain:

```text
[recover_tpu_funcs] DONE — added ... funcs total
```

A zero-function result does not necessarily indicate failure. It can mean that:

- the selected segment name is incorrect, or
- the relevant functions have already been recovered.

This stage performs heuristic function-boundary recovery. It does not reconstruct the original firmware source code and does not guarantee recovery of every function.

---

## 2.5 Run Tables 3 and 4

Open a fresh copy of `edgetpu-rio_eval_re.fw.i64` in **IDA Pro 9.2** and wait
for analysis to finish. Through **File → Script file…**, run:

```text
Public_artifacts/table3.py
Public_artifacts/table4.py
```

Each script prints an aligned table directly in IDA's **Output** window;
no result files are created. Keep the scripts beside the bundled firmware and dump logs.
Table 4 requires ARM Hex-Rays for its decompilation metric; otherwise that
metric is `N/A`. Neither script imports bytes or runs function recovery.

| Paper mapping | Script / input |
| --- | --- |
| §6.2, Table 3; Appendix C | `table3.py`: secure-DRAM log versus `edgetpu-rio.fw`; `[0x10000000, 0x1000EA84)`, file offset = address − `0x0FFFF000` |
| §6.2, Table 4; Appendix D | `table4.py`: current IDB, `[0x0FF00000, 0x0FF0E4E0)` |

The ranges above have exclusive ends. Table 4 includes the reserved gap but
excludes the final 32 bytes of the bundled on-chip log.

**Verified results on the supplied inputs** (IDA 9.2 / ARM Hex-Rays 9.2):

| Table 3 candidate pattern | Count |
| --- | ---: |
| PC-relative branch immediates | 92 |
| Long-branch veneers/trampolines | 9 |
| Cross-region pointer-table slots | 39 |
| Unattributed | 5 |

| Table 4 metric | Rate | Successful / total |
| --- | ---: | ---: |
| Bytes classified as code or data | 98.96% | 57,981 / 58,592 bytes |
| Instructions fully decoded | 99.52% | 20,462 / 20,561 insns |
| **Direct** BL/BLX targets resolved | 98.66% | 1,472 / 1,492 calls |
| B-family targets with consistent ISA metadata | 98.18% | 2,861 / 2,914 branches |
| Non-trivial functions decompiled | 98.98% | 291 / 294 functions |

**AE implementation note.** Table 4 depends on `recover_tpu_funcs.py`, which
we reimplemented for AE. We verified both table scripts on the supplied
artifacts. The Table 3 counts match the paper. The Table 4 rates differ
slightly from those in the paper (two of the five are higher, three lower),
and four of the five denominators differ; the results remain consistent with
the paper's conclusion that the recovered firmware is amenable to structural
analysis.

---

# Stage 3 — Open the Prepared Database and Scan Fault-Oracle Gadgets

> **Paper:** §6.3 (RQ2) — Table 5; scanner design in §5.

For the shortest path, directly open:

```text
edgetpu-rio_eval_re.fw.i64
```

in **IDA Pro 9.2**.

For offline use, we recommend the supplied reference dumps and prepared IDA database unless you specifically want to reproduce the reconstruction process from Stage 1 or Stage 2.

This database already contains:

- the reconstructed on-chip image and secure-DRAM firmware mapping,
- reconstructed firmware code,
- recovered functions, and
- the analysis state required by the scanner.

Do **not** rebase the prepared database.

Do **not** reimport the raw firmware when using this path.

Allow IDA analysis to finish and verify that the ARM Hex-Rays decompiler is available.

---

## 3.1 Run the Fault-Oracle Scanner

> **Paper:** §6.3 — Table 5.

In IDA, choose:

```text
File → Script file…
```

and run:

```text
Public_artifacts/faultoracle_scanner_mc.py
```

The scanner analyzes Hex-Rays microcode at `MMAT_LOCOPT` maturity.

Its configured `HANDLERS` list specifies the firmware entry addresses and payload registers to analyze.

The scanner reports candidate load/store sites whose effective addresses satisfy the implemented derived-value and interval checks.

These should be interpreted as:

> **candidate fault-oracle memory-access gadgets**

They are not conventional ROP gadgets, and scanner output alone does not imply that every reported site is a confirmed vulnerability.

---

## 3.2 Scanner Output

Results are printed in the IDA output window.

The output includes:

- handler address,
- candidate-site count,
- instruction address,
- defining site,
- operation size, and
- deduplicated site count.

A run ends with output of the form:

```text
TOTAL sites (after per-def-site dedup): ...
```

You can navigate to reported addresses in the IDA disassembly and pseudocode views to inspect the candidate sites.

To record a run, we recommend saving:

```text
IDA version
Hex-Rays version
database used
scanner output
```

---

## 3.3 Common Scanner Errors

If the scanner reports:

```text
no function at ...
```

check:

- whether the correct prepared database is open,
- segment mappings, and
- function-recovery results.

If the scanner reports:

```text
gen_microcode failed
```

check:

- ARM Hex-Rays availability,
- the function's analysis state, and
- whether the function is recognized correctly by IDA.

These messages indicate that the corresponding function was not analyzed successfully. They should not be interpreted as evidence that no candidate site exists.

The configured handler addresses are firmware-specific.

---

# Paper Result to Artifact Step Mapping

Section, table, and figure numbers refer to the paper.

| Paper | Result | Artifact step |
| --- | --- | --- |
| §6.1 | Experimental setup | Stage 1 §1.1–1.3; Stage 3 |
| §6.2, Table 2 | Secure-DRAM exact-match accuracy | Stage 1 §1.4 Region 2 |
| §6.2, Table 3 (App. C) | Candidate discrepancy patterns | Stage 2 §2.5: `Public_artifacts/table3.py` |
| §6.2, Table 4 (App. D) | On-chip structural validation | Stage 2 §2.4–2.5: `recover_tpu_funcs.py`, then `table4.py` on the resulting IDB |
| §6.2, Table 6 (App. D) | Per-word cost and throughput | Stage 1 §1.4, §1.6 |
| §6.3, Table 5 | Fault-oracle sites per handler | Stage 3 §3.1–3.2 |
| §6.4, Figure 3 | Relocation-aware recovery of `sub_100056CA` | Stage 2 §2.2–2.4 |
| §3.1, §3.3, §3.4 | Isolation boundary, log channel, KCI channel | Stage 1 §1.3–1.5, §1.9 |
| §4.2, §4.3 | Fault-oracle primitive, stack-cookie case study | Stage 1 §1.4 |
| §5, §5.1, §5.2 | Scanner design | Stage 3 §3.1 |

Table 5 rows map to the handlers in the scanner's `HANDLERS` list:
Setup `sub_1002B3E8`, Data transfer `sub_1002AD4C`, Teardown `sub_1002A734`,
Registration `sub_1002AE9C`, Execution `sub_FF04A34`. The scanner produces the
*Reported* column only; *Structurally valid* and *Reachable* are the manual
audit of §6.3.

---

# Notes

- The remote Tailscale/SSH review device used during artifact evaluation is not part of this release.
- The bundled dumps and the prepared IDA database allow the core offline analysis to be reproduced without a Pixel device.
- Where hardware instability may affect exact values, particularly during live memory acquisition, compare against the bundled reference artifacts rather than expecting identical values at every location.
