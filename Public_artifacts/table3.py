#!/usr/bin/env python3
"""Print Table 3 candidate counts as an aligned console table.

Run with Python 3 or IDA's File > Script file. Compare the bundled runtime
dump log with the pre-load firmware; no IDB or external packages are needed.
These encoding/value patterns are candidates, not verified relocations.
All address ranges are half-open.
"""

from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
START, END = 0x10000000, 0x1000EA84
FIRMWARE_BASE = 0x0FFFF000
PATTERNS = (
    "PC-relative branch immediates",
    "Long-branch veneers/trampolines",
    "Cross-region pointer-table slots",
    "Unattributed",
)


def load_log(path):
    """Reject malformed records and conflicting duplicates, including off-range ones."""
    words = {}
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", "time_start:", "time_end:", "time_elapsed_s:")):
            continue
        parts = line.split(":", 2)
        try:
            if len(parts) < 2:
                raise ValueError("missing value")
            ea, value = int(parts[0], 0), int(parts[1], 0)
            if ea < 0 or ea % 4 or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("unaligned address or non-32-bit value")
            if ea in words and words[ea] != value:
                raise ValueError("conflicting duplicate address")
        except ValueError as exc:
            raise ValueError(f"{path}:{line_no}: {exc}") from exc
        words[ea] = value
    return words


def branch_encoding(word):
    """Aligned little-endian T32 BL or unconditional B.W encoding pattern."""
    first, second = word & 0xFFFF, word >> 16
    return first & 0xF800 == 0xF000 and second & 0xD000 in (0xD000, 0x9000)


def arm_mov_register(word):
    """A32 MOV(register/shifted-register), excluding reserved conditions."""
    return (word >> 28 != 0xF and word & 0x0FEF0000 == 0x01A00000
            and word & 0x90 != 0x90)


def mov_sites(differences, pointer_start, pointer_end):
    """Runs of >=2 adjacent MOV words, runtime +4, ascending pre-load pointers."""
    sites, current = set(), []
    for ea, old, new in differences:
        eligible = arm_mov_register(new) and pointer_start <= old < pointer_end
        follows = (current and ea == current[-1][0] + 4
                   and old > current[-1][1] and new == current[-1][2] + 4)
        if not eligible or (current and not follows):
            if len(current) >= 2:
                sites.update(item[0] for item in current)
            current = []
        if eligible:
            current.append((ea, old, new))
    if len(current) >= 2:
        sites.update(item[0] for item in current)
    return sites


def run(firmware_path=None, dump_path=None):
    """Measure the bundled range; optional paths support independent inputs/tests."""
    firmware_path = Path(firmware_path or HERE / "edgetpu-rio.fw").resolve()
    dump_path = Path(dump_path or HERE / "0x10000000_0x1000ea80_dump.log").resolve()
    firmware = firmware_path.read_bytes()
    if START < FIRMWARE_BASE or END - FIRMWARE_BASE > len(firmware):
        raise ValueError("comparison range is outside the firmware file mapping")
    runtime = load_log(dump_path)
    addresses = range(START, END, 4)
    missing = [ea for ea in addresses if ea not in runtime]
    if missing:
        raise ValueError(f"dump is missing {len(missing)} words; first missing 0x{missing[0]:08x}")
    differences = []
    for ea in addresses:
        offset = ea - FIRMWARE_BASE
        old = int.from_bytes(firmware[offset:offset + 4], "little")
        if old != runtime[ea]:
            differences.append((ea, old, runtime[ea]))
    veneers = mov_sites(differences, FIRMWARE_BASE, FIRMWARE_BASE + len(firmware))
    counts = Counter()
    for ea, old, new in differences:
        if branch_encoding(old):
            pattern = PATTERNS[0]
        elif ea in veneers:
            pattern = PATTERNS[1]
        elif old == 0 or 0x000E0000 <= old < 0x00100000:
            pattern = PATTERNS[2]  # Zero/handle values: pointer-table candidates only.
        else:
            pattern = PATTERNS[3]
        counts[pattern] += 1
    rows = [{"pattern_candidate": pattern, "count": counts[pattern]} for pattern in PATTERNS]
    total, changed = len(addresses), len(differences)
    comparison = {"matching_words": total - changed, "total_words": total,
                  "differing_words": changed, "match_rate_percent": 100 * (total - changed) / total}
    print("Table 3 — structural pattern candidates")
    border = "+" + "-" * 42 + "+" + "-" * 7 + "+"
    print(border)
    print(f"| {'Pattern candidate':<40} | {'Count':>5} |")
    print(border)
    for row in rows:
        print(f"| {row['pattern_candidate']:<40} | {row['count']:>5} |")
    print(border)
    print(f"Exact word matches: {total - changed}/{total} ({comparison['match_rate_percent']:.2f}%)")
    print(f"Differing words: {changed}")
    return {"rows": rows, "comparison": comparison}


if __name__ == "__main__":
    run()
