#!/usr/bin/env python3
"""
Import EdgeTPU dump-log words into the currently opened IDA database.

Expected log format:
    0x0ff00000:0xbf182800
    0x0ff00018:0x43db6a23:cache_unstable

Each value is treated as a 32-bit little-endian word and patched at the
corresponding IDA effective address.

Usage in IDA:
    File -> Script file... -> select this script
    Then select 0x0ff00000_0x0ff0E4FF_dump.log when prompted.
"""

import os
import re
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_segment
import ida_segregs
import ida_ua


DEFAULT_LOG_NAME = "0x0ff00000_0x0ff0E4FF_dump.log"

# If True, entries whose target addresses are not mapped in the IDB are skipped.
# Set to False only if you intentionally want IDA to try patching unmapped EAs.
SKIP_UNMAPPED_ADDRESSES = True

# If True, create one segment covering the dump range before patching when the
# first dump address is not mapped in the IDB.
AUTO_CREATE_SEGMENT = True
AUTO_SEGMENT_NAME = ".dump_0ff"
AUTO_SEGMENT_CLASS = "CODE"

# If True, create a repeatable comment on tagged entries such as cache_unstable.
ANNOTATE_TAGGED_ENTRIES = True

# If True, ask IDA to re-run analysis on the patched dump range after import.
REANALYZE_AFTER_IMPORT = True

# If True, undefine the patched range before requesting code analysis. This helps
# IDA rediscover instructions and functions when the database previously had
# stale or missing bytes in this range.
UNDEFINE_BEFORE_REANALYSIS = True

LINE_RE = re.compile(
    r"^\s*(0x[0-9a-fA-F]+|\d+)\s*:\s*(0x[0-9a-fA-F]+|\d+)"
    r"(?:\s*:\s*([A-Za-z0-9_.-]+))?\s*$"
)


def choose_log_file():
    """Ask the user for a dump log path, preferring the script directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_path = os.path.join(script_dir, DEFAULT_LOG_NAME)
    prompt = "Select EdgeTPU dump log"

    if os.path.exists(default_path):
        selected = ida_kernwin.ask_file(False, default_path, prompt)
    else:
        selected = ida_kernwin.ask_file(False, "*.log", prompt)

    return selected


def parse_log(path):
    """Yield (line_number, address, value, optional_tag) tuples."""
    with open(path, "r", encoding="utf-8", errors="replace") as fp:
        for line_no, line in enumerate(fp, 1):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                continue
            if stripped.startswith("time_start:") or stripped.startswith("time_end:"):
                continue
            if stripped.startswith("time_elapsed_s:"):
                continue

            match = LINE_RE.match(stripped)
            if not match:
                yield (line_no, None, None, None)
                continue

            addr_s, value_s, tag = match.groups()
            addr = int(addr_s, 0)
            value = int(value_s, 0)
            if value < 0 or value > 0xFFFFFFFF:
                yield (line_no, None, None, None)
                continue

            yield (line_no, addr, value, tag)


def load_entries(path):
    """Load valid entries and count malformed lines."""
    entries = []
    malformed = 0

    for line_no, addr, value, tag in parse_log(path):
        if addr is None:
            malformed += 1
            print("[import_dump] malformed line {} skipped".format(line_no))
            continue
        entries.append((line_no, addr, value, tag))

    return entries, malformed


def ensure_segment_for_entries(entries):
    """Create a segment covering all dump entries when none exists there."""
    if not entries:
        return False

    min_addr = min(addr for _line_no, addr, _value, _tag in entries)
    max_addr = max(addr for _line_no, addr, _value, _tag in entries) + 4

    if ida_segment.getseg(min_addr) is not None:
        return False

    if not AUTO_CREATE_SEGMENT:
        return False

    answer = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        "No IDA segment covers 0x{:08x}.\n\n"
        "Create segment {} for range 0x{:08x}..0x{:08x}?".format(
            min_addr, AUTO_SEGMENT_NAME, min_addr, max_addr
        ),
    )
    if answer != ida_kernwin.ASKBTN_YES:
        return False

    seg = ida_segment.segment_t()
    seg.start_ea = min_addr
    seg.end_ea = max_addr
    seg.sel = ida_segment.setup_selector(min_addr >> 4)
    seg.bitness = 1

    ok = ida_segment.add_segm_ex(
        seg,
        AUTO_SEGMENT_NAME,
        AUTO_SEGMENT_CLASS,
        ida_segment.ADDSEG_NOSREG | ida_segment.ADDSEG_OR_DIE,
    )
    if not ok:
        raise RuntimeError(
            "failed to create segment 0x{:08x}..0x{:08x}".format(min_addr, max_addr)
        )

    print(
        "[import_dump] created segment {}: 0x{:08x}..0x{:08x}".format(
            AUTO_SEGMENT_NAME, min_addr, max_addr
        )
    )
    return True


def patch_word(addr, value):
    """Patch one 32-bit little-endian word at addr."""
    data = value.to_bytes(4, byteorder="little", signed=False)
    ida_bytes.patch_bytes(addr, data)


def mark_thumb(ea):
    """Mark an address as Thumb code when the IDA API supports it."""
    try:
        ida_segregs.split_sreg_range(ea, "T", 1, ida_idaapi.SR_user)
        return True
    except Exception:
        return False


def request_reanalysis(start_ea, end_ea):
    """Ask IDA to rebuild code and function analysis over the patched range."""
    if start_ea is None or end_ea is None or start_ea >= end_ea:
        return

    print("[import_dump] reanalyzing 0x{:08x}..0x{:08x}".format(start_ea, end_ea))

    if UNDEFINE_BEFORE_REANALYSIS:
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_SIMPLE, end_ea - start_ea)

    # Queue standard auto-analysis over the patched range.
    ida_auto.plan_range(start_ea, end_ea)
    ida_auto.auto_mark_range(start_ea, end_ea, ida_auto.AU_CODE)

    # Seed instruction decoding at every patched word address. Firmware in this
    # range is Thumb code, so mark candidate addresses as Thumb before creating
    # instructions. Even addresses are used here because the database address is
    # the real memory address; the low Thumb bit is a branch-target convention.
    for ea in range(start_ea, end_ea, 2):
        if ida_segment.getseg(ea) is None:
            continue
        mark_thumb(ea)
        ida_ua.create_insn(ea)

    # Try to create functions at named or already-recognized code starts in the
    # range. IDA may reject non-entry addresses; that is fine.
    ea = start_ea
    while ea < end_ea:
        if ida_bytes.is_code(ida_bytes.get_flags(ea)):
            name = ida_name.get_name(ea)
            if name or ida_funcs.get_func(ea) is None:
                ida_funcs.add_func(ea, ida_idaapi.BADADDR)
        ea = ida_bytes.next_head(ea, end_ea)
        if ea == ida_idaapi.BADADDR:
            break

    ida_auto.auto_wait()


def import_dump(path):
    entries, malformed = load_entries(path)
    ensure_segment_for_entries(entries)

    patched = 0
    skipped_unmapped = 0
    tagged = 0
    first_addr = None
    last_addr = None

    for _line_no, addr, value, tag in entries:
        if SKIP_UNMAPPED_ADDRESSES and ida_segment.getseg(addr) is None:
            skipped_unmapped += 1
            continue

        patch_word(addr, value)
        patched += 1
        first_addr = addr if first_addr is None else min(first_addr, addr)
        last_addr = addr if last_addr is None else max(last_addr, addr)

        if tag:
            tagged += 1
            if ANNOTATE_TAGGED_ENTRIES:
                ida_bytes.set_cmt(addr, "dump tag: {}".format(tag), True)

    ida_auto.auto_wait()

    print("[import_dump] log: {}".format(path))
    print("[import_dump] patched words: {}".format(patched))
    print("[import_dump] malformed lines skipped: {}".format(malformed))
    print("[import_dump] unmapped addresses skipped: {}".format(skipped_unmapped))
    print("[import_dump] tagged entries: {}".format(tagged))
    if first_addr is not None:
        print("[import_dump] patched range: 0x{:08x}..0x{:08x}".format(first_addr, last_addr))

    if REANALYZE_AFTER_IMPORT and first_addr is not None:
        request_reanalysis(first_addr, last_addr + 4)

    ida_kernwin.info(
        "Dump import complete.\n\n"
        "Patched words: {}\n"
        "Malformed lines skipped: {}\n"
        "Unmapped addresses skipped: {}\n"
        "Tagged entries: {}\n"
        "Reanalysis: {}".format(
            patched,
            malformed,
            skipped_unmapped,
            tagged,
            "requested" if REANALYZE_AFTER_IMPORT and first_addr is not None else "not requested",
        )
    )


def main():
    path = choose_log_file()
    if not path:
        print("[import_dump] canceled")
        return

    try:
        import_dump(path)
    except Exception:
        print("[import_dump] failed:")
        traceback.print_exc()
        ida_kernwin.warning("Dump import failed. See IDA output window for details.")


if __name__ == "__main__":
    main()
