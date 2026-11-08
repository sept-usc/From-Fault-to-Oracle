"""
recover_tpu_funcs.py — IDAPython script to recover undiscovered functions
in EdgeTPU firmware (ARM Cortex-M, Thumb-2 only).

Run inside IDA: File > Script file..., or via the MCP py_eval bridge.

Strategy (multi-pass, idempotent):
  Pass A — Prologue scan: walk every gap between known funcs at 2-byte
           alignment, detect Thumb-1/Thumb-2 prologue byte patterns
           (PUSH {LR}, PUSH.W {..., LR}, VPUSH, ...) and force-create funcs.
  Pass B — Call-target sweep: scan known funcs for BL/BLX targets that
           land inside a gap; create_insn + add_func at each.
  Pass C — Orphan-code adoption: any address that already disassembled as
           code but isn't part of a function gets add_func.
  Repeat A/B/C until no new funcs are created.

The script is safe to run multiple times. It only writes to undefined
or orphan regions; existing funcs are never split or merged.
"""

import idaapi
import idc
import ida_funcs
import ida_bytes
import ida_segment
import ida_idp
import ida_segregs
import ida_auto
import ida_ua
import bisect


SEG_NAME = "ROM"


def set_thumb(ea):
    """Mark EA as running in Thumb mode (T register = 1)."""
    try:
        ida_segregs.split_sreg_range(
            ea, ida_idp.str2reg("T"), 1, ida_segregs.SR_user
        )
    except Exception:
        pass


def list_gaps(seg_name=SEG_NAME):
    """Return [(start, end), ...] of gap regions between known funcs."""
    seg = ida_segment.get_segm_by_name(seg_name)
    if not seg:
        return []
    funcs = []
    n = ida_funcs.get_func_qty()
    for i in range(n):
        f = ida_funcs.getn_func(i)
        if f and seg.start_ea <= f.start_ea < seg.end_ea:
            funcs.append((f.start_ea, f.end_ea))
    funcs.sort()
    gaps = []
    prev = seg.start_ea
    for s, e in funcs:
        if s > prev:
            gaps.append((prev, s))
        if e > prev:
            prev = e
    if prev < seg.end_ea:
        gaps.append((prev, seg.end_ea))
    return gaps


def gap_lookup(gaps):
    """Build a fast (sorted-keys, gaps) tuple for binary-search lookup."""
    keys = [g[0] for g in gaps]
    return keys, gaps


def in_gap(ea, keys, gaps):
    i = bisect.bisect_right(keys, ea) - 1
    return i >= 0 and gaps[i][0] <= ea < gaps[i][1]


def is_thumb_prologue(ea):
    """Heuristic: do bytes at EA look like a Thumb function prologue?

    Matches:
      *  ?? B5     — PUSH {Rn..., LR}              (Thumb-1, 2 bytes)
      *  2D E9 ?? RR  with bit 14 (LR) set in RR   — PUSH.W {..., LR}
      *  2D ED ?? ?? — VPUSH {Sx-Sy} or similar
    """
    if not ida_bytes.is_loaded(ea):
        return False
    b0 = ida_bytes.get_byte(ea)
    b1 = ida_bytes.get_byte(ea + 1)

    # Thumb-1 PUSH {…, LR}
    if b1 == 0xB5:
        return True

    # Thumb-2 PUSH.W (STMDB SP!,…) with LR pushed
    if b0 == 0x2D and b1 == 0xE9:
        b3 = ida_bytes.get_byte(ea + 3)
        if b3 & 0x40:  # bit 14 of reglist => LR
            return True

    # VPUSH (FP regs); often part of float-using prologue paired with PUSH
    if b0 == 0x2D and b1 == 0xED:
        return True

    return False


def try_make_func(ea):
    """Force EA into Thumb code and create a function at it."""
    f = ida_funcs.get_func(ea)
    if f and f.start_ea == ea:
        return False  # already a function start

    # If it's mid-function, leave alone
    if f and f.start_ea != ea:
        return False

    # Undefine 4 bytes so analyzer reconsiders this address
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
    set_thumb(ea)

    if not idc.create_insn(ea):
        return False
    if not ida_funcs.add_func(ea):
        return False
    return True


def collect_call_targets_in_gaps(gaps):
    """Scan all existing funcs' BL/BLX/B targets that fall inside a gap."""
    keys, _ = gap_lookup(gaps)
    cands = set()
    n = ida_funcs.get_func_qty()
    insn = ida_ua.insn_t()
    for i in range(n):
        f = ida_funcs.getn_func(i)
        if not f:
            continue
        ea = f.start_ea
        end = f.end_ea
        while ea < end and ea != idc.BADADDR:
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                ea = idc.next_head(ea, end)
                continue
            mnem = insn.get_canon_mnem().upper()
            if mnem in ("BL", "BLX", "B"):
                target = insn.Op1.addr if insn.Op1.addr else idc.get_operand_value(ea, 0)
                if target and target != idc.BADADDR:
                    t = target & ~1  # strip Thumb bit
                    if in_gap(t, keys, gaps):
                        cands.add(t)
            ea += length
    return sorted(cands)


def adopt_orphan_code():
    """For each gap, find addresses that are already code but not in any
    function, and try to add_func at the head of each contiguous block.
    """
    added = 0
    gaps = list_gaps()
    for gs, ge in gaps:
        ea = gs
        while ea < ge:
            f = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_code(f) and ida_bytes.is_head(f) and ida_funcs.get_func(ea) is None:
                if ida_funcs.add_func(ea):
                    added += 1
                ea = idc.next_head(ea, ge)
                if ea == idc.BADADDR:
                    break
            else:
                ea = idc.next_head(ea, ge) if ida_bytes.is_head(f) else ea + 1
                if ea == idc.BADADDR:
                    break
    return added


def pass_A_prologues():
    gaps = list_gaps()
    cands = []
    for gs, ge in gaps:
        ea = (gs + 1) & ~1  # 2-byte align (Thumb)
        while ea + 4 <= ge:
            if is_thumb_prologue(ea):
                cands.append(ea)
            ea += 2
    added = 0
    for ea in cands:
        if try_make_func(ea):
            added += 1
    ida_auto.auto_wait()
    return added, len(cands)


def pass_B_call_targets():
    gaps = list_gaps()
    cands = collect_call_targets_in_gaps(gaps)
    added = 0
    for ea in cands:
        if try_make_func(ea):
            added += 1
    ida_auto.auto_wait()
    return added, len(cands)


def pass_C_orphans():
    n = adopt_orphan_code()
    ida_auto.auto_wait()
    return n


def gap_stats():
    gaps = list_gaps()
    total = sum(e - s for s, e in gaps)
    return len(gaps), total


def run(max_iter=4):
    print("[recover_tpu_funcs] starting…")
    print(f"  initial funcs: {ida_funcs.get_func_qty()}")
    n_gaps, total = gap_stats()
    print(f"  initial gaps: {n_gaps}  bytes: 0x{total:x}")

    grand = 0
    for it in range(max_iter):
        a, ac = pass_A_prologues()
        b, bc = pass_B_call_targets()
        c = pass_C_orphans()
        added = a + b + c
        grand += added
        ng, tg = gap_stats()
        print(
            f"  iter {it}: prologue {a}/{ac}, call-tgt {b}/{bc}, "
            f"orphan {c}; gaps now {ng} ({hex(tg)}); +{added}"
        )
        if added == 0:
            break

    print(f"[recover_tpu_funcs] DONE — added {grand} funcs total")
    print(f"  final funcs: {ida_funcs.get_func_qty()}")


if __name__ == "__main__":
    run()
