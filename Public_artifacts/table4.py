#!/usr/bin/env python3
"""Compute Table 4 from the current EdgeTPU IDA database (IDA 9.2).

Run with File > Script file... > table4.py after preparing the dump analysis.
Print an aligned table in IDA's output window. No recovery or patching is done.
The current bytes, code items, xrefs, functions, and ISA metadata are measured;
pending auto-analysis finishes first and Hex-Rays may populate its caches.
See README.md for preparation, metric definitions, and the paper mapping.
"""

import re

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idp
import ida_kernwin
import ida_segment
import ida_segregs
import ida_ua
import ida_xref
import idautils


START = 0x0FF00000
END = 0x0FF0E4E0  # Exclusive; the logical 58,592-byte validation window.
CONDITIONS = "EQ|NE|CS|HS|CC|LO|MI|PL|VS|VC|HI|LS|GE|LT|GT|LE|AL"
CALL_RE = re.compile(r"^(?:BL|BLX)(?:" + CONDITIONS + r")?$")
BRANCH_RE = re.compile(r"^(?:B|BX)(?:" + CONDITIONS + r")?$|^CBN?Z$")


class Cancelled(RuntimeError):
    """Stop without publishing a partial table."""


def _check_cancel():
    if ida_kernwin.user_cancelled():
        raise Cancelled("Cancelled; no table was printed.")


def _decode(ea, end=None):
    """Decode an existing code head and check its IDA item boundary."""
    flags = ida_bytes.get_full_flags(ea)
    if not (ida_bytes.is_head(flags) and ida_bytes.is_code(flags)):
        return None, False
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, ea)
    if size <= 0:
        return None, False
    valid = (size == ida_bytes.get_item_size(ea)
             and (end is None or ea + size <= end)
             and all(ida_bytes.is_loaded(p) for p in range(ea, ea + size))
             and bool(insn.get_canon_mnem()))
    return insn, valid


def _mnemonic(insn):
    return insn.get_canon_mnem().upper().split(".", 1)[0] if insn else ""


def _source_decodable(ea, insn):
    """For calls, accept decoded bytes independently of stale item size."""
    return bool(insn and insn.size > 0 and insn.get_canon_mnem()
                and START <= ea < ea + insn.size <= END
                and all(ida_bytes.is_loaded(p) for p in range(ea, ea + insn.size)))


def _thumb_state(ea):
    value = ida_segregs.get_sreg(ea, ida_idp.str2reg("T"))
    return int(value) if value in (0, 1) else None


def _is_return(insn):
    if _mnemonic(insn).startswith("BX") and insn.Op1.type == ida_ua.o_reg:
        if insn.Op1.reg == ida_idp.str2reg("LR"):
            return True
    try:
        return bool(ida_idp.is_ret_insn(insn, ida_idp.IRI_RET_LITERALLY))
    except TypeError:
        return bool(ida_idp.is_ret_insn(insn))


def _operand_targets(insn):
    targets = set()
    for operand in insn.ops:
        if operand.type == ida_ua.o_void:
            break
        if operand.type in (ida_ua.o_near, ida_ua.o_far):
            targets.add(int(operand.addr) & ~1)
    return targets


def _expected_target_state(insn, source_t):
    mnemonic = _mnemonic(insn)
    if insn.Op1.type == ida_ua.o_reg and mnemonic.startswith(("BX", "BLX")):
        # BX PC veneers enter ARM: the architectural PC has low bit zero.
        if (mnemonic.startswith("BX") and insn.Op1.reg == ida_idp.str2reg("PC")
                and source_t in (0, 1)):
            return 0
        return None
    if mnemonic.startswith("BLX"):
        return 1 - source_t if source_t in (0, 1) else None
    return source_t


def _flow_resolved(ea, insn, source_valid, is_call, targets, target_cache):
    allowed = ((ida_xref.fl_CN, ida_xref.fl_CF) if is_call
               else (ida_xref.fl_JN, ida_xref.fl_JF))
    targets = targets | {int(xref.to) & ~1 for xref in idautils.XrefsFrom(ea, 0)
                         if xref.type in allowed}
    # Count sites, not edges. Fallthrough/data xrefs are not branch targets.
    # Every recovered target must pass; unknown targets stay unresolved.
    if not targets:
        return False
    if not (_source_decodable(ea, insn) if is_call else source_valid):
        return False
    expected_t = _expected_target_state(insn, _thumb_state(ea))
    for target in targets:
        if target not in target_cache:
            _, valid = _decode(target)
            target_cache[target] = (valid, _thumb_state(target))
        valid, target_t = target_cache[target]
        if not valid:
            return False
        if not is_call and (expected_t is None or target_t != expected_t):
            return False
    return True


def _classified_bytes():
    count = 0
    for ea in range(START, END):
        if (ea - START) % 4096 == 0:
            _check_cancel()
        if ida_bytes.is_loaded(ea):
            flags = ida_bytes.get_full_flags(ida_bytes.get_item_head(ea))
            count += bool(ida_bytes.is_code(flags) or ida_bytes.is_data(flags))
    return count


def _instructions_and_flow():
    counts = {key: [0, 0] for key in ("instructions", "calls", "branches")}
    target_cache = {}
    for index, ea in enumerate(idautils.Heads(START, END)):
        if index % 256 == 0:
            _check_cancel()
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        insn, valid = _decode(ea, END)
        counts["instructions"][0] += valid
        counts["instructions"][1] += 1
        mnemonic = _mnemonic(insn)
        if CALL_RE.fullmatch(mnemonic):
            targets = _operand_targets(insn)
            if not targets:  # The declared call population is DIRECT calls.
                continue
            key, is_call = "calls", True
        elif BRANCH_RE.fullmatch(mnemonic) and not _is_return(insn):
            targets = _operand_targets(insn)
            key, is_call = "branches", False
        else:
            continue
        counts[key][1] += 1
        counts[key][0] += _flow_resolved(ea, insn, valid, is_call, targets, target_cache)
    return counts


def _functions(minimum, decompile):
    # Snapshot the population before decompilation; count all function chunks.
    eligible = []
    for ea in sorted(set(idautils.Functions(START, END))):
        _check_cancel()
        function = ida_funcs.get_func(ea)
        if function.flags & ida_funcs.FUNC_THUNK:
            continue
        heads = sum(ida_bytes.is_code(ida_bytes.get_full_flags(p))
                    for p in set(idautils.FuncItems(ea)))
        if heads >= minimum:
            eligible.append(ea)
    if not decompile:
        return None, len(eligible)
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return None, len(eligible)
    except ImportError:
        return None, len(eligible)
    successes = 0
    for ea in eligible:
        _check_cancel()
        try:
            failure = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile(ea, failure, ida_hexrays.DECOMP_NO_CACHE)
            _check_cancel()
            successes += bool(cfunc)
        except Cancelled:
            raise
        except Exception:
            _check_cancel()
    return successes, len(eligible)


def _metric(label, numerator, denominator, unit):
    rate = 100.0 * numerator / denominator if numerator is not None and denominator else None
    return {"metric": label, "numerator": numerator, "denominator": denominator,
            "rate_percent": rate, "unit": unit}


def _print_table(metrics):
    headers = ("Metric", "Rate", "Successful / total")
    rows = []
    for row in metrics:
        rate = "N/A" if row["rate_percent"] is None else "{:.2f}%".format(row["rate_percent"])
        numerator = "N/A" if row["numerator"] is None else "{:,}".format(row["numerator"])
        total = "{} / {:,} {}".format(numerator, row["denominator"], row["unit"])
        rows.append((row["metric"], rate, total))
    widths = [max(len(row[i]) for row in [headers] + rows) for i in range(3)]
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    def line(row):
        return "| " + " | ".join(row[i].ljust(widths[i]) if i == 0
                                  else row[i].rjust(widths[i]) for i in range(3)) + " |"
    print("Table 4")
    print(border)
    print(line(headers))
    print(border)
    for row in rows:
        print(line(row))
    print(border)


def run(min_function_instructions=5, decompile=True):
    """Measure the open database; print the final table and return its rows.

    Non-trivial functions have at least min_function_instructions code heads
    across all chunks and are not IDA thunks. Hex-Rays unavailable/disabled is
    N/A, not a failed decompilation. Calls measure addresses; branches also
    require source/item consistency and known matching ARM/Thumb metadata.
    """
    if not isinstance(min_function_instructions, int) or min_function_instructions < 1:
        raise ValueError("min_function_instructions must be a positive integer")
    if ida_ida.inf_get_procname().lower() != "arm" or ida_ida.inf_is_be() or ida_ida.inf_is_64bit():
        raise RuntimeError("Expected a 32-bit little-endian ARM IDA database")
    if not (ida_segment.getseg(START) and ida_segment.getseg(END - 1)):
        raise RuntimeError("The on-chip validation window is not mapped")
    if not ida_auto.auto_wait():
        raise Cancelled("Auto-analysis cancelled; no table was printed.")
    classified = _classified_bytes()
    counts = _instructions_and_flow()
    functions = _functions(min_function_instructions, decompile)
    metrics = [
        _metric("Bytes classified as code or data", classified, END - START, "bytes"),
        _metric("Instructions fully decoded", *counts["instructions"], "insns"),
        _metric("Direct BL/BLX targets resolved", *counts["calls"], "calls"),
        _metric("B-family targets with consistent ISA metadata", *counts["branches"], "branches"),
        _metric("Non-trivial functions decompiled", *functions, "functions"),
    ]
    _check_cancel()
    _print_table(metrics)
    print("Scope: [0x{:08X}, 0x{:08X}); direct calls; ISA-consistent branches; "
          "non-thunk functions >= {} code heads.".format(
              START, END, min_function_instructions))
    return {"metrics": metrics, "start": START, "end_exclusive": END,
            "min_function_instructions": min_function_instructions}


if __name__ == "__main__":
    run()
