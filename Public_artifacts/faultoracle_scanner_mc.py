"""
Crash-Oracle Gadget Scanner — Microcode Edition
================================================

Runs on IDA Pro Hex-Rays microcode (MMAT_CALLS maturity).  Equivalent
scanning algorithm as the assembly-level variant, but operates on the
decompiler's normalized IR, which collapses Thumb-2 narrow/wide
encodings, expands pre/post-indexed addressing modes into explicit
m_add + m_ldx pairs, and surfaces IT-block conditional execution as
two-way CFG branches.

Abstract domain: reduced product of
  - two-level taint lattice  { clean, tainted, derived }
  - 32-bit unsigned interval domain
over the microblock CFG.

Sinks:
  m_ldx / m_stx whose address expression reads any `derived` mreg
  whose interval upper bound >= B_LO at the sink.

Source:
  The payload argument's mreg (determined per handler).

"""

import ida_hexrays as hr
import ida_funcs
import idc
from collections import deque, defaultdict


# ---- Configuration ----------------------------------------------------------
B_LO = 0x10000
U32  = 0xFFFFFFFF

# Microcode maturity used for the scan.
#
# MMAT_CALLS -- the level this scanner originally used -- runs *after*
# Hex-Rays' global dead-code elimination.  That pass deletes a load whose
# loaded *value* is never consumed.  For a crash/fault oracle that is exactly
# the wrong transformation: the dereference itself is the observable, so an
# access with a dead result is still a usable oracle site.
#
# On this firmware the DCE silently removed a complete vtable chain from the
# execution handler (sub_FF04A34):
#     0x0FF04AD8  SUBS R3, R6, R3   ; vtable = payload - soffset   (derivation)
#     0x0FF04ADA  LDRH R2, [R3]     ; sink   -- deleted at MMAT_CALLS
#     0x0FF04B94  LDRH R3, [R3,#8]  ; sink   -- deleted at MMAT_CALLS
# 31 of the function's 150 microblocks disappear between MMAT_LOCOPT and
# MMAT_CALLS, taking that site with them.
#
# MMAT_LOCOPT still provides everything the microcode IR is wanted for --
# Thumb-2 narrow/wide encodings collapsed, pre/post-indexed addressing modes
# expanded into explicit m_add + m_ldx pairs, IT-block predication turned into
# two-way CFG edges -- but runs before that DCE, so side-effecting accesses
# survive.  The nested-operand walkers below (mop_f / mop_a / mop_p) are kept:
# they are harmless at MMAT_LOCOPT and let the same code run at MMAT_CALLS.
MATURITY = hr.MMAT_LOCOPT

# Paper table row labels, keyed by handler name.
PAPER_ROW = {
    "B_setup":        "Setup",
    "C_datatransfer": "Data transfer",
    "D_teardown":     "Teardown",
    "E_registration": "Registration",
    "F_execution":    "Execution",
}

MR_FIRST = hr.mr_first       # usually 8 on ARM
def arm_r(n):
    """Map ARM register number (0=R0, 1=R1, ..., 15=PC) to its microreg id."""
    return MR_FIRST + n * 4


# Handler registry:  (name, entry_ea, payload_arm_reg_index)
HANDLERS = [
    ("A_dispatch",     0x0FF04FFC, 2),   # a3 (R2); payload actually enters via
                                         #   stack, so this handler's sites
                                         #   need inter-procedural support
    ("B_setup",        0x1002B3E9, 1),   # flatBuffer_payload (R1)
    ("C_datatransfer", 0x1002AD4D, 2),
    ("D_teardown",     0x1002A735, 2),
    ("E_registration", 0x1002AE9D, 2),
    ("F_execution",    0x0FF04A35, 2),   # payload_a3 (R2)
]


# ---- Interval domain --------------------------------------------------------
class I:
    __slots__ = ('lo', 'hi')
    def __init__(self, lo, hi):
        self.lo = lo & U32; self.hi = hi & U32
    @staticmethod
    def top(): return I(0, U32)
    @staticmethod
    def const(k): k &= U32; return I(k, k)
    def is_top(self): return self.lo == 0 and self.hi == U32
    def meet(self, o):
        if o is None: return I(self.lo, self.hi)
        lo = max(self.lo, o.lo); hi = min(self.hi, o.hi)
        if lo > hi: return I(lo, lo)
        return I(lo, hi)
    def join(self, o):
        if o is None: return I(self.lo, self.hi)
        return I(min(self.lo, o.lo), max(self.hi, o.hi))
    def __eq__(self, o):
        return o is not None and self.lo == o.lo and self.hi == o.hi
    def __repr__(self):
        if self.is_top(): return 'T'
        if self.lo == self.hi: return f'#{self.lo:#x}'
        return f'[{self.lo:#x},{self.hi:#x}]'


# ---- Abstract state ---------------------------------------------------------
class S:
    __slots__ = ('taint', 'derived', 'intv', 'src')
    def __init__(self):
        self.taint = set()
        self.derived = set()
        self.intv = {}
        self.src = {}    # derived reg -> def_site ea
    def copy(self):
        o = S()
        o.taint   = set(self.taint)
        o.derived = set(self.derived)
        o.intv    = dict(self.intv)
        o.src     = dict(self.src)
        return o
    def join(self, o):
        r = S()
        r.taint   = self.taint | o.taint
        r.derived = self.derived | o.derived
        for k in set(self.intv) | set(o.intv):
            a = self.intv.get(k); b = o.intv.get(k)
            if a is None:   r.intv[k] = b
            elif b is None: r.intv[k] = a
            else:           r.intv[k] = a.join(b)
        for k in set(self.src) | set(o.src):
            a = self.src.get(k); b = o.src.get(k)
            if a is None:   r.src[k] = b
            elif b is None: r.src[k] = a
            else:           r.src[k] = min(a, b)
        return r
    def eq(self, o):
        if self.taint   != o.taint:   return False
        if self.derived != o.derived: return False
        if set(self.intv) != set(o.intv): return False
        for k in self.intv:
            if not (self.intv[k] == o.intv[k]): return False
        if self.src != o.src: return False
        return True


# ---- Microcode operand introspection ---------------------------------------

def mop_reads(mop, out=None):
    """Recursively collect every microreg id (and stack-slot token) that
       reading `mop` would observe, descending into nested mop_d sub-
       expressions.  Segment selectors (mreg 72 'cs') are stripped: they
       are constant data-segment references, not arithmetic inputs."""
    if out is None: out = set()
    if mop is None: return out
    t = mop.t
    if t == hr.mop_r:
        if mop.r != 72:            # drop segment selector
            out.add(mop.r)
    elif t == hr.mop_d:
        # Nested instruction: recurse into its read operands.
        ins = mop.d
        if ins is not None:
            mop_reads(ins.l, out)
            mop_reads(ins.r, out)
            # ins.d for a nested expression is typically the result mop,
            # not a read, so we skip it.
    elif t == hr.mop_S:
        out.add(('S', mop.s.off))
    # Other mop types (mop_n, mop_v, mop_l, mop_b, mop_f, mop_h, ...)
    # do not read a live register.
    return out


def mop_dest(mop):
    """Return the destination microreg id (or stack slot token) for a
       writable mop, else None."""
    if mop is None: return None
    if mop.t == hr.mop_r:
        return mop.r
    if mop.t == hr.mop_S:
        return ('S', mop.s.off)
    return None


def mop_const(mop):
    """If mop is an immediate constant, return its value; else None."""
    if mop is None: return None
    if mop.t == hr.mop_n:
        return mop.nnn.value & U32
    return None


def mop_interval(mop, state):
    """Abstract interval for a mop in the current state."""
    if mop is None: return I.top()
    t = mop.t
    if t == hr.mop_n:
        return I.const(mop.nnn.value)
    if t == hr.mop_r:
        return state.intv.get(mop.r, I.top())
    if t == hr.mop_S:
        return state.intv.get(('S', mop.s.off), I.top())
    return I.top()


def mop_is_reg_or_slot_read(mop, state_set):
    """Does reading `mop` observe any member of `state_set`?"""
    for r in mop_reads(mop):
        if r in state_set:
            return True
    return False


def is_tainted_value(mop, state):
    """True if evaluating this mop produces an attacker-reachable value.

    At MMAT_CALLS maturity the decompiler folds many load / arithmetic
    sequences into nested mop_d expression trees (e.g. an m_sub whose R
    operand is a nested m_ldx).  We recurse through these so that taint
    semantics are not missed just because the instruction happens to be
    a sub-expression."""
    if mop is None: return False
    if mop.t == hr.mop_r:
        return mop.r in state.taint
    if mop.t == hr.mop_S:
        return ('S', mop.s.off) in state.taint
    if mop.t == hr.mop_n:
        return False
    if mop.t == hr.mop_d:
        sub = mop.d
        if sub is None: return False
        return is_tainted_value(sub.l, state) or is_tainted_value(sub.r, state)
    return False


def is_derived_value(mop, state):
    """True if evaluating this mop produces a 32-bit wrap-capable
    attacker-controlled value — the gate for crash-oracle exploitability.

    Rules (recursive over nested mop_d):
      - Register / stack slot: membership in state.derived.
      - Constant: never derived.
      - Nested m_ldx of size 4 whose address reads tainted memory: derived.
      - Nested m_ldx of size < 4 (narrow load): NOT derived (zero-extended
        value cannot span the 4 GiB address space).
      - Nested arithmetic (m_sub / m_add / m_neg): derived iff any sub-
        operand is derived.
      - Sign/zero extension (m_xds / m_xdu): preserves derived iff source
        was already derived.
      - Truncation (m_low / m_high): always clears derived.
      - m_and with constant < B_LO: always clears derived (truncation).
      - m_mov / m_ldc: propagates from source operand.
      - Conservative fallback: not derived."""
    if mop is None: return False
    if mop.t == hr.mop_r:
        return mop.r in state.derived
    if mop.t == hr.mop_S:
        return ('S', mop.s.off) in state.derived
    if mop.t == hr.mop_n:
        return False
    if mop.t != hr.mop_d:
        return False
    sub = mop.d
    if sub is None: return False
    op = sub.opcode
    if op == hr.m_ldx:
        if mop.size != 4:
            return False
        return is_tainted_value(sub.r, state)
    if op in (hr.m_add, hr.m_sub):
        return is_derived_value(sub.l, state) or is_derived_value(sub.r, state)
    if op == hr.m_neg:
        return is_derived_value(sub.l, state)
    if op in (hr.m_xds, hr.m_xdu):
        return is_derived_value(sub.l, state)
    if op in (hr.m_low, hr.m_high):
        return False
    if op == hr.m_and:
        c = mop_const(sub.r) or mop_const(sub.l)
        if c is not None and c < B_LO:
            return False
        return is_derived_value(sub.l, state) or is_derived_value(sub.r, state)
    if op in (hr.m_mov, hr.m_ldc):
        return is_derived_value(sub.l, state)
    return False


def _descend_mop(mop, cb):
    """Recurse into every minsn embedded in `mop` and its sub-mops.

    At MMAT_CALLS, dangerous loads frequently end up folded as:
      - mop_d  (nested instruction, walked via L/R/D)
      - mop_f  (call-info: arguments live in mcallinfo_t.args)
      - mop_a  (address-of: wraps a sub-mop)
      - mop_p  (pair: lop / hop)
    Skipping any of these blinds the scanner to the actual sink — for
    example, when sub_1002AB8C(..., *(R2 + *(R5+R3)), ...) gets compiled,
    the `LDR R1, [R2, R4]` becomes a nested mop_d inside `mcallinfo.args[1]`,
    which a plain L/R/D walk would never visit.
    """
    if mop is None:
        return
    t = mop.t
    if t == hr.mop_d and mop.d is not None:
        walk_subinsns(mop.d, cb)
    elif t == hr.mop_f and mop.f is not None:
        ci = mop.f
        for i in range(ci.args.size()):
            _descend_mop(ci.args[i], cb)
    elif t == hr.mop_a and mop.a is not None:
        _descend_mop(mop.a, cb)
    elif t == hr.mop_p and mop.pair is not None:
        _descend_mop(mop.pair.lop, cb)
        _descend_mop(mop.pair.hop, cb)


def walk_subinsns(ins, cb):
    """Invoke cb(sub_ins) for `ins` and for every nested instruction
    appearing in its operands (recursively).  Descends into nested mop_d,
    mcallinfo.args (mop_f), mop_a and mop_p — necessary at MMAT_CALLS
    where ldx/stx are routinely folded into call-argument expressions."""
    cb(ins)
    for m in (ins.l, ins.r, ins.d):
        _descend_mop(m, cb)


# ---- Transfer function ------------------------------------------------------

def set_derived(state, dst, def_site, inherit=None):
    state.derived.add(dst)
    if inherit is not None and inherit in state.src:
        state.src[dst] = state.src[inherit]
    else:
        state.src[dst] = def_site


def clear_derived(state, dst):
    state.derived.discard(dst)
    state.src.pop(dst, None)


def _addr_derivation_source(addr_mop, state):
    """Find a def_site for the derivation driving this address expression.
    Recurses through nested mop_d.  Returns (def_site_ea, source_mreg_list)
    or (None, []).

    `source_mreg_list` is the list of registers (or stack-slot tokens) read
    by the innermost derived load's address expression — these are the
    "derivation source" pointers (e.g. the payload register that a folded
    `LDR Rd, [Rb, Ri]` indexes through).  Non-empty even when the derived
    value itself was folded into a nested mop_d and never lived in a named
    mreg, which is exactly the case where the top-level `derived_mregs`
    list reported by the sink callback would be empty."""
    if addr_mop is None:
        return None, []
    # Direct register read
    if addr_mop.t == hr.mop_r and addr_mop.r in state.derived:
        return state.src.get(addr_mop.r), [addr_mop.r]
    if addr_mop.t == hr.mop_S:
        k = ('S', addr_mop.s.off)
        if k in state.derived:
            return state.src.get(k), [k]
    # Nested expression: check the whole expression and walk sub-mops
    if addr_mop.t == hr.mop_d:
        sub = addr_mop.d
        if sub is None:
            return None, []
        # A nested m_ldx sz=4 reading tainted memory itself produces
        # a derived value — the "source" is that nested load's ea.
        if sub.opcode == hr.m_ldx and addr_mop.size == 4 and \
           is_tainted_value(sub.r, state):
            # The mregs that index into the tainted region.
            source_regs = sorted(mop_reads(sub.r))
            return sub.ea, source_regs
        for m in (sub.l, sub.r):
            ds, regs = _addr_derivation_source(m, state)
            if ds is not None:
                return ds, regs
    return None, []


def _check_sinks_in(ins, state, sites, collected_pcs):
    """Walk `ins` and all nested sub-instructions; report m_ldx / m_stx
    sinks whose address expression either (a) reads a register in
    `state.derived`, or (b) evaluates to a derived value through a nested
    mop_d sub-expression (e.g. a folded phrase-mode load).  In either
    case we require the derived value's interval upper bound to remain
    >= B_LO."""
    def cb(sub):
        if sub.opcode not in (hr.m_ldx, hr.m_stx):
            return
        addr_mop = sub.r if sub.opcode == hr.m_ldx else sub.d
        size_mop = sub.d if sub.opcode == hr.m_ldx else sub.l
        addr_reads = mop_reads(addr_mop)
        derived_in_addr = [r for r in addr_reads if r in state.derived]

        # Either a direct derived-register read, or a nested-expression
        # derivation that did not leave its value in a named mreg.
        has_nested_deriv = is_derived_value(addr_mop, state)
        if not derived_in_addr and not has_nested_deriv:
            return

        dangerous = False; def_site = None
        # Prefer interval-checked direct-register derivations.
        for r in derived_in_addr:
            iv = state.intv.get(r, I.top())
            if iv.hi >= B_LO:
                dangerous = True
                def_site = state.src.get(r, sub.ea)
                break
        nested_src_regs = []
        if not dangerous and has_nested_deriv:
            # Nested derivation has no single mreg to check interval on;
            # its interval is T by construction (a 32-bit attacker load),
            # so treat as dangerous.  Derivation source is the innermost
            # nested m_ldx's ea.
            ds, src_regs = _addr_derivation_source(addr_mop, state)
            dangerous = True
            def_site = ds if ds is not None else sub.ea
            nested_src_regs = src_regs

        if dangerous and sub.ea not in collected_pcs:
            collected_pcs.add(sub.ea)
            sites.append({
                'pc': sub.ea,
                'def_site': def_site,
                'op': 'ldx' if sub.opcode == hr.m_ldx else 'stx',
                'size': size_mop.size if size_mop is not None else 0,
                'derived_mregs': derived_in_addr,
                # Registers read by the innermost folded ldx address.
                # Populated when derived_mregs is empty (nested derivation),
                # so the report still names a controllable input.
                'nested_src_mregs': nested_src_regs,
            })
    walk_subinsns(ins, cb)


def transfer(ins, state, sites):
    """Apply one microcode instruction to `state`; append a site record
       if the instruction (or any nested sub-instruction) is a crash-
       oracle sink."""
    # Sink detection walks nested sub-instructions so we catch m_ldx /
    # m_stx that are folded as mop_d sub-expressions of arithmetic ops
    # (common at MMAT_CALLS maturity).
    local_pcs = set()
    _check_sinks_in(ins, state, sites, local_pcs)

    op = ins.opcode

    # --- Top-level m_ldx: also propagate taint/derived onto the destination
    if op == hr.m_ldx:
        d = mop_dest(ins.d)
        if d is not None:
            addr_reads = mop_reads(ins.r)
            addr_tainted = any(r in state.taint for r in addr_reads)
            if addr_tainted:
                state.taint.add(d)
                # Width gate: only 32-bit loads yield a wrap-capable value.
                if ins.d.size == 4:
                    set_derived(state, d, ins.ea)
                else:
                    clear_derived(state, d)
                state.intv[d] = I.top()
            else:
                state.taint.discard(d)
                clear_derived(state, d)
                state.intv[d] = I.top()
        return

    # --- m_stx has no destination register to update (it writes memory) ---
    if op == hr.m_stx:
        return

    # --- Non-sink ops: compute destination's taint/derived/interval --------
    d = mop_dest(ins.d)
    if d is None:
        return

    # Use recursive is_tainted_value / is_derived_value so that nested
    # sub-expressions (folded loads and arithmetic) contribute correctly.
    src_tainted = is_tainted_value(ins.l, state) or is_tainted_value(ins.r, state)
    src_derived = is_derived_value(ins.l, state) or is_derived_value(ins.r, state)
    # inherit from whichever operand first carries a derivation source
    inherit_reg = None
    for m in (ins.l, ins.r):
        if is_derived_value(m, state):
            # Find a representative mreg to inherit src from
            for r in mop_reads(m):
                if r in state.src:
                    inherit_reg = r
                    break
            if inherit_reg is not None:
                break

    # --- Copy / constant load ---
    if op == hr.m_mov:
        if ins.l is not None and ins.l.t == hr.mop_n:
            state.taint.discard(d); clear_derived(state, d)
            state.intv[d] = I.const(ins.l.nnn.value)
        else:
            if src_tainted: state.taint.add(d)
            else:           state.taint.discard(d)
            if src_derived:
                set_derived(state, d, ins.ea, inherit_reg)
            else:
                clear_derived(state, d)
            state.intv[d] = mop_interval(ins.l, state)
        return

    if op == hr.m_ldc:
        state.taint.discard(d); clear_derived(state, d)
        c = mop_const(ins.l)
        state.intv[d] = I.const(c) if c is not None else I.top()
        return

    # --- Arithmetic: m_add / m_sub / m_neg ---
    if op == hr.m_add:
        if src_tainted: state.taint.add(d)
        else:           state.taint.discard(d)
        if src_derived: set_derived(state, d, ins.ea, inherit_reg)
        else:           clear_derived(state, d)
        a = mop_interval(ins.l, state); b = mop_interval(ins.r, state)
        state.intv[d] = I((a.lo + b.lo) & U32, (a.hi + b.hi) & U32)
        return

    if op == hr.m_sub:
        if src_tainted: state.taint.add(d)
        else:           state.taint.discard(d)
        if src_derived: set_derived(state, d, ins.ea, inherit_reg)
        else:           clear_derived(state, d)
        a = mop_interval(ins.l, state); b = mop_interval(ins.r, state)
        state.intv[d] = I((a.lo - b.hi) & U32, (a.hi - b.lo) & U32)
        return

    if op == hr.m_neg:
        if src_tainted: state.taint.add(d)
        else:           state.taint.discard(d)
        if src_derived: set_derived(state, d, ins.ea, inherit_reg)
        else:           clear_derived(state, d)
        state.intv[d] = I.top()
        return

    # --- Sign/zero extension: preserve width-capable derived status ---
    if op in (hr.m_xds, hr.m_xdu):
        if src_tainted: state.taint.add(d)
        else:           state.taint.discard(d)
        # Extension FROM a smaller value: the result register holds the
        # same semantic value, widened.  If the source was derived (i.e.
        # already 32-bit wrap-capable), the extended value remains so.
        # If the source was narrow (e.g. 16-bit ldrh result, not derived),
        # zero-extending it cannot magically produce a 32-bit controllable
        # value, so we keep derived = false.
        if src_derived:
            set_derived(state, d, ins.ea, inherit_reg)
        else:
            clear_derived(state, d)
        state.intv[d] = mop_interval(ins.l, state)
        return

    # --- Truncation: m_low / m_high ---
    if op in (hr.m_low, hr.m_high):
        if src_tainted: state.taint.add(d)
        else:           state.taint.discard(d)
        # Truncating a derived 32-bit value to 16 or 8 bits loses the
        # ability to span the address space → no longer derived.
        clear_derived(state, d)
        state.intv[d] = I.top()
        return

    # --- Bitwise: AND-with-small-constant is a truncation sanitizer ---
    if op == hr.m_and:
        if src_tainted: state.taint.add(d)
        else:           state.taint.discard(d)
        c = mop_const(ins.r) or mop_const(ins.l)
        if c is not None and c < B_LO:
            # AND with constant < B_LO: result bounded → cannot wrap
            clear_derived(state, d)
        else:
            if src_derived: set_derived(state, d, ins.ea, inherit_reg)
            else:           clear_derived(state, d)
        state.intv[d] = I.top()
        return

    # --- Bitwise OR / XOR / shifts: conservative ---
    if op in (hr.m_or, hr.m_xor, hr.m_shl, hr.m_shr, hr.m_sar,
              hr.m_mul, hr.m_udiv, hr.m_sdiv, hr.m_umod, hr.m_smod):
        if src_tainted: state.taint.add(d)
        else:           state.taint.discard(d)
        if src_derived: set_derived(state, d, ins.ea, inherit_reg)
        else:           clear_derived(state, d)
        state.intv[d] = I.top()
        return

    # --- Calls: clobber the destination conservatively ---
    if op in (hr.m_call, hr.m_icall):
        state.taint.discard(d); clear_derived(state, d)
        state.intv[d] = I.top()
        return

    # --- Conservative fallback for any opcode we don't model explicitly ---
    state.taint.discard(d); clear_derived(state, d)
    state.intv[d] = I.top()


# ---- Edge refinement for sanitizer intervals --------------------------------
#
# At MMAT_CALLS, conditional branches appear as m_jnz / m_jz / m_jb / m_jae /
# m_ja / m_jbe / m_jg / m_jge / m_jl / m_jle.  They encode both the comparison
# and the branch target in a single instruction.  On the taken edge we can
# tighten the corresponding register's interval.

def refine_on_edge(state, block_tail_ins, target_ea_taken, edge_is_taken):
    """Return a refined copy of `state` given the branch edge outcome."""
    if block_tail_ins is None:
        return state
    op = block_tail_ins.opcode
    # Only handle the common jump-with-comparison forms
    if op not in (hr.m_jnz, hr.m_jz, hr.m_jb, hr.m_jae,
                  hr.m_ja, hr.m_jbe, hr.m_jg, hr.m_jge,
                  hr.m_jl, hr.m_jle):
        return state
    # The two compared operands are L (register-valued) and R (typically a
    # constant).  Only narrow the interval of a register operand.
    reg_mop, imm_mop = None, None
    if block_tail_ins.l is not None and block_tail_ins.l.t == hr.mop_r:
        reg_mop = block_tail_ins.l
        if block_tail_ins.r is not None and block_tail_ins.r.t == hr.mop_n:
            imm_mop = block_tail_ins.r
    if reg_mop is None or imm_mop is None:
        return state
    reg = reg_mop.r
    k   = imm_mop.nnn.value & U32

    # Derive the tightening interval per opcode.
    # On the taken edge, the condition holds; on the fall-through it fails.
    tight = None
    if op == hr.m_jb:   tight = I(0, k - 1) if edge_is_taken and k > 0 else I(k, U32)
    elif op == hr.m_jae: tight = I(k, U32) if edge_is_taken else I(0, k - 1) if k > 0 else I(0, 0)
    elif op == hr.m_jbe: tight = I(0, k) if edge_is_taken else I(k + 1 if k < U32 else U32, U32)
    elif op == hr.m_ja:  tight = I(k + 1 if k < U32 else U32, U32) if edge_is_taken else I(0, k)
    elif op == hr.m_jz:  tight = I(k, k) if edge_is_taken else None
    elif op == hr.m_jnz: tight = None if edge_is_taken else I(k, k)
    else:
        return state   # signed comparisons: not relevant for pointer bounds

    if tight is None:
        return state

    out = state.copy()
    cur = out.intv.get(reg, I.top())
    out.intv[reg] = cur.meet(tight)
    return out


# ---- Fixpoint over microblock CFG ------------------------------------------

def scan_handler(name, ea, payload_arm_reg):
    ea = ea & ~1
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"[!] {name}: no function at {ea:#x}")
        return []

    hf  = hr.hexrays_failure_t()
    mba = hr.gen_microcode(hr.mba_ranges_t(func), hf, None, 0, MATURITY)
    if mba is None:
        print(f"[!] {name}: gen_microcode failed: {hf.desc()}")
        return []

    payload_mreg = arm_r(payload_arm_reg)
    n_blocks = mba.qty
    in_state = [S() for _ in range(n_blocks)]
    # Seed entry-block taint: the payload register is tainted but not yet
    # derived (it is a pointer TO attacker memory; reading through it
    # produces derived values, but the pointer itself is not a wrap-capable
    # attacker-chosen integer).
    in_state[0].taint.add(payload_mreg)
    in_state[0].intv[payload_mreg] = I.top()

    worklist   = deque(range(n_blocks))
    seen_iter  = defaultdict(int)
    sites_per_blk = defaultdict(list)

    MAX_REVISITS = 6
    HARD_CAP     = 4000
    total_visits = 0

    while worklist:
        total_visits += 1
        if total_visits > HARD_CAP:
            break
        b = worklist.popleft()
        seen_iter[b] += 1
        blk = mba.get_mblock(b)

        state = in_state[b].copy()
        local = []
        ins = blk.head
        tail = None
        while ins:
            transfer(ins, state, local)
            tail = ins
            ins = ins.next
        sites_per_blk[b] = local

        # Widen on revisit: collapse all intervals to ⊤ after MAX_REVISITS
        # iterations on this block.  Keeps fixpoint bounded; biases interval
        # domain toward overapproximation (more sinks reported), taint
        # remains monotone (growing only).
        if seen_iter[b] > MAX_REVISITS:
            for k in list(state.intv.keys()):
                state.intv[k] = I.top()

        # Propagate to successors with edge refinement.
        nsucc = blk.nsucc()
        for si in range(nsucc):
            succ_n = blk.succ(si)
            # For 2-way branches, succ index 0 is typically taken-edge;
            # but microcode convention: succset[0] = fall-through,
            #                         succset[1] = taken.
            # We try both interpretations conservatively.
            is_taken = (nsucc == 2 and si == 1)
            refined  = refine_on_edge(state, tail, succ_n, is_taken)
            new = in_state[succ_n].join(refined)
            if not new.eq(in_state[succ_n]):
                in_state[succ_n] = new
                if succ_n not in worklist:
                    worklist.append(succ_n)

    # Flatten + dedup by def_site
    raw = []
    seen_pc = set()
    for lst in sites_per_blk.values():
        for s in lst:
            if s['pc'] in seen_pc: continue
            seen_pc.add(s['pc'])
            raw.append(s)

    by_def = {}
    for s in raw:
        key = s.get('def_site', s['pc'])
        cur = by_def.get(key)
        if cur is None or s['pc'] < cur['pc']:
            if cur is not None:
                s['dedup_count'] = cur.get('dedup_count', 1) + 1
            else:
                s['dedup_count'] = 1
            by_def[key] = s
        else:
            cur['dedup_count'] = cur.get('dedup_count', 1) + 1
    return sorted(by_def.values(), key=lambda s: s['pc'])


# ---- Main -------------------------------------------------------------------

def main():
    print("=" * 78)
    mat_name = {getattr(hr, n): n for n in dir(hr) if n.startswith("MMAT_")}
    print("Crash-Oracle Scanner (Microcode Edition) — {}, B_LO = {:#x}"
          .format(mat_name.get(MATURITY, MATURITY), B_LO))
    print("=" * 78)
    all_sites = {}
    total = 0
    for name, ea, pr in HANDLERS:
        sites = scan_handler(name, ea, pr)
        all_sites[name] = sites
        total += len(sites)
        print(f"\n[{name}] entry={ea:#x} payload=R{pr}  sites={len(sites)}")
        for s in sites:
            extra = ""
            if not s['derived_mregs'] and s.get('nested_src_mregs'):
                extra = f"  nested_src_mregs={s['nested_src_mregs']}"
            print(f"  {s['pc']:#010x}  def_site={s['def_site']:#x}  "
                  f"{s['op']} sz={s['size']}  "
                  f"derived_mregs={s['derived_mregs']}{extra}  "
                  f"dedup={s.get('dedup_count',1)}")
    # ---- Per-handler summary, in the paper table's row order ------------
    print("\n" + "=" * 78)
    print(f"{'Handler':<22}{'Reported':>10}")
    print("-" * 78)
    paper_total = 0
    for name, _, _ in HANDLERS:
        row = PAPER_ROW.get(name)
        if row is None:          # handler not shown in the paper table
            continue
        n = len(all_sites.get(name, []))
        paper_total += n
        print(f"{row:<22}{n:>10}")
    print("-" * 78)
    print(f"{'Total':<22}{paper_total:>10}")
    for name, _, _ in HANDLERS:
        if name not in PAPER_ROW:
            print(f"  ({name}: {len(all_sites.get(name, []))} site(s), "
                  f"not a paper table row)")
    print(f"\n{'='*78}\nTOTAL sites (after per-def-site dedup): {total}")
    return all_sites


if __name__ == "__main__":
    main()
