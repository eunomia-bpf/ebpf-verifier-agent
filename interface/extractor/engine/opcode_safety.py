"""Opcode-driven safety condition inference from BPF ISA semantics.

No keyword matching. No regex on error messages.
Safety conditions derived entirely from the BPF instruction opcode byte.

The BPF opcode byte has the following structure:
  7  6  5  4  3  2  1  0
 [    op    ][ src][class]

The class (bits 2:0) determines the instruction type and its safety domain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..shared_utils import is_pointer_type_name, is_nullable_pointer_type
from .helper_signatures import (
    get_helper_id_by_name,
    get_helper_signature,
    get_helper_safety_condition,
    get_helper_safety_conditions,
)


# ---------------------------------------------------------------------------
# BPF opcode class constants (bits 2:0 of opcode byte)
# ---------------------------------------------------------------------------

BPF_LD    = 0x00  # Special loads (LD_IMM64, LD_ABS/IND)
BPF_LDX   = 0x01  # Memory load from [src_reg + off]
BPF_ST    = 0x02  # Memory store immediate to [dst_reg + off]
BPF_STX   = 0x03  # Memory store register to [dst_reg + off]
BPF_ALU   = 0x04  # 32-bit arithmetic/logic
BPF_JMP   = 0x05  # 64-bit jumps, calls, and exits
BPF_JMP32 = 0x06  # 32-bit jumps
BPF_ALU64 = 0x07  # 64-bit arithmetic/logic

# Special opcode bytes
BPF_CALL = 0x85   # JMP | CALL
BPF_EXIT = 0x95   # JMP | EXIT

# Memory access size encoding (bits 4:3)
_SIZE_MAP = {0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}
_UNKNOWN_NUMERIC_GAP = 1 << 62


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class OpcodeClass(Enum):
    LD     = 0
    LDX    = 1
    ST     = 2
    STX    = 3
    ALU    = 4
    JMP    = 5
    JMP32  = 6
    ALU64  = 7


class SafetyDomain(Enum):
    """The abstract domain in which the safety condition lives."""
    MEMORY_BOUNDS      = "memory_bounds"      # off + size <= range
    POINTER_TYPE       = "pointer_type"       # register must be a valid pointer
    SCALAR_BOUND       = "scalar_bound"       # scalar must have bounded umax
    NULL_SAFETY        = "null_safety"        # pointer must not be ptr_or_null
    REFERENCE_BALANCE  = "ref_balance"        # all refs released at exit
    ARG_CONTRACT       = "arg_contract"       # helper/kfunc argument types
    WRITE_PERMISSION   = "write_permission"   # target must be writable
    ARITHMETIC_LEGALITY = "arith_legality"   # pointer arithmetic allowed?


@dataclass(frozen=True)
class SafetyCondition:
    """A single safety condition derived from an opcode."""
    domain: SafetyDomain
    critical_register: str       # Which register must satisfy this condition
    required_property: str       # Human-readable description of what's required
    access_size: int | None = None   # For memory access conditions
    expected_types: tuple[str, ...] = ()
    allow_null: bool = False
    requires_range: bool = False
    requires_writable: bool = False
    helper_id: int | None = None
    helper_name: str | None = None
    constraint: str | None = None


@dataclass(frozen=True)
class OpcodeInfo:
    """Decoded opcode information."""
    raw: int                      # The raw opcode byte as an integer
    opclass: OpcodeClass          # Instruction class
    is_memory_access: bool        # True for LDX/ST/STX
    is_call: bool                 # True for CALL (0x85)
    is_exit: bool                 # True for EXIT (0x95)
    is_alu: bool                  # True for ALU/ALU64
    is_branch: bool               # True for conditional branches
    access_size: int | None       # For memory ops: 1/2/4/8 bytes
    src_reg: str | None           # Decoded from bytecode text (e.g. "R1")
    dst_reg: str | None           # Decoded from bytecode text (e.g. "R3")
    call_target: str | None = None
    helper_id: int | None = None


# ---------------------------------------------------------------------------
# Register extraction from bytecode text
# ---------------------------------------------------------------------------

# Patterns to extract src/dst registers from verifier bytecode text.
# Examples:
#   "r6 = *(u8 *)(r0 +2)"   -> dst=R6, src=R0
#   "*(u64 *)(r10 -8) = r1" -> dst=R10, src=R1
#   "r0 |= r6"              -> dst=R0, src=R6
#   "r5 += r0"              -> dst=R5, src=R0
#   "call bpf_map_lookup_elem" -> no regs
_LOAD_RE = re.compile(
    r"^\s*(?P<dst>[rw]\d+)\s*=\s*\*\([^\)]+\)\s*\(\s*(?P<src>[rw]\d+)",
    re.IGNORECASE,
)
_STORE_REG_RE = re.compile(
    r"^\s*\*\([^\)]+\)\s*\(\s*(?P<dst>[rw]\d+)[^)]*\)\s*=\s*(?P<src>[rw]\d+)",
    re.IGNORECASE,
)
_STORE_IMM_RE = re.compile(
    r"^\s*\*\([^\)]+\)\s*\(\s*(?P<dst>[rw]\d+)",
    re.IGNORECASE,
)
_ALU_RE = re.compile(
    r"^\s*(?P<dst>[rw]\d+)\s*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|>>>=|=)\s*(?P<src>[rw]\d+)?",
    re.IGNORECASE,
)
_CALL_TARGET_RE = re.compile(
    r"^\s*call\s+(?:(?P<pc>pc[+-]\d+)|(?P<name>[a-zA-Z0-9_]+)(?:#(?P<helper_id>\d+))?|#(?P<imm>\d+))",
    re.IGNORECASE,
)


def _normalize_reg(r: str | None) -> str | None:
    """Normalize a register token like 'r3' or 'w3' to 'R3'."""
    if r is None:
        return None
    m = re.match(r"^[rwRW](\d+)$", r.strip())
    if m:
        return f"R{m.group(1)}"
    return None


def _extract_regs_from_bytecode(bytecode: str) -> tuple[str | None, str | None]:
    """Extract (src_reg, dst_reg) from a verifier bytecode text line.

    Returns (src, dst) as normalized register names (e.g. 'R0', 'R3').
    Either may be None if not extractable.
    """
    if not bytecode:
        return None, None

    text = bytecode.strip()

    # Memory load: dst = *(uN *)(src + off)
    m = _LOAD_RE.match(text)
    if m:
        return _normalize_reg(m.group("src")), _normalize_reg(m.group("dst"))

    # Memory store register: *(uN *)(dst + off) = src
    m = _STORE_REG_RE.match(text)
    if m:
        return _normalize_reg(m.group("src")), _normalize_reg(m.group("dst"))

    # Memory store immediate: *(uN *)(dst + off) = imm
    m = _STORE_IMM_RE.match(text)
    if m:
        return None, _normalize_reg(m.group("dst"))

    # ALU / assignment: dst op= src  or  dst = src
    m = _ALU_RE.match(text)
    if m:
        dst = _normalize_reg(m.group("dst"))
        src = _normalize_reg(m.group("src")) if m.group("src") else None
        return src, dst

    return None, None

# ---------------------------------------------------------------------------
# Opcode decoder
# ---------------------------------------------------------------------------

def decode_opcode(hex_str: str, bytecode_text: str) -> OpcodeInfo:
    """Decode a 2-hex-digit opcode byte plus bytecode text into OpcodeInfo.

    Args:
        hex_str: The 2-character hex opcode string parsed from the verifier log
                 (e.g., "71" for LDX byte, "4f" for ALU64 OR).
        bytecode_text: The human-readable bytecode text (e.g., "r6 = *(u8 *)(r0 +2)").

    Returns:
        OpcodeInfo with all decoded fields.
    """
    raw = int(hex_str, 16)
    opclass = OpcodeClass(raw & 0x07)

    is_memory = opclass in (OpcodeClass.LDX, OpcodeClass.ST, OpcodeClass.STX)
    is_call = (raw == BPF_CALL)
    is_exit = (raw == BPF_EXIT)
    is_alu = opclass in (OpcodeClass.ALU, OpcodeClass.ALU64)
    is_branch = (
        opclass in (OpcodeClass.JMP, OpcodeClass.JMP32)
        and not is_call
        and not is_exit
    )

    access_size: int | None = None
    if is_memory:
        size_bits = (raw >> 3) & 0x03
        access_size = _SIZE_MAP.get(size_bits << 3)

    src_reg, dst_reg = _extract_regs_from_bytecode(bytecode_text)
    call_target, helper_id = _extract_call_target(bytecode_text) if is_call else (None, None)

    return OpcodeInfo(
        raw=raw,
        opclass=opclass,
        is_memory_access=is_memory,
        is_call=is_call,
        is_exit=is_exit,
        is_alu=is_alu,
        is_branch=is_branch,
        access_size=access_size,
        src_reg=src_reg,
        dst_reg=dst_reg,
        call_target=call_target,
        helper_id=helper_id,
    )


# ---------------------------------------------------------------------------
# Safety condition derivation (ISA-driven, zero keyword matching)
# ---------------------------------------------------------------------------

def derive_safety_conditions(
    info: OpcodeInfo,
    error_register: str | None = None,
) -> list[SafetyCondition]:
    """Derive all safety conditions implied by the opcode class.

    This is the ISA-derived mapping: opcode class -> safety domain.
    No error message parsing. No keyword heuristics.
    """
    conditions: list[SafetyCondition] = []

    if info.opclass == OpcodeClass.LDX:
        # Memory load: dst = *(uN *)(src + off)
        # Safety: src_reg must be a valid, non-null pointer with sufficient range.
        base = info.src_reg or "R?"
        conditions.append(SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register=base,
            required_property="must be a valid, non-scalar pointer type",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register=base,
            required_property="must not be ptr_or_null (null check required before dereference)",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register=base,
            required_property=f"off + {info.access_size or '?'} <= range",
            access_size=info.access_size,
        ))

    elif info.opclass in (OpcodeClass.ST, OpcodeClass.STX):
        # Memory store: *(uN *)(dst + off) = src  or  *(uN *)(dst + off) = imm
        # Safety: dst_reg must be a valid, non-null, writable pointer.
        base = info.dst_reg or "R?"
        conditions.append(SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register=base,
            required_property="must be a valid, non-null, writable pointer type",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register=base,
            required_property="must not be ptr_or_null (null check required before store)",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register=base,
            required_property=f"off + {info.access_size or '?'} <= range",
            access_size=info.access_size,
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.WRITE_PERMISSION,
            critical_register=base,
            required_property="pointee must be writable (not rdonly_mem or read-only packet data)",
        ))

    elif info.is_alu:
        # ALU / ALU64: dst op= src  or  dst op= imm
        # Safety depends on whether dst is a pointer (pointer arithmetic case) or scalar.
        dst = info.dst_reg or "R?"
        src = info.src_reg

        # If dst is a pointer, arithmetic legality applies.
        conditions.append(SafetyCondition(
            domain=SafetyDomain.ARITHMETIC_LEGALITY,
            critical_register=dst,
            required_property="if pointer, arithmetic must be legal for this pointer type (pkt/map_value/fp allow it; ctx/sock prohibit it)",
        ))
        # If src is a register and dst is a pointer, src (scalar) must be bounded.
        if src is not None:
            conditions.append(SafetyCondition(
                domain=SafetyDomain.SCALAR_BOUND,
                critical_register=src,
                required_property="if adding to a pointer, scalar must have known unsigned bounds (umax < 2^32)",
            ))

    elif info.is_call:
        if info.helper_id is not None:
            signature = get_helper_signature(info.helper_id)
            if signature is not None and error_register is not None:
                specific = get_helper_safety_condition(info.helper_id, error_register)
                if specific is not None:
                    return [specific]

            if signature is not None:
                helper_conditions = get_helper_safety_conditions(info.helper_id)
                return helper_conditions

        # Fallback for subprogram calls / unknown helpers.
        for i in range(1, 6):
            conditions.append(SafetyCondition(
                domain=SafetyDomain.ARG_CONTRACT,
                critical_register=f"R{i}",
                required_property="must match the helper/kfunc prototype (correct type and bounds)",
            ))

    elif info.is_exit:
        # EXIT: all acquired references must be released; R0 must satisfy return contract.
        conditions.append(SafetyCondition(
            domain=SafetyDomain.REFERENCE_BALANCE,
            critical_register="R0",
            required_property="all acquired references must be released before exit",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="R0 must satisfy the program type's return value contract",
        ))

    # Branches (JMP/JMP32 excluding CALL/EXIT) have no memory safety conditions.
    # LD (0x00) also has minimal safety concerns (mainly BTF/map metadata).

    return conditions


# ---------------------------------------------------------------------------
# Safety condition evaluation against register state
# ---------------------------------------------------------------------------

def evaluate_condition(
    condition: SafetyCondition,
    register_state: dict[str, Any],
) -> str:
    """Evaluate a safety condition against a register state snapshot.

    Args:
        condition: A SafetyCondition derived from the opcode.
        register_state: dict of register name -> RegisterState.

    Returns:
        'satisfied', 'violated', or 'unknown'
    """
    reg = register_state.get(condition.critical_register)
    if reg is None:
        return "unknown"

    reg_type = getattr(reg, "type", "") or ""

    match condition.domain:
        case SafetyDomain.POINTER_TYPE:
            if is_pointer_type_name(reg_type):
                return "satisfied"
            if _is_scalar_like(reg_type):
                return "violated"   # scalar where pointer is required
            return "unknown"

        case SafetyDomain.NULL_SAFETY:
            if is_nullable_pointer_type(reg_type):
                return "violated"   # ptr_or_null — null check not done
            if is_pointer_type_name(reg_type):
                return "satisfied"  # concrete pointer, non-null
            return "unknown"

        case SafetyDomain.MEMORY_BOUNDS:
            if not is_pointer_type_name(reg_type):
                return "unknown"    # can't check bounds on non-pointer
            off = getattr(reg, "off", None) or 0
            rng = getattr(reg, "range", None)
            if rng is None:
                return "unknown"
            if rng == 0:
                return "violated"   # no range proven accessible
            access_size = condition.access_size or 1
            if off + access_size > rng:
                return "violated"
            return "satisfied"

        case SafetyDomain.SCALAR_BOUND:
            return _evaluate_scalar_bound_reg(reg)

        case SafetyDomain.ARITHMETIC_LEGALITY:
            if not is_pointer_type_name(reg_type):
                return "satisfied"  # scalar-scalar arithmetic is always legal
            # ctx and sock pointers prohibit arithmetic
            prohibited = {"ctx", "sock", "sock_or_null", "ptr_sock"}
            if reg_type.lower() in prohibited:
                return "violated"
            return "satisfied"      # pkt/map_value/fp allow arithmetic

        case SafetyDomain.WRITE_PERMISSION:
            # Cannot determine write permission from register state alone;
            # the verifier tracks this via rdonly_mem type annotation.
            if "rdonly" in reg_type.lower():
                return "violated"
            return "unknown"

        case SafetyDomain.ARG_CONTRACT:
            return _evaluate_helper_arg_contract(condition, reg)

        case SafetyDomain.REFERENCE_BALANCE:
            # This requires cross-instruction knowledge.
            return "unknown"

        case _:
            return "unknown"


def compute_condition_gap(
    condition: SafetyCondition,
    register_state: dict[str, Any],
) -> int | None:
    """Return a numeric distance to satisfying a SafetyCondition."""
    reg = register_state.get(condition.critical_register)
    if reg is None:
        return None

    reg_type = getattr(reg, "type", "") or ""

    match condition.domain:
        case SafetyDomain.POINTER_TYPE:
            if is_pointer_type_name(reg_type):
                return 0
            return 1 if reg_type else None

        case SafetyDomain.NULL_SAFETY:
            if is_nullable_pointer_type(reg_type):
                return 1
            if is_pointer_type_name(reg_type):
                return 0
            return 1 if reg_type else None

        case SafetyDomain.MEMORY_BOUNDS:
            if not is_pointer_type_name(reg_type):
                return 1 if reg_type else None
            rng = getattr(reg, "range", None)
            if rng is None:
                return _UNKNOWN_NUMERIC_GAP
            off = getattr(reg, "off", None) or 0
            access_size = condition.access_size or 1
            return max(0, off + access_size - rng)

        case SafetyDomain.SCALAR_BOUND:
            if not _is_scalar_like(reg_type):
                return None
            umax = getattr(reg, "umax", None)
            smax = getattr(reg, "smax", None)
            if umax is None and smax is None:
                return _UNKNOWN_NUMERIC_GAP
            if umax is not None:
                return max(0, umax - ((1 << 32) - 1))
            return 0

        case SafetyDomain.ARITHMETIC_LEGALITY:
            if not is_pointer_type_name(reg_type):
                return 0
            prohibited = {"ctx", "sock", "sock_or_null", "ptr_sock"}
            return 1 if reg_type.lower() in prohibited else 0

        case SafetyDomain.WRITE_PERMISSION:
            if not reg_type:
                return None
            return 1 if "rdonly" in reg_type.lower() else 0

        case SafetyDomain.ARG_CONTRACT:
            result = _evaluate_helper_arg_contract(condition, reg)
            if result == "satisfied":
                return 0
            if result == "violated":
                return 1
            return _UNKNOWN_NUMERIC_GAP

        case SafetyDomain.REFERENCE_BALANCE:
            return None

        case _:
            return None


# ---------------------------------------------------------------------------
# High-level: infer conditions from the error instruction's opcode
# ---------------------------------------------------------------------------

def infer_conditions_from_error_insn(
    error_insn: Any,
    error_register: str | None = None,
) -> list[SafetyCondition]:
    """Derive safety conditions from the error instruction's opcode byte.

    This is the primary entry point for opcode-driven analysis.
    No error message parsing. No keyword heuristics.

    Args:
        error_insn: A TracedInstruction with .bytecode (str) and .opcode attribute.
                    The opcode may be a hex string (from InstructionLine) or None.

    Returns:
        List of SafetyCondition objects (may be empty if opcode not available).
    """
    bytecode = getattr(error_insn, "bytecode", "") or ""
    raw_opcode = (
        getattr(error_insn, "opcode_hex", None)
        or getattr(error_insn, "_opcode_hex", None)
    )

    if not raw_opcode:
        return []
    info = decode_opcode(raw_opcode, bytecode)

    conditions = derive_safety_conditions(info, error_register=error_register)

    # Refine using register state at the error point:
    # For ALU conditions, only keep pointer-arithmetic conditions if dst IS a pointer,
    # and scalar-bound conditions only if the register IS a scalar.
    state = getattr(error_insn, "pre_state", {}) or {}
    refined: list[SafetyCondition] = []
    for cond in conditions:
        reg = state.get(cond.critical_register)
        if reg is None:
            refined.append(cond)
            continue
        reg_type = getattr(reg, "type", "") or ""
        if cond.domain == SafetyDomain.ARITHMETIC_LEGALITY:
            # Only keep if dst IS a pointer (scalar ALU has no safety conditions)
            if is_pointer_type_name(reg_type):
                refined.append(cond)
        elif cond.domain == SafetyDomain.SCALAR_BOUND:
            # Only keep if register IS a scalar
            if _is_scalar_like(reg_type):
                refined.append(cond)
        else:
            refined.append(cond)

    return refined


def _infer_opcode_class_from_bytecode(bytecode: str) -> OpcodeInfo | None:
    """Infer OpcodeInfo from bytecode text when the raw opcode byte is unavailable.

    This is used when TracedInstruction does not carry the raw opcode.
    We heuristically identify the instruction class from the text.
    """
    if not bytecode:
        return None

    text = bytecode.strip().lower()

    # Memory load: "rN = *(uN *)(rM + off)"
    if re.match(r"[rw]\d+\s*=\s*\*\(", text):
        src_reg, dst_reg = _extract_regs_from_bytecode(bytecode)
        # Access size from type annotation
        size = _extract_access_size_from_bytecode(text)
        return OpcodeInfo(
            raw=0x01,  # LDX
            opclass=OpcodeClass.LDX,
            is_memory_access=True,
            is_call=False,
            is_exit=False,
            is_alu=False,
            is_branch=False,
            access_size=size,
            src_reg=src_reg,
            dst_reg=dst_reg,
        )

    # Memory store register: "*(uN *)(rM + off) = rK"
    if re.match(r"\*\(", text):
        src_reg, dst_reg = _extract_regs_from_bytecode(bytecode)
        size = _extract_access_size_from_bytecode(text)
        # STX if src_reg present, ST if immediate
        is_stx = src_reg is not None
        return OpcodeInfo(
            raw=0x03 if is_stx else 0x02,
            opclass=OpcodeClass.STX if is_stx else OpcodeClass.ST,
            is_memory_access=True,
            is_call=False,
            is_exit=False,
            is_alu=False,
            is_branch=False,
            access_size=size,
            src_reg=src_reg,
            dst_reg=dst_reg,
        )

    # CALL
    if text.startswith("call "):
        call_target, helper_id = _extract_call_target(bytecode)
        return OpcodeInfo(
            raw=BPF_CALL,
            opclass=OpcodeClass.JMP,
            is_memory_access=False,
            is_call=True,
            is_exit=False,
            is_alu=False,
            is_branch=False,
            access_size=None,
            src_reg=None,
            dst_reg=None,
            call_target=call_target,
            helper_id=helper_id,
        )

    # EXIT
    if text.startswith("exit"):
        return OpcodeInfo(
            raw=BPF_EXIT,
            opclass=OpcodeClass.JMP,
            is_memory_access=False,
            is_call=False,
            is_exit=True,
            is_alu=False,
            is_branch=False,
            access_size=None,
            src_reg=None,
            dst_reg=None,
        )

    # Branches: "if rN <op> rM/imm, goto ..."
    if re.match(r"if\s|goto\s", text):
        return OpcodeInfo(
            raw=0x05,  # JMP
            opclass=OpcodeClass.JMP,
            is_memory_access=False,
            is_call=False,
            is_exit=False,
            is_alu=False,
            is_branch=True,
            access_size=None,
            src_reg=None,
            dst_reg=None,
        )

    # ALU: "rN op= rM" or "rN op= imm"
    if re.match(r"[rw]\d+\s*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|=)", text):
        src_reg, dst_reg = _extract_regs_from_bytecode(bytecode)
        return OpcodeInfo(
            raw=0x07,  # ALU64
            opclass=OpcodeClass.ALU64,
            is_memory_access=False,
            is_call=False,
            is_exit=False,
            is_alu=True,
            is_branch=False,
            access_size=None,
            src_reg=src_reg,
            dst_reg=dst_reg,
        )

    # Byte-swap: "be16/be32/be64 rN" or "le16/le32/le64 rN"
    if re.match(r"(?:be|le)\d+\s", text):
        m = re.match(r"(?:be|le)\d+\s+(?P<reg>[rw]\d+)", text)
        dst_reg = _normalize_reg(m.group("reg")) if m else None
        return OpcodeInfo(
            raw=0x04,  # ALU (byte-swap is ALU class)
            opclass=OpcodeClass.ALU,
            is_memory_access=False,
            is_call=False,
            is_exit=False,
            is_alu=True,
            is_branch=False,
            access_size=None,
            src_reg=None,
            dst_reg=dst_reg,
        )

    return None


def _extract_access_size_from_bytecode(text: str) -> int | None:
    """Extract memory access size in bytes from a bytecode text.

    Examples:
      "*(u8 *)(r0 +2)" -> 1
      "*(u16 *)(r0 +2)" -> 2
      "*(u32 *)(r0 +4)" -> 4
      "*(u64 *)(r10 -8)" -> 8
    """
    m = re.search(r"\*\(u(\d+)\s*\*\)", text)
    if m:
        bits = int(m.group(1))
        return bits // 8
    return None


def _is_scalar_like(reg_type: str) -> bool:
    """Return True if the type represents a scalar (non-pointer) value."""
    lowered = reg_type.lower()
    return (
        lowered.startswith("inv")
        or lowered.startswith("scalar")
        or lowered == "unknown"
    )


def _extract_call_target(bytecode: str) -> tuple[str | None, int | None]:
    """Extract the textual CALL target and helper ID from bytecode text."""
    if not bytecode:
        return None, None

    match = _CALL_TARGET_RE.match(bytecode.strip())
    if match is None:
        return None, None

    if match.group("pc") is not None:
        return match.group("pc"), None

    helper_name = match.group("name")
    helper_id_text = match.group("helper_id") or match.group("imm")
    helper_id = int(helper_id_text) if helper_id_text is not None else None

    normalized_name: str | None
    if helper_name is None:
        normalized_name = None
    elif helper_name.startswith("bpf_"):
        normalized_name = helper_name
    else:
        normalized_name = f"bpf_{helper_name}"

    if helper_id is None and normalized_name is not None:
        helper_id = get_helper_id_by_name(normalized_name)

    return normalized_name, helper_id


def _evaluate_scalar_bound_reg(reg: Any) -> str:
    reg_type = getattr(reg, "type", "") or ""
    if not _is_scalar_like(reg_type):
        return "unknown"

    umax = getattr(reg, "umax", None)
    smax = getattr(reg, "smax", None)
    if umax is None and smax is None:
        return "violated"
    if umax is not None and umax < (1 << 32):
        return "satisfied"
    if umax is not None and umax >= (1 << 32):
        return "violated"
    return "unknown"


def _evaluate_helper_arg_contract(condition: SafetyCondition, reg: Any) -> str:
    reg_type = getattr(reg, "type", "") or ""
    expected_types = condition.expected_types
    if not expected_types:
        return "unknown"

    if not any(_matches_helper_expected_type(reg_type, expected) for expected in expected_types):
        if is_pointer_type_name(reg_type) or _is_scalar_like(reg_type):
            return "violated"
        return "unknown"

    if is_nullable_pointer_type(reg_type) and not condition.allow_null:
        return "violated"

    if condition.requires_range and reg_type.lower() != "fp":
        rng = getattr(reg, "range", None)
        if rng == 0:
            return "violated"
        if rng is None:
            return "unknown"

    if condition.requires_writable and "rdonly" in reg_type.lower():
        return "violated"

    if expected_types == ("scalar",):
        return "satisfied" if _is_scalar_like(reg_type) else "violated"

    return "satisfied"


def _matches_helper_expected_type(reg_type: str, expected_type: str) -> bool:
    lowered = reg_type.lower()

    if expected_type == "scalar":
        return _is_scalar_like(lowered)
    if expected_type == "ptr":
        return is_pointer_type_name(lowered)
    if expected_type == "map_ptr":
        return lowered == "map_ptr"
    if expected_type == "ctx":
        return lowered == "ctx"
    if expected_type == "fp":
        return lowered == "fp"
    if expected_type == "sock":
        return lowered.startswith("sock") or lowered == "ptr_sock"
    if expected_type == "dynptr":
        return lowered.startswith("dynptr")

    return False


# ---------------------------------------------------------------------------
# Predicate adapter: wrap SafetyCondition into the Predicate interface
# ---------------------------------------------------------------------------

class OpcodeConditionPredicate:
    """Adapter that wraps a SafetyCondition into the Predicate protocol.

    This allows the opcode-driven analysis to be used with TraceMonitor
    and TransitionAnalyzer without changing those components.

    The Predicate protocol requires:
    - evaluate(state, insn=None) -> 'satisfied'|'violated'|'unknown'
    - describe_violation(state, insn=None) -> str
    - target_regs: list[str]  (used by pipeline to determine proof_registers)
    """

    def __init__(self, condition: SafetyCondition) -> None:
        self.condition = condition
        self.target_regs: list[str] = [condition.critical_register]

    def evaluate(self, state: dict, insn: Any = None) -> str:
        return evaluate_condition(self.condition, state)

    def compute_gap(self, state: dict, insn: Any = None) -> int | None:
        return compute_condition_gap(self.condition, state)

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        reg = state.get(self.condition.critical_register)
        if reg is None:
            return (
                f"OpcodeCondition[{self.condition.domain.value}]: "
                f"{self.condition.critical_register} not in state; "
                f"required: {self.condition.required_property}"
            )
        reg_type = getattr(reg, "type", "unknown")
        umax = getattr(reg, "umax", None)
        rng = getattr(reg, "range", None)
        off = getattr(reg, "off", None)
        details = f"type={reg_type}"
        if umax is not None:
            details += f", umax={umax}"
        if rng is not None:
            details += f", range={rng}"
        if off is not None:
            details += f", off={off}"
        return (
            f"OpcodeCondition[{self.condition.domain.value}] violated on "
            f"{self.condition.critical_register} ({details}): "
            f"required={self.condition.required_property}"
        )

    def __repr__(self) -> str:
        return (
            f"OpcodeConditionPredicate({self.condition.domain.value}, "
            f"reg={self.condition.critical_register})"
        )


# ---------------------------------------------------------------------------
# Find the violated condition at the error instruction
# ---------------------------------------------------------------------------

def find_violated_condition(
    error_insn: Any,
    conditions: list[SafetyCondition],
) -> SafetyCondition | None:
    """Identify which safety condition is violated at the error instruction.

    Evaluates each condition against the pre-state of the error instruction.
    Returns the first violated condition, or the first condition if none is
    explicitly violated (best-effort fallback).

    Args:
        error_insn: TracedInstruction at the error site.
        conditions: List of SafetyConditions from infer_conditions_from_error_insn().

    Returns:
        The violated SafetyCondition, or None if conditions is empty.
    """
    if not conditions:
        return None

    state = getattr(error_insn, "pre_state", {}) or {}

    for cond in conditions:
        result = evaluate_condition(cond, state)
        if result == "violated":
            return cond

    # No explicitly violated condition found — return the first (primary) condition
    # as a best-effort fallback.
    return conditions[0]
