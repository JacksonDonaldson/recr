// GPU backend for codezip's whole-image scan.
//
// The SLEIGH resolution algorithm is table-driven: a decision tree picks a
// constructor by byte/context patterns, then the constructor's operands are
// laid out and nested subtables are resolved recursively.  Everything needed
// for an instruction's length, type, and control-flow targets is therefore
// data, which lets the same algorithm run one thread per address.
//
// This file also holds the address-checking kernel, which reports how many
// contiguous mapped bytes follow each address.

#include <cuda_runtime.h>
#include <stdint.h>
#include <string.h>

// Frames beyond this depth are handed back to the Python resolver.  The x86-64
// specification nests at most 11 deep on real code.
#define MAX_DEPTH 12
#define MAX_OPERANDS 16
#define MAX_ESTACK 16

// x86-64 instructions are at most 15 bytes.  The CPU decoder reads at most
// this many bytes, so the window and the mapped-byte check must agree.
#define MAX_INSTRUCTION_LENGTH 15

enum { P_INSTR = 0, P_CTX = 1, P_COMBINE = 2, P_OR = 3 };

enum {
    E_CONST = 0,
    E_TOKEN,
    E_CONTEXT,
    E_ZERO,
    E_OPERAND,
    E_NEG,
    E_NOT,
    E_ADD,
    E_SUB,
    E_MUL,
    E_LSHIFT,
    E_RSHIFT,
    E_AND,
    E_OR,
    E_XOR,
    E_DIV,
};

// Instruction classes.  Keep in sync with ``gpu/tables.py``.
enum {
    TYPE_NONE = 0,
    TYPE_CALL = 1,
    TYPE_RET = 2,
    TYPE_BRANCH = 3,
    TYPE_NOP = 4,
    TYPE_ARITHMETIC = 5,
};

enum {
    OPCODE_BRANCH = 1 << 0,
    OPCODE_CBRANCH = 1 << 1,
    OPCODE_BRANCHIND = 1 << 2,
    OPCODE_CALLIND = 1 << 3,
};

enum {
    KIND_ABSOLUTE = 0,
    KIND_UNK_LOCAL = 1,
    KIND_UNK_NONLOCAL = 2,
    KIND_NONE = 3,
};

enum {
    STATUS_UNDECODED = 0,
    STATUS_STRAIGHT = 1,
    STATUS_DEFER = 2,
    STATUS_FLOW = 3,
};

// Header element indices into the int32 table blob.
enum {
    H_MAGIC = 0,
    H_NODES,
    H_PAIRS,
    H_PCHILD,
    H_NCHILD,
    H_PATTERNS,
    H_BLOCKS,
    H_WORDS,
    H_CTORS,
    H_OPERANDS,
    H_CTX,
    H_INSTRS,
    H_SUBTABLES,
    H_BUILD,
    H_ROOT,
    H_LEN,
};

// Strides of each section, in int32 elements.
#define NODE_STRIDE 7
#define PAIR_STRIDE 2
#define PATTERN_STRIDE 4
#define BLOCK_STRIDE 4
#define WORD_STRIDE 2
#define CTOR_STRIDE 9
#define OPERAND_STRIDE 6
#define CTX_STRIDE 4
#define INSTR_STRIDE 9
#define SUBTABLE_STRIDE 3

struct Seg {
    int64_t va;
    int64_t file_offset;
    int64_t file_size;
    int64_t mem_size;
};

struct Env {
    const int32_t *tables;
    const Seg *segs;
    int nsegs;
    const uint8_t *image;
    int64_t image_len;
    const uint8_t *win;
    uint64_t context;
};

struct Frame {
    int32_t ctor;
    int32_t base_offset;
    uint64_t context;
    int32_t next;
    int32_t type_class;
    int32_t first_child_type;
    int32_t has_rel;
    int32_t rel_off;
    int32_t rel_size;
    uint32_t opcode_mask;
    int16_t off[MAX_OPERANDS];
    int16_t len[MAX_OPERANDS];
};

struct Resolution {
    int length;
    int type_class;
    int has_rel;
    int rel_off;
    int rel_size;
    uint32_t opcode_mask;
};

__device__ __forceinline__ const int32_t *section(const int32_t *t, int index) {
    return t + t[index];
}

// ---------------------------------------------------------------- primitives

__device__ __forceinline__ uint32_t win_be4(const uint8_t *win, int pos) {
    uint32_t value = 0;
#pragma unroll
    for (int i = 0; i < 4; ++i) {
        int p = pos + i;
        uint32_t byte =
            (p >= 0 && p < MAX_INSTRUCTION_LENGTH) ? (uint32_t)win[p] : 0u;
        value = (value << 8) | byte;
    }
    return value;
}

__device__ __forceinline__ uint32_t win_bits(
    const uint8_t *win, int startbit, int size
) {
    int byte_offset = startbit >> 3;
    int bit_offset = startbit & 7;
    int byte_count = ((bit_offset + size - 1) >> 3) + 1;
    uint32_t raw = 0;
    for (int i = 0; i < byte_count; ++i) {
        int p = byte_offset + i;
        uint32_t byte =
            (p >= 0 && p < MAX_INSTRUCTION_LENGTH) ? (uint32_t)win[p] : 0u;
        raw = (raw << 8) | byte;
    }
    uint32_t value = raw << (8 * (4 - byte_count) + bit_offset);
    value >>= (32 - size);
    return value & ((size >= 32) ? 0xFFFFFFFFu : ((1u << size) - 1u));
}

__device__ __forceinline__ uint64_t ctx_bits(
    uint64_t context, int startbit, int size
) {
    if (size <= 0) {
        return 0;
    }
    if (size >= 64) {
        return context >> (64 - startbit);
    }
    return (context >> (64 - startbit - size)) & ((1ull << size) - 1ull);
}

__device__ __forceinline__ uint32_t ctx_bytes(
    uint64_t context, int byte_start, int count
) {
    uint32_t words[2] = {
        (uint32_t)((context >> 32) & 0xFFFFFFFFu),
        (uint32_t)(context & 0xFFFFFFFFu),
    };
    int int_start = byte_start >> 2;
    if (int_start < 0 || int_start >= 2) {
        return 0;
    }
    uint32_t value = words[int_start];
    int byte_offset = byte_start & 3;
    int unused = 4 - count;
    if (byte_offset > 0) {
        value = (value << (byte_offset * 8)) & 0xFFFFFFFFu;
    }
    if (unused > 0) {
        value >>= (unused * 8);
    }
    int remaining = count - 4 + byte_offset;
    if (remaining > 0 && int_start + 1 < 2) {
        uint32_t second = words[int_start + 1];
        int unused_second = 4 - remaining;
        if (unused_second > 0) {
            second >>= (unused_second * 8);
        }
        value |= second;
    }
    return value;
}

__device__ __forceinline__ uint64_t byte_swap(uint64_t value, int size) {
    uint64_t result = 0;
    for (int i = 0; i < size; ++i) {
        result = (result << 8) | (value & 0xFFu);
        value >>= 8;
    }
    return result;
}

// ------------------------------------------------------------ pattern match

__device__ __forceinline__ bool match_block_instr(
    const int32_t *t, int block, const uint8_t *win, int base_offset
) {
    const int32_t *b = section(t, H_BLOCKS) + block * BLOCK_STRIDE;
    int nonzerosize = b[3];
    if (nonzerosize <= 0) {
        return nonzerosize == 0;
    }
    const int32_t *words = section(t, H_WORDS) + b[1] * WORD_STRIDE;
    int count = b[2];
    int offset = base_offset + b[0];
    for (int i = 0; i < count; ++i) {
        if ((win_be4(win, offset) & (uint32_t)words[2 * i]) !=
            (uint32_t)words[2 * i + 1]) {
            return false;
        }
        offset += 4;
    }
    return true;
}

__device__ __forceinline__ bool match_block_ctx(
    const int32_t *t, int block, uint64_t context
) {
    const int32_t *b = section(t, H_BLOCKS) + block * BLOCK_STRIDE;
    int nonzerosize = b[3];
    if (nonzerosize <= 0) {
        return nonzerosize == 0;
    }
    const int32_t *words = section(t, H_WORDS) + b[1] * WORD_STRIDE;
    int count = b[2];
    int offset = b[0];
    for (int i = 0; i < count; ++i) {
        if ((ctx_bytes(context, offset, 4) & (uint32_t)words[2 * i]) !=
            (uint32_t)words[2 * i + 1]) {
            return false;
        }
        offset += 4;
    }
    return true;
}

__device__ bool match_pattern(
    const int32_t *t,
    int pattern,
    const uint8_t *win,
    uint64_t context,
    int base_offset
) {
    const int32_t *p = section(t, H_PATTERNS) + pattern * PATTERN_STRIDE;
    int kind = p[0];
    if (kind == P_INSTR) {
        return match_block_instr(t, p[1], win, base_offset);
    }
    if (kind == P_CTX) {
        return match_block_ctx(t, p[1], context);
    }
    const int32_t *children = section(t, H_PCHILD) + p[2];
    int count = p[3];
    if (kind == P_COMBINE) {
        for (int i = 0; i < count; ++i) {
            if (!match_pattern(t, children[i], win, context, base_offset)) {
                return false;
            }
        }
        return true;
    }
    if (kind == P_OR) {
        for (int i = 0; i < count; ++i) {
            if (match_pattern(t, children[i], win, context, base_offset)) {
                return true;
            }
        }
        return false;
    }
    return false;
}

__device__ int resolve_decision(
    const int32_t *t,
    int node,
    const uint8_t *win,
    uint64_t context,
    int base_offset
) {
    for (;;) {
        const int32_t *n = section(t, H_NODES) + node * NODE_STRIDE;
        int bitsize = n[1];
        if (bitsize == 0) {
            const int32_t *pairs = section(t, H_PAIRS) + n[5] * PAIR_STRIDE;
            int count = n[6];
            for (int i = 0; i < count; ++i) {
                if (match_pattern(
                        t, pairs[2 * i], win, context, base_offset)) {
                    return pairs[2 * i + 1];
                }
            }
            return -1;
        }
        uint32_t value = n[2] ? (uint32_t)ctx_bits(context, n[0], bitsize)
                              : win_bits(win, base_offset * 8 + n[0], bitsize);
        if ((int)value >= n[4]) {
            return -1;
        }
        node = section(t, H_NCHILD)[n[3] + (int)value];
    }
}

// ------------------------------------------------------------ expressions

__device__ bool eval_expr(
    const Env *env,
    int start,
    int ctor,
    const int16_t *op_off,
    uint32_t *seen,
    int base_offset,
    int64_t *out
);

__device__ bool operand_ref(
    const Env *env,
    int ctor,
    const int16_t *op_off,
    int index,
    uint32_t *seen,
    int64_t *out
) {
    const int32_t *t = env->tables;
    const int32_t *c = section(t, H_CTORS) + ctor * CTOR_STRIDE;
    int count = c[2];
    if (index < 0 || index >= count || index >= 32) {
        return false;
    }
    uint32_t bit = 1u << index;
    if (*seen & bit) {
        return false;
    }
    *seen |= bit;
    const int32_t *op =
        section(t, H_OPERANDS) + (c[1] + index) * OPERAND_STRIDE;
    int definition = op[4];
    if (definition < 0) {
        return false;
    }
    return eval_expr(
        env, definition, ctor, op_off, seen, op_off[index], out
    );
}

__device__ bool eval_expr(
    const Env *env,
    int start,
    int ctor,
    const int16_t *op_off,
    uint32_t *seen,
    int base_offset,
    int64_t *out
) {
    const int32_t *t = env->tables;
    const int32_t *program = section(t, H_INSTRS) + start;
    int count = program[0];
    const int32_t *ins = program + 1;
    int64_t stack[MAX_ESTACK];
    int sp = 0;

    for (int i = 0; i < count; ++i) {
        const int32_t *op = ins + i * INSTR_STRIDE;
        int kind = op[0];
        switch (kind) {
        case E_CONST:
            stack[sp++] = ((int64_t)op[2] << 32) | (uint32_t)op[1];
            break;
        case E_TOKEN: {
            int bigendian = op[1];
            int signbit = op[2];
            int startbit = op[3];
            int endbit = op[4];
            int bytestart = op[5];
            int byteend = op[6];
            int shift = op[7];
            int size = byteend - bytestart + 1;
            uint64_t value = 0;
            int remaining = size;
            int position = base_offset + bytestart;
            while (remaining >= 4) {
                value = (value << 32) | win_be4(env->win, position);
                position += 4;
                remaining -= 4;
            }
            if (remaining > 0) {
                uint32_t chunk = 0;
                for (int k = 0; k < remaining; ++k) {
                    int q = position + k;
                    uint32_t byte = (q >= 0 && q < MAX_INSTRUCTION_LENGTH)
                                        ? (uint32_t)env->win[q]
                                        : 0u;
                    chunk = (chunk << 8) | byte;
                }
                value = (value << (8 * remaining)) | chunk;
            }
            if (!bigendian) {
                value = byte_swap(value, size);
            }
            value >>= shift;
            int bits = endbit - startbit + 1;
            uint64_t mask = (bits >= 64) ? ~0ull : ((1ull << bits) - 1ull);
            value &= mask;
            int64_t signed_value = (int64_t)value;
            if (signbit && bits > 0 && bits < 64 &&
                (value & (1ull << (bits - 1)))) {
                signed_value -= (int64_t)(1ull << bits);
            }
            stack[sp++] = signed_value;
            break;
        }
        case E_CONTEXT: {
            int signbit = op[1];
            int startbit = op[2];
            int endbit = op[3];
            int bits = endbit - startbit + 1;
            uint64_t value = ctx_bits(env->context, startbit, bits);
            int64_t signed_value = (int64_t)value;
            if (signbit && bits > 0 && bits < 64 &&
                (value & (1ull << (bits - 1)))) {
                signed_value -= (int64_t)(1ull << bits);
            }
            stack[sp++] = signed_value;
            break;
        }
        case E_ZERO:
            stack[sp++] = 0;
            break;
        case E_OPERAND: {
            uint32_t local = 0;
            uint32_t *shared = seen ? seen : &local;
            int64_t value;
            if (!operand_ref(env, ctor, op_off, op[1], shared, &value)) {
                return false;
            }
            stack[sp++] = value;
            break;
        }
        case E_NEG:
            stack[sp - 1] = -stack[sp - 1];
            break;
        case E_NOT:
            stack[sp - 1] = ~stack[sp - 1];
            break;
        default: {
            int64_t rhs = stack[--sp];
            int64_t lhs = stack[sp - 1];
            int64_t result;
            switch (kind) {
            case E_ADD:
                result = lhs + rhs;
                break;
            case E_SUB:
                result = lhs - rhs;
                break;
            case E_MUL:
                result = lhs * rhs;
                break;
            case E_LSHIFT:
                result = lhs << rhs;
                break;
            case E_RSHIFT:
                result = lhs >> rhs;
                break;
            case E_AND:
                result = lhs & rhs;
                break;
            case E_OR:
                result = lhs | rhs;
                break;
            case E_XOR:
                result = lhs ^ rhs;
                break;
            case E_DIV: {
                if (rhs == 0) {
                    return false;
                }
                result = lhs / rhs;
                if ((lhs % rhs != 0) && ((lhs < 0) != (rhs < 0))) {
                    result -= 1;
                }
                break;
            }
            default:
                return false;
            }
            stack[sp - 1] = result;
            break;
        }
        }
        if (sp < 0 || sp > MAX_ESTACK) {
            return false;
        }
    }
    if (sp != 1) {
        return false;
    }
    *out = stack[0];
    return true;
}

// --------------------------------------------------------------- resolution

// Returns 0 on success, 1 when the address cannot be decoded, and 2 when the
// frame needs the Python resolver (depth or operand-count limit).
__device__ int start_frame(
    const Env *env_in,
    Frame *frame,
    int subtable,
    int base_offset,
    uint64_t context,
    int depth
) {
    Env local = *env_in;
    local.context = context;
    const Env *env = &local;
    const int32_t *t = env->tables;
    if (depth > 64) {
        return 1;
    }
    const int32_t *st = section(t, H_SUBTABLES) + subtable * SUBTABLE_STRIDE;
    int node = st[0];
    if (node < 0) {
        return 1;
    }
    int constructor_id =
        resolve_decision(t, node, env->win, context, base_offset);
    if (constructor_id < 0 || constructor_id >= st[2]) {
        return 1;
    }
    int ctor = st[1] + constructor_id;
    const int32_t *c = section(t, H_CTORS) + ctor * CTOR_STRIDE;
    int count = c[2];
    if (count > MAX_OPERANDS) {
        return 2;
    }

    const int32_t *ops = section(t, H_OPERANDS) + c[1] * OPERAND_STRIDE;
    for (int i = 0; i < count; ++i) {
        const int32_t *op = ops + i * OPERAND_STRIDE;
        int offset;
        if (op[0] < 0) {
            offset = base_offset + op[1];
        } else {
            if (op[0] >= i) {
                return 2;
            }
            offset = frame->off[op[0]] + frame->len[op[0]];
        }
        if (offset < 0 || offset > 30000) {
            return 2;
        }
        frame->off[i] = (int16_t)offset;
        frame->len[i] = (int16_t)op[2];
    }

    int ctxop_base = c[3];
    int ctxop_count = c[4];
    for (int i = 0; i < ctxop_count; ++i) {
        const int32_t *co =
            section(t, H_CTX) + (ctxop_base + i) * CTX_STRIDE;
        int word = co[0];
        int shift = co[1];
        if (word < 0 || word > 1 || shift < 0 || shift > 63) {
            return 2;
        }
        int64_t value;
        if (!eval_expr(
                env, co[3], ctor, frame->off, nullptr, base_offset, &value)) {
            continue;
        }
        uint32_t mask = (uint32_t)co[2];
        int word_shift = 32 * (1 - word);
        uint64_t shifted_mask = ((uint64_t)mask) << word_shift;
        context &= ~shifted_mask;
        context |= ((((uint64_t)value << shift) & (uint64_t)mask)
                    << word_shift);
    }

    frame->ctor = ctor;
    frame->base_offset = base_offset;
    frame->context = context;
    frame->next = 0;
    frame->type_class = c[5];
    frame->first_child_type = 0;
    frame->has_rel = 0;
    frame->rel_off = 0;
    frame->rel_size = 0;
    frame->opcode_mask = (uint32_t)c[6];
    return 0;
}

__device__ bool is_build_operand(
    const int32_t *t, int ctor, int operand_index
) {
    const int32_t *c = section(t, H_CTORS) + ctor * CTOR_STRIDE;
    const int32_t *children = section(t, H_BUILD) + c[7];
    int count = c[8];
    for (int i = 0; i < count; ++i) {
        if (children[i] == operand_index) {
            return true;
        }
    }
    return false;
}

// Returns 0 on success, 1 when undecodable, 2 when the address needs Python.
__device__ int resolve_full(
    const Env *env, int root, uint64_t context, Resolution *out
) {
    const int32_t *t = env->tables;
    Frame stack[MAX_DEPTH];
    int sp = 0;
    int status = start_frame(env, &stack[0], root, 0, context, 0);
    if (status != 0) {
        return status;
    }

    for (;;) {
        Frame *frame = &stack[sp];
        const int32_t *c =
            section(t, H_CTORS) + frame->ctor * CTOR_STRIDE;
        int count = c[2];
        if (frame->next < count) {
            int i = frame->next++;
            const int32_t *op =
                section(t, H_OPERANDS) + (c[1] + i) * OPERAND_STRIDE;

            int next_info = op[5];
            if (next_info >= 0 && !frame->has_rel) {
                int index = next_info >> 1;
                if (index < count) {
                    frame->has_rel = 1;
                    frame->rel_off = frame->off[index];
                    frame->rel_size = frame->len[index];
                }
            }

            int base = op[0];
            if (base >= 0) {
                int offset = frame->off[base] + frame->len[base];
                if (offset < 0 || offset > 30000) {
                    return 2;
                }
                frame->off[i] = (int16_t)offset;
            }
            int subsym = op[3];
            if (subsym >= 0) {
                if (sp + 1 >= MAX_DEPTH) {
                    return 2;
                }
                int result = start_frame(
                    env,
                    &stack[sp + 1],
                    subsym,
                    frame->off[i],
                    frame->context,
                    sp + 1
                );
                if (result != 0) {
                    return result;
                }
                ++sp;
            }
            continue;
        }

        int length = c[0] + frame->base_offset;
        for (int i = 0; i < count; ++i) {
            int candidate = frame->off[i] + frame->len[i];
            if (candidate > length) {
                length = candidate;
            }
        }
        length -= frame->base_offset;
        if (frame->type_class == 0) {
            frame->type_class = frame->first_child_type;
        }

        --sp;
        if (sp < 0) {
            out->length = length;
            out->type_class = frame->type_class;
            out->has_rel = frame->has_rel;
            out->rel_off = frame->rel_off;
            out->rel_size = frame->rel_size;
            out->opcode_mask = frame->opcode_mask;
            return 0;
        }

        Frame *parent = &stack[sp];
        int finished = parent->next - 1;
        parent->len[finished] = (int16_t)length;
        if (parent->type_class == 0 && parent->first_child_type == 0 &&
            frame->type_class != 0) {
            parent->first_child_type = frame->type_class;
        }
        if (!parent->has_rel && frame->has_rel) {
            parent->has_rel = 1;
            parent->rel_off = frame->rel_off;
            parent->rel_size = frame->rel_size;
        }
        if (is_build_operand(t, parent->ctor, finished)) {
            parent->opcode_mask |= frame->opcode_mask;
        }
    }
}

// -------------------------------------------------------------- flow targets

// Returns the target of a relative branch, or 0 when there is none.
__device__ bool relative_target(
    const Resolution *res,
    const uint8_t *win,
    int available,
    int64_t address,
    int64_t *out
) {
    if (!res->has_rel) {
        return false;
    }
    int offset = res->rel_off;
    int size = res->rel_size;
    if (size <= 0 || size > 8 || offset < 0 || offset + size > available) {
        return false;
    }
    int64_t displacement = 0;
    for (int i = size - 1; i >= 0; --i) {
        displacement = (displacement << 8) | win[offset + i];
    }
    int bits = size * 8;
    if (bits < 64 && (displacement & (1ll << (bits - 1)))) {
        displacement -= (1ll << bits);
    }
    *out = address + res->length + displacement;
    return true;
}

// Mirrors ``SlaSpec.flow_targets``.  Returns the number of targets written.
__device__ int build_flows(
    const Resolution *res,
    const uint8_t *win,
    int available,
    int64_t address,
    int64_t *targets,
    uint8_t *kinds
) {
    int64_t next = address + res->length;
    uint32_t mask = res->opcode_mask;

    if (res->type_class == TYPE_RET) {
        return 0;
    }

    if (res->type_class == TYPE_BRANCH) {
        if (mask & OPCODE_BRANCHIND) {
            kinds[0] = KIND_UNK_LOCAL;
            return 1;
        }
        if (!(mask & OPCODE_BRANCH) && !(mask & OPCODE_CBRANCH)) {
            kinds[0] = KIND_UNK_LOCAL;
            return 1;
        }
        int64_t target;
        if (!relative_target(res, win, available, address, &target)) {
            kinds[0] = KIND_UNK_LOCAL;
            return 1;
        }
        if (mask & OPCODE_CBRANCH) {
            targets[0] = target;
            kinds[0] = KIND_ABSOLUTE;
            if (target == next) {
                return 1;
            }
            targets[1] = next;
            kinds[1] = KIND_ABSOLUTE;
            return 2;
        }
        targets[0] = target;
        kinds[0] = KIND_ABSOLUTE;
        return 1;
    }

    if (res->type_class == TYPE_CALL) {
        int64_t target;
        if (mask & OPCODE_CALLIND) {
            kinds[0] = KIND_UNK_NONLOCAL;
        } else if (relative_target(res, win, available, address, &target)) {
            targets[0] = target;
            kinds[0] = KIND_ABSOLUTE;
        } else {
            kinds[0] = KIND_UNK_NONLOCAL;
        }
        if (kinds[0] == KIND_ABSOLUTE && targets[0] == next) {
            return 1;
        }
        targets[1] = next;
        kinds[1] = KIND_ABSOLUTE;
        return 2;
    }

    targets[0] = next;
    kinds[0] = KIND_ABSOLUTE;
    return 1;
}

// ------------------------------------------------------------ address space

__device__ __forceinline__ int segment_of(const Env *env, int64_t address) {
    for (int i = 0; i < env->nsegs; ++i) {
        const Seg *seg = &env->segs[i];
        if (address >= seg->va && address < seg->va + seg->mem_size) {
            return i;
        }
    }
    return -1;
}

__device__ __forceinline__ uint8_t fetch_byte(const Env *env, int64_t address) {
    int index = segment_of(env, address);
    if (index < 0) {
        return 0;
    }
    const Seg *seg = &env->segs[index];
    int64_t offset = address - seg->va;
    if (offset >= seg->file_size) {
        return 0;
    }
    int64_t position = seg->file_offset + offset;
    if (position < 0 || position >= env->image_len) {
        return 0;
    }
    return env->image[position];
}

__device__ bool read_bytes(
    const Env *env, int64_t address, int length, uint8_t *buffer
) {
    for (int i = 0; i < length; ++i) {
        int index = segment_of(env, address + i);
        if (index < 0) {
            return false;
        }
        const Seg *seg = &env->segs[index];
        int64_t offset = address + i - seg->va;
        if (offset < seg->file_size &&
            seg->file_offset + offset < env->image_len) {
            buffer[i] = env->image[seg->file_offset + offset];
        } else {
            buffer[i] = 0;
        }
    }
    return true;
}

__device__ __forceinline__ int contiguous_span(
    const Env *env, int64_t address, int limit
) {
    int span = 0;
    for (int pass = 0; pass <= env->nsegs && span < limit; ++pass) {
        int64_t current = address + span;
        int index = segment_of(env, current);
        if (index < 0) {
            break;
        }
        int64_t end = env->segs[index].va + env->segs[index].mem_size;
        int64_t add = end - current;
        if (add > limit - span) {
            add = limit - span;
        }
        span += (int)add;
    }
    return span;
}

__device__ __forceinline__ int find_entry(
    const int64_t *entries, int count, int64_t value
) {
    int low = 0;
    int high = count - 1;
    while (low <= high) {
        int middle = low + ((high - low) >> 1);
        int64_t candidate = entries[middle];
        if (candidate == value) {
            return middle;
        }
        if (candidate < value) {
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }
    return -1;
}

// ------------------------------------------------------------------- kernels

__global__ void check_addresses_kernel(
    const Env env, int64_t start, int count, uint8_t *avail
) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) {
        return;
    }
    avail[i] = (uint8_t)contiguous_span(
        &env, start + i, MAX_INSTRUCTION_LENGTH);
}

__global__ void decode_range_kernel(
    const Env env,
    int64_t start,
    int count,
    const uint8_t *avail,
    int root,
    uint64_t context,
    uint8_t *out_status,
    uint8_t *out_type,
    uint16_t *out_length,
    int64_t *out_targets,
    uint8_t *out_kinds
) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) {
        return;
    }
    int64_t address = start + i;
    int available = avail[i];
    if (available <= 0) {
        out_status[i] = STATUS_UNDECODED;
        out_type[i] = 0;
        out_length[i] = 0;
        out_kinds[i * 2] = KIND_NONE;
        out_kinds[i * 2 + 1] = KIND_NONE;
        return;
    }

    uint8_t window[MAX_INSTRUCTION_LENGTH];
    for (int k = 0; k < MAX_INSTRUCTION_LENGTH; ++k) {
        window[k] = (k < available) ? fetch_byte(&env, address + k) : 0;
    }

    Env local = env;
    local.win = window;
    Resolution res;
    int status = resolve_full(&local, root, context, &res);
    if (status == 2) {
        out_status[i] = STATUS_DEFER;
        out_type[i] = 0;
        out_length[i] = 0;
        out_kinds[i * 2] = KIND_NONE;
        out_kinds[i * 2 + 1] = KIND_NONE;
        return;
    }
    if (status != 0 || res.length <= 0 || res.length > available) {
        out_status[i] = STATUS_UNDECODED;
        out_type[i] = 0;
        out_length[i] = 0;
        out_kinds[i * 2] = KIND_NONE;
        out_kinds[i * 2 + 1] = KIND_NONE;
        return;
    }

    int64_t targets[2] = {0, 0};
    uint8_t kinds[2] = {KIND_NONE, KIND_NONE};
    build_flows(&res, window, available, address, targets, kinds);

    if (res.type_class == TYPE_NONE) {
        out_status[i] = STATUS_DEFER;
        out_type[i] = 0;
    } else if (res.type_class == TYPE_ARITHMETIC ||
               res.type_class == TYPE_NOP) {
        out_status[i] = STATUS_STRAIGHT;
        out_type[i] = (uint8_t)res.type_class;
    } else {
        out_status[i] = STATUS_FLOW;
        out_type[i] = (uint8_t)res.type_class;
    }
    out_length[i] = (uint16_t)res.length;
    out_targets[i * 2] = targets[0];
    out_targets[i * 2 + 1] = targets[1];
    out_kinds[i * 2] = kinds[0];
    out_kinds[i * 2 + 1] = kinds[1];
}

__global__ void scan_pointers_kernel(
    const Env env,
    int64_t start,
    int count,
    const int64_t *entries,
    int nentries,
    int64_t *hits,
    int *counter,
    int max_hits
) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) {
        return;
    }
    int64_t address = start + i;
    uint8_t buffer[8];

    if (read_bytes(&env, address, 8, buffer)) {
        uint64_t value = 0;
        for (int k = 7; k >= 0; --k) {
            value = (value << 8) | buffer[k];
        }
        int index = find_entry(entries, nentries, (int64_t)value);
        if (index >= 0) {
            int slot = atomicAdd(counter, 1);
            if (slot < max_hits) {
                hits[slot * 2] = address;
                hits[slot * 2 + 1] = entries[index];
            }
        }
        // A 64-bit reading whose high half is zero is the same address as its
        // 32-bit reading; the reference implementation keeps one value.
        int index32 = (value & 0xFFFFFFFFull) == value
                          ? -1
                          : find_entry(entries, nentries,
                                       (int64_t)(value & 0xFFFFFFFFull));
        if (index32 >= 0) {
            int slot = atomicAdd(counter, 1);
            if (slot < max_hits) {
                hits[slot * 2] = address;
                hits[slot * 2 + 1] = entries[index32];
            }
        }
        return;
    }

    if (read_bytes(&env, address, 4, buffer)) {
        uint64_t value = 0;
        for (int k = 3; k >= 0; --k) {
            value = (value << 8) | buffer[k];
        }
        int index = find_entry(entries, nentries, (int64_t)value);
        if (index >= 0) {
            int slot = atomicAdd(counter, 1);
            if (slot < max_hits) {
                hits[slot * 2] = address;
                hits[slot * 2 + 1] = entries[index];
            }
        }
    }
}

// ------------------------------------------------------------------- host API

struct Handle {
    int32_t *tables;
    uint8_t *image;
    Seg *segs;
    int nsegs;
    int64_t image_len;
};

static void launch_1d(int count, int *blocks, int *threads) {
    *threads = 256;
    *blocks = (count + *threads - 1) / *threads;
}

static Env make_env(const Handle *handle) {
    Env env;
    env.tables = handle->tables;
    env.segs = handle->segs;
    env.nsegs = handle->nsegs;
    env.image = handle->image;
    env.image_len = handle->image_len;
    env.win = nullptr;
    env.context = 0;
    return env;
}

extern "C" int codezip_probe(char *name, int name_length) {
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count <= 0) {
        return 0;
    }
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) != cudaSuccess) {
        return 0;
    }
    if (name != nullptr && name_length > 0) {
        strncpy(name, prop.name, (size_t)name_length - 1);
        name[name_length - 1] = '\0';
    }
    return count;
}

extern "C" const char *codezip_error(int code) {
    return cudaGetErrorString((cudaError_t)code);
}

extern "C" int codezip_open(
    const int32_t *tables,
    int32_t tables_length,
    const uint8_t *image,
    int64_t image_length,
    const int64_t *segs,
    int nsegs,
    void **out_handle
) {
    if (tables == nullptr || image == nullptr || segs == nullptr ||
        out_handle == nullptr || tables_length <= 0 || image_length < 0 ||
        nsegs <= 0) {
        return (int)cudaErrorInvalidValue;
    }
    // Resolution recurses through nested subtables and operand definitions, so
    // the default 1 KiB device stack is far too small.
    cudaDeviceSetLimit(cudaLimitStackSize, 1 << 16);

    Handle *handle = new Handle();
    handle->nsegs = nsegs;
    handle->image_len = image_length;
    size_t tables_bytes = (size_t)tables_length * sizeof(int32_t);
    size_t segs_bytes = (size_t)nsegs * sizeof(Seg);

    cudaError_t error = cudaMalloc((void **)&handle->tables, tables_bytes);
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            handle->tables, tables, tables_bytes, cudaMemcpyHostToDevice);
    }
    if (error == cudaSuccess) {
        error = cudaMalloc((void **)&handle->image, (size_t)image_length);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            handle->image, image, (size_t)image_length, cudaMemcpyHostToDevice);
    }
    if (error == cudaSuccess) {
        error = cudaMalloc((void **)&handle->segs, segs_bytes);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            handle->segs, segs, segs_bytes, cudaMemcpyHostToDevice);
    }
    if (error != cudaSuccess) {
        cudaFree(handle->tables);
        cudaFree(handle->image);
        cudaFree(handle->segs);
        delete handle;
        return (int)error;
    }
    *out_handle = handle;
    return 0;
}

extern "C" void codezip_close(void *opaque) {
    Handle *handle = (Handle *)opaque;
    if (handle == nullptr) {
        return;
    }
    cudaFree(handle->tables);
    cudaFree(handle->image);
    cudaFree(handle->segs);
    delete handle;
}

extern "C" int codezip_check_addresses(
    void *opaque, int64_t start, int count, uint8_t *avail
) {
    Handle *handle = (Handle *)opaque;
    if (handle == nullptr || count < 0 || (count > 0 && avail == nullptr)) {
        return (int)cudaErrorInvalidValue;
    }
    if (count == 0) {
        return 0;
    }
    Env env = make_env(handle);

    uint8_t *device = nullptr;
    cudaError_t error = cudaMalloc((void **)&device, (size_t)count);
    if (error != cudaSuccess) {
        return (int)error;
    }
    int blocks = 0;
    int threads = 0;
    launch_1d(count, &blocks, &threads);
    check_addresses_kernel<<<blocks, threads>>>(env, start, count, device);
    error = cudaGetLastError();
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            avail, device, (size_t)count, cudaMemcpyDeviceToHost);
    }
    cudaFree(device);
    return (int)error;
}

extern "C" int codezip_decode_range(
    void *opaque,
    int64_t start,
    int count,
    const uint8_t *avail,
    int root,
    int64_t context_low,
    int64_t context_high,
    uint8_t *out_status,
    uint8_t *out_type,
    uint16_t *out_length,
    int64_t *out_targets,
    uint8_t *out_kinds
) {
    Handle *handle = (Handle *)opaque;
    if (handle == nullptr || count < 0 || avail == nullptr ||
        out_status == nullptr || out_type == nullptr ||
        out_length == nullptr || out_targets == nullptr ||
        out_kinds == nullptr) {
        return (int)cudaErrorInvalidValue;
    }
    if (count == 0) {
        return 0;
    }
    Env env = make_env(handle);
    uint64_t context = ((uint64_t)context_high << 32) | (uint32_t)context_low;

    uint8_t *d_avail = nullptr;
    uint8_t *d_status = nullptr;
    uint8_t *d_type = nullptr;
    uint16_t *d_length = nullptr;
    int64_t *d_targets = nullptr;
    uint8_t *d_kinds = nullptr;
    cudaError_t error = cudaMalloc((void **)&d_avail, (size_t)count);
    if (error == cudaSuccess) {
        error = cudaMalloc((void **)&d_status, (size_t)count);
    }
    if (error == cudaSuccess) {
        error = cudaMalloc((void **)&d_type, (size_t)count);
    }
    if (error == cudaSuccess) {
        error = cudaMalloc((void **)&d_length, (size_t)count * sizeof(uint16_t));
    }
    if (error == cudaSuccess) {
        error = cudaMalloc(
            (void **)&d_targets, (size_t)count * 2 * sizeof(int64_t));
    }
    if (error == cudaSuccess) {
        error = cudaMalloc((void **)&d_kinds, (size_t)count * 2);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            d_avail, avail, (size_t)count, cudaMemcpyHostToDevice);
    }
    if (error == cudaSuccess) {
        int blocks = 0;
        int threads = 0;
        launch_1d(count, &blocks, &threads);
        decode_range_kernel<<<blocks, threads>>>(
            env,
            start,
            count,
            d_avail,
            root,
            context,
            d_status,
            d_type,
            d_length,
            d_targets,
            d_kinds);
        error = cudaGetLastError();
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            out_status, d_status, (size_t)count, cudaMemcpyDeviceToHost);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            out_type, d_type, (size_t)count, cudaMemcpyDeviceToHost);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            out_length, d_length, (size_t)count * sizeof(uint16_t),
            cudaMemcpyDeviceToHost);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            out_targets, d_targets, (size_t)count * 2 * sizeof(int64_t),
            cudaMemcpyDeviceToHost);
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            out_kinds, d_kinds, (size_t)count * 2, cudaMemcpyDeviceToHost);
    }

    cudaFree(d_avail);
    cudaFree(d_status);
    cudaFree(d_type);
    cudaFree(d_length);
    cudaFree(d_targets);
    cudaFree(d_kinds);
    return (int)error;
}

extern "C" int codezip_scan_pointers(
    void *opaque,
    int64_t start,
    int count,
    const int64_t *entries,
    int nentries,
    int64_t *hits,
    int *out_count,
    int max_hits
) {
    Handle *handle = (Handle *)opaque;
    if (handle == nullptr || count < 0 || entries == nullptr ||
        nentries <= 0 || hits == nullptr || out_count == nullptr) {
        return (int)cudaErrorInvalidValue;
    }
    if (count == 0) {
        *out_count = 0;
        return 0;
    }
    Env env = make_env(handle);

    int64_t *d_entries = nullptr;
    int64_t *d_hits = nullptr;
    int *d_counter = nullptr;
    cudaError_t error = cudaMalloc(
        (void **)&d_entries, (size_t)nentries * sizeof(int64_t));
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            d_entries, entries, (size_t)nentries * sizeof(int64_t),
            cudaMemcpyHostToDevice);
    }
    if (error == cudaSuccess) {
        error = cudaMalloc(
            (void **)&d_hits, (size_t)max_hits * 2 * sizeof(int64_t));
    }
    if (error == cudaSuccess) {
        error = cudaMalloc((void **)&d_counter, sizeof(int));
    }
    if (error == cudaSuccess) {
        error = cudaMemset(d_counter, 0, sizeof(int));
    }

    if (error == cudaSuccess) {
        int blocks = 0;
        int threads = 0;
        launch_1d(count, &blocks, &threads);
        scan_pointers_kernel<<<blocks, threads>>>(
            env, start, count, d_entries, nentries, d_hits, d_counter,
            max_hits);
        error = cudaGetLastError();
    }
    if (error == cudaSuccess) {
        error = cudaMemcpy(
            out_count, d_counter, sizeof(int), cudaMemcpyDeviceToHost);
    }
    if (error == cudaSuccess && *out_count > 0) {
        int written = (*out_count < max_hits) ? *out_count : max_hits;
        error = cudaMemcpy(
            hits, d_hits, (size_t)written * 2 * sizeof(int64_t),
            cudaMemcpyDeviceToHost);
    }

    cudaFree(d_entries);
    cudaFree(d_hits);
    cudaFree(d_counter);
    return (int)error;
}
