# IR model and ISA contract

Data model and ISA encoding contract shared by the uplifter, optimizers,
and ISAs. Referenced from plan.txt.

Types:

    class Address:
        enum kind: absolute, UNK_LOCAL, UNK_NONLOCAL
        ulonglong value        # only set when kind == absolute

        UNK_LOCAL: the instruction has targets inside the current function that
            cannot be resolved to a finite set (e.g. an indirect jump through a table).
        UNK_NONLOCAL: the target is outside the function or is not a known function entry.

    class StateSpace:
        enum kind: register, flag, memory
        string name
        uint size

        registers are canonical - sub-registers map to their parent
        flags are one state space
        memory is conservatively aliased until an alias analysis exists
        for memory: base, index, scale, displacement, or an opaque alias set

    class Instruction:
        bytestring original_data
        enum type:
            call
            call_indirect
            branch
            ret
            nop
            arithmetic
            rip_relative
            pc_relative     # forms a PC-relative address without jumping
            outline_result_call

        BasicBlock outline_target
        uint length
        ulonglong address

        list[StateSpace] modifies
        list[StateSpace] depends_on
        list[Address] flows_from
        list[Address] flows_to

    class BasicBlock:
        list[Instruction] instructions
        bool used_for_outlining
        Address start_location
        Function containing_function

        a basic block is a maximal straight-line sequence ending at a branch or return;
        calls do not end a block.  It owns its instructions.

    class Function:
        name
        file_offset
        start_address
        length              # declared extent; outlining never moves it

        list[BasicBlock] basic_blocks
        list[Reference] incoming_references
        list[Reference] outgoing_references

        function has_unk_local_reference:
            return any(ref.to.kind == UNK_LOCAL for ref in outgoing_references)

        a function owns its basic blocks, not its instructions

        outlining may rewrite live code and leave an unused tail inside the
        declared extent.  The tail is reported as FreeSpace; length is not
        reduced.

    class Reference:
        Address from
        Address to

    class JumpRange:
        int minimum
        int maximum

        Inclusive offsets from the start of a fixed-width direct jump.

    class FreeSpace:
        Address start
        uint size
        string diagnostic

Canonical encoding:

    position_invariant_instruction_encoding is the instruction's bytes after
    relinking it to a standard address.  It is the matching key: two instructions
    with the same canonical bytes have the same operands and the same absolute
    targets.

ISA contract:

    class ISA:
        supports_outlining: bool
        function disassemble(binary, address) -> Instruction
        function decode_flows(binary, address) -> DecodedFlow
        function decode_range(binary, start, end) -> Iterator[DecodedFlow | None]
        function decode_control_flow_range(binary, start, end)
                -> Iterator[DecodedFlow]
        pointer_size: int
        function is_outlinable(instruction) -> bool
        function can_reorder_across(instruction) -> bool
        function add_extra_stack_space(instruction, pointer_size) -> Instruction
        function make_call_instruction() -> Instruction
        function outline_call_target_bounds(first, last) -> (min, max) | None
        function jump_displacement_range() -> JumpRange
        function make_return_instruction() -> Instruction
        function uses_red_zone(function) -> bool
        function can_outline_region(function, block, instructions,
                window_start, window_length) -> bool
        function relocate_instruction(instruction, new_base_address) -> Instruction
        function set_instruction_target(instruction, new_target_address) -> Instruction
        function can_encode(instruction, address) -> bool
        function required_length(instruction, address) -> uint
        function try_interpret_as_pointer(binary, offset) -> set[Address]
        function iter_pointer_references(binary, start, end, targets)
                -> Iterator[(address, target)]
        function iter_control_flow_references(binary, start, end, targets)
                -> Iterator[(address, target)]
        function iter_address_references(binary, start, end, targets)
                -> Iterator[(address, target)]

        pointer_size is the architecture's native pointer width in bytes. On
        x86-64 it is also the size of the implicit stack push at an outline call.
        An ISA opts in to outlining with supports_outlining after implementing
        its call, return, and site-safety rules.

        make_call_instruction returns an untargeted direct call with the
        instruction's final length.  make_return_instruction returns the return
        used to end a shared block.  The outliner patches the call's target with
        set_instruction_target after placing the shared block.

        outline_call_target_bounds can give inclusive bounds for a destination
        reachable from both source addresses. An empty interval rejects all
        destinations. None leaves the search unrestricted. Every candidate
        still requires the final set_instruction_target check.

        jump_displacement_range describes the recompiler's direct entry,
        return, and fragment jumps without address wrapping. Placement uses
        it to constrain source or destination addresses and still validates
        the final encoding, including alignment.

        uses_red_zone tracks the stack depth through the function's control-flow
        graph.  It returns true when a memory access is below the current RSP,
        including RBP-relative locals in a frame-pointer function that never
        subtracts from RSP, and when a stack-pointer update cannot be modeled.

        can_outline_region decides whether replacing
        instructions[window_start:window_start + window_length] with a call can
        be done without changing behavior.
        instructions is the block's instruction order after the outliner
        reorders it.  The default implementation returns true.  An ISA that
        pushes a return address over the red zone overrides it to prove that
        the slot the call writes is dead on every path: the moved window must
        not touch the slot, and the slot must not be read before a covering
        write, a call at the same stack depth, or a return makes it dead.
        Instructions that copy RSP or RBP into another register, or compute an
        RSP- or RBP-relative address with LEA, reject the site because the
        analysis cannot follow the alias.

        On RISC-V the call writes the alternate link register x5 (t0) and
        leaves SP alone. The register must be dead at the reordered window's
        exit and the window must neither read nor write it. Functions with
        LR/SC instructions are ineligible because a new jump can change the
        reservation sequence's forward-progress guarantees.

        can_reorder_across allows architectures to mark barriers in addition
        to the outliner's register and memory dependency checks. RISC-V keeps
        calls, atomics, system instructions, and PC-relative instructions in
        place during block reordering.

        try_interpret_as_pointer reads little-endian pointer-sized and 32-bit
        values at offset, and returns every Address that could be read.  A
        width whose read would cross unmapped memory is omitted, so an offset
        near the end of a mapped range can still yield a 32-bit address.

        decode_flows returns the address, length, type, and flows_to of the
        instruction at address without computing modifies or depends_on.  Those
        state effects dominate decode cost, and a whole-image cross-reference
        scan only needs control flow.  The reported fields are identical to
        disassemble's, and the same ValueError is raised when no instruction
        decodes.

        decode_range decodes one instruction at every address in [start, end),
        yielding None where nothing decodes.  It is the whole-image form of
        decode_flows: element i is decode_flows(start + i) or None.  An ISA may
        override it to batch the work, but the results must not differ.

        decode_control_flow_range is decode_range restricted to the flows that
        can produce a cross-reference.  Straight-line instructions are dropped
        because their only flow is the fallthrough, which is never a reference.
        It must never drop a flow the default filter would have kept.

        iter_pointer_references yields (address, target) for every address in
        [start, end) whose pointer readings include a value in targets.  It
        matches calling try_interpret_as_pointer at each address.

        iter_control_flow_references yields absolute targets in targets from
        decode_control_flow_range in the same order. It omits fallthrough
        edges unless the decoded instruction is a branch.

        iter_address_references yields (address, target) for target addresses
        formed across instruction sequences in [start, end). The source is
        the instruction that materializes or consumes the address. For example,
        RISC-V uses LUI or AUIPC to form a base and a separate instruction to
        apply the signed low offset. A scanner may overestimate references.

        disassemble fills flows_to:
            straight-line instruction: [address + length]
            direct conditional branch: [target, address + length]
            direct unconditional branch: [target]
            direct call: [target, address + length]
            indirect branch: [UNK_LOCAL]
            indirect call: [UNK_NONLOCAL, address + length]
            return: []
            flows_from is left empty; the code-flow recovery pass fills it.

        disassemble models unknown transfers conservatively using the
        architecture's calling convention. On x86-64:
            calls depend on the System V AMD64 argument state (RDI, RSI, RDX,
            RCX, R8, R9, ZMM0-ZMM7, RAX for varargs, RSP, and memory)
            calls, returns, and indirect branches clobber every tracked state
            space except callee-saved RBX, RBP, R12-R15

        On RISC-V, state uses ABI register names at their full width. The
        immutable zero register contributes no state. CSR accesses share one
        csreg space and alias floating-point status and rounding state. Calls
        conservatively depend on integer and floating-point argument registers,
        SP, GP, TP, and memory. Unknown transfers preserve the integer
        callee-saved registers, SP, GP, and TP.

        is_outlinable returns false if:
            flows are present and flows_to is not a single fallthrough edge
            rsp is in modifies (push / pop / call / leave / add rsp)
            rsp is used as a value rather than only as an address base
            type is call, call_indirect, branch, or ret
            the instruction is a trap or control transfer (int, hlt, ud2, ...)
            an rsp-relative memory operand cannot be biased in place

        add_extra_stack_space returns a re-encoded instruction with [pointer size]
        added to every rsp-relative memory operand.  It is used for instructions
        that are being outlined, since the outlining call pushes a return address
        and changes rsp by that amount.  Registers that the call does not change,
        such as rbp, are left alone.  It raises ValueError if the instruction
        cannot be re-encoded without changing length or semantics.

        relocate_instruction preserves the instruction's absolute target(s):
            a moved call still calls the same address, and a moved rip-relative
            load still reads the same location.  It may return a different length.
            RISC-V re-encodes B, J, CB, and CJ displacements from the current
            PC. AUIPC can move only when its original result remains encodable
            in the existing upper-immediate field, without changing a consumer.

        set_instruction_target returns the re-encoded instruction and fails if the
            new target does not fit (e.g. jmp rel8 out of range).

        can_encode / required_length let callers reject growth before committing.

        no full assembler is required: relocated instructions are patched in place
        (disp / imm fields), and synthesized instructions are emitted by a small encoder.

Invariants:

    - BasicBlock is the only owner of instructions.
    - Function is the only owner of basic blocks.
    - flows_from / flows_to are absolute addresses, not block-relative.
    - every instruction that can be outlined has is_outlinable == true.
    - no instruction is relocated without an isa.can_encode check.
