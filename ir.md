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
            outline_result_call

        BasicBlock outline_target
        uint length
        ulonglong address

        list[StateSpace] modifies
        list[StateSpace] depends_on
        list[Address] flows_from
        list[Address] flows_to

        function is_outlinable:
            false if flows_to != flows_from + 1
            false if rsp is in modifies (push / pop / call / leave / add rsp)
            false if type is ret or call_indirect

        function add_extra_stack_space:
            adds [pointer size] to all stack-relative memory operands
            [to be used for instructions that are being outlined, since they'll run with that many more bytes on the stack]

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
        length

        list[BasicBlock] basic_blocks
        list[Reference] incoming_references
        list[Reference] outgoing_references

        function has_unk_local_reference:
            return any(ref.to.kind == UNK_LOCAL for ref in outgoing_references)

        function uses_red_zone:
            scan all instructions for negative stack accesses - leaf functions that access the stack that way can't get outlined.

        a function owns its basic blocks, not its instructions

    class Reference:
        Address from
        Address to

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
        function disassemble(binary, address) -> Instruction
        function relocate_instruction(instruction, new_base_address) -> Instruction
        function set_instruction_target(instruction, new_target_address) -> Instruction
        function can_encode(instruction, address) -> bool
        function required_length(instruction, address) -> uint
        function try_interpret_as_pointer(binary, offset) -> Address | None

        relocate_instruction preserves the instruction's absolute target(s):
            a moved call still calls the same address, and a moved rip-relative
            load still reads the same location.  It may return a different length.

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
