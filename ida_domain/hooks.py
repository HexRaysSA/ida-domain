# type: ignore
import logging

import ida_idaapi
from ida_dbg import DBG_Hooks
from ida_hexrays import Hexrays_Hooks
from ida_idp import IDB_Hooks, IDP_Hooks
from ida_kernwin import UI_Hooks, View_Hooks
from typing_extensions import Any, TypeAlias, Union

from .base import DatabaseEntity

logger = logging.getLogger(__name__)


class _BaseHooks(DatabaseEntity):
    def __init__(self) -> None:
        super().__init__(None)
        self._is_hooked: bool = False

    @property
    def is_hooked(self) -> bool:
        return self._is_hooked

    def log(self, msg: str = '') -> None:
        """
        Utility method to optionally log called hooks and their parameters.
        """
        import inspect

        if msg:
            logger.debug('>>> %s: %s' % self.__class__.__name__ % msg)
        else:
            stack = inspect.stack()
            frame, _, _, _, _, _ = stack[1]
            args, _, _, values = inspect.getargvalues(frame)
            method_name = inspect.getframeinfo(frame)[2]
            argstrs = []
            for arg in args[1:]:
                argstrs.append('%s=%s' % (arg, str(values[arg])))
            logger.debug(
                '>>> %s.%s: %s' % (self.__class__.__name__, method_name, ', '.join(argstrs))
            )


class ProcessorHooks(_BaseHooks, IDP_Hooks):
    """
    Convenience class for IDP (processor) events handling.
    """

    def __init__(self) -> None:
        _BaseHooks.__init__(self)
        IDP_Hooks.__init__(self)

    def hook(self) -> None:
        """
        Hook (activate) the event handlers.
        """
        if not self.is_hooked:
            if IDP_Hooks.hook(self):
                self._is_hooked = True

    def unhook(self) -> None:
        """
        Un-hook (de-activate) the event handlers.
        """
        if self.is_hooked:
            if IDP_Hooks.unhook(self):
                self._is_hooked = False

    def ev_init(
        self,
        idp_modname: str,
    ) -> int:
        """
        The IDP module is just loaded.

        Args:
            idp_modname (str): Processor module name.

        Returns:
            int: <0 on failure.
        """
        return IDP_Hooks.ev_init(self, idp_modname)

    def ev_term(
        self,
    ) -> int:
        """
        The IDP module is being unloaded.
        """
        return IDP_Hooks.ev_term(self)

    def ev_newprc(
        self,
        pnum: int,
        keep_cfg: bool,
    ) -> int:
        """
        Called before changing processor type.

        Args:
            pnum (int): Processor number in the array of processor names.
            keep_cfg (bool): True to not modify kernel configuration.

        Returns:
            int: 1 if OK, <0 to prohibit change.
        """
        return IDP_Hooks.ev_newprc(self, pnum, keep_cfg)

    def ev_newasm(
        self,
        asmnum: int,
    ) -> int:
        """
        Called before setting a new assembler.

        Args:
            asmnum (int): The assembler number. See also ev_asm_installed.
        """
        return IDP_Hooks.ev_newasm(self, asmnum)

    def ev_newfile(
        self,
        fname: 'char *',
    ) -> int:
        """
        Called when a new file has been loaded.

        Args:
            fname (char *): The input file name.
        """
        return IDP_Hooks.ev_newfile(self, fname)

    def ev_oldfile(
        self,
        fname: 'char *',
    ) -> int:
        """
        Called when an old file has been loaded.

        Args:
            fname (char *): The input file name.
        """
        return IDP_Hooks.ev_oldfile(self, fname)

    def ev_newbinary(
        self,
        filename: 'char *',
        fileoff: 'qoff64_t',
        basepara: 'ida_idaapi.ea_t',
        binoff: 'ida_idaapi.ea_t',
        nbytes: 'uint64',
    ) -> int:
        """
        Called when IDA is about to load a binary file.

        Args:
            filename (char *): Binary file name.
            fileoff (qoff64_t): Offset in the file.
            basepara (ea_t): Base loading paragraph.
            binoff (ea_t): Loader offset.
            nbytes (uint64): Number of bytes to load.
        """
        return IDP_Hooks.ev_newbinary(self, filename, fileoff, basepara, binoff, nbytes)

    def ev_endbinary(
        self,
        ok: bool,
    ) -> int:
        """
        Called after IDA has loaded a binary file.

        Args:
            ok (bool): True if file loaded successfully.
        """
        return IDP_Hooks.ev_endbinary(self, ok)

    def ev_set_proc_options(
        self,
        options: str,
        confidence: int,
    ) -> int:
        """
        Called if the user specified an option string in the command line or via SetProcessorType.

        Can be used for setting a processor subtype. Also called if option string is passed to
        set_processor_type() and IDC's SetProcessorType().

        Args:
            options (str): Option string (e.g., processor subtype).
            confidence (int): 0 for loader's suggestion, 1 for user's decision.

        Returns:
            int: <0 if bad option string.
        """
        return IDP_Hooks.ev_set_proc_options(self, options, confidence)

    def ev_ana_insn(
        self,
        out: 'insn_t *',
    ) -> bool:
        """
        Analyze one instruction and fill the 'out' structure.

        This function shouldn't change the database, flags, or anything else.
        All such actions should be performed only by ev_emu_insn().
        insn_t::ea contains address of instruction to analyze.

        Args:
            out (insn_t *): Structure to be filled with the analyzed instruction.

        Returns:
            bool: Length of the instruction in bytes, or 0 if instruction can't be decoded.
        """
        return IDP_Hooks.ev_ana_insn(self, out)

    def ev_emu_insn(
        self,
        insn: 'insn_t const *',
    ) -> bool:
        """
        Emulate an instruction, create cross-references, plan subsequent analyses,
        modify flags, etc.

        Upon entry, all information about the instruction is in the 'insn' structure.

        Args:
            insn (insn_t const *): Structure containing instruction information.

        Returns:
            bool: True (1) if OK; False (-1) if the kernel should delete the instruction.
        """
        return IDP_Hooks.ev_emu_insn(self, insn)

    def ev_out_header(
        self,
        outctx: 'outctx_t *',
    ) -> int:
        """
        Produce the start of disassembled text.

        Args:
            outctx (outctx_t *): Output context.
        """
        return IDP_Hooks.ev_out_header(self, outctx)

    def ev_out_footer(
        self,
        outctx: 'outctx_t *',
    ) -> int:
        """
        Produce the end of disassembled text.

        Args:
            outctx (outctx_t *): Output context.
        """
        return IDP_Hooks.ev_out_footer(self, outctx)

    def ev_out_segstart(
        self,
        outctx: 'outctx_t *',
        seg: 'segment_t *',
    ) -> int:
        """
        Produce the start of a segment in disassembled output.

        Args:
            outctx (outctx_t *): Output context.
            seg (segment_t *): Segment.

        Returns:
            int: 1 if OK, 0 if not implemented.
        """
        return IDP_Hooks.ev_out_segstart(self, outctx, seg)

    def ev_out_segend(
        self,
        outctx: 'outctx_t *',
        seg: 'segment_t *',
    ) -> int:
        """
        Produce the end of a segment in disassembled output.

        Args:
            outctx (outctx_t *): Output context.
            seg (segment_t *): Segment.

        Returns:
            int: 1 if OK, 0 if not implemented.
        """
        return IDP_Hooks.ev_out_segend(self, outctx, seg)

    def ev_out_assumes(
        self,
        outctx: 'outctx_t *',
    ) -> int:
        """
        Produce assume directives when segment register value changes.

        Args:
            outctx (outctx_t *): Output context.

        Returns:
            int: 1 if OK, 0 if not implemented.
        """
        return IDP_Hooks.ev_out_assumes(self, outctx)

    def ev_out_insn(
        self,
        outctx: 'outctx_t *',
    ) -> bool:
        """
        Generate text representation of an instruction in 'ctx.insn'.

        outctx_t provides functions to output the generated text.
        This function shouldn't change the database, flags, or anything else.
        All these actions should be performed only by emu_insn().

        Args:
            outctx (outctx_t *): Output context.
        """
        return IDP_Hooks.ev_out_insn(self, outctx)

    def ev_out_mnem(
        self,
        outctx: 'outctx_t *',
    ) -> int:
        """
        Generate instruction mnemonics.

        This callback should append the colored mnemonics to ctx.outbuf. Optional notification;
        if absent, out_mnem will be called.

        Args:
            outctx (outctx_t *): Output context.

        Returns:
            int: 1 if appended the mnemonics, 0 if not implemented.
        """
        return IDP_Hooks.ev_out_mnem(self, outctx)

    def ev_out_operand(
        self,
        outctx: 'outctx_t *',
        op: 'op_t const *',
    ) -> bool:
        """
        Generate text representation of an instruction operand.

        outctx_t provides functions to output the generated text.
        All these actions should be performed only by emu_insn().

        Args:
            outctx (outctx_t *): Output context.
            op (op_t const *): Operand.

        Returns:
            bool: True (1) if OK, False (-1) if the operand is hidden.
        """
        return IDP_Hooks.ev_out_operand(self, outctx, op)

    def ev_out_data(
        self,
        outctx: 'outctx_t *',
        analyze_only: bool,
    ) -> int:
        """
        Generate text representation of data items.

        This function may change the database and create cross-references if analyze_only is set.

        Args:
            outctx (outctx_t *): Output context.
            analyze_only (bool): True if only analysis should be performed.

        Returns:
            int: 1 if OK, 0 if not implemented.
        """
        return IDP_Hooks.ev_out_data(self, outctx, analyze_only)

    def ev_out_label(
        self,
        outctx: 'outctx_t *',
        colored_name: str,
    ) -> int:
        """
        The kernel is going to generate an instruction label line or a function header.

        Args:
            outctx (outctx_t *): Output context.
            colored_name (str): Colored name string.

        Returns:
            int: <0 if the kernel should not generate the label, 0 if not implemented or continue.
        """
        return IDP_Hooks.ev_out_label(self, outctx, colored_name)

    def ev_out_special_item(
        self,
        outctx: 'outctx_t *',
        segtype: 'uchar',
    ) -> int:
        """
        Generate text representation of an item in a special segment.

        Examples: absolute symbols, externs, communal definitions, etc.

        Args:
            outctx (outctx_t *): Output context.
            segtype (uchar): Segment type.

        Returns:
            int: 1 if OK, 0 if not implemented, -1 on overflow.
        """
        return IDP_Hooks.ev_out_special_item(self, outctx, segtype)

    def ev_gen_regvar_def(
        self,
        outctx: 'outctx_t *',
        v: 'regvar_t *',
    ) -> int:
        """
        Generate register variable definition line.

        Args:
            outctx (outctx_t *): Output context.
            v (regvar_t *): Register variable.

        Returns:
            int: >0 if generated the definition text, 0 if not implemented.
        """
        return IDP_Hooks.ev_gen_regvar_def(self, outctx, v)

    def ev_gen_src_file_lnnum(
        self,
        outctx: 'outctx_t *',
        file: str,
        lnnum: 'size_t',
    ) -> int:
        """
        Callback: generate an analog of '#line 123'.

        Args:
            outctx (outctx_t *): Output context.
            file (str): Source file name (may be None).
            lnnum (size_t): Line number.

        Returns:
            int: 1 if directive has been generated, 0 if not implemented.
        """
        return IDP_Hooks.ev_gen_src_file_lnnum(self, outctx, file, lnnum)

    def ev_creating_segm(
        self,
        seg: 'segment_t *',
    ) -> int:
        """
        A new segment is about to be created.

        Args:
            seg (segment_t *): The segment being created.

        Returns:
            int: 1 if OK, <0 if the segment should not be created.
        """
        return IDP_Hooks.ev_creating_segm(self, seg)

    def ev_moving_segm(
        self,
        seg: 'segment_t *',
        to: ida_idaapi.ea_t,
        flags: int,
    ) -> int:
        """
        May the kernel move the segment?

        Args:
            seg (segment_t *): Segment to move.
            to (ea_t): New segment start address.
            flags (int): Combination of Move segment flags.

        Returns:
            int: 0 for yes, <0 for the kernel should stop.
        """
        return IDP_Hooks.ev_moving_segm(self, seg, to, flags)

    def ev_coagulate(
        self,
        start_ea: ida_idaapi.ea_t,
    ) -> int:
        """
        Try to define some unexplored bytes.

        This notification will be called if the kernel tried all possibilities and could not find
        anything more useful than to convert to array of bytes. The module can help the kernel and
        convert the bytes into something more useful.

        Args:
            start_ea (ea_t): Start address.

        Returns:
            int: Number of converted bytes.
        """
        return IDP_Hooks.ev_coagulate(self, start_ea)

    def ev_undefine(
        self,
        ea: ida_idaapi.ea_t,
    ) -> int:
        """
        An item in the database (instruction or data) is being deleted.

        Args:
            ea (ea_t): Address.

        Returns:
            int: 1 to not delete srranges at the item end, 0 to allow srranges to be deleted.
        """
        return IDP_Hooks.ev_undefine(self, ea)

    def ev_treat_hindering_item(
        self,
        hindering_item_ea: ida_idaapi.ea_t,
        new_item_flags: 'flags64_t',
        new_item_ea: ida_idaapi.ea_t,
        new_item_length: 'asize_t',
    ) -> int:
        """
        An item hinders creation of another item.

        Args:
            hindering_item_ea (ea_t): Address of the hindering item.
            new_item_flags (flags64_t): Flags for the new item (0 for code).
            new_item_ea (ea_t): Address of the new item.
            new_item_length (asize_t): Length of the new item.

        Returns:
            int: 0 for no reaction, !=0 if the kernel may delete the hindering item.
        """
        return IDP_Hooks.ev_treat_hindering_item(
            self,
            hindering_item_ea,
            new_item_flags,
            new_item_ea,
            new_item_length,
        )

    def ev_rename(
        self,
        ea: ida_idaapi.ea_t,
        new_name: str,
    ) -> int:
        """
        The kernel is going to rename a byte.

        Args:
            ea (ea_t): Address of the item to rename.
            new_name (str): New name to assign.

        Returns:
            int:
                <0: If the kernel should not rename it.
                 2: To inhibit the notification. The kernel should not rename, but 'set_name()'
                    should return 'true'. (Also see 'renamed'.)
                 The return value is ignored when kernel is going to delete name.
        """
        return IDP_Hooks.ev_rename(self, ea, new_name)

    def ev_is_far_jump(
        self,
        icode: int,
    ) -> int:
        """
        Checks if the instruction is an indirect far jump or call instruction.
        Meaningful only if the processor has 'near' and 'far' reference types.

        Args:
            icode (int): Instruction code.

        Returns:
            int:
                0: Not implemented.
                1: Yes, is a far jump/call.
               -1: No.
        """
        return IDP_Hooks.ev_is_far_jump(self, icode)

    def ev_is_sane_insn(
        self,
        insn: 'insn_t const *',
        no_crefs: int,
    ) -> int:
        """
        Checks if the instruction is sane for the current file type.

        Args:
            insn (insn_t const *): The instruction.
            no_crefs (int): 1 if the instruction has no code refs
                (IDA just tries to convert unexplored bytes to an instruction),
                0 if created because of some coderef, user request or other
                weighty reason.

        Returns:
            int:
                >=0: OK (sane).
                <0: No, the instruction isn't likely to appear in the program.
        """
        return IDP_Hooks.ev_is_sane_insn(self, insn, no_crefs)

    def ev_is_cond_insn(
        self,
        insn: 'insn_t const *',
    ) -> int:
        """
        Checks if the instruction is conditional.

        Args:
            insn (insn_t const *): The instruction address.

        Returns:
            int:
                1: Yes, conditional instruction.
               -1: No, not conditional.
                0: Not implemented or not an instruction.
        """
        return IDP_Hooks.ev_is_cond_insn(self, insn)

    def ev_is_call_insn(
        self,
        insn: 'insn_t const *',
    ) -> int:
        """
        Checks if the instruction is a "call".

        Args:
            insn (insn_t const *): The instruction.

        Returns:
            int:
                0: Unknown.
               <0: No, not a call.
                1: Yes, is a call.
        """
        return IDP_Hooks.ev_is_call_insn(self, insn)

    def ev_is_ret_insn(
        self,
        insn: 'insn_t const *',
        flags: 'uchar',
    ) -> int:
        """
        Checks if the instruction is a "return".

        Args:
            insn (insn_t const *): The instruction.
            flags (uchar): Combination of IRI_... flags.

        Returns:
            int:
                0: Unknown.
               <0: No, not a return.
                1: Yes, is a return.
        """
        return IDP_Hooks.ev_is_ret_insn(self, insn, flags)

    def ev_may_be_func(
        self,
        insn: 'insn_t const *',
        state: int,
    ) -> int:
        """
        Checks if a function can start at this instruction.

        Args:
            insn (insn_t const *): The instruction.
            state (int): Autoanalysis phase. 0 for creating functions, 1 for creating chunks.

        Returns:
            int: Probability (1..100).
        """
        return IDP_Hooks.ev_may_be_func(self, insn, state)

    def ev_is_basic_block_end(
        self,
        insn: 'insn_t const *',
        call_insn_stops_block: bool,
    ) -> int:
        """
        Checks if the current instruction is the end of a basic block.

        This function should be defined for processors with delayed jump slots.

        Args:
            insn (insn_t const *): The instruction.
            call_insn_stops_block (bool): True if call instruction stops block.

        Returns:
            int:
                0: Unknown.
               <0: No, not the end.
                1: Yes, is the end.
        """
        return IDP_Hooks.ev_is_basic_block_end(self, insn, call_insn_stops_block)

    def ev_is_indirect_jump(
        self,
        insn: 'insn_t const *',
    ) -> int:
        """
        Determine if instruction is an indirect jump.

        If CF_JUMP bit cannot describe all jump types, please define this callback.

        Args:
            insn (insn_t const *): The instruction.

        Returns:
            int:
                0: Use CF_JUMP.
                1: No, not indirect jump.
                2: Yes, is indirect jump.
        """
        return IDP_Hooks.ev_is_indirect_jump(self, insn)

    def ev_is_insn_table_jump(
        self,
    ) -> int:
        """
        Reserved.
        """
        return IDP_Hooks.ev_is_insn_table_jump(self)

    def ev_is_switch(
        self,
        si: 'switch_info_t',
        insn: 'insn_t const *',
    ) -> int:
        """
        Find 'switch' idiom or override processor module's decision.

        Called for instructions marked with CF_JUMP.

        Args:
            si (switch_info_t): Output, switch info.
            insn (insn_t const *): Instruction possibly belonging to a switch.

        Returns:
            int:
                1: Switch is found, 'si' is filled.
                -1: No switch found. Forbids switch creation by processor module.
                0: Not implemented.
        """
        return IDP_Hooks.ev_is_switch(self, si, insn)

    def ev_calc_switch_cases(
        self,
        casevec: 'casevec_t *',
        targets: 'eavec_t *',
        insn_ea: ida_idaapi.ea_t,
        si: 'switch_info_t',
    ) -> int:
        """
        Calculate case values and targets for a custom jump table.

        Args:
            casevec (casevec_t *): Vector of case values (may be None).
            targets (eavec_t *): Corresponding target addresses (may be None).
            insn_ea (ea_t): Address of the 'indirect jump' instruction.
            si (switch_info_t): Switch information.

        Returns:
            int:
                1: Success.
                <=0: Failed.
        """
        return IDP_Hooks.ev_calc_switch_cases(self, casevec, targets, insn_ea, si)

    def ev_create_switch_xrefs(
        self,
        jumpea: ida_idaapi.ea_t,
        si: 'switch_info_t',
    ) -> int:
        """
        Create xrefs for a custom jump table.

        Must be implemented if module uses custom jump tables, SWI_CUSTOM.

        Args:
            jumpea (ea_t): Address of the jump instruction.
            si (switch_info_t): Switch information.

        Returns:
            int: Must return 1.
        """
        return IDP_Hooks.ev_create_switch_xrefs(self, jumpea, si)

    def ev_is_align_insn(
        self,
        ea: ida_idaapi.ea_t,
    ) -> int:
        """
        Checks if the instruction is created only for alignment purposes.

        Do not directly call this function, use is_align_insn().

        Args:
            ea (ea_t): Instruction address.

        Returns:
            int: Number of bytes in the instruction.
        """
        return IDP_Hooks.ev_is_align_insn(self, ea)

    def ev_is_alloca_probe(
        self,
        ea: ida_idaapi.ea_t,
    ) -> int:
        """
        Checks if the function at 'ea' behaves as __alloca_probe.

        Args:
            ea (ea_t): Function address.

        Returns:
            int:
                1: Yes.
                0: No.
        """
        return IDP_Hooks.ev_is_alloca_probe(self, ea)

    def ev_delay_slot_insn(
        self,
        ea: 'ida_idaapi.ea_t',
        bexec: bool,
        fexec: bool,
    ) -> 'PyObject *':
        """
        Get delay slot instruction.

        Args:
            ea (ea_t): Input: Instruction address in question.
                Output: If the answer is positive and the delay slot contains a valid instruction,
                returns the address of the delay slot instruction, else BADADDR
                (invalid instruction, e.g. a branch).
            bexec (bool): Execute slot if jumping, initially set to True.
            fexec (bool): Execute slot if not jumping, initially set to True.

        Returns:
            PyObject*: 1 for a positive answer, <=0 for ordinary instruction.
        """
        return IDP_Hooks.ev_delay_slot_insn(self, ea, bexec, fexec)

    def ev_is_sp_based(
        self,
        mode: 'int *',
        insn: 'insn_t const *',
        op: 'op_t const *',
    ) -> int:
        """
        Check whether the operand is relative to stack pointer or frame pointer.

        This event is used to determine how to output a stack variable.
        If not implemented, all operands are sp based by default.
        Implement this only if some stack references use frame pointer instead
        of stack pointer.

        Args:
            mode (int *): Out, combination of SP/FP operand flags.
            insn (insn_t const *): The instruction.
            op (op_t const *): The operand.

        Returns:
            int: 0 if not implemented, 1 if ok.
        """
        return IDP_Hooks.ev_is_sp_based(self, mode, insn, op)

    def ev_can_have_type(
        self,
        op: 'op_t const *',
    ) -> int:
        """
        Can the operand have a type (offset, segment, decimal, etc)?

        For example, a register AX can't have a type,
        meaning the user can't change its representation.
        See bytes.hpp for information about types and flags.

        Args:
            op (op_t const *): The operand.

        Returns:
            int: 0 if unknown, <0 if no, 1 if yes.
        """
        return IDP_Hooks.ev_can_have_type(self, op)

    def ev_cmp_operands(
        self,
        op1: 'op_t const *',
        op2: 'op_t const *',
    ) -> int:
        """
        Compare instruction operands.

        Args:
            op1 (op_t const *): First operand.
            op2 (op_t const *): Second operand.

        Returns:
            int: 1 if equal, -1 if not equal, 0 if not implemented.
        """
        return IDP_Hooks.ev_cmp_operands(self, op1, op2)

    def ev_adjust_refinfo(
        self,
        ri: 'refinfo_t',
        ea: 'ida_idaapi.ea_t',
        n: int,
        fd: 'fixup_data_t const *',
    ) -> int:
        """
        Called from apply_fixup before converting operand to reference.

        Can be used for changing the reference info (e.g. PPC module adds REFINFO_NOBASE for some
        references).

        Args:
            ri (refinfo_t): Reference info.
            ea (ea_t): Instruction address.
            n (int): Operand number.
            fd (fixup_data_t const *): Fixup data.

        Returns:
            int: <0 to not create an offset, 0 if not implemented or refinfo adjusted.
        """
        return IDP_Hooks.ev_adjust_refinfo(self, ri, ea, n, fd)

    def ev_get_operand_string(
        self,
        insn: 'insn_t const *',
        opnum: int,
    ) -> 'PyObject *':
        """
        Request text string for operand (cli, java, ...).

        Args:
            insn (insn_t const *): The instruction.
            opnum (int): Operand number, -1 means any string operand.

        Returns:
            PyObject*: 0 if no string (or empty string), >0 for original string length (without
            terminating zero).
        """
        return IDP_Hooks.ev_get_operand_string(self, insn, opnum)

    def ev_get_reg_name(
        self,
        reg: int,
        width: 'size_t',
        reghi: int,
    ) -> 'PyObject *':
        """
        Generate text representation of a register.

        Most processor modules do not need to implement this callback. It is useful only if
        processor_t::reg_names[reg] does not provide the correct register name.

        Args:
            reg (int): Internal register number as defined in the processor module.
            width (size_t): Register width in bytes.
            reghi (int): If not -1, returns the register pair.

        Returns:
            PyObject*: -1 if error, strlen(buf) if success.
        """
        return IDP_Hooks.ev_get_reg_name(self, reg, width, reghi)

    def ev_str2reg(
        self,
        regname: str,
    ) -> int:
        """
        Convert a register name to a register number.

        The register number is the register index in the processor_t::reg_names array.
        Most processor modules do not need to implement this callback; useful only if
        processor_t::reg_names[reg] does not provide the correct register names.

        Args:
            regname (str): Register name.

        Returns:
            int: Register number + 1, 0 if not implemented or could not be decoded.
        """
        return IDP_Hooks.ev_str2reg(self, regname)

    def ev_get_autocmt(
        self,
        insn: 'insn_t const *',
    ) -> 'PyObject *':
        """
        Callback: get dynamic auto comment.

        Will be called if the autocomments are enabled and the comment retrieved from ida.int
        starts with '$!'. 'insn' contains valid info.

        Args:
            insn (insn_t const *): The instruction.

        Returns:
            PyObject*: 1 if a new comment has been generated,
                0 if not handled (buffer not changed).
        """
        return IDP_Hooks.ev_get_autocmt(self, insn)

    def ev_get_bg_color(
        self,
        color: 'bgcolor_t *',
        ea: 'ida_idaapi.ea_t',
    ) -> int:
        """
        Get item background color.

        Plugins can hook this callback to color disassembly lines dynamically.

        Args:
            color (bgcolor_t *): Out, background color.
            ea (ea_t): Address.

        Returns:
            int: 0 if not implemented, 1 if color set.
        """
        return IDP_Hooks.ev_get_bg_color(self, color, ea)

    def ev_is_jump_func(
        self,
        pfn: 'func_t *',
        jump_target: 'ea_t *',
        func_pointer: 'ea_t *',
    ) -> int:
        """
        Determine if the function is a trivial "jump" function.

        Args:
            pfn (func_t *): The function.
            jump_target (ea_t *): Out, jump target.
            func_pointer (ea_t *): Out, function pointer.

        Returns:
            int: <0 if no, 0 if don't know, 1 if yes (see jump_target and func_pointer).
        """
        return IDP_Hooks.ev_is_jump_func(self, pfn, jump_target, func_pointer)

    def ev_func_bounds(
        self,
        possible_return_code: 'int *',
        pfn: 'func_t *',
        max_func_end_ea: 'ida_idaapi.ea_t',
    ) -> int:
        """
        Called after find_func_bounds() finishes. The module may fine-tune the function bounds.

        Args:
            possible_return_code (int *): In/out, possible return code.
            pfn (func_t *): The function.
            max_func_end_ea (ea_t): From the kernel's point of view.
        """
        return IDP_Hooks.ev_func_bounds(self, possible_return_code, pfn, max_func_end_ea)

    def ev_verify_sp(
        self,
        pfn: 'func_t *',
    ) -> int:
        """
        Called after all function instructions have been analyzed.

        Now the processor module can analyze the stack pointer for the whole function.

        Args:
            pfn (func_t *): The function.

        Returns:
            int: 0 if ok, <0 if bad stack pointer.
        """
        return IDP_Hooks.ev_verify_sp(self, pfn)

    def ev_verify_noreturn(
        self,
        pfn: 'func_t *',
    ) -> int:
        """
        The kernel wants to set 'noreturn' flags for a function.

        Args:
            pfn (func_t *): The function.

        Returns:
            int: 0 if ok, any other value means do not set 'noreturn' flag.
        """
        return IDP_Hooks.ev_verify_noreturn(self, pfn)

    def ev_create_func_frame(
        self,
        pfn: 'func_t *',
    ) -> int:
        """
        Create a function frame for a newly created function.

        Set up frame size, its attributes, etc.

        Args:
            pfn (func_t *): The function.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_create_func_frame(self, pfn)

    def ev_get_frame_retsize(
        self,
        frsize: 'int *',
        pfn: 'func_t const *',
    ) -> int:
        """
        Get size of function return address in bytes.

        If not implemented, the kernel will assume:
            * 8 bytes for 64-bit function
            * 4 bytes for 32-bit function
            * 2 bytes otherwise

        Args:
            frsize (int *): Out, frame size.
            pfn (func_t const *): The function (cannot be nullptr).

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_get_frame_retsize(self, frsize, pfn)

    def ev_get_stkvar_scale_factor(
        self,
    ) -> int:
        """
        Should stack variable references be multiplied by a coefficient
        before being used in the stack frame?

        Currently used by TMS320C55 because the references into the stack
        should be multiplied by 2.

        Returns:
            int: Scaling factor, or 0 if not implemented.
        """
        return IDP_Hooks.ev_get_stkvar_scale_factor(self)

    def ev_demangle_name(
        self,
        name: str,
        disable_mask: int,
        demreq: int,
    ) -> 'PyObject *':
        """
        Demangle a C++ (or other language) name into a user-readable string.

        This event is called by demangle_name().

        Args:
            name (str): Mangled name.
            disable_mask (int): Flags to inhibit parts of output or compiler info/other (see MNG_).
            demreq (int): Operation to perform (demreq_type_t).

        Returns:
            PyObject*: 1 if success, 0 if not implemented.
        """
        return IDP_Hooks.ev_demangle_name(self, name, disable_mask, demreq)

    def ev_add_cref(
        self,
        _from: 'ida_idaapi.ea_t',
        to: 'ida_idaapi.ea_t',
        type: 'cref_t',
    ) -> int:
        """
        A code reference is being created.

        Args:
            _from (ea_t): Source address.
            to (ea_t): Target address.
            type (cref_t): Reference type.

        Returns:
            int: <0 to cancel cref creation, 0 to not implement or continue.
        """
        return IDP_Hooks.ev_add_cref(self, _from, to, type)

    def ev_add_dref(
        self,
        _from: 'ida_idaapi.ea_t',
        to: 'ida_idaapi.ea_t',
        type: 'dref_t',
    ) -> int:
        """
        A data reference is being created.

        Args:
            _from (ea_t): Source address.
            to (ea_t): Target address.
            type (dref_t): Reference type.

        Returns:
            int: <0 to cancel dref creation, 0 to not implement or continue.
        """
        return IDP_Hooks.ev_add_dref(self, _from, to, type)

    def ev_del_cref(
        self,
        _from: 'ida_idaapi.ea_t',
        to: 'ida_idaapi.ea_t',
        expand: bool,
    ) -> int:
        """
        A code reference is being deleted.

        Args:
            _from (ea_t): Source address.
            to (ea_t): Target address.
            expand (bool): Whether to expand the cref deletion.

        Returns:
            int: <0 to cancel cref deletion, 0 to not implement or continue.
        """
        return IDP_Hooks.ev_del_cref(self, _from, to, expand)

    def ev_del_dref(
        self,
        _from: 'ida_idaapi.ea_t',
        to: 'ida_idaapi.ea_t',
    ) -> int:
        """
        A data reference is being deleted.

        Args:
            _from (ea_t): Source address.
            to (ea_t): Target address.

        Returns:
            int: <0 to cancel dref deletion, 0 to not implement or continue.
        """
        return IDP_Hooks.ev_del_dref(self, _from, to)

    def ev_coagulate_dref(
        self,
        _from: 'ida_idaapi.ea_t',
        to: 'ida_idaapi.ea_t',
        may_define: bool,
        code_ea: 'ea_t *',
    ) -> int:
        """
        Data reference is being analyzed. Plugin may correct 'code_ea'
        (e.g., for thumb mode refs, we clear the last bit).

        Args:
            _from (ea_t): Source address.
            to (ea_t): Target address.
            may_define (bool): Whether a definition may be created.
            code_ea (ea_t *): Pointer to the effective code address (may be modified).

        Returns:
            int: <0 for failed dref analysis,
                >0 for done dref analysis,
                0 to not implement or continue.
        """
        return IDP_Hooks.ev_coagulate_dref(self, _from, to, may_define, code_ea)

    def ev_may_show_sreg(
        self,
        current_ea: 'ida_idaapi.ea_t',
    ) -> int:
        """
        The kernel wants to display the segment registers in the messages window.

        Args:
            current_ea (ea_t): Current address.

        Returns:
            int: <0 if the kernel should not show the segment registers
                (assuming the module has done it),
                0 if not implemented.
        """
        return IDP_Hooks.ev_may_show_sreg(self, current_ea)

    def ev_auto_queue_empty(
        self,
        type: 'atype_t',
    ) -> int:
        """
        One analysis queue is empty.

        Args:
            type (atype_t): The queue type.

        Returns:
            int: See also idb_event::auto_empty_finally.
        """
        return IDP_Hooks.ev_auto_queue_empty(self, type)

    def ev_validate_flirt_func(
        self,
        start_ea: 'ida_idaapi.ea_t',
        funcname: str,
    ) -> int:
        """
        FLIRT has recognized a library function.
        This callback can be used by a plugin or proc module
        to intercept and validate such a function.

        Args:
            start_ea (ea_t): Function start address.
            funcname (str): Recognized function name.

        Returns:
            int: -1 to not create a function, 0 if function is validated.
        """
        return IDP_Hooks.ev_validate_flirt_func(self, start_ea, funcname)

    def ev_adjust_libfunc_ea(
        self,
        sig: 'idasgn_t const *',
        libfun: 'libfunc_t const *',
        ea: 'ea_t *',
    ) -> int:
        """
        Called when a signature module has been matched against bytes in the database.
        This is used to
        compute the offset at which a particular module's libfunc should be applied.

        Args:
            sig (idasgn_t const *): Signature.
            libfun (libfunc_t const *): Library function.
            ea (ea_t *): Pointer to effective address (may be modified).

        Returns:
            int: 1 if the address was modified, <=0 if not (use default algorithm).
        """
        return IDP_Hooks.ev_adjust_libfunc_ea(self, sig, libfun, ea)

    def ev_assemble(
        self,
        ea: 'ida_idaapi.ea_t',
        cs: 'ida_idaapi.ea_t',
        ip: 'ida_idaapi.ea_t',
        use32: bool,
        line: str,
    ) -> 'PyObject *':
        """
        Assemble an instruction. Display a warning if an error is found.

        Args:
            ea (ea_t): Linear address of instruction.
            cs (ea_t): Code segment of instruction.
            ip (ea_t): Instruction pointer of instruction.
            use32 (bool): Is it a 32-bit segment?
            line (str): Line to assemble.

        Returns:
            PyObject*: Size of the instruction in bytes.
        """
        return IDP_Hooks.ev_assemble(self, ea, cs, ip, use32, line)

    def ev_extract_address(
        self,
        out_ea: 'ea_t *',
        screen_ea: 'ida_idaapi.ea_t',
        string: str,
        position: 'size_t',
    ) -> int:
        """
        Extract address from a string.

        Args:
            out_ea (ea_t *): Output address (pointer).
            screen_ea (ea_t): Current screen address.
            string (str): Source string.
            position (size_t): Position in the string.

        Returns:
            int: 1 for success,
                0 for standard algorithm,
                -1 for error.
        """
        return IDP_Hooks.ev_extract_address(self, out_ea, screen_ea, string, position)

    def ev_realcvt(
        self,
        m: 'void *',
        e: 'fpvalue_t *',
        swt: 'uint16',
    ) -> int:
        """
        Floating point to IEEE conversion.

        Args:
            m (void *): Pointer to processor-specific floating point value.
            e (fpvalue_t *): IDA representation of a floating point value.
            swt (uint16): Operation (see realcvt() in ieee.h).

        Returns:
            int: 0 if not implemented.
        """
        return IDP_Hooks.ev_realcvt(self, m, e, swt)

    def ev_gen_asm_or_lst(
        self,
        starting: bool,
        fp: 'FILE *',
        is_asm: bool,
        flags: int,
        outline: 'html_line_cb_t **',
    ) -> int:
        """
        Generating asm or lst file. Called twice: at the beginning and at the end of
            listing generation.
        The processor module can intercept this event and adjust its output.

        Args:
            starting (bool): True if beginning listing generation.
            fp (FILE *): Output file.
            is_asm (bool): True for assembler, False for listing.
            flags (int): Flags passed to gen_file().
            outline (html_line_cb_t **): Pointer to pointer to outline callback.
                If defined, it will be used by the kernel to output the generated lines.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_gen_asm_or_lst(self, starting, fp, is_asm, flags, outline)

    def ev_gen_map_file(
        self,
        nlines: 'int *',
        fp: 'FILE *',
    ) -> int:
        """
        Generate map file. If not implemented, the kernel itself will create the map file.

        Args:
            nlines (int *): Number of lines in the map file (-1 means write error).
            fp (FILE *): Output file.

        Returns:
            int: 0 if not implemented, 1 for ok, -1 for write error.
        """
        return IDP_Hooks.ev_gen_map_file(self, nlines, fp)

    def ev_create_flat_group(
        self,
        image_base: 'ida_idaapi.ea_t',
        bitness: int,
        dataseg_sel: 'sel_t',
    ) -> int:
        """
        Create special segment representing the flat group.

        Args:
            image_base (ea_t): Image base.
            bitness (int): Bitness.
            dataseg_sel (sel_t): Data segment selector.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_create_flat_group(self, image_base, bitness, dataseg_sel)

    def ev_getreg(
        self,
        regval: 'uval_t *',
        regnum: int,
    ) -> int:
        """
        IBM PC only internal request. Should never be used for other purposes. Get register value
        by internal index.

        Args:
            regval (uval_t *): Output register value.
            regnum (int): Register number.

        Returns:
            int: 1 for ok, 0 if not implemented, -1 for failed (undefined value or bad regnum).
        """
        return IDP_Hooks.ev_getreg(self, regval, regnum)

    def ev_analyze_prolog(
        self,
        ea: 'ida_idaapi.ea_t',
    ) -> int:
        """
        Analyzes function prolog/epilog and updates purge and function attributes.

        Args:
            ea (ea_t): Start address of the function.

        Returns:
            int: 1 for ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_analyze_prolog(self, ea)

    def ev_calc_spdelta(
        self,
        spdelta: 'sval_t *',
        insn: 'insn_t const *',
    ) -> int:
        """
        Calculate amount of change to SP for the given instruction.
        This event is required to decompile code snippets.

        Args:
            spdelta (sval_t *): Output stack pointer delta.
            insn (insn_t const *): The instruction.

        Returns:
            int: 1 for ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_calc_spdelta(self, spdelta, insn)

    def ev_calcrel(self) -> int:
        """
        Reserved.

        Returns:
            int: Reserved return value.
        """
        return IDP_Hooks.ev_calcrel(self)

    def ev_find_reg_value(
        self,
        pinsn: 'insn_t const *',
        reg: int,
    ) -> 'PyObject *':
        """
        Find register value via a register tracker.

        The returned value in 'out' is valid before executing the instruction.

        Args:
            pinsn (insn_t const *): The instruction.
            reg (int): Register index.

        Returns:
            PyObject*: 1 if implemented and value was found,
                       0 if not implemented,
                      -1 if decoding failed or no value found.
        """
        return IDP_Hooks.ev_find_reg_value(self, pinsn, reg)

    def ev_find_op_value(
        self,
        pinsn: 'insn_t const *',
        opn: int,
    ) -> 'PyObject *':
        """
        Find operand value via a register tracker.

        The returned value in 'out' is valid before executing the instruction.

        Args:
            pinsn (insn_t const *): The instruction.
            opn (int): Operand index.

        Returns:
            PyObject*: 1 if implemented and value was found,
                       0 if not implemented,
                      -1 if decoding failed or no value found.
        """
        return IDP_Hooks.ev_find_op_value(self, pinsn, opn)

    def ev_replaying_undo(
        self,
        action_name: str,
        vec: 'undo_records_t const *',
        is_undo: bool,
    ) -> int:
        """
        Replaying an undo/redo buffer.

        Args:
            action_name (str): Action being undone or redone
                (can be None for intermediary buffers).
            vec (undo_records_t const *): Undo records vector.
            is_undo (bool): True if undo, False if redo.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_replaying_undo(self, action_name, vec, is_undo)

    def ev_ending_undo(
        self,
        action_name: str,
        is_undo: bool,
    ) -> int:
        """
        Ended undoing/redoing an action.

        Args:
            action_name (str): Action that was undone or redone (not None).
            is_undo (bool): True if undo, False if redo.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_ending_undo(self, action_name, is_undo)

    def ev_set_code16_mode(
        self,
        ea: 'ida_idaapi.ea_t',
        code16: bool,
    ) -> int:
        """
        Set ISA 16-bit mode (for some processors, e.g. ARM Thumb, PPC VLE, MIPS16).

        Args:
            ea (ea_t): Address to set new ISA mode.
            code16 (bool): True for 16-bit mode, False for 32-bit mode.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_set_code16_mode(self, ea, code16)

    def ev_get_code16_mode(
        self,
        ea: 'ida_idaapi.ea_t',
    ) -> int:
        """
        Get ISA 16-bit mode.

        Args:
            ea (ea_t): Address to get the ISA mode.

        Returns:
            int: 1 for 16-bit mode, 0 if not implemented or 32-bit mode.
        """
        return IDP_Hooks.ev_get_code16_mode(self, ea)

    def ev_get_procmod(self) -> int:
        """
        Get pointer to the processor module object.

        All processor modules must implement this. The pointer is returned as size_t.

        Returns:
            int: Processor module object pointer as size_t.
        """
        return IDP_Hooks.ev_get_procmod(self)

    def ev_asm_installed(
        self,
        asmnum: int,
    ) -> int:
        """
        After setting a new assembler.

        Args:
            asmnum (int): Assembler number (see also ev_newasm).

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_asm_installed(self, asmnum)

    def ev_get_reg_accesses(
        self,
        accvec: 'reg_accesses_t',
        insn: 'insn_t const *',
        flags: int,
    ) -> int:
        """
        Get info about registers that are used/changed by an instruction.

        Args:
            accvec (reg_accesses_t): Output info about accessed registers.
            insn (insn_t const *): Instruction in question.
            flags (int): Reserved, must be 0.

        Returns:
            int: -1 if accvec is None,
                1 if found the requested access and filled accvec,
                0 if not implemented.
        """
        return IDP_Hooks.ev_get_reg_accesses(self, accvec, insn, flags)

    def ev_is_control_flow_guard(
        self,
        p_reg: 'int *',
        insn: 'insn_t const *',
    ) -> int:
        """
        Detect if an instruction is a "thunk call" to a flow guard function
        (equivalent to call reg/return/nop).

        Args:
            p_reg (int *): Indirect register number, may be -1.
            insn (insn_t const *): Call/jump instruction.

        Returns:
            int: -1 if no thunk detected,
                 1 if indirect call,
                 2 if security check routine call (NOP),
                 3 if return thunk,
                 0 if not implemented.
        """
        return IDP_Hooks.ev_is_control_flow_guard(self, p_reg, insn)

    def ev_create_merge_handlers(
        self,
        md: 'merge_data_t *',
    ) -> int:
        """
        Create merge handlers, if needed.
        This event is generated immediately after opening idbs.

        Args:
            md (merge_data_t *): Merge data pointer.

        Returns:
            int: Must be 0.
        """
        return IDP_Hooks.ev_create_merge_handlers(self, md)

    def ev_privrange_changed(
        self,
        old_privrange: 'range_t',
        delta: 'adiff_t',
    ) -> int:
        """
        Privrange interval has been moved to a new location.
        Most common actions: fix indices of netnodes used by module.

        Args:
            old_privrange (range_t): Old privrange interval.
            delta (adiff_t): Address difference.

        Returns:
            int: 0 for Ok, -1 for error (and message in errbuf).
        """
        return IDP_Hooks.ev_privrange_changed(self, old_privrange, delta)

    def ev_cvt64_supval(
        self,
        node: 'nodeidx_t',
        tag: 'uchar',
        idx: 'nodeidx_t',
        data: 'uchar const *',
    ) -> int:
        """
        Perform 32-64 conversion for a netnode array element.

        Args:
            node (nodeidx_t): Node index.
            tag (uchar): Tag value.
            idx (nodeidx_t): Index.
            data (uchar const *): Data pointer.

        Returns:
            int: 0 if nothing was done,
                 1 if converted successfully,
                -1 for error (and message in errbuf).
        """
        return IDP_Hooks.ev_cvt64_supval(self, node, tag, idx, data)

    def ev_cvt64_hashval(
        self,
        node: 'nodeidx_t',
        tag: 'uchar',
        name: str,
        data: 'uchar const *',
    ) -> int:
        """
        Perform 32-64 conversion for a hash value.

        Args:
            node (nodeidx_t): Node index.
            tag (uchar): Tag value.
            name (str): Name string.
            data (uchar const *): Data pointer.

        Returns:
            int: 0 if nothing was done,
                 1 if converted successfully,
                -1 for error (and message in errbuf).
        """
        return IDP_Hooks.ev_cvt64_hashval(self, node, tag, name, data)

    def ev_gen_stkvar_def(
        self,
        outctx: 'outctx_t *',
        stkvar: 'udm_t',
        v: int,
        tid: 'tid_t',
    ) -> int:
        """
        Generate stack variable definition line.

        Default line is:
            varname = type ptr value,
        where 'type' is one of byte, word, dword, qword, tbyte.

        Args:
            outctx (outctx_t *): Output context.
            stkvar (udm_t): Stack variable (const).
            v (int): Stack variable value.
            tid (tid_t): Stack variable TID.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_gen_stkvar_def(self, outctx, stkvar, v, tid)

    def ev_is_addr_insn(
        self,
        type: 'int *',
        insn: 'insn_t const *',
    ) -> int:
        """
        Does the instruction calculate some address using an immediate operand?

        For example, in PC, such operand may be o_displ: 'lea eax, [esi+4]'

        Args:
            type (int *): Pointer to the returned instruction type.
                0: "add" instruction (immediate operand is a relative value)
                1: "move" instruction (immediate operand is absolute)
                2: "sub" instruction (immediate operand is a relative value)
            insn (insn_t const *): Instruction.

        Returns:
            int: >0 for operand number + 1,
                 0 if not implemented.
        """
        return IDP_Hooks.ev_is_addr_insn(self, type, insn)

    def ev_next_exec_insn(
        self,
        target: 'ea_t *',
        ea: 'ida_idaapi.ea_t',
        tid: int,
        getreg: 'processor_t::regval_getter_t *',
        regvalues: 'regval_t',
    ) -> int:
        """
        Get next address to be executed.

        Must return the next address to be executed.
        If the instruction following the current one is executed, return BADADDR.
        Usually used for jumps, branches, calls, returns.
        This is essential if "single step" is not supported in hardware.

        Args:
            target (ea_t *): Out: pointer to the answer.
            ea (ea_t): Instruction address.
            tid (int): Current thread id.
            getreg (processor_t::regval_getter_t *): Function to get register values.
            regvalues (regval_t): Register values array (const).

        Returns:
            int: 0 if unimplemented,
                 1 if implemented.
        """
        return IDP_Hooks.ev_next_exec_insn(self, target, ea, tid, getreg, regvalues)

    def ev_calc_step_over(
        self,
        target: 'ea_t *',
        ip: 'ida_idaapi.ea_t',
    ) -> int:
        """
        Calculate the address of the instruction which will be executed after "step over".

        The kernel will put a breakpoint there. If the step over is equal to step into or we cannot
        calculate the address, return BADADDR.

        Args:
            target (ea_t *): Pointer to the answer.
            ip (ea_t): Instruction address.

        Returns:
            int: 0 if unimplemented, 1 if implemented.
        """
        return IDP_Hooks.ev_calc_step_over(self, target, ip)

    def ev_calc_next_eas(
        self,
        res: 'eavec_t *',
        insn: 'insn_t const *',
        over: bool,
    ) -> int:
        """
        Calculate list of addresses the instruction in 'insn' may pass control to.

        This callback is required for source level debugging.

        Args:
            res (eavec_t *): Output array for the results.
            insn (insn_t const *): The instruction.
            over (bool): Calculate for step over (ignore call targets).

        Returns:
            int: <0 if incalculable (indirect jumps, for example),
                 >=0 for the number of addresses of called functions in the array.
                 They must be put at the beginning of the array (0 if over=True).
        """
        return IDP_Hooks.ev_calc_next_eas(self, res, insn, over)

    def ev_get_macro_insn_head(
        self,
        head: 'ea_t *',
        ip: 'ida_idaapi.ea_t',
    ) -> int:
        """
        Calculate the start of a macro instruction.

        This notification is called if IP points to the middle of an instruction.

        Args:
            head (ea_t *): Output answer; BADADDR means normal instruction.
            ip (ea_t): Instruction address.

        Returns:
            int: 0 if unimplemented, 1 if implemented.
        """
        return IDP_Hooks.ev_get_macro_insn_head(self, head, ip)

    def ev_get_dbr_opnum(
        self,
        opnum: 'int *',
        insn: 'insn_t const *',
    ) -> int:
        """
        Get the number of the operand to be displayed in the debugger reference view (text mode).

        Args:
            opnum (int *): Operand number (output, -1 means no such operand).
            insn (insn_t const *): The instruction.

        Returns:
            int: 0 if unimplemented, 1 if implemented.
        """
        return IDP_Hooks.ev_get_dbr_opnum(self, opnum, insn)

    def ev_insn_reads_tbit(
        self,
        insn: 'insn_t const *',
        getreg: 'processor_t::regval_getter_t *',
        regvalues: 'regval_t',
    ) -> int:
        """
        Check if insn will read the TF bit.

        Args:
            insn (insn_t const *): The instruction.
            getreg (processor_t::regval_getter_t *): Function to get register values.
            regvalues (regval_t): Register values array.

        Returns:
            int: 2 if will generate 'step' exception,
                 1 if will store the TF bit in memory,
                 0 if no.
        """
        return IDP_Hooks.ev_insn_reads_tbit(self, insn, getreg, regvalues)

    def ev_clean_tbit(
        self,
        ea: 'ida_idaapi.ea_t',
        getreg: 'processor_t::regval_getter_t *',
        regvalues: 'regval_t',
    ) -> int:
        """
        Clear the TF bit after an insn like pushf stored it in memory.

        Args:
            ea (ea_t): Instruction address.
            getreg (processor_t::regval_getter_t *): Function to get register values.
            regvalues (regval_t): Register values array.

        Returns:
            int: 1 if ok, 0 if failed.
        """
        return IDP_Hooks.ev_clean_tbit(self, ea, getreg, regvalues)

    def ev_get_reg_info(
        self,
        main_regname: 'char const **',
        bitrange: 'bitrange_t',
        regname: str,
    ) -> int:
        """
        Get register information by its name.

        Example: "ah" returns:
            - main_regname="eax"
            - bitrange_t = { offset==8, nbits==8 }

        This callback may be unimplemented if the register names are all present in
        processor_t::reg_names and they all have the same size.

        Args:
            main_regname (char const **): Output main register name.
            bitrange (bitrange_t): Output position and size of the value within 'main_regname'
                (empty bitrange == whole register).
            regname (str): Register name.

        Returns:
            int: 1 if ok, -1 if failed (not found), 0 if unimplemented.
        """
        return IDP_Hooks.ev_get_reg_info(self, main_regname, bitrange, regname)

    def ev_update_call_stack(
        self,
        stack: 'call_stack_t',
        tid: int,
        getreg: 'processor_t::regval_getter_t *',
        regvalues: 'regval_t',
    ) -> int:
        """
        Calculate the call stack trace for the given thread.

        This callback is invoked when the process is suspended and should fill the 'trace' object
        with the information about the current call stack. Note that this callback is NOT invoked
        if the current debugger backend implements stack tracing via
        debugger_t::event_t::ev_update_call_stack. The debugger-specific algorithm takes priority.
        Implementing this callback in the processor module is useful when multiple debugging
        platforms follow similar patterns, and thus the same processor-specific algorithm can be
        used for different platforms.

        Args:
            stack (call_stack_t): Result object to fill with call stack trace.
            tid (int): Thread ID.
            getreg (processor_t::regval_getter_t *): Function to get register values.
            regvalues (regval_t): Register values array.

        Returns:
            int: 1 if ok, -1 if failed, 0 if unimplemented.
        """
        return IDP_Hooks.ev_update_call_stack(self, stack, tid, getreg, regvalues)

    def ev_setup_til(
        self,
    ) -> int:
        """
        Setup default type libraries.

        Called after loading a new file into the database. The processor module may load TILs,
        setup memory model, and perform other actions required to set up the type system.
        This is an optional callback.

        Returns:
            int: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_setup_til(self)

    def ev_get_abi_info(
        self,
        comp: 'comp_t',
    ) -> int:
        """
        Get all possible ABI names and optional extensions for given compiler.

        abiname/option is a string entirely consisting of letters, digits and underscore.

        Args:
            comp (comp_t): Compiler ID.

        Returns:
            int: 0 if not implemented, 1 if ok.
        """
        return IDP_Hooks.ev_get_abi_info(self, comp)

    def ev_max_ptr_size(
        self,
    ) -> int:
        """
        Get maximal size of a pointer in bytes.

        Returns:
            int: Maximum possible size of a pointer.
        """
        return IDP_Hooks.ev_max_ptr_size(self)

    def ev_get_default_enum_size(
        self,
    ) -> int:
        """
        Get default enum size.

        Note:
            Not generated anymore. inf_get_cc_size_e() is used instead.
        """
        return IDP_Hooks.ev_get_default_enum_size(self)

    def ev_get_cc_regs(
        self,
        regs: 'callregs_t',
        cc: 'callcnv_t',
    ) -> int:
        """
        Get register allocation convention for given calling convention.

        Args:
            regs (callregs_t): Output for register allocation info.
            cc (callcnv_t): Calling convention.

        Returns:
            int: 1 if handled, 0 if not implemented.
        """
        return IDP_Hooks.ev_get_cc_regs(self, regs, cc)

    def ev_get_simd_types(
        self,
        out: 'simd_info_vec_t *',
        simd_attrs: 'simd_info_t',
        argloc: 'argloc_t',
        create_tifs: bool,
    ) -> int:
        """
        Get SIMD-related types according to given attributes and/or argument location.

        Args:
            out (simd_info_vec_t *): Output vector of SIMD types.
            simd_attrs (simd_info_t): SIMD attributes (may be None).
            argloc (argloc_t): Argument location (may be None).
            create_tifs (bool): Return valid tinfo_t objects, create if necessary.

        Returns:
            int: Number of found types, -1 on error.
        """
        return IDP_Hooks.ev_get_simd_types(self, out, simd_attrs, argloc, create_tifs)

    def ev_calc_cdecl_purged_bytes(
        self,
        ea: 'ida_idaapi.ea_t',
    ) -> int:
        """
        Calculate number of purged bytes after call.

        Args:
            ea (ea_t): Address of the call instruction.

        Returns:
            int: Number of purged bytes (usually add sp, N).
        """
        return IDP_Hooks.ev_calc_cdecl_purged_bytes(self, ea)

    def ev_calc_purged_bytes(
        self,
        p_purged_bytes: 'int *',
        fti: 'func_type_data_t',
    ) -> int:
        """
        Calculate number of purged bytes by the given function type.

        Args:
            p_purged_bytes (int *): Pointer to output value.
            fti (func_type_data_t): Function type details.

        Returns:
            int: 1 if handled, 0 if not implemented.
        """
        return IDP_Hooks.ev_calc_purged_bytes(self, p_purged_bytes, fti)

    def ev_calc_retloc(
        self,
        retloc: 'argloc_t',
        rettype: 'tinfo_t',
        cc: 'callcnv_t',
    ) -> int:
        """
        Calculate return value location.

        Args:
            retloc (argloc_t): Output argument location.
            rettype (tinfo_t): Return type information.
            cc (callcnv_t): Calling convention.

        Returns:
            int: 0 if not implemented, 1 if ok, -1 on error.
        """
        return IDP_Hooks.ev_calc_retloc(self, retloc, rettype, cc)

    def ev_calc_arglocs(
        self,
        fti: 'func_type_data_t',
    ) -> int:
        """
        Calculate function argument locations.

        This callback should fill retloc, all arglocs, and stkargs.
        This callback is never called for CM_CC_SPECIAL functions.

        Args:
            fti (func_type_data_t): Points to the func type info.

        Returns:
            int: 0 if not implemented, 1 if ok, -1 on error.
        """
        return IDP_Hooks.ev_calc_arglocs(self, fti)

    def ev_calc_varglocs(
        self,
        ftd: 'func_type_data_t',
        aux_regs: 'regobjs_t',
        aux_stkargs: 'relobj_t',
        nfixed: int,
    ) -> int:
        """
        Calculate locations of the arguments that correspond to '...'.

        On some platforms, variadic calls require passing additional information (e.g., number of
        floating variadic arguments must be passed in rax on gcc-x64).
        The locations and values that
        constitute this additional information are returned in the buffers pointed by aux_regs and
        aux_stkargs.

        Args:
            ftd (func_type_data_t): Info about all arguments (including varargs), inout.
            aux_regs (regobjs_t): Buffer for hidden register arguments, may be None.
            aux_stkargs (relobj_t): Buffer for hidden stack arguments, may be None.
            nfixed (int): Number of fixed arguments.

        Returns:
            int: 0 if not implemented, 1 if ok, -1 on error.
        """
        return IDP_Hooks.ev_calc_varglocs(self, ftd, aux_regs, aux_stkargs, nfixed)

    def ev_adjust_argloc(
        self,
        argloc: 'argloc_t',
        optional_type: 'tinfo_t',
        size: int,
    ) -> int:
        """
        Adjust argloc according to its type/size and platform endianess.

        Args:
            argloc (argloc_t): Argument location, inout.
            optional_type (tinfo_t): Type information (may be None).
            size (int): Argument size; ignored if type is not None.

        Returns:
            int: 0 if not implemented, 1 if ok, -1 on error.
        """
        return IDP_Hooks.ev_adjust_argloc(self, argloc, optional_type, size)

    def ev_lower_func_type(
        self,
        argnums: 'intvec_t *',
        fti: 'func_type_data_t',
    ) -> int:
        """
        Get function arguments to convert to pointers when lowering prototype.

        The processor module can also modify 'fti' for non-standard conversions. argnums[0] can
        contain a special negative value indicating that the return value should be passed as a
        hidden 'retstr' argument:
            - -1: first argument, return pointer to the argument
            - -2: last argument, return pointer to the argument
            - -3: first argument, return void

        Args:
            argnums (intvec_t): Output, numbers of arguments to convert to pointers
                (ascending order).
            fti (func_type_data_t): Inout, function type details.

        Returns:
            int: 0 if not implemented,
                 1 if argnums was filled,
                 2 if argnums was filled and fti substantially changed.
        """
        return IDP_Hooks.ev_lower_func_type(self, argnums, fti)

    def ev_equal_reglocs(
        self,
        a1: 'argloc_t',
        a2: 'argloc_t',
    ) -> int:
        """
        Are two register arglocs the same?

        Args:
            a1 (argloc_t): First argument location.
            a2 (argloc_t): Second argument location.

        Returns:
            int: 1 if yes, -1 if no, 0 if not implemented.
        """
        return IDP_Hooks.ev_equal_reglocs(self, a1, a2)

    def ev_use_stkarg_type(
        self,
        ea: 'ida_idaapi.ea_t',
        arg: 'funcarg_t',
    ) -> int:
        """
        Use information about a stack argument.

        Args:
            ea (ea_t): Address of the push instruction which pushes the argument onto the stack.
            arg (funcarg_t): Argument information.

        Returns:
            int: 1 if ok, <=0 if failed (kernel will create a comment for the instruction).
        """
        return IDP_Hooks.ev_use_stkarg_type(self, ea, arg)

    def ev_use_regarg_type(
        self,
        ea: 'ida_idaapi.ea_t',
        rargs: 'funcargvec_t const *',
    ) -> 'PyObject *':
        """
        Use information about register argument.

        Args:
            ea (ea_t): Address of the instruction.
            rargs (funcargvec_t): Vector of register arguments.

        Returns:
            PyObject*: 1 if ok, 0 if not implemented.
        """
        return IDP_Hooks.ev_use_regarg_type(self, ea, rargs)

    def ev_use_arg_types(
        self,
        ea: 'ida_idaapi.ea_t',
        fti: 'func_type_data_t',
        rargs: 'funcargvec_t *',
    ) -> int:
        """
        Use information about callee arguments.

        Args:
            ea (ea_t): Address of the call instruction.
            fti (func_type_data_t): Function type info.
            rargs (funcargvec_t): Array of register arguments.

        Returns:
            int: 1 if handled (removes handled args from fti/rargs), 0 if not implemented.
        """
        return IDP_Hooks.ev_use_arg_types(self, ea, fti, rargs)

    def ev_arg_addrs_ready(
        self,
        caller: 'ida_idaapi.ea_t',
        n: int,
        tif: 'tinfo_t',
        addrs: 'ea_t *',
    ) -> int:
        """
        Argument address info is ready.

        Args:
            caller (ea_t): Address of the caller.
            n (int): Number of formal arguments.
            tif (tinfo_t): Call prototype.
            addrs (ea_t *): Argument initialization addresses.

        Returns:
            int: <0 to avoid saving into idb; other values mean "ok to save".
        """
        return IDP_Hooks.ev_arg_addrs_ready(self, caller, n, tif, addrs)

    def ev_decorate_name(
        self,
        name: str,
        mangle: bool,
        cc: int,
        optional_type: 'tinfo_t',
    ) -> 'PyObject *':
        """
        Decorate or undecorate a C symbol name.

        Args:
            name (str): Name of the symbol.
            mangle (bool): True to mangle, False to unmangle.
            cc (int): Calling convention (callcnv_t).
            optional_type (tinfo_t): Optional type information.

        Returns:
            PyObject*: 1 if success, 0 if not implemented or failed.
        """
        return 0

    def ev_arch_changed(self) -> int:
        """
        The loader finished parsing arch-related info;
        processor module might use it to finish init.

        Returns:
            int: 1 if success, 0 if not implemented or failed.
        """
        return IDP_Hooks.ev_arch_changed(self)

    def ev_get_stkarg_area_info(
        self,
        out: 'stkarg_area_info_t',
        cc: 'callcnv_t',
    ) -> int:
        """
        Get metrics of the stack argument area.

        Args:
            out (stkarg_area_info_t): Output info.
            cc (callcnv_t): Calling convention.

        Returns:
            int: 1 if success, 0 if not implemented.
        """
        return IDP_Hooks.ev_get_stkarg_area_info(self, out, cc)

    def ev_last_cb_before_loader(self) -> int:
        return IDP_Hooks.ev_last_cb_before_loader(self)

    def ev_loader(self) -> int:
        """
        This code and higher ones are reserved for the loaders.
        The arguments and the return values are defined by the loaders.
        """
        return IDP_Hooks.ev_loader(self)


class DatabaseHooks(_BaseHooks, IDB_Hooks):
    """
    Convenience class for IDB (database) events handling.
    """

    def __init__(self) -> None:
        _BaseHooks.__init__(self)
        IDB_Hooks.__init__(self)

    def hook(self) -> None:
        """
        Hook (activate) the event handlers.
        """
        if not self.is_hooked:
            if IDB_Hooks.hook(self):
                self._is_hooked = True

    def unhook(self) -> None:
        """
        Un-hook (de-activate) the event handlers.
        """
        if self.is_hooked:
            if IDB_Hooks.unhook(self):
                self._is_hooked = False

    def closebase(self) -> None:
        """
        The database will be closed now.
        """
        return IDB_Hooks.closebase(self)

    def savebase(self) -> None:
        """
        The database is being saved.
        """
        return IDB_Hooks.savebase(self)

    def upgraded(self, _from: int) -> None:
        """
        The database has been upgraded and the receiver can upgrade its info as well.
        """
        return IDB_Hooks.upgraded(self, _from)

    def auto_empty(self) -> None:
        """
        Info: all analysis queues are empty. This callback is called once when the initial
        analysis is finished. If the queue is not empty upon the return from this callback,
        it will be called later again.
        """
        return IDB_Hooks.auto_empty(self)

    def auto_empty_finally(self) -> None:
        """
        Info: all analysis queues are empty definitively. This callback is called only once.
        """
        return IDB_Hooks.auto_empty_finally(self)

    def determined_main(self, main: 'ida_idaapi.ea_t') -> None:
        """
        The main() function has been determined.

        Args:
            main (ea_t): Address of the main() function.
        """
        return IDB_Hooks.determined_main(self, main)

    def extlang_changed(self, kind: int, el: 'extlang_t *', idx: int) -> None:
        """
        The list of extlangs or the default extlang was changed.

        Args:
            kind (int): 0: extlang installed, 1: extlang removed, 2: default extlang changed.
            el (extlang_t *): Pointer to the extlang affected.
            idx (int): Extlang index.
        """
        return IDB_Hooks.extlang_changed(self, kind, el, idx)

    def idasgn_loaded(self, short_sig_name: str) -> None:
        """
        FLIRT signature has been loaded for normal processing
        (not for recognition of startup sequences).

        Args:
            short_sig_name (str): The short signature name.
        """
        return IDB_Hooks.idasgn_loaded(self, short_sig_name)

    def kernel_config_loaded(self, pass_number: int) -> None:
        """
        This event is issued when ida.cfg is parsed.

        Args:
            pass_number (int): Pass number.
        """
        return IDB_Hooks.kernel_config_loaded(self, pass_number)

    def loader_finished(self, li: 'linput_t *', neflags: 'uint16', filetypename: str) -> None:
        """
        External file loader finished its work.
        Use this event to augment the existing loader functionality.

        Args:
            li (linput_t *): Loader input pointer.
            neflags (uint16): Load file flags.
            filetypename (str): File type name.
        """
        return IDB_Hooks.loader_finished(self, li, neflags, filetypename)

    def flow_chart_created(self, fc: 'qflow_chart_t') -> None:
        """
        GUI has retrieved a function flow chart.
        Plugins may modify the flow chart in this callback.

        Args:
            fc (qflow_chart_t *): Function flow chart.
        """
        return IDB_Hooks.flow_chart_created(self, fc)

    def compiler_changed(self, adjust_inf_fields: bool) -> None:
        """
        The kernel has changed the compiler information (idainfo::cc structure; get_abi_name).

        Args:
            adjust_inf_fields (bool): May change inf fields.
        """
        return IDB_Hooks.compiler_changed(self, adjust_inf_fields)

    def changing_ti(
        self, ea: 'ida_idaapi.ea_t', new_type: 'type_t const *', new_fnames: 'p_list const *'
    ) -> None:
        """
        An item typestring (c/c++ prototype) is to be changed.

        Args:
            ea (ea_t): Address.
            new_type (type_t const *): New type.
            new_fnames (p_list const *): New field names.
        """
        return IDB_Hooks.changing_ti(self, ea, new_type, new_fnames)

    def ti_changed(
        self, ea: 'ida_idaapi.ea_t', type: 'type_t const *', fnames: 'p_list const *'
    ) -> None:
        """
        An item typestring (c/c++ prototype) has been changed.

        Args:
            ea (ea_t): Address.
            type (type_t const *): Type.
            fnames (p_list const *): Field names.
        """
        return IDB_Hooks.ti_changed(self, ea, type, fnames)

    def changing_op_ti(
        self,
        ea: 'ida_idaapi.ea_t',
        n: int,
        new_type: 'type_t const *',
        new_fnames: 'p_list const *',
    ) -> None:
        """
        An operand typestring (c/c++ prototype) is to be changed.

        Args:
            ea (ea_t): Address.
            n (int): Operand number.
            new_type (type_t const *): New type.
            new_fnames (p_list const *): New field names.
        """
        return IDB_Hooks.changing_op_ti(self, ea, n, new_type, new_fnames)

    def op_ti_changed(
        self, ea: 'ida_idaapi.ea_t', n: int, type: 'type_t const *', fnames: 'p_list const *'
    ) -> None:
        """
        An operand typestring (c/c++ prototype) has been changed.

        Args:
            ea (ea_t): Address.
            n (int): Operand number.
            type (type_t const *): Type.
            fnames (p_list const *): Field names.
        """
        return IDB_Hooks.op_ti_changed(self, ea, n, type, fnames)

    def changing_op_type(self, ea: 'ida_idaapi.ea_t', n: int, opinfo: 'opinfo_t') -> None:
        """
        An operand type (offset, hex, etc...) is to be changed.

        Args:
            ea (ea_t): Address.
            n (int): Operand number (eventually or'ed with OPND_OUTER or OPND_ALL).
            opinfo (opinfo_t): Additional operand info.
        """
        return IDB_Hooks.changing_op_type(self, ea, n, opinfo)

    def op_type_changed(self, ea: 'ida_idaapi.ea_t', n: int) -> None:
        """
        An operand type (offset, hex, etc...) has been set or deleted.

        Args:
            ea (ea_t): Address.
            n (int): Operand number (eventually OR'ed with OPND_OUTER or OPND_ALL).
        """
        return IDB_Hooks.op_type_changed(self, ea, n)

    def segm_added(self, s: 'segment_t *') -> None:
        """
        A new segment has been created.

        Args:
            s (segment_t *): The newly created segment. See also adding_segm.
        """
        return IDB_Hooks.segm_added(self, s)

    def deleting_segm(self, start_ea: 'ida_idaapi.ea_t') -> None:
        """
        A segment is to be deleted.

        Args:
            start_ea (ea_t): Start address of the segment to delete.
        """
        return IDB_Hooks.deleting_segm(self, start_ea)

    def segm_deleted(
        self, start_ea: 'ida_idaapi.ea_t', end_ea: 'ida_idaapi.ea_t', flags: int
    ) -> None:
        """
        A segment has been deleted.

        Args:
            start_ea (ea_t): Start address of the deleted segment.
            end_ea (ea_t): End address of the deleted segment.
            flags (int): Segment flags.
        """
        return IDB_Hooks.segm_deleted(self, start_ea, end_ea, flags)

    def changing_segm_start(
        self, s: 'segment_t *', new_start: 'ida_idaapi.ea_t', segmod_flags: int
    ) -> None:
        """
        Segment start address is to be changed.

        Args:
            s (segment_t *): The segment.
            new_start (ea_t): New start address.
            segmod_flags (int): Segment modification flags.
        """
        return IDB_Hooks.changing_segm_start(self, s, new_start, segmod_flags)

    def segm_start_changed(self, s: 'segment_t *', oldstart: 'ida_idaapi.ea_t') -> None:
        """
        Segment start address has been changed.

        Args:
            s (segment_t *): The segment.
            oldstart (ea_t): Old start address.
        """
        return IDB_Hooks.segm_start_changed(self, s, oldstart)

    def changing_segm_end(
        self, s: 'segment_t *', new_end: 'ida_idaapi.ea_t', segmod_flags: int
    ) -> None:
        """
        Segment end address is to be changed.

        Args:
            s (segment_t *): The segment.
            new_end (ea_t): New end address.
            segmod_flags (int): Segment modification flags.
        """
        return IDB_Hooks.changing_segm_end(self, s, new_end, segmod_flags)

    def segm_end_changed(self, s: 'segment_t *', oldend: 'ida_idaapi.ea_t') -> None:
        """
        Segment end address has been changed.

        Args:
            s (segment_t *): The segment.
            oldend (ea_t): Old end address.
        """
        return IDB_Hooks.segm_end_changed(self, s, oldend)

    def changing_segm_name(self, s: 'segment_t *', oldname: str) -> None:
        """
        Segment name is being changed.

        Args:
            s (segment_t *): The segment whose name is changing.
            oldname (str): The old segment name.
        """
        return IDB_Hooks.changing_segm_name(self, s, oldname)

    def segm_name_changed(self, s: 'segment_t *', name: str) -> None:
        """
        Segment name has been changed.

        Args:
            s (segment_t *): The segment whose name has changed.
            name (str): The new segment name.
        """
        return IDB_Hooks.segm_name_changed(self, s, name)

    def changing_segm_class(self, s: 'segment_t *') -> None:
        """
        Segment class is being changed.

        Args:
            s (segment_t *): The segment whose class is changing.
        """
        return IDB_Hooks.changing_segm_class(self, s)

    def segm_class_changed(self, s: 'segment_t *', sclass: str) -> None:
        """
        Segment class has been changed.

        Args:
            s (segment_t *): The segment whose class has changed.
            sclass (str): The new segment class.
        """
        return IDB_Hooks.segm_class_changed(self, s, sclass)

    def segm_attrs_updated(self, s: 'segment_t *') -> None:
        """
        Segment attributes have been changed.

        Args:
            s (segment_t *): The segment whose attributes have been updated.
        """
        return IDB_Hooks.segm_attrs_updated(self, s)

    def segm_moved(
        self,
        _from: 'ida_idaapi.ea_t',
        to: 'ida_idaapi.ea_t',
        size: 'asize_t',
        changed_netmap: bool,
    ) -> None:
        """
        Segment has been moved.

        Args:
            _from (ea_t): Original segment start address.
            to (ea_t): New segment start address.
            size (asize_t): Size of the segment.
            changed_netmap (bool): See also idb_event::allsegs_moved.
        """
        return IDB_Hooks.segm_moved(self, _from, to, size, changed_netmap)

    def allsegs_moved(self, info: 'segm_move_infos_t *') -> None:
        """
        Program rebasing is complete. This event is generated after a series of segm_moved events.

        Args:
            info (segm_move_infos_t *): Information about all moved segments.
        """
        return IDB_Hooks.allsegs_moved(self, info)

    def func_added(self, pfn: 'func_t *') -> None:
        """
        The kernel has added a function.

        Args:
            pfn (func_t *): The function that was added.
        """
        return IDB_Hooks.func_added(self, pfn)

    def func_updated(self, pfn: 'func_t *') -> None:
        """
        The kernel has updated a function.

        Args:
            pfn (func_t *): The function that was updated.
        """
        return IDB_Hooks.func_updated(self, pfn)

    def set_func_start(self, pfn: 'func_t *', new_start: 'ida_idaapi.ea_t') -> None:
        """
        Function chunk start address will be changed.

        Args:
            pfn (func_t *): The function to modify.
            new_start (ea_t): The new start address.
        """
        return IDB_Hooks.set_func_start(self, pfn, new_start)

    def set_func_end(self, pfn: 'func_t *', new_end: 'ida_idaapi.ea_t') -> None:
        """
        Function chunk end address will be changed.

        Args:
            pfn (func_t *): The function to modify.
            new_end (ea_t): The new end address.
        """
        return IDB_Hooks.set_func_end(self, pfn, new_end)

    def deleting_func(self, pfn: 'func_t *') -> None:
        """
        The kernel is about to delete a function.

        Args:
            pfn (func_t *): The function that will be deleted.
        """
        return IDB_Hooks.deleting_func(self, pfn)

    def frame_deleted(self, pfn: 'func_t *') -> None:
        """
        The kernel has deleted a function frame.

        Args:
            pfn (func_t *): The function whose frame was deleted.
        """
        return IDB_Hooks.frame_deleted(self, pfn)

    def thunk_func_created(self, pfn: 'func_t *') -> None:
        """
        A thunk bit has been set for a function.

        Args:
            pfn (func_t *): The thunk function created.
        """
        return IDB_Hooks.thunk_func_created(self, pfn)

    def func_tail_appended(self, pfn: 'func_t *', tail: 'func_t *') -> None:
        """
        A function tail chunk has been appended.

        Args:
            pfn (func_t *): The function to which the tail was appended.
            tail (func_t *): The tail function chunk.
        """
        return IDB_Hooks.func_tail_appended(self, pfn, tail)

    def deleting_func_tail(self, pfn: 'func_t *', tail: 'range_t') -> None:
        """
        A function tail chunk is to be removed.

        Args:
            pfn (func_t *): The function from which the tail will be removed.
            tail (range_t): The tail range to be removed.
        """
        return IDB_Hooks.deleting_func_tail(self, pfn, tail)

    def func_tail_deleted(self, pfn: 'func_t *', tail_ea: 'ida_idaapi.ea_t') -> None:
        """
        A function tail chunk has been removed.

        Args:
            pfn (func_t *): The function from which the tail was removed.
            tail_ea (ea_t): The start address of the tail that was deleted.
        """
        return IDB_Hooks.func_tail_deleted(self, pfn, tail_ea)

    def tail_owner_changed(
        self, tail: 'func_t *', owner_func: 'ida_idaapi.ea_t', old_owner: 'ida_idaapi.ea_t'
    ) -> None:
        """
        A tail chunk owner has been changed.

        Args:
            tail (func_t *): The tail function chunk.
            owner_func (ea_t): The new owner function address.
            old_owner (ea_t): The previous owner function address.
        """
        return IDB_Hooks.tail_owner_changed(self, tail, owner_func, old_owner)

    def func_noret_changed(self, pfn: 'func_t *') -> None:
        """
        FUNC_NORET bit has been changed.

        Args:
            pfn (func_t *): The function whose noreturn bit was changed.
        """
        return IDB_Hooks.func_noret_changed(self, pfn)

    def stkpnts_changed(self, pfn: 'func_t *') -> None:
        """
        Stack change points have been modified.

        Args:
            pfn (func_t *): The function whose stack points were modified.
        """
        return IDB_Hooks.stkpnts_changed(self, pfn)

    def updating_tryblks(self, tbv: 'tryblks_t const *') -> None:
        """
        About to update tryblk information.

        Args:
            tbv (tryblks_t const *): The try blocks being updated.
        """
        return IDB_Hooks.updating_tryblks(self, tbv)

    def tryblks_updated(self, tbv: 'tryblks_t const *') -> None:
        """
        Updated tryblk information.

        Args:
            tbv (tryblks_t const *): The updated try blocks.
        """
        return IDB_Hooks.tryblks_updated(self, tbv)

    def deleting_tryblks(self, range: 'range_t') -> None:
        """
        About to delete tryblk information in given range.

        Args:
            range (range_t): The range from which try blocks will be deleted.
        """
        return IDB_Hooks.deleting_tryblks(self, range)

    def sgr_changed(
        self,
        start_ea: 'ida_idaapi.ea_t',
        end_ea: 'ida_idaapi.ea_t',
        regnum: int,
        value: 'sel_t',
        old_value: 'sel_t',
        tag: 'uchar',
    ) -> None:
        """
        The kernel has changed a segment register value.

        Args:
            start_ea (ea_t): Start address of the affected range.
            end_ea (ea_t): End address of the affected range.
            regnum (int): Register number.
            value (sel_t): New value.
            old_value (sel_t): Previous value.
            tag (uchar): Segment register range tag.
        """
        return IDB_Hooks.sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag)

    def make_code(self, insn: 'insn_t const *') -> None:
        """
        An instruction is being created.

        Args:
            insn (insn_t const *): The instruction being created.
        """
        return IDB_Hooks.make_code(self, insn)

    def make_data(
        self, ea: 'ida_idaapi.ea_t', flags: 'flags64_t', tid: 'tid_t', len: 'asize_t'
    ) -> None:
        """
        A data item is being created.

        Args:
            ea (ea_t): Effective address.
            flags (flags64_t): Item flags.
            tid (tid_t): Type ID.
            len (asize_t): Length in bytes.
        """
        return IDB_Hooks.make_data(self, ea, flags, tid, len)

    def destroyed_items(
        self, ea1: 'ida_idaapi.ea_t', ea2: 'ida_idaapi.ea_t', will_disable_range: bool
    ) -> None:
        """
        Instructions/data have been destroyed in [ea1, ea2).

        Args:
            ea1 (ea_t): Start address of destroyed range.
            ea2 (ea_t): End address of destroyed range.
            will_disable_range (bool): True if the range will be disabled.
        """
        return IDB_Hooks.destroyed_items(self, ea1, ea2, will_disable_range)

    def renamed(
        self, ea: 'ida_idaapi.ea_t', new_name: str, local_name: bool, old_name: str
    ) -> None:
        """
        The kernel has renamed a byte. See also the rename event.

        Args:
            ea (ea_t): Effective address of the renamed item.
            new_name (str): New name (can be None).
            local_name (bool): Whether the new name is local.
            old_name (str): Old name (can be None).
        """
        return IDB_Hooks.renamed(self, ea, new_name, local_name, old_name)

    def byte_patched(self, ea: 'ida_idaapi.ea_t', old_value: int) -> None:
        """
        A byte has been patched.

        Args:
            ea (ea_t): Address of the patched byte.
            old_value (int): Previous value (uint32).
        """
        return IDB_Hooks.byte_patched(self, ea, old_value)

    def changing_cmt(self, ea: 'ida_idaapi.ea_t', repeatable_cmt: bool, newcmt: str) -> None:
        """
        An item comment is to be changed.

        Args:
            ea (ea_t): Address of the item.
            repeatable_cmt (bool): True if the comment is repeatable.
            newcmt (str): New comment text.
        """
        return IDB_Hooks.changing_cmt(self, ea, repeatable_cmt, newcmt)

    def cmt_changed(self, ea: 'ida_idaapi.ea_t', repeatable_cmt: bool) -> None:
        """
        An item comment has been changed.

        Args:
            ea (ea_t): Address of the item.
            repeatable_cmt (bool): True if the comment is repeatable.
        """
        return IDB_Hooks.cmt_changed(self, ea, repeatable_cmt)

    def changing_range_cmt(
        self, kind: 'range_kind_t', a: 'range_t', cmt: str, repeatable: bool
    ) -> None:
        """
        Range comment is to be changed.

        Args:
            kind (range_kind_t): Kind of the range.
            a (range_t): The range.
            cmt (str): New comment text.
            repeatable (bool): True if the comment is repeatable.
        """
        return IDB_Hooks.changing_range_cmt(self, kind, a, cmt, repeatable)

    def range_cmt_changed(
        self, kind: 'range_kind_t', a: 'range_t', cmt: str, repeatable: bool
    ) -> None:
        """
        Range comment has been changed.

        Args:
            kind (range_kind_t): Kind of the range.
            a (range_t): The range.
            cmt (str): The comment text.
            repeatable (bool): True if the comment is repeatable.
        """
        return IDB_Hooks.range_cmt_changed(self, kind, a, cmt, repeatable)

    def extra_cmt_changed(self, ea: 'ida_idaapi.ea_t', line_idx: int, cmt: str) -> None:
        """
        An extra comment has been changed.

        Args:
            ea (ea_t): Address of the item.
            line_idx (int): Line index of the comment.
            cmt (str): The comment text.
        """
        return IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

    def item_color_changed(self, ea: 'ida_idaapi.ea_t', color: 'bgcolor_t') -> None:
        """
        An item color has been changed.

        Args:
            ea (ea_t): Address of the item.
            color (bgcolor_t): The new color. If color == DEFCOLOR, then the color is deleted.
        """
        return IDB_Hooks.item_color_changed(self, ea, color)

    def callee_addr_changed(self, ea: 'ida_idaapi.ea_t', callee: 'ida_idaapi.ea_t') -> None:
        """
        Callee address has been updated by the user.

        Args:
            ea (ea_t): Address of the call instruction.
            callee (ea_t): Updated callee address.
        """
        return IDB_Hooks.callee_addr_changed(self, ea, callee)

    def bookmark_changed(
        self, index: int, pos: 'lochist_entry_t const *', desc: str, operation: int
    ) -> None:
        """
        Bookmarked position changed.

        Args:
            index (int): Bookmark index (uint32).
            pos (lochist_entry_t): Position info.
            desc (str): Description, or None if deleted.
            operation (int): 0 = added, 1 = updated, 2 = deleted. If desc is None, the bookmark was
                deleted.
        """
        return IDB_Hooks.bookmark_changed(self, index, pos, desc, operation)

    def sgr_deleted(
        self, start_ea: 'ida_idaapi.ea_t', end_ea: 'ida_idaapi.ea_t', regnum: int
    ) -> None:
        """
        The kernel has deleted a segment register value.

        Args:
            start_ea (ea_t): Start address of the range.
            end_ea (ea_t): End address of the range.
            regnum (int): Register number.
        """
        return IDB_Hooks.sgr_deleted(self, start_ea, end_ea, regnum)

    def adding_segm(self, s: 'segment_t *') -> None:
        """
        A segment is being created.

        Args:
            s (segment_t): The segment being created.
        """
        return IDB_Hooks.adding_segm(self, s)

    def func_deleted(self, func_ea: 'ida_idaapi.ea_t') -> None:
        """
        A function has been deleted.

        Args:
            func_ea (ea_t): Address of the deleted function.
        """
        return IDB_Hooks.func_deleted(self, func_ea)

    def dirtree_mkdir(self, dt: 'dirtree_t *', path: str) -> None:
        """
        Dirtree: a directory has been created.

        Args:
            dt (dirtree_t): The dirtree object.
            path (str): Path to the created directory.
        """
        return IDB_Hooks.dirtree_mkdir(self, dt, path)

    def dirtree_rmdir(self, dt: 'dirtree_t *', path: str) -> None:
        """
        Dirtree: a directory has been deleted.

        Args:
            dt (dirtree_t): The dirtree object.
            path (str): Path to the deleted directory.
        """
        return IDB_Hooks.dirtree_rmdir(self, dt, path)

    def dirtree_link(self, dt: 'dirtree_t *', path: str, link: bool) -> None:
        """
        Dirtree: an item has been linked/unlinked.

        Args:
            dt (dirtree_t): The dirtree object.
            path (str): Path of the item.
            link (bool): True if linked, False if unlinked.
        """
        return IDB_Hooks.dirtree_link(self, dt, path, link)

    def dirtree_move(self, dt: 'dirtree_t *', _from: str, to: str) -> None:
        """
        Dirtree: a directory or item has been moved.

        Args:
            dt (dirtree_t): The dirtree object.
            _from (str): Source path.
            to (str): Destination path.
        """
        return IDB_Hooks.dirtree_move(self, dt, _from, to)

    def dirtree_rank(self, dt: 'dirtree_t *', path: str, rank: 'size_t') -> None:
        """
        Dirtree: a directory or item rank has been changed.

        Args:
            dt (dirtree_t): The dirtree object.
            path (str): Path of the directory or item.
            rank (size_t): New rank value.
        """
        return IDB_Hooks.dirtree_rank(self, dt, path, rank)

    def dirtree_rminode(self, dt: 'dirtree_t *', inode: 'inode_t') -> None:
        """
        Dirtree: an inode became unavailable.
        """
        return IDB_Hooks.dirtree_rminode(self, dt, inode)

    def dirtree_segm_moved(self, dt: 'dirtree_t *') -> None:
        """
        Dirtree: inodes were changed due to a segment movement or a program rebasing.
        """
        return IDB_Hooks.dirtree_segm_moved(self, dt)

    def local_types_changed(self, ltc: 'local_type_change_t', ordinal: int, name: str) -> None:
        """
        Local types have been changed.
        """
        return IDB_Hooks.local_types_changed(self, ltc, ordinal, name)

    def lt_udm_created(self, udtname: str, udm: 'udm_t') -> None:
        """
        Local type UDT member has been added.
        """
        return IDB_Hooks.lt_udm_created(self, udtname, udm)

    def lt_udm_deleted(self, udtname: str, udm_tid: 'tid_t', udm: 'udm_t') -> None:
        """
        Local type UDT member has been deleted.
        """
        return IDB_Hooks.lt_udm_deleted(self, udtname, udm_tid, udm)

    def lt_udm_renamed(self, udtname: str, udm: 'udm_t', oldname: str) -> None:
        """
        Local type UDT member has been renamed.
        """
        return IDB_Hooks.lt_udm_renamed(self, udtname, udm, oldname)

    def lt_udm_changed(
        self, udtname: str, udm_tid: 'tid_t', udmold: 'udm_t', udmnew: 'udm_t'
    ) -> None:
        """
        Local type UDT member has been changed.
        """
        return IDB_Hooks.lt_udm_changed(self, udtname, udm_tid, udmold, udmnew)

    def lt_udt_expanded(self, udtname: str, udm_tid: 'tid_t', delta: 'adiff_t') -> None:
        """
        A structure type has been expanded or shrunk.
        """
        return IDB_Hooks.lt_udt_expanded(self, udtname, udm_tid, delta)

    def frame_created(self, func_ea: ida_idaapi.ea_t) -> None:
        """
        A function frame has been created.
        """
        return IDB_Hooks.frame_created(self, func_ea)

    def frame_udm_created(self, func_ea: ida_idaapi.ea_t, udm: 'udm_t') -> None:
        """
        Frame member has been added.
        """
        return IDB_Hooks.frame_udm_created(self, func_ea, udm)

    def frame_udm_deleted(self, func_ea: ida_idaapi.ea_t, udm_tid: 'tid_t', udm: 'udm_t') -> None:
        """
        Frame member has been deleted.
        """
        return IDB_Hooks.frame_udm_deleted(self, func_ea, udm_tid, udm)

    def frame_udm_renamed(self, func_ea: ida_idaapi.ea_t, udm: 'udm_t', oldname: str) -> None:
        """
        Frame member has been renamed.
        """
        return IDB_Hooks.frame_udm_renamed(self, func_ea, udm, oldname)

    def frame_udm_changed(
        self, func_ea: ida_idaapi.ea_t, udm_tid: 'tid_t', udmold: 'udm_t', udmnew: 'udm_t'
    ) -> None:
        """
        Frame member has been changed.
        """
        return IDB_Hooks.frame_udm_changed(self, func_ea, udm_tid, udmold, udmnew)

    def frame_expanded(self, func_ea: ida_idaapi.ea_t, udm_tid: 'tid_t', delta: 'adiff_t') -> None:
        """
        A frame type has been expanded or shrunk.
        """
        return IDB_Hooks.frame_expanded(self, func_ea, udm_tid, delta)

    def idasgn_matched_ea(self, ea: ida_idaapi.ea_t, name: str, lib_name: str) -> None:
        """
        A FLIRT match has been found.
        """
        return IDB_Hooks.idasgn_matched_ea(self, ea, name, lib_name)

    def lt_edm_created(self, enumname: str, edm: 'edm_t') -> None:
        """
        Local type enum member has been added.
        """
        return IDB_Hooks.lt_edm_created(self, enumname, edm)

    def lt_edm_deleted(self, enumname: str, edm_tid: 'tid_t', edm: 'edm_t') -> None:
        """
        Local type enum member has been deleted.
        """
        return IDB_Hooks.lt_edm_deleted(self, enumname, edm_tid, edm)

    def lt_edm_renamed(self, enumname: str, edm: 'edm_t', oldname: str) -> None:
        """
        Local type enum member has been renamed.
        """
        return IDB_Hooks.lt_edm_renamed(self, enumname, edm, oldname)

    def lt_edm_changed(
        self, enumname: str, edm_tid: 'tid_t', edmold: 'edm_t', edmnew: 'edm_t'
    ) -> None:
        """
        Local type enum member has been changed.
        """
        return IDB_Hooks.lt_edm_changed(self, enumname, edm_tid, edmold, edmnew)

    def local_type_renamed(self, ordinal: int, oldname: str, newname: str) -> None:
        """
        Local type has been renamed.
        """
        return IDB_Hooks.local_type_renamed(self, ordinal, oldname, newname)


class DebuggerHooks(_BaseHooks, DBG_Hooks):
    """
    Convenience class for debugger events handling.
    """

    def __init__(self) -> None:
        _BaseHooks.__init__(self)
        DBG_Hooks.__init__(self)

    def hook(self) -> None:
        """
        Hook (activate) the event handlers.
        """
        if not self.is_hooked:
            if DBG_Hooks.hook(self):
                self._is_hooked = True

    def unhook(self) -> None:
        """
        Un-hook (de-activate) the event handlers.
        """
        if self.is_hooked:
            if DBG_Hooks.unhook(self):
                self._is_hooked = False

    def dbg_process_start(
        self,
        pid: 'pid_t',
        tid: 'thid_t',
        ea: ida_idaapi.ea_t,
        modinfo_name: str,
        modinfo_base: ida_idaapi.ea_t,
        modinfo_size: 'asize_t',
    ) -> None:
        """
        Called on process started.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            modinfo_name (str): Module info name.
            modinfo_base (ea_t): Module info base address.
            modinfo_size (asize_t): Module info size.
        """
        return DBG_Hooks.dbg_process_start(
            self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size
        )

    def dbg_process_exit(
        self, pid: 'pid_t', tid: 'thid_t', ea: ida_idaapi.ea_t, exit_code: int
    ) -> None:
        """
        Called on process exit.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            exit_code (int): Exit code.
        """
        return DBG_Hooks.dbg_process_exit(self, pid, tid, ea, exit_code)

    def dbg_process_attach(
        self,
        pid: 'pid_t',
        tid: 'thid_t',
        ea: ida_idaapi.ea_t,
        modinfo_name: str,
        modinfo_base: ida_idaapi.ea_t,
        modinfo_size: 'asize_t',
    ) -> None:
        """
        Called on process attached.
        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            modinfo_name (str): Module info name.
            modinfo_base (ea_t): Module info base address.
            modinfo_size (asize_t): Module info size.
        """
        return DBG_Hooks.dbg_process_attach(
            self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size
        )

    def dbg_process_detach(self, pid: 'pid_t', tid: 'thid_t', ea: ida_idaapi.ea_t) -> None:
        """
        Called on process detach.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
        """
        return DBG_Hooks.dbg_process_detach(self, pid, tid, ea)

    def dbg_thread_start(self, pid: 'pid_t', tid: 'thid_t', ea: ida_idaapi.ea_t) -> None:
        """
        Called on thread start.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
        """
        return DBG_Hooks.dbg_thread_start(self, pid, tid, ea)

    def dbg_thread_exit(
        self, pid: 'pid_t', tid: 'thid_t', ea: ida_idaapi.ea_t, exit_code: int
    ) -> None:
        """
        Called on thread exit.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            exit_code (int): Exit code.
        """
        return DBG_Hooks.dbg_thread_exit(self, pid, tid, ea, exit_code)

    def dbg_library_load(
        self,
        pid: 'pid_t',
        tid: 'thid_t',
        ea: ida_idaapi.ea_t,
        modinfo_name: str,
        modinfo_base: ida_idaapi.ea_t,
        modinfo_size: 'asize_t',
    ) -> None:
        """
        Called on library load.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            modinfo_name (str): Module info name.
            modinfo_base (ea_t): Module info base address.
            modinfo_size (asize_t): Module info size.
        """
        return DBG_Hooks.dbg_library_load(
            self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size
        )

    def dbg_library_unload(
        self, pid: 'pid_t', tid: 'thid_t', ea: ida_idaapi.ea_t, info: str
    ) -> None:
        """
        Called on library unload.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            info (str): Info string.
        """
        return DBG_Hooks.dbg_library_unload(self, pid, tid, ea, info)

    def dbg_information(self, pid: 'pid_t', tid: 'thid_t', ea: ida_idaapi.ea_t, info: str) -> None:
        """
        Debug information.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            info (str): Info string.
        """
        return DBG_Hooks.dbg_information(self, pid, tid, ea, info)

    def dbg_exception(
        self,
        pid: 'pid_t',
        tid: 'thid_t',
        ea: ida_idaapi.ea_t,
        exc_code: int,
        exc_can_cont: bool,
        exc_ea: ida_idaapi.ea_t,
        exc_info: str,
    ) -> int:
        """
        Debug exception.

        Args:
            pid (pid_t): Process ID.
            tid (thid_t): Thread ID.
            ea (ea_t): Address.
            exc_code (int): Exception code.
            exc_can_cont (bool): Can continue.
            exc_ea (ea_t): Exception address.
            exc_info (str): Exception info.
        """
        return DBG_Hooks.dbg_exception(
            self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info
        )

    def dbg_suspend_process(self) -> None:
        """
        The process is now suspended.
        """
        return DBG_Hooks.dbg_suspend_process(self)

    def dbg_bpt(self, tid: 'thid_t', bptea: ida_idaapi.ea_t) -> int:
        """
        A user defined breakpoint was reached.
        Args:
            tid (thid_t): Thread ID.
            bptea (ea_t): Breakpoint address.
        """
        return DBG_Hooks.dbg_bpt(self, tid, bptea)

    def dbg_trace(self, tid: 'thid_t', ip: ida_idaapi.ea_t) -> int:
        """
        A step occurred (one instruction was executed).
        This event notification is only generated if step tracing is enabled.
        Args:
            tid (thid_t): Thread ID.
            ip (ea_t): Current instruction pointer. Usually points after the executed instruction.
        Returns:
            int: 1 = do not log this trace event, 0 = log it.
        """
        return DBG_Hooks.dbg_trace(self, tid, ip)

    def dbg_request_error(self, failed_command: int, failed_dbg_notification: int) -> None:
        """
        An error occurred during the processing of a request.
        Args:
            failed_command (ui_notification_t): The failed command.
            failed_dbg_notification (dbg_notification_t): The failed debugger notification.
        """
        return DBG_Hooks.dbg_request_error(self, failed_command, failed_dbg_notification)

    def dbg_step_into(self) -> None:
        """
        Called on step into.
        """
        return DBG_Hooks.dbg_step_into(self)

    def dbg_step_over(self) -> None:
        """
        Called on step over.
        """
        return DBG_Hooks.dbg_step_over(self)

    def dbg_run_to(self, pid: 'pid_t', tid: 'thid_t', ea: ida_idaapi.ea_t) -> None:
        """
        Called on run to.
        """
        return DBG_Hooks.dbg_run_to(self, pid, tid, ea)

    def dbg_step_until_ret(self) -> None:
        """
        Called on step until ret.
        """
        return DBG_Hooks.dbg_step_until_ret(self)

    def dbg_bpt_changed(self, bptev_code: int, bpt: 'bpt_t') -> None:
        """
        Breakpoint has been changed.
        Args:
            bptev_code (int): Breakpoint modification events.
            bpt (bpt_t): Breakpoint.
        """
        return DBG_Hooks.dbg_bpt_changed(self, bptev_code, bpt)

    def dbg_started_loading_bpts(self) -> None:
        """
        Started loading breakpoint info from idb.
        """
        return DBG_Hooks.dbg_started_loading_bpts(self)

    def dbg_finished_loading_bpts(self) -> None:
        """
        Finished loading breakpoint info from idb.
        """
        return DBG_Hooks.dbg_finished_loading_bpts(self)


class UIHooks(_BaseHooks, UI_Hooks):
    """
    Convenience class for UI events handling.
    """

    def __init__(self) -> None:
        _BaseHooks.__init__(self)
        UI_Hooks.__init__(self)

    def hook(self) -> None:
        """
        Hook (activate) the event handlers.
        """
        if not self.is_hooked:
            if UI_Hooks.hook(self):
                self._is_hooked = True

    def unhook(self) -> None:
        """
        Un-hook (de-activate) the event handlers.
        """
        if self.is_hooked:
            if UI_Hooks.unhook(self):
                self._is_hooked = False

    def range(self) -> None:
        """
        The disassembly range has been changed (idainfo::min_ea ... idainfo::max_ea).
        UI should redraw the scrollbars. See also: ui_lock_range_refresh.
        """
        return UI_Hooks.range(self)

    def idcstart(self) -> None:
        """
        Start of IDC engine work.
        """
        return UI_Hooks.idcstart(self)

    def idcstop(self) -> None:
        """
        Stop of IDC engine work.
        """
        return UI_Hooks.idcstop(self)

    def suspend(self) -> None:
        """
        Suspend graphical interface. Only the text version.
        Interface should respond to it.
        """
        return UI_Hooks.suspend(self)

    def resume(self) -> None:
        """
        Resume the suspended graphical interface. Only the text version.
        Interface should respond to it.
        """
        return UI_Hooks.resume(self)

    def saving(self) -> None:
        """
        The kernel is flushing its buffers to the disk.
        The user interface should save its state.
        """
        return UI_Hooks.saving(self)

    def saved(self, path: str) -> None:
        """
        The kernel has saved the database. This callback just informs the interface.
        Note that at the time this notification is sent, the internal paths are not updated yet,
        and calling get_path(PATH_TYPE_IDB) will return the previous path.
        Args:
            path (str): The database path.
        """
        return UI_Hooks.saved(self, path)

    def database_closed(self) -> None:
        """
        The database has been closed.
        See also processor_t::closebase, it occurs earlier.
        See also ui_initing_database. This is not the same as IDA exiting.
        If you need to perform cleanup at the exiting time, use qatexit().
        """
        return UI_Hooks.database_closed(self)

    def debugger_menu_change(self, enable: bool) -> None:
        """
        Notifies about debugger menu modification.
        Args:
            enable (bool): True if the debugger menu has been added
                or a different debugger has been selected.
                False if the debugger menu will be removed (user switched to "No debugger").
        """
        return UI_Hooks.debugger_menu_change(self, enable)

    def widget_visible(self, widget: 'TWidget *') -> None:
        """
        Called when a TWidget is displayed on the screen.
        Use this event to populate the window with controls.
        Args:
            widget (TWidget*): The widget that became visible.
        """
        return UI_Hooks.widget_visible(self, widget)

    def widget_closing(self, widget: 'TWidget *') -> None:
        """
        Called when a TWidget is about to close. This event precedes ui_widget_invisible.
        Use this to perform any actions relevant to the lifecycle of this widget.
        Args:
            widget (TWidget*): The widget that is about to close.
        """
        return UI_Hooks.widget_closing(self, widget)

    def widget_invisible(self, widget: 'TWidget *') -> None:
        """
        Called when a TWidget is being closed. Use this event to destroy the window controls.
        Args:
            widget (TWidget*): The widget that became invisible.
        """
        return UI_Hooks.widget_invisible(self, widget)

    def get_ea_hint(self, ea: ida_idaapi.ea_t) -> 'PyObject *':
        """
        Requests a simple hint for an address. Use this event to generate a custom hint.
        See also: more generic ui_get_item_hint.
        Args:
            ea (ea_t): The address for which the hint is requested.
        Returns:
            PyObject*: True if a hint was generated.
        """
        return UI_Hooks.get_ea_hint(self, ea)

    def get_item_hint(self, ea: ida_idaapi.ea_t, max_lines: int) -> 'PyObject *':
        """
        Requests a multiline hint for an item.
        See also: more generic ui_get_custom_viewer_hint.
        Args:
            ea (ea_t): Address or item id (e.g., structure or enum member).
            max_lines (int): Maximum number of lines to show.
        Returns:
            PyObject*: True if a hint was generated.
        """
        return UI_Hooks.get_item_hint(self, ea, max_lines)

    def get_custom_viewer_hint(self, viewer: 'TWidget *', place: 'place_t') -> 'PyObject *':
        """
        Requests a hint for a viewer (idaview or custom).

        Each subscriber should append their hint lines to HINT and increment IMPORTANT_LINES
        accordingly. Completely overwriting the existing lines in HINT is possible but not
        recommended.

        If the REG_HINTS_MARKER sequence is found in the returned hints string, it will be
        replaced with the contents of the "regular" hints. If the SRCDBG_HINTS_MARKER sequence is
        found, it will be replaced with the contents of the source-level debugger-generated hints.

        Special keywords:
            - HIGHLIGHT text: Where 'text' will be highlighted.
            - CAPTION caption: Caption for the hint widget.

        Args:
            viewer (TWidget*): The viewer widget.
            place (place_t*): The current position in the viewer.

        Returns:
            PyObject*: 0 to continue collecting hints from other subscribers,
            1 to stop collecting hints.
        """
        return UI_Hooks.get_custom_viewer_hint(self, viewer, place)

    def database_inited(self, is_new_database: int, idc_script: str) -> None:
        """
        Called when database initialization has completed and the kernel is about to run IDC
        scripts.

        Args:
            is_new_database (int): Non-zero if the database is new.
            idc_script (str): The IDC script to run (may be None).

        Note:
            See also ui_initing_database. This event is called for both new and old databases.
        """
        return UI_Hooks.database_inited(self, is_new_database, idc_script)

    def ready_to_run(self) -> None:
        """
        Called when all UI elements have been initialized.

        Automatic plugins may hook to this event to perform their tasks.
        """
        return UI_Hooks.ready_to_run(self)

    def preprocess_action(self, name: str) -> int:
        """
        Called when the IDA UI is about to handle a user action.

        Args:
            name (str): UI action name. These names can be looked up in ida[tg]ui.cfg.

        Returns:
            int: 0 if OK, nonzero if a plugin has handled the command.
        """
        return UI_Hooks.preprocess_action(self, name)

    def postprocess_action(self) -> None:
        """
        Called after an IDA UI action has been handled.
        """
        return UI_Hooks.postprocess_action(self)

    def get_chooser_item_attrs(
        self, chooser: 'chooser_base_t', n: 'size_t', attrs: 'chooser_item_attrs_t'
    ) -> None:
        """
        Get item-specific attributes for a chooser.

        This callback is generated only after enable_chooser_attrs().

        Args:
            chooser (chooser_base_t): The chooser object.
            n (size_t): Index of the item.
            attrs (chooser_item_attrs_t): Attributes to be set.
        """
        return UI_Hooks.get_chooser_item_attrs(self, chooser, n, attrs)

    def updating_actions(self, ctx: 'action_ctx_base_t') -> None:
        """
        Called when IDA is about to update all actions.

        If your plugin needs to perform expensive operations more than once (e.g., once per
        action it registers), you should do them only once, right away.

        Args:
            ctx (action_update_ctx_t): The update context.
        """
        return UI_Hooks.updating_actions(self, ctx)

    def updated_actions(self) -> None:
        """
        Called when IDA is done updating actions.
        """
        return UI_Hooks.updated_actions(self)

    def populating_widget_popup(
        self, widget: 'TWidget *', popup_handle: 'TPopupMenu *', ctx: 'action_ctx_base_t' = None
    ) -> None:
        """
        Called when IDA is populating the context menu for a widget.

        This is your chance to attach_action_to_popup().
        See also `ui_finish_populating_widget_popup` if you want to augment the context menu with
        your own actions after the menu has been properly populated by the owning component or
        plugin (which typically does it on ui_populating_widget_popup).

        Args:
            widget (TWidget *): The widget for which the popup is being populated.
            popup_handle (TPopupMenu *): The popup menu handle.
            ctx (action_activation_ctx_t, optional): The action context.
        """
        return UI_Hooks.populating_widget_popup(self, widget, popup_handle, ctx)

    def finish_populating_widget_popup(
        self, widget: 'TWidget *', popup_handle: 'TPopupMenu *', ctx: 'action_ctx_base_t' = None
    ) -> None:
        """
        Called when IDA is about to be done populating the context menu for a widget.

        This is your chance to attach_action_to_popup().

        Args:
            widget (TWidget*): The widget for which the popup is being finalized.
            popup_handle (TPopupMenu*): The popup menu handle.
            ctx (action_activation_ctx_t, optional): The action context.
        """
        return UI_Hooks.finish_populating_widget_popup(self, widget, popup_handle, ctx)

    def plugin_loaded(self, plugin_info: 'plugin_info_t const *') -> None:
        """
        Called when a plugin has been loaded in memory.

        Args:
            plugin_info (plugin_info_t const*): Information about the loaded plugin.
        """
        return UI_Hooks.plugin_loaded(self, plugin_info)

    def plugin_unloading(self, plugin_info: 'plugin_info_t const *') -> None:
        """
        Called when a plugin is about to be unloaded.

        Args:
            plugin_info (plugin_info_t const*): Information about the plugin being unloaded.
        """
        return UI_Hooks.plugin_unloading(self, plugin_info)

    def current_widget_changed(self, widget: 'TWidget *', prev_widget: 'TWidget *') -> None:
        """
        Called when the currently-active TWidget has changed.

        Args:
            widget (TWidget*): The new active widget.
            prev_widget (TWidget*): The previously active widget.
        """
        return UI_Hooks.current_widget_changed(self, widget, prev_widget)

    def screen_ea_changed(self, ea: ida_idaapi.ea_t, prev_ea: ida_idaapi.ea_t) -> None:
        """
        Called when the "current address" has changed.

        Args:
            ea (ea_t): The new address.
            prev_ea (ea_t): The previous address.
        """
        return UI_Hooks.screen_ea_changed(self, ea, prev_ea)

    def create_desktop_widget(self, title: str, cfg: 'jobj_wrapper_t') -> 'PyObject *':
        """
        Create a widget to be placed in the widget tree (at desktop-creation time).

        Args:
            title (str): The widget title.
            cfg (jobj_t): Configuration object.

        Returns:
            PyObject*: The created widget, or None.
        """
        return UI_Hooks.create_desktop_widget(self, title, cfg)

    def get_lines_rendering_info(
        self,
        out: 'lines_rendering_output_t',
        widget: 'TWidget const *',
        info: 'lines_rendering_input_t',
    ) -> None:
        """
        Get lines rendering information.

        Args:
            out (lines_rendering_output_t): Output information to be populated.
            widget (TWidget const*): The widget for which rendering info is requested.
            info (lines_rendering_input_t): Input rendering information.
        """
        return UI_Hooks.get_lines_rendering_info(self, out, widget, info)

    def get_widget_config(self, widget: 'TWidget const *', cfg: 'jobj_t *') -> 'PyObject *':
        """
        Retrieve the widget configuration.

        This configuration will be passed back at `ui_create_desktop_widget` and
        `ui_set_widget_config` time.

        Args:
            widget (TWidget const *): The widget to retrieve configuration for.
            cfg (jobj_t *): Configuration object.

        Returns:
            PyObject*: The widget configuration.
        """
        return UI_Hooks.get_widget_config(self, widget, cfg)

    def set_widget_config(self, widget: 'TWidget const *', cfg: 'jobj_wrapper_t') -> None:
        """
        Set the widget configuration.

        Args:
            widget (TWidget const *): The widget to configure.
            cfg (jobj_t): Configuration object.
        """
        return UI_Hooks.set_widget_config(self, widget, cfg)

    def initing_database(self) -> None:
        """
        Called when database initialization has started.

        See also: `ui_database_inited`. This event is called for both new and old databases.
        """
        return UI_Hooks.initing_database(self)

    def destroying_procmod(self, procmod: 'procmod_t') -> None:
        """
        Called when the processor module is about to be destroyed.

        Args:
            procmod (procmod_t): The processor module being destroyed.
        """
        return UI_Hooks.destroying_procmod(self, procmod)

    def destroying_plugmod(self, plugmod: 'plugmod_t', entry: 'plugin_t const *') -> None:
        """
        Called when the plugin object is about to be destroyed.

        Args:
            plugmod (plugmod_t): The plugin object being destroyed.
            entry (plugin_t const *): Plugin entry.
        """
        return UI_Hooks.destroying_plugmod(self, plugmod, entry)

    def desktop_applied(self, name: str, from_idb: bool, type: int) -> None:
        """
        Called when a desktop has been applied.

        Args:
            name (str): The desktop name.
            from_idb (bool): True if the desktop was stored in the IDB, False if it comes from
                the registry.
            type (int): The desktop type (1-disassembly, 2-debugger, 3-merge).
        """
        return UI_Hooks.desktop_applied(self, name, from_idb, type)


class ViewHooks(_BaseHooks, View_Hooks):
    """
    Convenience class for IDA View events handling.
    """

    def __init__(self) -> None:
        _BaseHooks.__init__(self)
        View_Hooks.__init__(self)

    def hook(self) -> None:
        """
        Hook (activate) the event handlers.
        """
        if not self.is_hooked:
            if View_Hooks.hook(self):
                self._is_hooked = True

    def unhook(self) -> None:
        """
        Un-hook (de-activate) the event handlers.
        """
        if self.is_hooked:
            if View_Hooks.unhook(self):
                self._is_hooked = False

    def view_activated(self, view: 'TWidget *') -> None:
        """
        Called when a view is activated.
        Args:
            view (TWidget *): The activated view.
        """
        return View_Hooks.view_activated(self, view)

    def view_deactivated(self, view: 'TWidget *') -> None:
        """
        Called when a view is deactivated.
        Args:
            view (TWidget *): The deactivated view.
        """
        return View_Hooks.view_deactivated(self, view)

    def view_keydown(self, view: 'TWidget *', key: int, state: 'view_event_state_t') -> None:
        """
        Called when a key down event occurs in the view.
        Args:
            view (TWidget *): The view receiving the key event.
            key (int): The key code.
            state (view_event_state_t): The event state.
        """
        return View_Hooks.view_keydown(self, view, key, state)

    def view_click(self, view: 'TWidget *', event: 'view_mouse_event_t') -> None:
        """
        Called when a click event occurs in the view.
        Args:
            view (TWidget *): The view where the click occurred.
            event (view_mouse_event_t): The mouse event information.
        """
        return View_Hooks.view_click(self, view, event)

    def view_dblclick(self, view: 'TWidget *', event: 'view_mouse_event_t') -> None:
        """
        Called when a double-click event occurs in the view.
        Args:
            view (TWidget *): The view where the double-click occurred.
            event (view_mouse_event_t): The mouse event information.
        """
        return View_Hooks.view_dblclick(self, view, event)

    def view_curpos(self, view: 'TWidget *') -> None:
        """
        Called when the cursor position in a view changes.
        Args:
            view (TWidget *): The view whose cursor position changed.
        """
        return View_Hooks.view_curpos(self, view)

    def view_created(self, view: 'TWidget *') -> None:
        """
        Called when a view is created.
        Args:
            view (TWidget *): The created view.
        """
        return View_Hooks.view_created(self, view)

    def view_close(self, view: 'TWidget *') -> None:
        """
        Called when a view is closed.
        Args:
            view (TWidget *): The closed view.
        """
        return View_Hooks.view_close(self, view)

    def view_switched(self, view: 'TWidget *', rt: 'tcc_renderer_type_t') -> None:
        """
        Called when a view's renderer has changed.
        Args:
            view (TWidget *): The view that was switched.
            rt (tcc_renderer_type_t): The new renderer type.
        """
        return View_Hooks.view_switched(self, view, rt)

    def view_mouse_over(self, view: 'TWidget *', event: 'view_mouse_event_t') -> None:
        """
        Called when the mouse moves over (or out of) a node or an edge.
        This is only relevant in a graph view.
        Args:
            view (TWidget *): The graph view.
            event (view_mouse_event_t): The mouse event information.
        """
        return View_Hooks.view_mouse_over(self, view, event)

    def view_loc_changed(
        self, view: 'TWidget *', now: 'lochist_entry_t const *', was: 'lochist_entry_t const *'
    ) -> None:
        """
        Called when the location for the view has changed.
        (Can be either the place_t, the renderer_info_t, or both.)
        Args:
            view (TWidget *): The view whose location changed.
            now (lochist_entry_t const *): The new location.
            was (lochist_entry_t const *): The previous location.
        """
        return View_Hooks.view_loc_changed(self, view, now, was)

    def view_mouse_moved(self, view: 'TWidget *', event: 'view_mouse_event_t') -> None:
        """
        Called when the mouse moved in the view.
        Args:
            view (TWidget *): The view where the mouse moved.
            event (view_mouse_event_t): The mouse event information.
        """
        return View_Hooks.view_mouse_moved(self, view, event)


class DecompilerHooks(_BaseHooks, Hexrays_Hooks):
    """
    Convenience class for decompiler events handling.
    """

    def __init__(self) -> None:
        _BaseHooks.__init__(self)
        Hexrays_Hooks.__init__(self)

    def hook(self) -> None:
        """
        Hook (activate) the event handlers.
        """
        if not self.is_hooked:
            if Hexrays_Hooks.hook(self):
                self._is_hooked = True

    def unhook(self) -> None:
        """
        Un-hook (de-activate) the event handlers.
        """
        if self.is_hooked:
            # returns False, assume it succeeded
            Hexrays_Hooks.unhook(self)
            self._is_hooked = False

    def flowchart(
        self, fc: 'qflow_chart_t', mba: 'mba_t', reachable_blocks: 'bitset_t', decomp_flags: int
    ) -> int:
        """
        Flowchart has been generated.
        Args:
            fc (qflow_chart_t): The flowchart object.
            mba (mba_t): The microcode basic block array.
            reachable_blocks (bitset_t): Set of reachable blocks.
            decomp_flags (int): Decompiler flags.
        Returns:
            int: Microcode error code.
        """
        return Hexrays_Hooks.flowchart(self, fc, mba, reachable_blocks, decomp_flags)

    def stkpnts(self, mba: 'mba_t', *sps: 'stkpnts*t *') -> int:
        """
        SP change points have been calculated.
        Args:
            mba (mba_t): The microcode basic block array.
            *sps (stkpnts*t *): Stack pointer change points.
        Returns:
            int: Microcode error codes code.
                This event is generated for each inlined range as well.
        """
        return Hexrays_Hooks.stkpnts(self, mba, *sps)

    def prolog(
        self, mba: 'mba_t', fc: 'qflow_chart_t', reachable_blocks: 'bitset_t', decomp_flags: int
    ) -> int:
        """
        Prolog analysis has been finished.
        Args:
            mba (mba_t): The microcode basic block array.
            fc (qflow_chart_t): The function's flowchart.
            reachable_blocks (bitset_t): Set of reachable blocks.
            decomp_flags (int): Decompiler flags.
        Returns:
            int: Microcode error codes code.
                This event is generated for each inlined range as well.
        """
        return Hexrays_Hooks.prolog(self, mba, fc, reachable_blocks, decomp_flags)

    def microcode(self, mba: 'mba_t') -> int:
        """
        Microcode has been generated.
        Args:
            mba (mba_t): The microcode basic block array.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.microcode(self, mba)

    def preoptimized(self, mba: 'mba_t') -> int:
        """
        Microcode has been preoptimized.
        Args:
            mba (mba_t): The microcode basic block array.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.preoptimized(self, mba)

    def locopt(self, mba: 'mba_t') -> int:
        """
        Basic block level optimization has been finished.
        Args:
            mba (mba_t): The microcode basic block array.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.locopt(self, mba)

    def prealloc(self, mba: 'mba_t') -> int:
        """
        Local variables: preallocation step begins.
        Args:
            mba (mba_t): The microcode basic block array. This event may occur several times.
        Returns:
            int: 1 if microcode was modified, otherwise negative values are Microcode error codes.
        """
        return Hexrays_Hooks.prealloc(self, mba)

    def glbopt(self, mba: 'mba_t') -> int:
        """
        Global optimization has been finished.
        If microcode is modified, MERR_LOOP must be returned.
        It will cause a complete restart of the optimization.
        Args:
            mba (mba_t): The microcode basic block array.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.glbopt(self, mba)

    def pre_structural(
        self, ct: 'control_graph_t *', cfunc: 'cfunc_t', g: 'simple_graph_t'
    ) -> int:
        """
        Structure analysis is starting.
        Args:
            ct (control_graph_t *): Control graph (input/output).
            cfunc (cfunc_t): The current function (input).
            g (simple_graph_t): Control flow graph (input).
        Returns:
            int: Microcode error codes code; MERR_BLOCK means that the analysis has been
                performed by a plugin.
        """
        return Hexrays_Hooks.pre_structural(self, ct, cfunc, g)

    def structural(self, ct: 'control_graph_t *') -> int:
        """
        Structural analysis has been finished.
        Args:
            ct (control_graph_t *): The control graph.
        """
        return Hexrays_Hooks.structural(self, ct)

    def maturity(self, cfunc: 'cfunc_t', new_maturity: 'ctree_maturity_t') -> int:
        """
        Ctree maturity level is being changed.
        Args:
            cfunc (cfunc_t): The cfunc object.
            new_maturity (ctree_maturity_t): New ctree maturity level.
        """
        return Hexrays_Hooks.maturity(self, cfunc, new_maturity)

    def interr(self, errcode: int) -> int:
        """
        Internal error has occurred.
        Args:
            errcode (int): The error code.
        """
        return Hexrays_Hooks.interr(self, errcode)

    def combine(self, blk: 'mblock_t', insn: 'minsn_t') -> int:
        """
        Trying to combine instructions of a basic block.
        Args:
            blk (mblock_t): The basic block.
            insn (minsn_t): The instruction.
        Returns:
            int: 1 if combined the current instruction with a preceding one,
                -1 if the instruction should not be combined,
                0 otherwise.
        """
        return Hexrays_Hooks.combine(self, blk, insn)

    def print_func(self, cfunc: 'cfunc_t', vp: 'vc_printer_t') -> int:
        """
        Printing ctree and generating text.
        It is forbidden to modify ctree at this event.
        Args:
            cfunc (cfunc_t): The cfunc object.
            vp (vc_printer_t): The vc_printer object.
        Returns:
            int: 1 if text has been generated by the plugin.
        """
        return Hexrays_Hooks.print_func(self, cfunc, vp)

    def func_printed(self, cfunc: 'cfunc_t') -> int:
        """
        Function text has been generated.
        Plugins may modify the text in cfunc_t::sv.
        However, it is too late to modify the ctree or microcode.
        The text uses regular color codes (see lines.hpp).
        COLOR_ADDR is used to store pointers to ctree items.
        Args:
            cfunc (cfunc_t): The cfunc object.
        """
        return Hexrays_Hooks.func_printed(self, cfunc)

    def resolve_stkaddrs(self, mba: 'mba_t') -> int:
        """
        The optimizer is about to resolve stack addresses.
        Args:
            mba (mba_t): The microcode basic block array.
        """
        return Hexrays_Hooks.resolve_stkaddrs(self, mba)

    def build_callinfo(self, blk: 'mblock_t', type: 'tinfo_t') -> 'PyObject *':
        """
        Analyzing a call instruction.
        Args:
            blk (mblock_t): Block; blk->tail is the call.
            type (tinfo_t): Buffer for the output type.
        """
        return Hexrays_Hooks.build_callinfo(self, blk, type)

    def callinfo_built(self, blk: 'mblock_t') -> int:
        """
        A call instruction has been analyzed.
        Args:
            blk (mblock_t): Block; blk->tail is the call.
        """
        return Hexrays_Hooks.callinfo_built(self, blk)

    def calls_done(self, mba: 'mba_t') -> int:
        """
        All calls have been analyzed.
        This event is generated immediately after analyzing all calls,
        before any optimizations, call unmerging and block merging.
        Args:
            mba (mba_t): The microcode basic block array.
        """
        return Hexrays_Hooks.calls_done(self, mba)

    def begin_inlining(self, cdg: 'codegen_t', decomp_flags: int) -> int:
        """
        Starting to inline outlined functions.
        This is an opportunity to inline other ranges.
        Args:
            cdg (codegen_t): The code generator object.
            decomp_flags (int): Decompiler flags.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.begin_inlining(self, cdg, decomp_flags)

    def inlining_func(self, cdg: 'codegen_t', blk: int, mbr: 'mba_ranges_t') -> int:
        """
        A set of ranges is going to be inlined.
        Args:
            cdg (codegen_t): The code generator object.
            blk (int): The block containing call/jump to inline.
            mbr (mba_ranges_t): The range to inline.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.inlining_func(self, cdg, blk, mbr)

    def inlined_func(
        self, cdg: 'codegen_t', blk: int, mbr: 'mba_ranges_t', i1: int, i2: int
    ) -> int:
        """
        A set of ranges got inlined.
        Args:
            cdg (codegen_t): The code generator object.
            blk (int): The block containing call/jump to inline.
            mbr (mba_ranges_t): The range to inline.
            i1 (int): Block number of the first inlined block.
            i2 (int): Block number of the last inlined block (excluded).
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.inlined_func(self, cdg, blk, mbr, i1, i2)

    def collect_warnings(self, cfunc: 'cfunc_t') -> int:
        """
        Collect warning messages from plugins.
        These warnings will be displayed at the function header, after the user-defined comments.
        Args:
            cfunc (cfunc_t): The cfunc object.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.collect_warnings(self, cfunc)

    def open_pseudocode(self, vu: 'vdui_t') -> int:
        """
        New pseudocode view has been opened.
        Args:
            vu (vdui_t): The pseudocode UI object.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.open_pseudocode(self, vu)

    def switch_pseudocode(self, vu: 'vdui_t') -> int:
        """
        Existing pseudocode view has been reloaded with a new function.
        Its text has not been refreshed yet, only cfunc and mba pointers are ready.
        Args:
            vu (vdui_t): The pseudocode UI object.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.switch_pseudocode(self, vu)

    def refresh_pseudocode(self, vu: 'vdui_t') -> int:
        """
        Existing pseudocode text has been refreshed.
        Adding/removing pseudocode lines is forbidden in this event.
        Args:
            vu (vdui_t): The pseudocode UI object. See also hxe_text_ready, which happens earlier.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.refresh_pseudocode(self, vu)

    def close_pseudocode(self, vu: 'vdui_t') -> int:
        """
        Pseudocode view is being closed.
        Args:
            vu (vdui_t): The pseudocode UI object.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.close_pseudocode(self, vu)

    def keyboard(self, vu: 'vdui_t', key_code: int, shift_state: int) -> int:
        """
        Keyboard has been hit.
        Args:
            vu (vdui_t): The pseudocode UI object.
            key_code (int): Virtual key code.
            shift_state (int): Keyboard shift state.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.keyboard(self, vu, key_code, shift_state)

    def right_click(self, vu: 'vdui_t') -> int:
        """
        Mouse right click.
        Use hxe_populating_popup instead, in case you want to add items in the popup menu.
        Args:
            vu (vdui_t): The pseudocode UI object.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.right_click(self, vu)

    def double_click(self, vu: 'vdui_t', shift_state: int) -> int:
        """
        Mouse double click.
        Args:
            vu (vdui_t): The pseudocode UI object.
            shift_state (int): Keyboard shift state.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.double_click(self, vu, shift_state)

    def curpos(self, vu: 'vdui_t') -> int:
        """
        Current cursor position has been changed.
        For example, by left-clicking or using keyboard.
        Args:
            vu (vdui_t): The pseudocode UI object.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.curpos(self, vu)

    def create_hint(self, vu: 'vdui_t') -> 'PyObject *':
        """
        Create a hint for the current item.
        Args:
            vu (vdui_t): The pseudocode UI object.
        Returns:
            PyObject: 0 to continue collecting hints with other subscribers,
            1 to stop collecting hints.
        """
        return Hexrays_Hooks.create_hint(self, vu)

    def text_ready(self, vu: 'vdui_t') -> int:
        """
        Decompiled text is ready.
        This event can be used to modify the output text (sv).
        Obsolete. Please use hxe_func_printed instead.
        Args:
            vu (vdui_t): The pseudocode UI object.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.text_ready(self, vu)

    def populating_popup(
        self, widget: 'TWidget *', popup_handle: 'TPopupMenu *', vu: 'vdui_t'
    ) -> int:
        """
        Populating popup menu. We can add menu items now.
        Args:
            widget (TWidget): The widget object.
            popup_handle (TPopupMenu): The popup menu handle.
            vu (vdui_t): The pseudocode UI object.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.populating_popup(self, widget, popup_handle, vu)

    def lvar_name_changed(self, vu: 'vdui_t', v: 'lvar_t', name: str, is_user_name: bool) -> int:
        """
        Local variable got renamed.
        Args:
            vu (vdui_t): The pseudocode UI object.
            v (lvar_t): The local variable object.
            name (str): The new variable name.
            is_user_name (bool): True if this is a user-provided name. Note: It is possible
                to read/write user settings for lvars directly from the idb.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.lvar_name_changed(self, vu, v, name, is_user_name)

    def lvar_type_changed(self, vu: 'vdui_t', v: 'lvar_t', tinfo: 'tinfo_t') -> int:
        """
        Local variable type got changed.
        Args:
            vu (vdui_t): The pseudocode UI object.
            v (lvar_t): The local variable object.
            tinfo (tinfo_t): The new type info. Note: It is possible to read/write
                user settings for lvars directly from the idb.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.lvar_type_changed(self, vu, v, tinfo)

    def lvar_cmt_changed(self, vu: 'vdui_t', v: 'lvar_t', cmt: str) -> int:
        """
        Local variable comment got changed.
        Args:
            vu (vdui_t): The pseudocode UI object.
            v (lvar_t): The local variable object.
            cmt (str): The new comment. Note: It is possible to read/write
                user settings for lvars directly from the idb.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.lvar_cmt_changed(self, vu, v, cmt)

    def lvar_mapping_changed(self, vu: 'vdui_t', frm: 'lvar_t', to: 'lvar_t') -> int:
        """
        Local variable mapping got changed.
        Args:
            vu (vdui_t): The pseudocode UI object.
            frm (lvar_t): The original local variable.
            to (lvar_t): The mapped local variable.
                Note: It is possible to read/write user settings for lvars directly from the idb.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.lvar_mapping_changed(self, vu, frm, to)

    def cmt_changed(self, cfunc: 'cfunc_t', loc: 'treeloc_t', cmt: str) -> int:
        """
        Comment got changed.
        Args:
            cfunc (cfunc_t): The decompiled function.
            loc (treeloc_t): The tree location of the comment.
            cmt (str): The new comment string.
        Returns:
            int: 1 if the event has been handled.
        """
        return Hexrays_Hooks.cmt_changed(self, cfunc, loc, cmt)

    def mba_maturity(self, mba: 'mba_t', reqmat: 'mba_maturity_t') -> int:
        """
        Maturity level of an MBA was changed.
        Args:
            mba (mba_t): The microcode block.
            reqmat (mba_maturity_t): Requested maturity level.
        Returns:
            int: Microcode error codes code.
        """
        return Hexrays_Hooks.mba_maturity(self, mba, reqmat)


# Type alias to be used as a shorthand for a list of zero or more hook instances
HooksList: TypeAlias = list[
    Union[ProcessorHooks, DatabaseHooks, DebuggerHooks, DecompilerHooks, UIHooks, ViewHooks]
]
